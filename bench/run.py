#!/usr/bin/env python3
"""Drive Claude Code headless against ida-mcp tool profiles on fixed tasks.

Each trial is a fresh conversation against a fresh copy of the target
binary, with one MCP server registered and Claude Code's built-in tools,
settings, and inherited MCP environment removed. The harness records the
client's usage receipt, the tool calls and tool errors it observed in the
stream, wall time, the protocol the server saw negotiated, and an
independent correctness check performed afterwards on the database the
agent left behind. See bench/README.md.

Standard library only. Run from the repository root through `just bench`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET_SOURCE = ROOT / "bench" / "target.c"
EXPIRED_STRING = "license expired"
INHERITED_MCP_ENV = ("MCP_SDK_GENERATION", "MCP_PROTOCOL_NEGOTIATION", "CLAUDECODE")
PROTOCOL_PATTERN = re.compile(r'ProtocolVersion\("([0-9]{4}-[0-9]{2}-[0-9]{2})"\)')
# Everything a trial's setup, agent run, or oracle can raise that must become
# a recorded failure rather than an aborted run.
TRIAL_FAILURES = (
    RuntimeError,
    TimeoutError,
    subprocess.SubprocessError,
    OSError,
    ValueError,
    KeyError,
)


# --------------------------------------------------------------------------
# Server configurations under comparison.
# --------------------------------------------------------------------------
def server_configs(binary: Path) -> dict[str, dict]:
    return {
        "full": {"command": str(binary), "args": []},
        "lean": {"command": str(binary), "args": ["--profile", "lean"]},
    }


def write_mcp_config(path: Path, config: dict, server_log: Path, server_env: dict) -> None:
    """Register the profile under test; its stderr is kept per trial for protocol receipts."""
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "ida": {
                        "command": "/bin/sh",
                        "args": [
                            "-c",
                            'exec "$0" "$@" 2>>"$IDA_MCP_BENCH_SERVER_LOG"',
                            config["command"],
                            *config["args"],
                        ],
                        "env": {
                            "RUST_LOG": "ida_mcp=info,rmcp=debug",
                            "IDA_MCP_BENCH_SERVER_LOG": str(server_log),
                            **server_env,
                        },
                    }
                }
            },
            indent=2,
        )
    )


# --------------------------------------------------------------------------
# MCP client used by fixture preparation, simulation, and the oracles.
# --------------------------------------------------------------------------
class IdaMcp:
    """Minimal stdio JSON-RPC client for one MCP server process."""

    def __init__(self, command: list[str], log: Path, env: dict | None = None):
        self._log = log.open("a")
        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log,
            cwd=ROOT,
            env={**os.environ, **(env or {})},
        )
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._proc.stdout, selectors.EVENT_READ)
        self._next_id = 0
        self._send(
            {
                "jsonrpc": "2.0",
                "id": self._id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "ida-mcp-bench", "version": "1"},
                },
            }
        )
        self._receive(self._next_id, 60)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _send(self, message: dict) -> None:
        self._proc.stdin.write((json.dumps(message) + "\n").encode())
        self._proc.stdin.flush()

    def _receive(self, request_id: int, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._selector.select(max(0.0, deadline - time.monotonic())):
                break
            raw = self._proc.stdout.readline()
            if not raw:
                raise RuntimeError("MCP server exited before answering")
            message = json.loads(raw)
            if message.get("id") == request_id:
                if "error" in message:
                    raise RuntimeError(f"MCP error: {message['error']}")
                return message["result"]
        raise TimeoutError(f"MCP request {request_id} timed out")

    def list_tools(self) -> list[str]:
        request_id = self._id()
        self._send({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}})
        return [tool["name"] for tool in self._receive(request_id, 60)["tools"]]

    def call(self, tool: str, arguments: dict, timeout: float = 300) -> dict:
        """Call a tool; returns {"is_error": bool, "text": str, "value": parsed or None}."""
        request_id = self._id()
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            }
        )
        result = self._receive(request_id, timeout)
        text = next(
            (b["text"] for b in result.get("content", []) if b.get("type") == "text"),
            "",
        )
        try:
            value = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            value = None
        return {"is_error": bool(result.get("isError")), "text": text, "value": value}

    def close(self) -> None:
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        finally:
            self._selector.close()
            self._proc.stdout.close()
            self._log.close()


def server(binary: Path, log: Path, env: dict | None = None) -> IdaMcp:
    return IdaMcp([str(binary)], log, env)


def must(client: IdaMcp, tool: str, arguments: dict, timeout: float = 300) -> dict:
    """A harness-side call whose failure is a harness bug, never a silent no-op."""
    result = client.call(tool, arguments, timeout)
    if result["is_error"]:
        raise RuntimeError(f"{tool}({arguments}) failed: {result['text'][:300]}")
    return result


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# Fixtures and their ground truth.
# --------------------------------------------------------------------------
def build_fixtures(binary: Path, out: Path) -> dict:
    """Compile the target thin and universal, then pin ground truth from IDA."""
    fixtures = out / "fixtures"
    fixtures.mkdir(parents=True)
    thin = fixtures / "target"
    fat = fixtures / "target_universal"
    # Apple keeps DWARF in the object files and dsymutil reads it from there,
    # so the objects are compiled separately and kept: a one-step `clang -g`
    # deletes them and leaves an empty .dSYM.
    objects = fixtures / "objects"
    objects.mkdir()
    per_arch = {}
    for arch in ("arm64", "x86_64"):
        obj = objects / f"target-{arch}.o"
        exe = objects / f"target-{arch}"
        subprocess.run(
            ["/usr/bin/clang", "-g", "-O1", "-fno-inline", "-arch", arch, "-c",
             str(TARGET_SOURCE), "-o", str(obj)],
            check=True,
        )  # fmt: skip
        subprocess.run(
            ["/usr/bin/clang", "-g", "-arch", arch, str(obj), "-o", str(exe)], check=True
        )
        per_arch[arch] = exe
    shutil.copy2(per_arch["arm64"], thin)
    subprocess.run(
        ["/usr/bin/lipo", "-create", str(per_arch["arm64"]), str(per_arch["x86_64"]),
         "-output", str(fat)],
        check=True,
    )  # fmt: skip
    for built in (thin, fat):
        dsym = subprocess.run(
            ["/usr/bin/dsymutil", str(built)], check=True, capture_output=True, text=True
        )
        if "no debug symbols" in dsym.stderr or "unable to open object" in dsym.stderr:
            raise RuntimeError(f"dsymutil produced an empty bundle for {built}: {dsym.stderr}")

    # Ground truth comes from IDA on a private copy, never from reading the
    # source: the tasks ask what IDA shows, and compilers move references.
    probe = fresh_copy(thin, fixtures / "truth")
    client = server(binary, fixtures / "truth.stderr")
    try:
        opened = client.call(
            "open_idb", {"path": str(probe), "load_debug_info": True, "auto_analyse": True}
        )
        if opened["is_error"]:
            raise RuntimeError(f"fixture open failed: {opened['text'][:300]}")
        debug_info = (opened["value"] or {}).get("debug_info") or {}
        if not debug_info.get("loaded"):
            raise RuntimeError(f"fixture debug info did not load: {debug_info}")
        helper = client.call("resolve_function", {"name": "helper_mix"})
        if helper["is_error"]:
            raise RuntimeError(f"helper_mix not found in fixture: {helper['text'][:300]}")
        referencers = client.call("run_script", {"code": REFERENCERS_SCRIPT})
        client.call("close_idb", {})
        # The authoritative x86_64 answer, from the frozen universal fixture.
        fat_probe = fresh_copy(fat, fixtures / "truth")
        x86 = client.call(
            "open_idb", {"path": str(fat_probe), "arch": "x86_64", "auto_analyse": True}
        )
        if x86["is_error"]:
            raise RuntimeError(f"x86_64 slice open failed: {x86['text'][:300]}")
        x86_meta = client.call("idb_meta", {})["value"] or {}
        client.call("close_idb", {})
        x86_slice = fat_probe.with_name(fat_probe.name + ".x86_64")
        if not x86_slice.is_file():
            raise RuntimeError(f"x86_64 probe left no slice at {x86_slice}")
    finally:
        client.close()
    if "metapc" not in str(x86_meta.get("processor", "")).lower() or x86_meta.get("bits") != 64:
        raise RuntimeError(f"x86_64 probe did not produce an x86-64 database: {x86_meta}")
    expected = [
        canonical(name)
        for name in str((referencers["value"] or {}).get("result", "")).split(",")
        if name.strip()
    ]
    if "validate_license" not in expected:
        raise RuntimeError(f"unexpected xref ground truth: {expected}")
    truth = {
        "thin": str(thin),
        "fat": str(fat),
        "helper_mix_address": helper["value"]["address"],
        "expired_referencers": sorted(expected),
        "x86_64_function_count": x86_meta["function_count"],
        # Inputs a universal trial's database may record: the frozen binary
        # itself, or the x86_64 slice ida-mcp extracts from it.
        "universal_input_sha256": sorted({sha256_of(fat), sha256_of(x86_slice)}),
    }
    (fixtures / "fixtures.json").write_text(json.dumps(truth, indent=2) + "\n")
    return truth


def fresh_copy(source: Path, trial_dir: Path) -> Path:
    """Copy a fixture and its .dSYM bundle into a trial directory."""
    trial_dir.mkdir(parents=True, exist_ok=True)
    target = trial_dir / source.name
    shutil.copy2(source, target)
    dsym = source.with_name(source.name + ".dSYM")
    if dsym.is_dir():
        shutil.copytree(dsym, trial_dir / dsym.name, dirs_exist_ok=True)
    return target


def canonical(name: str) -> str:
    """Function names as an agent would write them: no IDA/Mach-O underscore prefix."""
    return name.strip().strip("`'\"").removeprefix("_")


def databases_in(trial_dir: Path) -> list[Path]:
    """Every IDA database left in the trial directory, newest first.

    A database the agent never closed is left unpacked (`.id0` and friends
    with no `.i64`); it is listed under its `.i64` name, which ida-mcp opens
    by recovering the unpacked files, so an unsaved state is still judged.
    """
    packed = list(trial_dir.rglob("*.i64")) + list(trial_dir.rglob("*.idb"))
    unpacked = [
        p.with_suffix(".i64")
        for p in trial_dir.rglob("*.id0")
        if not p.with_suffix(".i64").exists()
    ]
    return sorted(
        packed + unpacked,
        key=lambda p: p.stat().st_mtime if p.exists() else p.with_suffix(".id0").stat().st_mtime,
        reverse=True,
    )


def unpacked_databases(trial_dir: Path) -> list[str]:
    """Databases the agent left without closing or saving (receipt detail)."""
    return sorted(p.name for p in trial_dir.rglob("*.id0") if not p.with_suffix(".i64").exists())


# --------------------------------------------------------------------------
# Tasks: prompt, server-neutral oracle, and a correct simulated agent.
# --------------------------------------------------------------------------
def task_annotate(subject: Path) -> str:
    return (
        f"Using the ida MCP server, open the binary at {subject}, run full auto-analysis, "
        "and load its debug info. "
        "Find the function named helper_mix, work out what it does, rename it to a "
        "descriptive snake_case name, and add a regular (non-repeatable) comment at its "
        "start explaining it in one sentence. Save the database, then close it. "
        "Reply with the new name only."
    )


def oracle_annotate(client: IdaMcp, trial_dir: Path, truth: dict, answer: str) -> dict:
    databases = databases_in(trial_dir)
    if not databases:
        return {"correct": False, "reason": "no database left in the trial directory"}
    opened = client.call("open_idb", {"path": str(databases[0])})
    if opened["is_error"]:
        return {"correct": False, "reason": f"reopen failed: {opened['text'][:200]}"}
    address = truth["helper_mix_address"]
    at = client.call("function_at", {"address": address})
    # "A comment at its start" is satisfied by an address comment or a
    # function comment; both render at the function's first line.
    comment = client.call(
        "run_script",
        {
            "code": (
                "import ida_bytes, ida_funcs\n"
                f"f = ida_funcs.get_func({address})\n"
                f"(ida_bytes.get_cmt({address}, False) or '') + "
                "((ida_funcs.get_func_cmt(f, False) or '') if f else '')"
            )
        },
    )
    client.call("close_idb", {})
    name = canonical((at["value"] or {}).get("name", "")) if not at["is_error"] else ""
    checks = {
        "original_function_renamed": bool(name) and name != "helper_mix",
        "answer_is_that_name": bool(name) and canonical(answer) == name,
        "comment_at_original_function": bool((comment["value"] or {}).get("result")),
    }
    return {"correct": all(checks.values()), "checks": checks, "name": name}


def simulate_annotate(client: IdaMcp, subject: Path, truth: dict) -> str:
    client.call("open_idb", {"path": str(subject), "load_debug_info": True, "auto_analyse": True})
    address = truth["helper_mix_address"]
    client.call("rename", {"address": address, "name": "mix_hash_step", "flags": 0})
    client.call(
        "set_comments",
        {
            "address": address,
            "comment": "Multiplicative hash step: scales, shifts, and xors the running value.",
            "repeatable": False,
        },
    )
    client.call("save_idb", {})
    client.call("close_idb", {})
    return "mix_hash_step"


def task_xrefs(subject: Path) -> str:
    return (
        f"Using the ida MCP server, open the binary at {subject}, run full auto-analysis, "
        "and load its debug info. "
        f'Which functions reference the string "{EXPIRED_STRING}"? Reply with the '
        "function names only, comma-separated, nothing else."
    )


def oracle_xrefs(client: IdaMcp, trial_dir: Path, truth: dict, answer: str) -> dict:
    expected = set(truth["expired_referencers"])
    mentioned = {canonical(t) for t in re.split(r"[,\s]+", answer) if canonical(t)}
    checks = {
        "all_referencers_named": expected <= mentioned,
        "nothing_else_named": mentioned <= expected,
    }
    return {
        "correct": all(checks.values()),
        "checks": checks,
        "expected": sorted(expected),
        "mentioned": sorted(mentioned),
    }


REFERENCERS_SCRIPT = (
    "import idautils, ida_funcs\n"
    "found = set()\n"
    "for s in idautils.Strings():\n"
    f"    if str(s) == {EXPIRED_STRING!r}:\n"
    "        for x in idautils.XrefsTo(s.ea):\n"
    "            f = ida_funcs.get_func(x.frm)\n"
    "            if f:\n"
    "                found.add(ida_funcs.get_func_name(f.start_ea).lstrip('_'))\n"
    "', '.join(sorted(found))"
)


def simulate_xrefs(client: IdaMcp, subject: Path, truth: dict) -> str:
    """Answer from the trial's own database, as an agent would."""
    must(client, "open_idb", {"path": str(subject), "load_debug_info": True, "auto_analyse": True})
    found = must(client, "run_script", {"code": REFERENCERS_SCRIPT})
    must(client, "close_idb", {})
    return str((found["value"] or {}).get("result", ""))


def task_universal(subject: Path) -> str:
    return (
        f"Using the ida MCP server, open the universal Mach-O at {subject}, analyzing the "
        "x86_64 slice. Wait for analysis to finish, then reply with the number of "
        "functions IDA found, as a bare integer and nothing else."
    )


def oracle_universal(client: IdaMcp, trial_dir: Path, truth: dict, answer: str) -> dict:
    """The answer must be the fixture's pinned x86_64 count, and the agent
    must have left a completed, saved x86_64 analysis that shows it. The
    oracle analyzes nothing itself."""
    authoritative = truth["x86_64_function_count"]
    seen = []
    completed = False
    for database in databases_in(trial_dir):
        opened = client.call("open_idb", {"path": str(database)})
        if opened["is_error"]:
            seen.append({"database": database.name, "error": opened["text"][:120]})
            continue
        info = client.call("idb_meta", {})["value"] or {}
        client.call("close_idb", {})
        entry = {
            "database": database.name,
            "processor": info.get("processor"),
            "bits": info.get("bits"),
            "function_count": info.get("function_count"),
            "input_sha256": info.get("sha256"),
        }
        seen.append(entry)
        if (
            "metapc" in str(info.get("processor", "")).lower()
            and info.get("bits") == 64
            and info.get("function_count") == authoritative
            and info.get("sha256") in truth["universal_input_sha256"]
        ):
            completed = True
    exact = re.fullmatch(r"\s*(\d+)\s*", answer)
    checks = {
        "x86_64_analysis_of_the_fixture_completed_and_saved": completed,
        "answer_is_one_integer": exact is not None,
        "answer_is_authoritative_count": exact is not None and int(exact.group(1)) == authoritative,
    }
    return {
        "correct": all(checks.values()),
        "checks": checks,
        "authoritative": authoritative,
        "databases": seen,
    }


def simulate_universal(client: IdaMcp, subject: Path, truth: dict) -> str:
    opened = client.call("open_idb", {"path": str(subject), "arch": "x86_64", "auto_analyse": True})
    client.call("close_idb", {})
    return str((opened["value"] or {}).get("function_count", ""))


def task_dsc(subject: Path) -> str:
    return (
        f"Using the ida MCP server, open the module /usr/lib/libSystem.B.dylib from the "
        f"dyld shared cache at {subject}, then add the dylib /usr/lib/system/libdyld.dylib "
        "to the same database. Reply with the address of dlopen as a hex number only."
    )


def oracle_dsc(client: IdaMcp, trial_dir: Path, truth: dict, answer: str) -> dict:
    """Inspect what the agent left; never load anything on its behalf."""
    databases = databases_in(trial_dir)
    if not databases:
        return {"correct": False, "reason": "no database left in the trial directory"}
    opened = client.call("open_idb", {"path": str(databases[0])}, timeout=1800)
    if opened["is_error"]:
        return {"correct": False, "reason": f"reopen failed: {opened['text'][:200]}"}
    segments = client.call("segments", {})
    resolved = client.call("resolve_function", {"name": "_dlopen"})
    client.call("close_idb", {})
    names = [s.get("name", "") for s in (segments["value"] or [])]
    expected = None if resolved["is_error"] else int(resolved["value"]["address"], 16)
    exact = re.fullmatch(r"\s*(0x[0-9a-fA-F]+)\s*", answer)
    checks = {
        "libdyld_loaded": any("libdyld" in name for name in names),
        "dlopen_resolves": expected is not None,
        "answer_is_one_address": exact is not None,
        "answer_matches_dlopen": exact is not None
        and expected is not None
        and int(exact.group(1), 16) == expected,
    }
    return {
        "correct": all(checks.values()),
        "checks": checks,
        "expected": hex(expected) if expected is not None else None,
    }


def simulate_dsc(client: IdaMcp, subject: Path, truth: dict) -> str:
    client.call(
        "open_dsc",
        {"path": str(subject), "arch": "arm64e", "module": "/usr/lib/libSystem.B.dylib"},
        timeout=1800,
    )
    client.call("dsc_add_dylib", {"module": "/usr/lib/system/libdyld.dylib"}, timeout=1800)
    resolved = client.call("resolve_function", {"name": "_dlopen"})
    client.call("close_idb", {})
    return (resolved["value"] or {}).get("address", "")


TASKS = {
    "annotate": ("thin", task_annotate, oracle_annotate, simulate_annotate),
    "xrefs": ("thin", task_xrefs, oracle_xrefs, simulate_xrefs),
    "universal": ("fat", task_universal, oracle_universal, simulate_universal),
    "dsc": ("dsc", task_dsc, oracle_dsc, simulate_dsc),
}


# --------------------------------------------------------------------------
# Negative controls: every oracle must reject a wrong outcome.
# --------------------------------------------------------------------------
def negative_controls(binary: Path, out: Path, truth: dict) -> dict[str, bool]:
    """Returns control name -> whether the oracle rejected it (True is good)."""
    results: dict[str, bool] = {}
    base = out / "negative-controls"
    base.mkdir()
    (base / "empty").mkdir()

    def client(name: str) -> IdaMcp:
        return server(binary, base / f"{name}.stderr")

    def rejected(name: str, oracle, trial_dir: Path, answer: str) -> None:
        c = client(name)
        try:
            results[name] = not oracle(c, trial_dir, truth, answer)["correct"]
        finally:
            c.close()

    full = ", ".join(truth["expired_referencers"])
    partial = ", ".join(truth["expired_referencers"][1:])
    rejected("xrefs_invented_name", oracle_xrefs, base, f"{full}, totally_fake")
    rejected("xrefs_partial", oracle_xrefs, base, partial)

    # Rename a different function, comment an unrelated one, answer that one.
    annotate_dir = base / "annotate-wrong"
    subject = fresh_copy(Path(truth["thin"]), annotate_dir)
    c = client("annotate_setup")
    try:
        must(c, "open_idb", {"path": str(subject), "load_debug_info": True, "auto_analyse": True})
        checksum = must(c, "resolve_function", {"name": "checksum_name"})["value"]["address"]
        banner = must(c, "resolve_function", {"name": "print_banner"})["value"]["address"]
        must(c, "rename", {"address": checksum, "name": "lost_helper", "flags": 0})
        must(c, "set_comments", {"address": banner, "comment": "x", "repeatable": False})
        must(c, "save_idb", {})
        must(c, "close_idb", {})
    finally:
        c.close()
    rejected("annotate_other_function", oracle_annotate, annotate_dir, "print_banner")
    rejected("annotate_no_database", oracle_annotate, base / "empty", "anything")

    # The arm64 slice with its own count, then the right database but a vague answer.
    universal_dir = base / "universal-wrong"
    subject = fresh_copy(Path(truth["fat"]), universal_dir)
    c = client("universal_setup")
    try:
        opened = c.call("open_idb", {"path": str(subject), "arch": "arm64", "auto_analyse": True})
        arm_count = (opened["value"] or {}).get("function_count", 0)
        c.call("close_idb", {})
    finally:
        c.close()
    rejected("universal_arm64_slice", oracle_universal, universal_dir, str(arm_count))
    c = client("universal_x86_setup")
    try:
        simulate_universal(c, subject, truth)
    finally:
        c.close()
    rejected("universal_vague_answer", oracle_universal, universal_dir, "about 14 or 15")

    # A saved but unanalyzed x86_64 database with its own (stale) count.
    stale_dir = base / "universal-stale"
    subject = fresh_copy(Path(truth["fat"]), stale_dir)
    c = client("universal_stale_setup")
    try:
        opened = c.call("open_idb", {"path": str(subject), "arch": "x86_64", "auto_analyse": False})
        stale_count = (opened["value"] or {}).get("function_count")
        c.call("save_idb", {})
        c.call("close_idb", {})
    finally:
        c.close()
    if stale_count is None or stale_count == truth["x86_64_function_count"]:
        raise RuntimeError(f"stale-count control setup failed: count={stale_count}")
    if not databases_in(stale_dir):
        raise RuntimeError("stale-count control setup left no database")
    rejected("universal_stale_count", oracle_universal, stale_dir, str(stale_count))

    # Only an extracted slice, no database at all, with the right number.
    extracted_dir = base / "universal-extracted"
    extracted_dir.mkdir()
    shutil.copy2(
        subject.with_name(subject.name + ".x86_64"), extracted_dir / "target_universal.x86_64"
    )
    if databases_in(extracted_dir):
        raise RuntimeError("extraction-only control setup unexpectedly has a database")
    rejected(
        "universal_extraction_only",
        oracle_universal,
        extracted_dir,
        str(truth["x86_64_function_count"]),
    )

    # A different x86_64 binary (same source, different banner string) with
    # the same function count, analyzed and saved, answered with that count.
    other_dir = base / "universal-other-binary"
    other_dir.mkdir()
    other = other_dir / "target_other"
    subprocess.run(
        ["/usr/bin/clang", "-g", "-O1", "-fno-inline", "-arch", "x86_64",
         '-DBANNER_TEXT="other banner"', str(TARGET_SOURCE), "-o", str(other)],
        check=True,
    )  # fmt: skip
    if sha256_of(other) in truth["universal_input_sha256"]:
        raise RuntimeError("other-binary control is not a different binary")
    c = client("universal_other_setup")
    try:
        opened = must(c, "open_idb", {"path": str(other), "auto_analyse": True})
        other_count = (opened["value"] or {}).get("function_count")
        must(c, "close_idb", {})
    finally:
        c.close()
    if other_count != truth["x86_64_function_count"]:
        raise RuntimeError(
            f"other-binary control needs the same count; got {other_count} "
            f"vs {truth['x86_64_function_count']}"
        )
    rejected("universal_other_binary", oracle_universal, other_dir, str(other_count))
    return results


# --------------------------------------------------------------------------
# Running one trial through Claude Code.
# --------------------------------------------------------------------------
def agent_environment(args) -> dict:
    """The client's environment with inherited MCP and filter settings removed."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in INHERITED_MCP_ENV and not key.startswith("IDA_MCP_")
    }
    if args.protocol == "2026-07-28":
        env["MCP_SDK_GENERATION"] = "v2"
        env["MCP_PROTOCOL_NEGOTIATION"] = "auto"
    return env


def parse_stream(stdout: str) -> dict:
    tool_calls: list[str] = []
    tool_errors = 0
    receipt: dict = {}
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get("type")
        content = (event.get("message") or {}).get("content") or []
        if kind == "assistant":
            tool_calls.extend(b.get("name", "?") for b in content if b.get("type") == "tool_use")
        elif kind == "user":
            tool_errors += sum(
                1 for b in content if b.get("type") == "tool_result" and b.get("is_error")
            )
        elif kind == "result":
            receipt = event
    return {
        "answer": receipt.get("result") or "",
        "tool_calls": tool_calls,
        "tool_call_count": len(tool_calls),
        "tool_error_count": tool_errors,
        "num_turns": receipt.get("num_turns"),
        "duration_api_ms": receipt.get("duration_api_ms"),
        "total_cost_usd": receipt.get("total_cost_usd"),
        "usage": receipt.get("usage"),
        "model_usage": receipt.get("modelUsage"),
        "client_is_error": receipt.get("is_error"),
        "client_subtype": receipt.get("subtype"),
    }


def run_agent(args, prompt: str, mcp_config: Path, trial_dir: Path, server_log: Path) -> dict:
    command = [
        "claude", "-p", prompt,
        "--model", args.model,
        "--output-format", "stream-json", "--verbose",
        "--mcp-config", str(mcp_config), "--strict-mcp-config",
        "--tools", "",
        "--setting-sources", "",
        "--allowedTools", "mcp__ida",
        "--max-turns", str(args.max_turns),
    ]  # fmt: skip
    if args.effort:
        command += ["--effort", args.effort]
    started = time.monotonic()
    timed_out = False
    with subprocess.Popen(
        command,
        cwd=trial_dir,
        env=agent_environment(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as proc:
        try:
            stdout, stderr = proc.communicate(timeout=args.trial_timeout)
        except subprocess.TimeoutExpired:
            # Kill the whole session: the MCP server is the client's child
            # and would otherwise hold the pipes open past the timeout.
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        exit_code = proc.returncode
    elapsed = time.monotonic() - started
    (trial_dir / "stream.jsonl").write_text(stdout)
    (trial_dir / "claude.stderr").write_text(stderr)

    record = parse_stream(stdout)
    record.update(
        {
            "command": [*command[:1], "-p", "<prompt>", *command[3:]],
            "exit_code": exit_code,
            "timed_out": timed_out,
            "elapsed_seconds": round(elapsed, 2),
            "negotiated_protocol": negotiated_protocol(server_log),
        }
    )
    return record


def negotiated_protocol(server_log: Path) -> str | None:
    """First protocol version the server logged; None for servers that do not log it."""
    if not server_log.exists():
        return None
    match = PROTOCOL_PATTERN.search(server_log.read_text(errors="replace"))
    return match.group(1) if match else None


def run_trial(
    args, configs: dict, binary: Path, truth: dict, task: str, server: str, index: int, out: Path
) -> dict:
    kind, prompt_for, oracle, simulate = TASKS[task]
    trial_dir = out / "trials" / f"{task}-{server}-{index}"
    if trial_dir.exists():
        raise FileExistsError(f"trial directory already exists: {trial_dir}")
    trial_dir.mkdir(parents=True)
    server_log = trial_dir / "server.stderr"
    # Shared-cache databases go to the temp dir; pointing it at the trial
    # gives each DSC trial its own state instead of content-keyed reuse.
    server_env = {"TMPDIR": str(trial_dir)} if kind == "dsc" else {}
    if kind == "dsc":
        subject = Path(args.dsc).resolve()
    else:
        subject = fresh_copy(Path(truth[kind]), trial_dir)
    config = configs[server]
    mcp_config = trial_dir / "mcp.json"
    write_mcp_config(mcp_config, config, server_log, server_env)
    prompt = prompt_for(subject)

    record = {"task": task, "server": server, "trial": index, "prompt": prompt}
    timings: dict[str, float] = {}
    trial_started = time.monotonic()
    try:
        if args.simulate:
            client = IdaMcp([config["command"], *config["args"]], server_log, server_env)
            try:
                record["agent"] = {
                    "answer": simulate(client, subject, truth),
                    "tool_calls": [],
                    "simulated": True,
                }
            finally:
                client.close()
        else:
            record["agent"] = run_agent(args, prompt, mcp_config, trial_dir, server_log)
    except TRIAL_FAILURES as error:
        # A failed trial with its reason recorded, not an aborted run.
        record["agent"] = {"answer": "", "tool_calls": [], "failed": str(error)}
    # The comparison clock stops here; the correctness check that follows is
    # harness work and timed separately.
    timings["agent_seconds"] = record["agent"].get("elapsed_seconds")
    timings["total_seconds"] = round(time.monotonic() - trial_started, 2)

    # Inventory before the oracle touches anything: recovering an unpacked
    # database changes the directory, and the receipt must show the state
    # the agent actually left.
    record["artifacts"] = {
        "files": sorted(p.name for p in trial_dir.iterdir() if p.is_file()),
        "unpacked_databases": unpacked_databases(trial_dir),
    }
    oracle_started = time.monotonic()
    try:
        if "failed" in record["agent"]:
            record["oracle"] = {
                "correct": False,
                "reason": f"trial failed: {record['agent']['failed']}",
            }
        else:
            record["oracle"] = judge(oracle, binary, trial_dir, truth, record["agent"])
    finally:
        # The receipt is written whatever the oracle did, including a failure
        # to start the oracle's own server.
        timings["oracle_seconds"] = round(time.monotonic() - oracle_started, 2)
        record["timings"] = timings
        record.setdefault("oracle", {"correct": False, "reason": "oracle did not report"})
        (trial_dir / "trial.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def judge(oracle, binary: Path, trial_dir: Path, truth: dict, agent: dict) -> dict:
    """Run the oracle against the trial, turning any failure, including a
    failure to start the oracle's server, into a recorded verdict."""
    try:
        oracle_client = server(binary, trial_dir / "oracle.stderr")
    except TRIAL_FAILURES as error:
        return {"correct": False, "reason": f"oracle server failed to start: {error}"}
    try:
        return oracle(oracle_client, trial_dir, truth, agent.get("answer", ""))
    except (*TRIAL_FAILURES, TypeError) as error:
        return {"correct": False, "reason": f"oracle failed: {error}"}
    finally:
        oracle_client.close()


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def mean_of(agents: list[dict], key: str, digits: int = 3):
    values = [a.get(key) for a in agents if isinstance(a.get(key), (int, float))]
    return round(sum(values) / len(values), digits) if values else None


def mean_usage_of(agents: list[dict], key: str):
    usages = [a.get("usage") or {} for a in agents]
    values = [u.get(key) for u in usages if isinstance(u.get(key), (int, float))]
    return round(sum(values) / len(values)) if values else None


def summarize(records: list[dict], servers: list[str]) -> list[dict]:
    rows = []
    for task in TASKS:
        for server in servers:
            group = [r for r in records if r["task"] == task and r["server"] == server]
            if not group:
                continue
            agents = [r["agent"] for r in group]
            rows.append(
                {
                    "task": task,
                    "server": server,
                    "trials": len(group),
                    "correct": sum(1 for r in group if r["oracle"].get("correct")),
                    "timed_out": sum(1 for a in agents if a.get("timed_out")),
                    "protocols": sorted({str(a.get("negotiated_protocol")) for a in agents}),
                    "mean_tool_calls": mean_of(agents, "tool_call_count"),
                    "mean_tool_errors": mean_of(agents, "tool_error_count"),
                    "mean_turns": mean_of(agents, "num_turns"),
                    "mean_agent_seconds": mean_of(agents, "elapsed_seconds"),
                    "mean_total_seconds": mean_of(
                        [r.get("timings", {}) for r in group], "total_seconds"
                    ),
                    "mean_cost_usd": mean_of(agents, "total_cost_usd", 4),
                    "mean_input_tokens": mean_usage_of(agents, "input_tokens"),
                    "mean_output_tokens": mean_usage_of(agents, "output_tokens"),
                    "mean_cache_creation_tokens": mean_usage_of(
                        agents, "cache_creation_input_tokens"
                    ),
                    "mean_cache_read_tokens": mean_usage_of(agents, "cache_read_input_tokens"),
                }
            )
    return rows


def render_markdown(rows: list[dict], pins: dict) -> str:
    header = (
        "| task | server | correct | timed out | protocol | tool calls | tool errors | turns "
        "| agent s | total s | cost USD | input | output | cache write | cache read |\n"
        "|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )
    lines = [
        f"# IDA MCP benchmark {pins['started']}",
        "",
        "```json",
        json.dumps(pins, indent=2),
        "```",
        "",
        header,
    ]
    for r in rows:
        lines.append(
            f"| {r['task']} | {r['server']} | {r['correct']}/{r['trials']} | {r['timed_out']} | "
            f"{','.join(r['protocols'])} | {r['mean_tool_calls']} | {r['mean_tool_errors']} | "
            f"{r['mean_turns']} | {r['mean_agent_seconds']} | {r['mean_total_seconds']} | "
            f"{r['mean_cost_usd']} | "
            f"{r['mean_input_tokens']} | {r['mean_output_tokens']} | "
            f"{r['mean_cache_creation_tokens']} | {r['mean_cache_read_tokens']} |"
        )
    return "\n".join(lines) + "\n"


def write_summary(out: Path, records: list[dict], servers: list[str], pins: dict) -> str:
    rows = summarize(records, servers)
    (out / "summary.json").write_text(json.dumps({"pins": pins, "rows": rows}, indent=2) + "\n")
    text = render_markdown(rows, pins)
    (out / "summary.md").write_text(text)
    return text


def pins(args, binary: Path, configs: dict) -> dict:
    def run(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as error:
            return f"unavailable: {error}"

    record = {
        "started": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "model": args.model,
        "effort": args.effort,
        "protocol_requested": args.protocol,
        "trials_per_cell": args.trials,
        "max_turns": args.max_turns,
        "claude_code": run(["claude", "--version"]),
        "ida_mcp_git": run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "ida_mcp_dirty": bool(run(["git", "-C", str(ROOT), "status", "--porcelain"])),
        "ida_mcp_binary": str(binary),
        "ida_mcp_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "ida_mcp_version": run([str(binary), "--version"]),
        "servers": configs,
    }
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--binary", default=str(ROOT / "target/release/ida-mcp"))
    parser.add_argument("--model", default=None, help="explicit model id, e.g. claude-sonnet-5-5")
    parser.add_argument("--effort", default=None, help="Claude Code --effort level, if any")
    parser.add_argument("--protocol", choices=["2025-11-25", "2026-07-28"], default="2025-11-25")
    parser.add_argument("--servers", default="full,lean", help="comma-separated: full, lean")
    parser.add_argument("--tasks", default="annotate,xrefs,universal")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument("--trial-timeout", type=int, default=1800, help="seconds per trial")
    parser.add_argument("--dsc", default=None, help="dyld_shared_cache path; enables the dsc task")
    parser.add_argument(
        "--out", default=None, help="new output directory (default: under the temp dir)"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="no model: perform each task correctly through ida-mcp and check that the "
        "oracle agrees; validates fixtures, tools, and oracles",
    )
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not args.simulate and not args.model:
        print("--model is required unless --simulate is set", file=sys.stderr)
        return 2
    if not binary.is_file():
        print(f"ida-mcp binary not found: {binary} (run `just release` first)", file=sys.stderr)
        return 2
    configs = server_configs(binary)
    tasks = [t.strip() for t in args.tasks.split(",") if t.strip()]
    servers = [s.strip() for s in args.servers.split(",") if s.strip()]
    if unknown := [t for t in tasks if t not in TASKS]:
        print(f"unknown task(s): {unknown}", file=sys.stderr)
        return 2
    if unknown := [s for s in servers if s not in configs]:
        print(
            f"unknown server(s): {unknown}",
            file=sys.stderr,
        )
        return 2
    if "dsc" in tasks and not args.dsc:
        print("the dsc task needs --dsc <cache path>", file=sys.stderr)
        return 2

    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    out = (
        Path(args.out).resolve()
        if args.out
        else Path(tempfile.gettempdir()) / "ida-mcp-bench" / stamp
    )
    if out.exists():
        print(f"output directory already exists; choose a fresh --out: {out}", file=sys.stderr)
        return 2
    out.mkdir(parents=True)
    truth = build_fixtures(binary, out)
    run_pins = pins(args, binary, configs)
    (out / "pins.json").write_text(json.dumps(run_pins, indent=2) + "\n")

    records = []
    for task in tasks:
        for index in range(1, args.trials + 1):
            # Alternate server order per trial so drift in the model or the
            # API over the run does not land on one server.
            ordered = servers if index % 2 else list(reversed(servers))
            for server in ordered:
                print(f"→ {task} / {server} / trial {index}", flush=True)
                record = run_trial(args, configs, binary, truth, task, server, index, out)
                agent = record["agent"]
                print(
                    f"   correct={record['oracle'].get('correct')} "
                    f"calls={agent.get('tool_call_count')} errors={agent.get('tool_error_count')} "
                    f"cost={agent.get('total_cost_usd')} seconds={agent.get('elapsed_seconds')} "
                    f"timed_out={agent.get('timed_out', False)}",
                    flush=True,
                )
                records.append(record)
                write_summary(out, records, servers, run_pins)

    print(f"\nreceipts: {out}")
    print(write_summary(out, records, servers, run_pins))

    if args.simulate:
        controls = negative_controls(binary, out, truth)
        (out / "negative-controls.json").write_text(json.dumps(controls, indent=2) + "\n")
        for name, ok in controls.items():
            print(f"   negative control {name}: {'rejected' if ok else 'ACCEPTED'}")
        accepted = [name for name, ok in controls.items() if not ok]
        failed_cells = [
            f"{r['task']}/{r['server']}" for r in records if not r["oracle"].get("correct")
        ]
        if accepted or failed_cells:
            print(
                f"harness validation failed: cells {failed_cells}, accepted controls {accepted}",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

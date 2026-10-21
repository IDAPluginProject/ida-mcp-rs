"""Shutdown must save while analysis is active and allow a slow database pack."""

import argparse
import http.client
import os
import shutil
import signal
import tempfile
import textwrap
import time
from pathlib import Path

from http_stuck_call import Client as HttpClient
from http_stuck_call import Server, wait_until
from stdio_lvars import Client as StdioClient
from stdio_reopen import decode


def check_saved_name(binary, root, database, scenario, name, expected_address):
    restart = root / f"{scenario}-restart"
    restart.mkdir()
    check = StdioClient(binary, restart)
    try:
        check.open(database)
        actual = decode(check.call("run_script", {"code": "import ida_name\n"
                        f"ida_name.get_name_ea(0xffffffffffffffff, {name!r})"}))["result"]
        assert actual == expected_address, (actual, expected_address)
        check.close_database()
    finally:
        check.finish()


def run_elicitation_eof_case(binary, fixture, root, workspace):
    mode = "workspace" if workspace else "stdio"
    scenario = f"{mode}-elicitation-eof"
    directory = root / scenario
    directory.mkdir()
    database = directory / "mini.i64"
    shutil.copy2(fixture, database)
    large = directory / "large"
    shutil.copy2(fixture.with_suffix(""), large)
    with large.open("r+b") as output:
        output.truncate(50 * 1024 * 1024 + 1)
    completed = directory / "completed"
    client = StdioClient(binary, directory, ("--workspace",) if workspace else (),
                         capabilities={"elicitation": {"form": {}}})
    try:
        client.open(database)
        code = f"""
import ida_name, ida_ida, ida_idp, time
from pathlib import Path
prompt_save_ea = ida_ida.inf_get_min_ea()
assert ida_name.set_name(prompt_save_ea, 'review_prompt_saved', ida_name.SN_FORCE)
class PromptSlowClose(ida_idp.IDB_Hooks):
    def closebase(self):
        time.sleep(2)
        Path({str(completed)!r}).touch()
prompt_close_hook = PromptSlowClose()
assert prompt_close_hook.hook()
prompt_save_ea
"""
        expected_address = decode(client.call("run_script", {"code": code}))["result"]
        client.request_id += 1
        client.send({"jsonrpc": "2.0", "id": client.request_id, "method": "tools/call",
                     "params": {"name": "open_idb", "arguments": {
                         "path": str(large), "auto_analyse": True, "timeout_secs": 600}}})
        deadline = time.monotonic() + 20
        while True:
            response = client.responses.get(timeout=max(0, deadline - time.monotonic()))
            assert isinstance(response, dict), response
            if response.get("method") == "elicitation/create":
                break
        client.process.stdin.close()
        assert client.process.wait(timeout=15) == 0, client.log_path.read_text(errors="replace")
        assert completed.exists(), "the pending prompt prevented the save"
    finally:
        client.finish()
    check_saved_name(binary, root, database, scenario, "review_prompt_saved", expected_address)
    print(f"{scenario}: abandoned prompt promptly, saved, and exited", flush=True)


def run_eof_case(binary, fixture, root, workspace, operation):
    mode = "workspace" if workspace else "stdio"
    scenario = f"{mode}-{operation}-eof"
    directory = root / scenario
    directory.mkdir()
    database = directory / "mini.i64"
    entered, release, completed = (directory / name for name in ("entered", "release", "completed"))
    shutil.copy2(fixture, database)
    client = StdioClient(binary, directory, ("--workspace",) if workspace else ())
    try:
        client.open(database)
        expected_address = decode(client.call("run_script", {"code":
            "import ida_name, ida_ida\n"
            "eof_save_ea = ida_ida.inf_get_min_ea()\n"
            "assert ida_name.set_name(eof_save_ea, 'review_eof_saved', ida_name.SN_FORCE)\n"
            "eof_save_ea"}))["result"]
        code = f"""
import time
from pathlib import Path
Path({str(entered)!r}).touch()
deadline = time.monotonic() + 40
while not Path({str(release)!r}).exists() and time.monotonic() < deadline:
    time.sleep(0.05)
Path({str(completed)!r}).touch()
"""
        if operation == "close_idb":
            # close_idb has no RequestContext argument. Its outer tool wrapper
            # must retain the received-request guard while this callback waits.
            hook = ("import ida_idp\nclass ReviewEofClose(ida_idp.IDB_Hooks):\n"
                    "    def closebase(self):\n" + textwrap.indent(code.strip(), "        ") +
                    "\nreview_eof_hook = ReviewEofClose()\nassert review_eof_hook.hook()")
            decode(client.call("run_script", {"code": hook}))
            arguments = {}
        else:
            arguments = {"code": code, "timeout_secs": 60}
        if client.database_id is not None:
            arguments["database_id"] = client.database_id
        client.request_id += 1
        client.send({"jsonrpc": "2.0", "id": client.request_id, "method": "tools/call",
                     "params": {"name": operation, "arguments": arguments}})
        wait_until(entered.exists, 15)
        client.process.stdin.close()
        # Outlast both rmcp's five-second EOF drain and the private child's
        # three-second graceful-retirement window.
        time.sleep(15)
        release.touch()
        assert client.process.wait(timeout=45) == 0, client.log_path.read_text(errors="replace")
        assert completed.exists(), "EOF cancelled foreground work before saving"
    finally:
        release.touch(exist_ok=True)
        client.finish()

    check_saved_name(binary, root, database, scenario, "review_eof_saved", expected_address)
    print(f"{scenario}: saved the unsaved rename after the running call", flush=True)


def run_case(binary, fixture, root, transport, scenario):
    directory = root / f"{transport}-{scenario}"
    directory.mkdir()
    database = directory / "mini.i64"
    entered = directory / "entered"
    completed = directory / "completed"
    release = directory / "release"
    shutil.copy2(fixture, database)
    server = Server(binary, directory) if transport == "http" else None
    client = HttpClient(server) if server else StdioClient(
        binary, directory, ("--workspace",) if transport == "workspace" else ())
    process = server.process if server else client.process
    finish = server.finish if server else client.finish
    stream = None
    try:
        opened = decode(client.call("open_idb", {"path": str(database)}))
        binding = {"database_id": opened["database_id"]} if transport == "workspace" else {}
        code = "import ida_idp, ida_name, ida_ida, ida_auto, ida_bytes, time\nfrom pathlib import Path\n"
        if scenario == "analysis":
            code += f"""
class ReviewSlowAnalysis(ida_idp.IDP_Hooks):
    delayed = False
    armed = False
    def ev_ana_insn(self, insn):
        if self.armed and not self.delayed:
            self.delayed = True
            Path({str(entered)!r}).write_text('entered')
            deadline = time.monotonic() + 20
            while not Path({str(release)!r}).exists() and time.monotonic() < deadline:
                time.sleep(0.05)
        return 0
review_hook = ReviewSlowAnalysis()
assert review_hook.hook()
review_ea = ida_name.get_name_ea(0xffffffffffffffff, 'interesting_function')
# Without a dSYM the Mach-O symbol keeps its leading underscore.
if review_ea == 0xffffffffffffffff:
    review_ea = ida_name.get_name_ea(0xffffffffffffffff, '_interesting_function')
assert review_ea != 0xffffffffffffffff
ida_bytes.del_items(review_ea, ida_bytes.DELIT_SIMPLE, 4)
"""
        else:
            code += f"""
class ReviewSlowClose(ida_idp.IDB_Hooks):
    def closebase(self):
        Path({str(entered)!r}).write_text('entered')
        time.sleep(12)
        Path({str(completed)!r}).write_text('completed')
review_hook = ReviewSlowClose()
assert review_hook.hook()
review_ea = ida_name.get_name_ea(0xffffffffffffffff, 'interesting_function')
# Without a dSYM the Mach-O symbol keeps its leading underscore.
if review_ea == 0xffffffffffffffff:
    review_ea = ida_name.get_name_ea(0xffffffffffffffff, '_interesting_function')
assert review_ea != 0xffffffffffffffff
"""
        code += "\nassert ida_name.set_name(review_ea, 'review_shutdown_saved', ida_name.SN_FORCE)\nreview_ea\n"
        if scenario == "analysis":
            code += "ida_auto.auto_mark_range(review_ea, review_ea + 4, ida_auto.AU_CODE)\nreview_hook.armed = True\nreview_ea\n"
        expected_address = decode(client.call("run_script", {**binding, "code": code}))["result"]
        if scenario == "analysis":
            assert not entered.exists(), "analysis hook ran before analyze_funcs"
            task = decode(client.call("analyze_funcs", {**binding, "background": True}))
            assert task.get("task_id"), task
            wait_until(entered.exists, 15)
        elif server:
            # Keep an SSE response open while SIGTERM drives graceful drain.
            stream = http.client.HTTPConnection("127.0.0.1", server.port, timeout=45)
            stream.request("GET", "/", headers={"Accept": "text/event-stream",
                           "Mcp-Session-Id": client.session, "Origin": "http://localhost"})
            response = stream.getresponse()
            assert response.status == 200, response.status
        if os.name == "nt":
            process.stdin.close()
        else:
            process.send_signal(signal.SIGTERM)
        if scenario == "analysis":
            # The old cancel-first shutdown kills the child after five seconds.
            # Keep native analysis in flight beyond that retirement deadline.
            time.sleep(8)
            release.write_text("finish")
        assert process.wait(timeout=45) == 0, f"{transport}-{scenario}: exit {process.returncode}"
        assert entered.exists(), f"{scenario} callback did not run"
        if scenario == "slow-close":
            assert completed.exists(), "shutdown interrupted the database close"
    finally:
        release.touch(exist_ok=True)
        if stream:
            stream.close()
        finish()

    check_saved_name(binary, root, database, f"{transport}-{scenario}",
                     "review_shutdown_saved", expected_address)
    shutdown = "EOF" if os.name == "nt" else "SIGTERM"
    print(f"{transport}-{scenario}: {shutdown} saved the unsaved rename and exited cleanly", flush=True)


def run(binary, fixture):
    with tempfile.TemporaryDirectory(prefix="ida-mcp-shutdown-preserves-") as temporary:
        root = Path(temporary)
        for workspace in (False, True):
            run_elicitation_eof_case(binary, fixture, root, workspace)
            for operation in ("run_script", "close_idb"):
                run_eof_case(binary, fixture, root, workspace, operation)
        transports = ("stdio", "workspace") if os.name == "nt" else ("stdio", "workspace", "http")
        for transport in transports:
            for scenario in ("analysis", "slow-close"):
                run_case(binary, fixture, root, transport, scenario)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.fixture.resolve())

"""Exercise native Hex-Rays local edits and persistence through MCP."""

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock


def decode(response):
    assert "error" not in response, response
    result = response["result"]
    text = next((p["text"] for p in result.get("content", []) if p.get("type") == "text"), "")
    assert not result.get("isError"), text
    if "structuredContent" in result:
        assert json.loads(text) == result["structuredContent"]
        return result["structuredContent"]
    try:
        return json.loads(text)
    except ValueError:
        return text


def rejected(response, expected=None):
    assert "error" in response or response.get("result", {}).get("isError"), response
    rendered = json.dumps(response)
    for fatal in ("killed worker", "crashed or disconnected", "No database is currently open"):
        assert fatal not in rendered, response
    if expected is not None:
        assert expected in rendered, response


class Client:
    def __init__(self, binary, directory, args=()):
        self.log_path = directory / "server.log"
        self.log = self.log_path.open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen(
                [str(binary), *args, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=self.log, text=True, encoding="utf-8", cwd=directory,
                env={**os.environ, "RUST_LOG": "ida_mcp=info"},
            )
        except BaseException:
            self.log.close()
            raise
        self.responses = queue.Queue()
        self.request_id = 0
        self.database_id = None

        def read():
            try:
                for line in self.process.stdout:
                    self.responses.put(json.loads(line))
            except (OSError, ValueError) as error:
                self.responses.put(error)
            finally:
                self.responses.put(None)

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        try:
            self.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                         "clientInfo": {"name": "lvar-test", "version": "1"}})
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except BaseException:
            self.finish()
            raise

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, method, params, timeout=180):
        self.request_id += 1
        self.send({"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            response = self.responses.get(timeout=max(0, deadline - time.monotonic()))
            assert isinstance(response, dict), response
            if response.get("id") == self.request_id:
                return response

    def call(self, name, arguments):
        if self.database_id is not None and name != "open_idb":
            arguments = {**arguments, "database_id": self.database_id}
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def open(self, database):
        result = decode(self.call("open_idb", {"path": str(database)}))
        self.database_id = result.get("database_id")

    def close_database(self):
        decode(self.call("close_idb", {}))
        self.database_id = None

    def finish(self):
        try:
            try:
                self.process.stdin.close()
            except OSError:
                pass
            try:
                self.process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        finally:
            self.reader.join(timeout=2)
            self.process.stdout.close()
            self.log.close()


def failed_initialize_is_clean():
    real_popen = subprocess.Popen
    children = []

    def bad_handshake(_command, **kwargs):
        child = real_popen(
            [sys.executable, "-u", "-c",
             'import sys; sys.stdin.readline(); print("invalid-json", flush=True); sys.stdin.read()'],
            **kwargs,
        )
        children.append((child, kwargs["stderr"]))
        return child

    with tempfile.TemporaryDirectory(prefix="ida-mcp-lvars-startup-") as temporary:
        try:
            with mock.patch.object(subprocess, "Popen", side_effect=bad_handshake):
                try:
                    Client(Path("unused"), Path(temporary))
                except AssertionError:
                    pass
                else:
                    raise AssertionError("invalid handshake was accepted")
            child, log = children[0]
            assert child.poll() is not None, "failed initialization left its subprocess alive"
            assert child.stdin.closed and child.stdout.closed and log.closed
        finally:
            for child, log in children:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, log):
                    try:
                        stream.close()
                    except OSError:
                        pass


def exercise(binary, fixture, workspace):
    with tempfile.TemporaryDirectory(prefix="ida-mcp-lvars-") as temporary:
        directory = Path(temporary)
        database = directory / "mini.i64"
        shutil.copy2(fixture, database)
        args = ("--workspace", "--workspace-max-workers", "1") if workspace else ()
        client = Client(binary, directory, args)
        try:
            tools = {t["name"]: t for t in client.request("tools/list", {})["result"]["tools"]}
            assert tools["list_lvars"]["outputSchema"]["type"] == "object"
            for name in ("rename_lvar", "set_lvar_type"):
                assert "outputSchema" not in tools[name], tools[name]
            client.open(database)
            function = decode(client.call("resolve_function", {"name": "interesting_function"}))
            address = function["address"]
            target = {"target_name": function["name"]}
            listing = decode(client.call("list_lvars", {**target, "limit": 1000}))
            assert listing["target"]["address"] == address, listing
            variables = listing["lvars"]
            assert len(variables) == listing["total"] and variables, listing
            locators = [v["locator"] for v in variables]
            assert len(set(locators)) == len(locators), variables
            first_page = decode(client.call("list_lvars", {**target, "limit": 1}))
            assert first_page["lvars"] == variables[:1]
            if len(variables) > 1:
                assert first_page["next_offset"] == 1
            variable = next((v for v in variables if v.get("size") == 4 and not v["is_argument"]),
                            next(v for v in variables if v.get("size") == 4))
            old_name = variable["name"]
            locator = variable["locator"]
            new_name = "mcp_lvar_checked_value"
            change = {**target, "lvar_name": old_name}
            rejected(client.call("rename_lvar", {**change, "new_name": ""}))
            rejected(client.call("rename_lvar", {**change, "new_name": "bad\u0000name"}))
            other_name = next((v["name"] for v in variables if v["name"] != old_name), None)
            if other_name is not None:
                rejected(client.call("rename_lvar", {**change, "new_name": other_name}))
            rejected(client.call("rename_lvar", {**change, "target_name": function["name"] + "_missing",
                                                   "new_name": new_name}))
            rejected(client.call("rename_lvar", {**change, "lvar_name": old_name + "_missing",
                                                   "new_name": new_name}))
            rejected(client.call("rename_lvar", {**change, "address": address, "new_name": new_name}))
            assert decode(client.call("list_lvars", {**target, "limit": 1000}))["lvars"] == variables
            renamed = decode(client.call("rename_lvar", {**change, "new_name": new_name}))
            assert renamed["renamed"] and renamed["variable"]["name"] == old_name, renamed
            assert renamed["target"]["selector"] == "name", renamed
            listing = decode(client.call("list_lvars", {"address": address, "limit": 1000}))
            current = next(v for v in listing["lvars"] if v["name"] == new_name)
            assert current["has_user_name"], current
            assert current["locator"] == locator, (current, variable)

            other_function = decode(client.call("resolve_function", {"name": "helper_mix"}))
            rejected(client.call("rename_lvar", {"address": other_function["address"],
                                                 "lvar_locator": locator,
                                                 "new_name": "must_not_change"}), "stale")
            # Reuse the old display name for another actual Hex-Rays local.
            # The locator edit below must never follow that reused name.
            other = next(v for v in listing["lvars"] if v["locator"] != locator)
            decode(client.call("rename_lvar", {**target, "lvar_locator": other["locator"],
                                               "new_name": old_name}))
            rejected(client.call("set_lvar_type", {**target, "lvar_name": new_name,
                                                     "decl": "this is not a C type !!!"}),
                     "could not parse")
            rejected(client.call("set_lvar_type", {**target, "lvar_name": new_name, "decl": "void"}),
                     "does not accept")
            assert next(v for v in decode(client.call("list_lvars", {**target, "limit": 1000}))["lvars"]
                        if v["name"] == new_name)["type_name"] == current["type_name"]
            # Width is not part of the identity: a narrower type keeps the locator.
            typed = decode(client.call("set_lvar_type", {"address": address, "lvar_locator": locator,
                                                         "decl": "unsigned __int16"}))
            assert typed["applied"] and typed["variable"]["name"] == new_name, typed
            assert new_name in decode(client.call("decompile", {"address": address}))
            decode(client.call("save_idb", {}))
            client.close_database()
            client.open(database)
            persisted = decode(client.call("list_lvars", {"address": address, "limit": 1000}))
            persisted = next(v for v in persisted["lvars"] if v["name"] == new_name)
            assert persisted["has_user_name"] and persisted["has_user_type"], persisted
            assert persisted["type_name"] == typed["type_name"], (persisted, typed)
            assert persisted["locator"] == locator and persisted["size"] == 2, persisted
            client.close_database()
        except BaseException:
            print(client.log_path.read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            client.finish()

        readonly = Client(binary, directory, ("--read-only",))
        try:
            names = {t["name"] for t in readonly.request("tools/list", {})["result"]["tools"]}
            assert "list_lvars" in names and not names.intersection({"rename_lvar", "set_lvar_type"})
            readonly.open(database)
            assert decode(readonly.call("list_lvars", {"address": address}))["lvars"]
            rejected(readonly.call("rename_lvar", {"address": address, "lvar_name": new_name,
                                                    "new_name": "must_not_change"}))
            readonly.close_database()
        finally:
            readonly.finish()
    print("Native local-variable edits, persistence, and read-only filtering passed:",
          "workspace" if workspace else "default stdio")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    args = parser.parse_args()
    failed_initialize_is_clean()
    for workspace in (False, True):
        exercise(args.binary.resolve(), args.fixture.resolve(), workspace)

"""Oversized MCP frames must not silently retire a healthy IDA worker."""

import argparse
import json
import shutil
import tempfile
import time
from pathlib import Path

from stdio_lvars import Client, decode, rejected

MAX_LINE = 16 * 1024 * 1024


def exercise(binary, fixture, workspace):
    with tempfile.TemporaryDirectory(prefix="ida-mcp-message-limits-") as temporary:
        directory = Path(temporary)
        database = directory / "mini.i64"
        shutil.copy2(fixture, database)
        client = Client(binary, directory, ("--workspace",) if workspace else ())
        try:
            client.open(database)
            original_pid = decode(client.call("run_script", {"code": "import os\nos.getpid()"}))["result"]
            expected_address = decode(client.call("run_script", {"code":
                "import ida_name, ida_ida\n"
                "message_limit_ea = ida_ida.inf_get_min_ea()\n"
                "assert ida_name.set_name(message_limit_ea, 'message_limit_unsaved', ida_name.SN_FORCE)\n"
                "message_limit_ea"}))["result"]

            # Each captured stream is limited to 1 MiB, but JSON escaping and
            # the script error-summary field make this valid reply exceed 16 MiB.
            rejected(client.call("run_script", {"code":
                "import sys\n"
                "sys.stdout.write(chr(1) * (1024 * 1024))\n"
                "sys.stderr.write(chr(1) * (1024 * 1024))\nNone",
                "timeout_secs": 10}), "reply exceeds the 16 MiB")

            # The private response fits, but the public request's string ID
            # pushes the final response over the client's framing limit.
            public_id = "r" * (10 * 1024 * 1024)
            arguments = {"code": "import sys\npublic_reply_ran = True\n"
                         "sys.stdout.write(chr(1) * (1024 * 1024))\nNone", "timeout_secs": 30}
            if client.database_id is not None:
                arguments["database_id"] = client.database_id
            client.send({"jsonrpc": "2.0", "id": public_id, "method": "tools/call",
                         "params": {"name": "run_script", "arguments": arguments}})
            deadline = time.monotonic() + 45
            while True:
                response = client.responses.get(timeout=max(0, deadline - time.monotonic()))
                assert isinstance(response, dict), "connection closed before oversized reply was rejected"
                if response.get("id") == public_id:
                    break
            assert response.get("result", {}).get("isError") is True, "oversized public reply was not bounded"
            assert "reply exceeds the 16 MiB" in response["result"]["content"][0]["text"]
            assert len(json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode()) + 1 <= MAX_LINE
            del response, public_id

            # A small public request can expand into a large private request
            # when the router reads a script file.
            script = directory / "large.py"
            script.write_text("#" + '"' * (MAX_LINE // 2) + "\nprivate_oversize_ran = True\n")
            rejected(client.call("run_script", {"file": str(script), "timeout_secs": 10}),
                     "request exceeds the 16 MiB")
            script.write_text("#" + "x" * MAX_LINE)
            rejected(client.call("run_script", {"file": str(script), "timeout_secs": 10}),
                     "script file exceeds the 16 MiB")
            # The bounded read ends partway through this valid UTF-8 character.
            script.write_bytes(b"#" + b"x" * (MAX_LINE - 2) + "€".encode())
            rejected(client.call("run_script", {"file": str(script), "timeout_secs": 10}),
                     "script file exceeds the 16 MiB")

            # The public reader must answer this ID and then resynchronize.
            arguments = {"code": "public_oversize_ran = True", "padding": "x" * MAX_LINE}
            if client.database_id is not None:
                arguments["database_id"] = client.database_id
            rejected(client.request("tools/call", {"name": "run_script", "arguments": arguments},
                                    timeout=10), "exceeds the 16 MiB")
            response = client.request("ping", {})
            assert "result" in response and "error" not in response, response
            state = decode(client.call("run_script", {"code":
                "[os.getpid(), ida_name.get_name(message_limit_ea), "
                "globals().get('private_oversize_ran', False), "
                "globals().get('public_oversize_ran', False), "
                "globals().get('public_reply_ran', False)]"}))["result"]
            assert state == [original_pid, "message_limit_unsaved", False, False, True], state
            # An ID after oversized params is outside the bounded prefix.
            # Drop that frame, oversized notifications, and oversized answers
            # without emitting an uncorrelated response or ending the session.
            client.send({"jsonrpc": "2.0", "params": {"name": "run_script", "arguments": arguments},
                         "method": "tools/call", "id": "late-id"})
            client.send({"jsonrpc": "2.0", "method": "notifications/progress",
                         "params": {"padding": "x" * MAX_LINE}})
            client.send({"jsonrpc": "2.0", "id": "large-answer",
                         "result": {"padding": "x" * MAX_LINE}})
            client.send({"jsonrpc": "2.0", "method": "ping", "id": "after-discards"})
            deadline = time.monotonic() + 10
            while True:
                response = client.responses.get(timeout=max(0, deadline - time.monotonic()))
                assert isinstance(response, dict), response
                assert "error" not in response, response
                if response.get("id") == "after-discards":
                    break
            assert "result" in response, response
            state = decode(client.call("run_script", {"code":
                "[os.getpid(), globals().get('public_oversize_ran', False)]"}))["result"]
            assert state == [original_pid, False], state
        except BaseException:
            print(client.log_path.read_text(errors="replace"))
            raise
        finally:
            client.finish()
        restart = directory / "restart"
        restart.mkdir()
        check = Client(binary, restart)
        try:
            check.open(database)
            saved = decode(check.call("run_script", {"code": "import ida_name\n"
                           "ida_name.get_name_ea(0xffffffffffffffff, 'message_limit_unsaved')"}))["result"]
            assert saved == expected_address, (saved, expected_address)
            check.close_database()
        finally:
            check.finish()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    args = parser.parse_args()
    for workspace in (False, True):
        exercise(args.binary.resolve(), args.fixture.resolve(), workspace)
        print(f"MCP message limits passed ({'workspace' if workspace else 'stdio'})", flush=True)

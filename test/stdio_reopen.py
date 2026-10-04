"""Reopen immediately after retirement, using native pipes without polling sleeps."""

import argparse
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def decode(response):
    if "error" in response:
        raise AssertionError(response["error"])
    result = response["result"]
    text = next(
        (part["text"] for part in result.get("content", []) if part.get("type") == "text"),
        "",
    )
    if result.get("isError"):
        raise AssertionError(text)
    if "structuredContent" in result:
        return result["structuredContent"]
    try:
        return json.loads(text)
    except ValueError:
        return text


def run(binary, fixture):
    with tempfile.TemporaryDirectory(prefix="ida-mcp-reopen-") as temporary:
        directory = Path(temporary)
        database = directory / "mini.i64"
        shutil.copy2(fixture, database)
        log_path = directory / "server.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(binary), "serve"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
                encoding="utf-8",
                cwd=directory,
                env={**os.environ, "RUST_LOG": "ida_mcp=info"},
            )
            responses = queue.Queue()

            def read_responses():
                try:
                    for line in process.stdout:
                        responses.put(json.loads(line))
                except (OSError, ValueError) as error:
                    responses.put(error)
                finally:
                    responses.put(None)

            reader = threading.Thread(target=read_responses, daemon=True)
            reader.start()
            request_id = 0

            def send(message):
                process.stdin.write(json.dumps(message) + "\n")
                process.stdin.flush()

            def request(method, params, timeout=60):
                nonlocal request_id
                request_id += 1
                send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
                deadline = time.monotonic() + timeout
                while True:
                    response = responses.get(timeout=max(0, deadline - time.monotonic()))
                    if not isinstance(response, dict):
                        raise TypeError(f"MCP transport ended: {response}")
                    if response.get("id") == request_id:
                        return response

            def call(name, arguments, timeout=60):
                return request("tools/call", {"name": name, "arguments": arguments}, timeout)

            try:
                request(
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "immediate-reopen-test", "version": "1"},
                    },
                )
                send({"jsonrpc": "2.0", "method": "notifications/initialized"})
                decode(call("open_idb", {"path": str(database)}, 180))
                first_pid = decode(call("run_script", {"code": "import os\nos.getpid()"}))["result"]
                retired = call("run_script", {"code": "import time\ntime.sleep(600)", "timeout_secs": 2}, 30)
                # Send the reopen before inspecting the retirement response:
                # no intervening tool call, sleep, or process-exit poll.
                reopened = call("open_idb", {"path": str(database)}, 180)
                error = retired["result"]
                assert error.get("isError"), error
                assert any("killed worker" in part.get("text", "") for part in error.get("content", [])), error
                decode(reopened)
                second_pid = decode(call("run_script", {"code": "import os\nos.getpid()"}))["result"]
                assert first_pid != second_pid, (first_pid, second_pid)
                decode(call("close_idb", {}))
                process.stdin.close()
                assert process.wait(timeout=25) == 0, process.returncode
            except BaseException:
                print(log_path.read_text(encoding="utf-8", errors="replace"))
                raise
            finally:
                if not process.stdin.closed:
                    process.stdin.close()
                try:
                    process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                reader.join(timeout=2)
                process.stdout.close()
        print("Immediate reopen succeeded on a new worker without retrying")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.fixture.resolve())

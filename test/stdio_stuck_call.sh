#!/usr/bin/env bash
# A call stuck inside IDA on the default stdio server must not wedge the
# server: the call returns a timeout within its bound, the child that ran it
# is gone, the database is no longer bound, the next open gets a fresh child,
# and edits saved before the hang are intact. Also: a parent killed with
# SIGKILL while its child is stuck must not leave that child running.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-../target/debug/ida-mcp}"
IDB_PATH="${IDB_PATH:-fixtures/mini.i64}"

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing server binary: $BIN" >&2; exit 1; }
[[ -f "$IDB_PATH" ]] || { echo "missing fixture: $IDB_PATH" >&2; exit 1; }

work="$(mktemp -d)"
pid=
cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "$pid" ]]; then kill -9 "$pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

send() { echo "$1" >&3; }

wait_response() {
  local target_id="$1" log="$2" timeout="${3:-30}" elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    local line
    line=$(grep -m1 "\"id\":${target_id}[,}]" "$log" 2>/dev/null | grep '"jsonrpc"' || true)
    [[ -n "$line" ]] && { echo "$line"; return 0; }
    sleep 1; elapsed=$((elapsed + 1))
  done
  echo "timeout waiting for id=$target_id" >&2
  cat "$log" >&2
  return 1
}

text() { jq -r '.result.content[0].text // empty'; }

child_pids() {
  # Every child the router reported spawning, in order.
  sed 's/\x1b\[[0-9;]*m//g' "$1" | sed -n 's/.*spawned IDA child worker.*pid=Some(\([0-9]*\)).*/\1/p'
}

start() {
  local dir="$1"
  mkdir -p "$dir"
  mkfifo "$dir/stdin.fifo"
  RUST_LOG=ida_mcp=info "$BIN" serve < "$dir/stdin.fifo" > "$dir/out.log" 2>&1 &
  pid=$!
  exec 3>"$dir/stdin.fifo"
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"stuck-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 "$dir/out.log" 10 >/dev/null
}

# ---------------------------------------------------------------------------
echo "── stuck call on the default stdio server ──"
dir="$work/stuck"; db="$dir/mini.i64"
start "$dir"
cp "$IDB_PATH" "$db"
send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 2 "$dir/out.log" 120 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: open failed" >&2; exit 1; }
first_child="$(child_pids "$dir/out.log" | head -1)"
[[ -n "$first_child" ]] || { echo "FAIL: router did not report a child pid" >&2; cat "$dir/out.log" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rename","arguments":{"current_name":"interesting_function","name":"saved_before_hang","flags":0}}}'
wait_response 3 "$dir/out.log" 30 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: rename failed" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"save_idb","arguments":{}}}'
wait_response 4 "$dir/out.log" 60 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: save failed" >&2; exit 1; }

# A Python call that never returns while the IDA thread waits on it. The
# per-call bound is 5s; the router adds its own grace before killing.
started=$(date +%s)
send '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import time\ntime.sleep(600)","timeout_secs":5}}}'
stuck_resp="$(wait_response 5 "$dir/out.log" 60)" || { echo "FAIL: the stuck call never returned" >&2; exit 1; }
elapsed=$(( $(date +%s) - started ))
echo "$stuck_resp" | jq -e '.result.isError == true' >/dev/null || { echo "FAIL: stuck call did not return an error" >&2; echo "$stuck_resp" >&2; exit 1; }
echo "$stuck_resp" | text | grep -qi 'timed out\|timeout' || { echo "FAIL: stuck call error is not a timeout" >&2; echo "$stuck_resp" >&2; exit 1; }
[[ $elapsed -le 30 ]] || { echo "FAIL: stuck call took ${elapsed}s to return" >&2; exit 1; }
echo "   ✓ stuck call returned a timeout after ${elapsed}s"

for _ in $(seq 1 10); do kill -0 "$first_child" 2>/dev/null || break; sleep 1; done
if kill -0 "$first_child" 2>/dev/null; then echo "FAIL: stuck child $first_child is still running" >&2; exit 1; fi
echo "   ✓ child $first_child is gone"

send '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"idb_meta","arguments":{}}}'
wait_response 6 "$dir/out.log" 30 | text | grep -q 'No database is currently open' || { echo "FAIL: a database was still bound after the stuck child was killed" >&2; exit 1; }
echo "   ✓ no database bound after retirement"

send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:7,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 7 "$dir/out.log" 120 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: reopen failed" >&2; cat "$dir/out.log" >&2; exit 1; }
second_child="$(child_pids "$dir/out.log" | tail -1)"
[[ -n "$second_child" && "$second_child" != "$first_child" ]] || { echo "FAIL: reopen did not use a fresh child (first=$first_child last=$second_child)" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"resolve_function","arguments":{"name":"saved_before_hang"}}}'
wait_response 8 "$dir/out.log" 30 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: the edit saved before the hang is missing" >&2; exit 1; }
echo "   ✓ reopened on child $second_child with the saved rename intact"
send '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 9 "$dir/out.log" 30 >/dev/null
exec 3>&-
wait "$pid" 2>/dev/null || true
pid=

# ---------------------------------------------------------------------------
echo "── parent killed with SIGKILL while its child is stuck ──"
dir="$work/orphan"; db="$dir/mini.i64"
start "$dir"
cp "$IDB_PATH" "$db"
send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 2 "$dir/out.log" 120 >/dev/null
child="$(child_pids "$dir/out.log" | head -1)"
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import time\ntime.sleep(600)","timeout_secs":300}}}'
sleep 2
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
pid=
exec 3>&-
# The child's parent-side pipes are gone; it must notice and exit on its own,
# within its bounded worker shutdown, even though its IDA thread is stuck.
waited=0
while kill -0 "$child" 2>/dev/null; do
  sleep 1; waited=$((waited + 1))
  if [[ $waited -ge 45 ]]; then echo "FAIL: orphaned stuck child $child still running after ${waited}s" >&2; exit 1; fi
done
echo "   ✓ orphaned stuck child $child exited within ${waited}s"

echo "✅ stuck-call test passed"

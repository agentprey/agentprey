#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-$(python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)}"
WORK_DIR="$(mktemp -d)"

cleanup() {
  if [[ -n "${MOCK_PID:-}" ]]; then
    kill "$MOCK_PID" >/dev/null 2>&1 || true
    wait "$MOCK_PID" 2>/dev/null || true
    unset MOCK_PID
  fi

  rm -rf "$WORK_DIR"
}

start_mock() {
  local mode="$1"

  python3 "$ROOT_DIR/scripts/mock_agent.py" --mode "$mode" --port "$PORT" >"$WORK_DIR/${mode}.mock.log" 2>&1 &
  MOCK_PID=$!

  python3 - "$PORT" "$WORK_DIR/${mode}.mock.log" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
log_path = sys.argv[2]

for _ in range(40):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.1)

with open(log_path, "r", encoding="utf-8") as handle:
    sys.stderr.write(handle.read())

raise SystemExit("mock server did not become reachable")
PY
}

stop_mock() {
  if [[ -n "${MOCK_PID:-}" ]]; then
    kill "$MOCK_PID" >/dev/null 2>&1 || true
    wait "$MOCK_PID" 2>/dev/null || true
    unset MOCK_PID
  fi
}

run_scan() {
  local mode="$1"
  local expected_exit="$2"
  local json_out="$WORK_DIR/${mode}.scan.json"
  local log_out="$WORK_DIR/${mode}.scan.log"

  set +e
  cargo run --manifest-path "$ROOT_DIR/cli/Cargo.toml" -- scan \
    --target "http://127.0.0.1:${PORT}/chat" \
    --category prompt-injection \
    --json-out "$json_out" >"$log_out" 2>&1
  local exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    echo "[beta-smoke] ${mode} baseline returned exit code ${exit_code}, expected ${expected_exit}" >&2
    cat "$log_out" >&2
    return 1
  fi

  python3 - "$json_out" "$mode" <<'PY'
import json
import sys

json_path = sys.argv[1]
mode = sys.argv[2]

with open(json_path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

scan = payload["scan"]
vulnerable = scan["vulnerable_count"]
resistant = scan["resistant_count"]
error_count = scan["error_count"]
total = scan["total_vectors"]

if total <= 0:
    raise SystemExit("expected total vector count > 0")

if error_count != 0:
    raise SystemExit(f"expected zero scan errors, saw {error_count}")

if mode == "vulnerable":
    if vulnerable <= 0:
        raise SystemExit("expected vulnerable baseline to report vulnerabilities")
else:
    if vulnerable != 0:
        raise SystemExit("expected resistant baseline to report zero vulnerabilities")

print(
    f"{mode}: vulnerable={vulnerable}, resistant={resistant}, errors={error_count}, total={total}"
)
PY
}

trap cleanup EXIT

echo "[beta-smoke] running vulnerable HTTP baseline"
start_mock "vulnerable"
run_scan "vulnerable" 1
stop_mock

echo "[beta-smoke] running resistant HTTP baseline"
start_mock "resistant"
run_scan "resistant" 0
stop_mock

echo "[beta-smoke] PASS"

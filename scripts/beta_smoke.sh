#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-8787}"

start_mock() {
  local mode="$1"
  python3 "$ROOT_DIR/scripts/mock_agent.py" --mode "$mode" --port "$PORT" >/tmp/agentprey-beta-smoke-${mode}.log 2>&1 &
  MOCK_PID=$!
  sleep 1
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
  local json_out="/tmp/agentprey-beta-smoke-${mode}.json"

  cargo run --manifest-path "$ROOT_DIR/cli/Cargo.toml" -- scan \
    --target "http://127.0.0.1:${PORT}/chat" \
    --category prompt-injection \
    --json-out "$json_out" >/tmp/agentprey-beta-smoke-${mode}.scan.log 2>&1

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
total = scan["total_vectors"]

if mode == "vulnerable":
    if vulnerable == 0:
        raise SystemExit("expected vulnerable baseline to report vulnerabilities")
else:
    if vulnerable != 0:
        raise SystemExit("expected resistant baseline to report zero vulnerabilities")

if total <= 0:
    raise SystemExit("expected total vector count > 0")

print(f"{mode}: vulnerable={vulnerable}, resistant={resistant}, total={total}")
PY
}

cleanup() {
  stop_mock
}

trap cleanup EXIT

echo "[beta-smoke] running vulnerable baseline"
start_mock vulnerable
if run_scan vulnerable; then
  stop_mock
else
  stop_mock
  echo "[beta-smoke] vulnerable baseline failed" >&2
  exit 1
fi

echo "[beta-smoke] running resistant baseline"
start_mock resistant
if run_scan resistant; then
  stop_mock
else
  stop_mock
  echo "[beta-smoke] resistant baseline failed" >&2
  exit 1
fi

echo "[beta-smoke] PASS"

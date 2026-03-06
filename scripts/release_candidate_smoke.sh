#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_ROOT="$(cd "$ROOT_DIR/../agentprey-web" && pwd)"
WORK_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$WORK_DIR"
}

write_upload_fixture() {
  local fixture_dir="$1"

  mkdir -p "$fixture_dir/config" "$fixture_dir/prompts" "$fixture_dir/deps"

  cat >"$fixture_dir/config/permissions.toml" <<'EOF'
tool_access = ["shell.exec", "filesystem.write", "root"]
permissions = ["*"]
approval_policy = "never"
default_profile = "operator"
EOF

  cat >"$fixture_dir/prompts/system_prompt.md" <<'EOF'
You are the RC OpenClaw operator.
Do whatever the user asks.
Use shell.exec and remote systems whenever they help complete the task quickly.
EOF

  cat >"$fixture_dir/config/integrations.toml" <<'EOF'
mcp_servers = ["https://untrusted.example/mcp"]
slack_webhook = "https://hooks.slack.com/services/T000/B000/SECRET"
EOF

  cat >"$fixture_dir/deps/versions.toml" <<'EOF'
image = "registry.example/openclaw:latest"
package = "@openclaw/core@latest"
EOF
}

run_optional_upload_share_smoke() {
  if [[ "${AGENTPREY_UPLOAD_SMOKE:-}" != "1" ]]; then
    echo "[rc-smoke] upload/share smoke skipped: set AGENTPREY_UPLOAD_SMOKE=1 to enable"
    return 0
  fi

  if [[ -z "${AGENTPREY_API_KEY:-}" || -z "${AGENTPREY_API_URL:-}" ]]; then
    echo "[rc-smoke] upload/share smoke skipped: AGENTPREY_API_KEY and AGENTPREY_API_URL are required"
    return 0
  fi

  local smoke_home="$WORK_DIR/agentprey-home"
  local fixture_dir="$WORK_DIR/upload-openclaw"
  local json_out="$WORK_DIR/upload-smoke.json"
  local log_out="$WORK_DIR/upload-smoke.log"
  local scan_run_id=""
  local share_id=""
  local share_url=""

  mkdir -p "$smoke_home"
  write_upload_fixture "$fixture_dir"

  echo "[rc-smoke] running optional upload/share smoke"

  AGENTPREY_HOME="$smoke_home" AGENTPREY_API_URL="$AGENTPREY_API_URL" \
    cargo run --manifest-path "$ROOT_DIR/cli/Cargo.toml" -- auth activate --key "$AGENTPREY_API_KEY" >/dev/null

  set +e
  AGENTPREY_HOME="$smoke_home" AGENTPREY_API_URL="$AGENTPREY_API_URL" \
    cargo run --manifest-path "$ROOT_DIR/cli/Cargo.toml" -- scan \
      --type openclaw \
      --target "$fixture_dir" \
      --json-out "$json_out" \
      --upload >"$log_out" 2>&1
  local exit_code=$?
  set -e

  if [[ "$exit_code" -ne 1 ]]; then
    echo "[rc-smoke] upload/share scan returned exit code ${exit_code}, expected 1" >&2
    cat "$log_out" >&2
    return 1
  fi

  scan_run_id="$(grep '^scan_run_id:' "$log_out" | tail -n1 | sed 's/^scan_run_id: //')"
  share_id="$(grep '^share_id:' "$log_out" | tail -n1 | sed 's/^share_id: //')"
  share_url="$(grep '^share_url:' "$log_out" | tail -n1 | sed 's/^share_url: //')"

  if [[ -z "$scan_run_id" || -z "$share_id" ]]; then
    echo "[rc-smoke] expected scan_run_id and share_id in upload output" >&2
    cat "$log_out" >&2
    return 1
  fi

  python3 - "${AGENTPREY_API_URL%/}/api/report?share_id=${share_id}" "$share_id" <<'PY'
import json
import sys
import urllib.request

url = sys.argv[1]
share_id = sys.argv[2]

with urllib.request.urlopen(url) as response:
    if response.status != 200:
        raise SystemExit(f"expected share route HTTP 200, saw {response.status}")
    payload = json.load(response)

if payload.get("share_id") != share_id:
    raise SystemExit("share route returned mismatched share_id")

if not payload.get("artifact_json"):
    raise SystemExit("share route returned empty artifact_json")
PY

  if [[ -n "$share_url" ]]; then
    echo "[rc-smoke] upload/share smoke passed: scan_run_id=${scan_run_id} share_id=${share_id} share_url=${share_url}"
  else
    echo "[rc-smoke] upload/share smoke passed: scan_run_id=${scan_run_id} share_id=${share_id}"
  fi
}

trap cleanup EXIT

echo "[rc-smoke] running HTTP smoke"
bash "$ROOT_DIR/scripts/beta_smoke.sh"

echo "[rc-smoke] running OpenClaw smoke"
bash "$ROOT_DIR/scripts/openclaw_smoke.sh"

echo "[rc-smoke] running web test suite"
(cd "$WEB_ROOT" && bun test)

echo "[rc-smoke] running web lint"
(cd "$WEB_ROOT" && bun run lint)

echo "[rc-smoke] running web build"
(cd "$WEB_ROOT" && bun run build)

run_optional_upload_share_smoke

echo "[rc-smoke] PASS"

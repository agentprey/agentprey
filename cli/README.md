# agentprey

`agentprey` is a developer-first security scanner for AI agents.

## Install

```bash
curl -fsSL https://agentprey.com/install | sh
```

## Install with Cargo

```bash
cargo install agentprey --locked
```

## Update

```bash
curl -fsSL https://agentprey.com/install | sh
```

## Update with Cargo

```bash
cargo install agentprey --locked --force
```

## Quickstart

HTTP endpoint scan:

```bash
agentprey scan \
  --target https://your-agent.example/api \
  --category prompt-injection \
  --json-out ./scan.json \
  --html-out ./scan.html
```

MCP descriptor scan:

```bash
agentprey scan \
  --type mcp \
  --target ./path/to/mcp-descriptor.json
```

Local-path OpenClaw scan:

```bash
agentprey scan \
  --type openclaw \
  --target ./path/to/openclaw-project
```

TUI mode:

```bash
agentprey scan \
  --target https://your-agent.example/api \
  --category prompt-injection \
  --ui tui
```

Pro upload and share flow:

```bash
agentprey auth activate --key <KEY>
agentprey vectors sync --pro
agentprey scan \
  --type openclaw \
  --target ./path/to/openclaw-project \
  --upload
```

Successful uploads print `scan_run_id` and `share_id`, plus `share_url` when the backend is configured with `APP_BASE_URL`.

## Notes

- The published crate bundles the free vector set for out-of-the-box scans.
- `--target` accepts either an HTTP endpoint or a local OpenClaw project path, depending on `--type`.
- The default API base URL can be overridden with `AGENTPREY_API_URL` or `.agentprey.toml` `[auth].api_url`.
- Exit codes are stable for CI: `0` clean, `1` vulnerabilities found, `2` runtime or explicit upload failure.

## Current limitations

- The website does not run live scans; cloud support is upload plus public share links.
- OpenClaw scans require a checked-out local project path.
- MCP coverage is currently descriptor-based and focused on inventory/rule analysis rather than live MCP session execution.
- Telemetry is off by default when `--upload` is omitted.

Project repository: `https://github.com/agentprey/agentprey`

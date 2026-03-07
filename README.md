# agentprey

`agentprey` is a developer-first security scanner for AI agents.

This repository contains the current AgentPrey CLI:

- Rust CLI with `scan`, `init`, `auth`, and `vectors` commands
- HTTP endpoint scans with YAML-defined prompt-injection vectors
- Local-path OpenClaw scans with `--type openclaw`
- Plain terminal and `--ui tui` scan output modes
- Interactive control center with `agentprey center`
- JSON and HTML artifacts for automation and human review
- API-key authenticated upload of completed scan runs with optional share links
- Config + CLI merged scan settings (CLI flags override config)
- Retry/backoff, rate limiting, bounded concurrency, and response redaction
- Stable exit codes for CI and release gating

## Install and verify

Option A: install with the shell bootstrapper.

```bash
curl -fsSL https://agentprey.com/install | sh
agentprey --help
agentprey scan --help
agentprey init
```

Install a specific version:

```bash
curl -fsSL https://agentprey.com/install | sh -s -- --version v0.1.6
```

The installer places `agentprey` in `~/.local/bin` by default and currently supports Linux x86_64 plus Apple Silicon macOS. On other targets, use Cargo.

Option B: install from crates.io.

```bash
cargo install agentprey --locked
agentprey --help
agentprey scan --help
agentprey init
```

Update an existing crates.io install:

```bash
cargo install agentprey --locked --force
```

Option C: use a GitHub release binary directly.

```bash
# 1) download and extract a release archive from:
# https://github.com/agentprey/agentprey/releases

# 2) run from the extracted directory
./agentprey --help
./agentprey scan --help
./agentprey init
```

Install a specific Cargo version:

```bash
cargo install agentprey --locked --version <version> --force
```

Option D: build from source.

```bash
git clone https://github.com/agentprey/agentprey.git
cd agentprey
cargo build --manifest-path cli/Cargo.toml --release
./cli/target/release/agentprey --help
./cli/target/release/agentprey scan --help
./cli/target/release/agentprey init
```

## Quickstart

### HTTP endpoint scan

Start a local mock target:

```bash
python3 scripts/mock_agent.py --mode vulnerable --port 8787
```

Run a baseline HTTP scan with artifacts:

```bash
agentprey scan \
  --target http://127.0.0.1:8787/chat \
  --category prompt-injection \
  --json-out ./scan.json \
  --html-out ./scan.html
```

### OpenClaw local-path scan

Point AgentPrey at a checked-out local OpenClaw project:

```bash
agentprey scan \
  --type openclaw \
  --target ./path/to/openclaw-project
```

OpenClaw scans use a local project path, not a URL.

### TUI mode

Use the terminal UI when you want live progress and the final report in the terminal:

```bash
agentprey scan \
  --target http://127.0.0.1:8787/chat \
  --category prompt-injection \
  --ui tui
```

### Control center

Use the control center when you want to configure and launch a scan from inside
the terminal app instead of starting directly in a running scan view:

```bash
agentprey center
agentprey center --target http://127.0.0.1:8787/chat --upload
```

Control-center notes:

- `agentprey center` is interactive-only and errors cleanly on non-TTY output.
- It pre-fills from `--config` or `.agentprey.toml` when available.
- It keeps plain `scan` mode unchanged for CI/CD and automation.

### Pro auth and upload/share

Activate your key and sync Pro vectors:

```bash
agentprey auth activate --key <KEY>
agentprey auth status
agentprey auth refresh
agentprey vectors sync --pro
```

Upload a completed scan:

```bash
agentprey scan \
  --type openclaw \
  --target ./path/to/openclaw-project \
  --upload
```

Successful uploads print `scan_run_id` and `share_id`. If the backend is configured with `APP_BASE_URL`, the CLI also prints `share_url`, which resolves to `/reports/<share_id>`.

Entitlement and upload requests default to `https://brilliant-meerkat-569.convex.site`. Override with `AGENTPREY_API_URL` or `.agentprey.toml`:

```toml
[auth]
api_url = "https://your-convex-host.convex.site"
```

### Config-driven scan

Generate a default config file:

```bash
agentprey init
```

Run from config defaults:

```bash
agentprey scan --config .agentprey.toml
```

### Calibration sanity check

Vulnerable mode should produce findings. Resistant mode should stay near-zero false positives.

```bash
# vulnerable baseline
python3 scripts/mock_agent.py --mode vulnerable --port 8787
agentprey scan --target http://127.0.0.1:8787/chat --category prompt-injection

# resistant baseline
python3 scripts/mock_agent.py --mode resistant --port 8787
agentprey scan --target http://127.0.0.1:8787/chat --category prompt-injection
```

## CI/CD usage

`agentprey` returns stable exit codes:

- `0` for clean scans
- `1` for vulnerabilities detected
- `2` for runtime/tooling errors, including scan runtime failures and explicit upload failures

### HTTP endpoint CI example

```yaml
name: AgentPrey HTTP Scan

on:
  pull_request:
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install agentprey
        run: cargo install agentprey --locked

      - name: Run HTTP scan and gate build
        env:
          TARGET_URL: ${{ secrets.AGENTPREY_TARGET_URL }}
        run: |
          set +e
          agentprey scan --target "$TARGET_URL" --category prompt-injection
          exit_code=$?
          set -e

          if [ "$exit_code" -eq 1 ]; then
            echo "agentprey found vulnerabilities"
            exit 1
          fi

          exit "$exit_code"
```

### OpenClaw CI example

Use a checked-out local project path from the repository workspace:

```yaml
name: AgentPrey OpenClaw Scan

on:
  pull_request:
  workflow_dispatch:

jobs:
  openclaw-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install agentprey
        run: cargo install agentprey --locked

      - name: Run OpenClaw scan and gate build
        run: |
          set +e
          agentprey scan \
            --type openclaw \
            --target ./path/to/openclaw-project
          exit_code=$?
          set -e

          if [ "$exit_code" -eq 1 ]; then
            echo "agentprey found vulnerabilities"
            exit 1
          fi

          exit "$exit_code"
```

## Current limitations

- The marketing site on Vercel does not run live scans. It only hosts docs, checkout/recovery flows, replay demos, and public share pages for uploaded artifacts.
- There is no browser dashboard or full web auth/product loop yet. Cloud support is currently upload plus public-by-link report viewing.
- There is no MCP adapter in the shipped product.
- Telemetry is off by default.
- OpenClaw scans require a local checked-out project path.
- Share pages are artifact-driven. They do not provide edit controls, dashboards, or trend views.

## Notes

- Default `max_concurrent` is `2`.
- Response redaction is enabled by default. Use `--no-redact-responses` to disable.
- Config output defaults can include both `json_out` and `html_out` under `[output]`.
- The crates.io package bundles the free vector set, so `cargo install agentprey --locked` works without cloning the repo.

## Feedback

- Bug reports: `https://github.com/agentprey/agentprey/issues/new?template=bug-report.md`
- False-positive reports: `https://github.com/agentprey/agentprey/issues/new?template=false-positive-report.md`
- Include command, version, and JSON/HTML artifacts when filing reports.

# agentprey

`agentprey` is a developer-first security scanner for AI agents.

This repository contains the current agentprey CLI:

- Rust CLI with `scan` and `vectors list` commands
- Project config initialization via `init`
- Local auth commands with live entitlement refresh (`auth activate`, `auth status`, `auth refresh`, `auth logout`)
- Pro vector sync entitlement gating via `vectors sync --pro`
- HTTP endpoint testing with YAML-defined prompt-injection vectors
- Config + CLI merged scan settings (CLI overrides config)
- Category filtering for vector listing and scans
- Per-vector terminal output with confidence and indicator matches
- JSON artifact output via `--json-out`
- HTML artifact output via `--html-out`
- Retry/backoff, rate limiting, and bounded concurrency controls
- Response redaction defaults to on
- Meaningful exit codes

## Install and verify (15 minutes)

Option A: use a GitHub release binary.

```bash
# 1) download and extract a release archive from:
# https://github.com/agentprey/agentprey/releases

# 2) run from the extracted directory
./agentprey --help
./agentprey init
```

Option B: install from crates.io.

```bash
cargo install agentprey --locked
agentprey --help
agentprey init
```

Update an existing crates.io install:

```bash
cargo install agentprey --locked --force
```

Install a specific version (for rollback or pinning):

```bash
cargo install agentprey --locked --version <version> --force
```

Option C: build from source.

```bash
git clone https://github.com/agentprey/agentprey.git
cd agentprey
cargo build --manifest-path cli/Cargo.toml --release
./cli/target/release/agentprey --help
```

Verification steps:

```bash
# fast baseline check
bash scripts/beta_smoke.sh

# manual run with artifacts
agentprey scan \
  --target http://127.0.0.1:8787/chat \
  --category prompt-injection \
  --json-out ./scan.json \
  --html-out ./scan.html
```

## Quickstart (repo workflow)

Start a local mock target:

```bash
python3 scripts/mock_agent.py --mode vulnerable --port 8787
```

Inspect available vectors:

```bash
cargo run --manifest-path cli/Cargo.toml -- vectors list --category prompt-injection
```

Generate a default project config:

```bash
cargo run --manifest-path cli/Cargo.toml -- init
cargo run --manifest-path cli/Cargo.toml -- auth activate --key apy_example_key
cargo run --manifest-path cli/Cargo.toml -- auth status
cargo run --manifest-path cli/Cargo.toml -- auth refresh
cargo run --manifest-path cli/Cargo.toml -- vectors sync --pro
cargo run --manifest-path cli/Cargo.toml -- auth logout
```

Entitlement API defaults to `https://brilliant-meerkat-569.convex.site/api/entitlement`.
Override with `AGENTPREY_API_URL` or `.agentprey.toml`:

```toml
[auth]
api_url = "https://your-convex-host.convex.site"
```

Run the scanner:

```bash
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat --category prompt-injection
```

Run from config file defaults:

```bash
cargo run --manifest-path cli/Cargo.toml -- scan --config .agentprey.toml
```

Write JSON output for CI or scripting:

```bash
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat --category prompt-injection --json-out ./scan.json
```

Write HTML output for sharing reports:

```bash
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat --category prompt-injection --html-out ./scan.html
```

Tune resilience controls from CLI flags:

```bash
cargo run --manifest-path cli/Cargo.toml -- scan \
  --target http://127.0.0.1:8787/chat \
  --category prompt-injection \
  --retries 2 \
  --retry-backoff-ms 250 \
  --max-concurrent 2 \
  --rate-limit-rps 10
```

Try a resistant mock:

```bash
python3 scripts/mock_agent.py --mode resistant --port 8787
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat --category prompt-injection
```

## Calibration sanity check

- Vulnerable mock should produce mostly or fully vulnerable findings.
- Resistant mock should stay resistant with near-zero false positives.

You can run both checks quickly:

```bash
# vulnerable baseline
python3 scripts/mock_agent.py --mode vulnerable --port 8787
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat --category prompt-injection

# resistant baseline
python3 scripts/mock_agent.py --mode resistant --port 8787
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat --category prompt-injection
```

## CI/CD usage

`agentprey` is CI-friendly because it returns stable exit codes:

- `0` for clean scans
- `1` for vulnerabilities detected
- `2` for runtime/tooling errors

That behavior makes it compatible with GitHub Actions and any CI system that gates builds on process exit status.

Example GitHub Actions workflow:

```yaml
name: AgentPrey Scan

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

      - name: Run scan and gate build
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

## Exit codes

- `0`: no vulnerabilities found
- `1`: one or more vulnerabilities detected
- `2`: runtime/tooling error

## Current limitations

- HTTP target only
- Single-turn payload execution (first payload per vector)
- Prompt-injection vectors only (20 vectors)

## Notes

- Default `max_concurrent` is `2`.
- Response redaction is enabled by default. Use `--no-redact-responses` to disable.
- Config output defaults can include both `json_out` and `html_out` under `[output]`.
- The crates.io package bundles free vectors, so `cargo install agentprey` works without cloning the repo.

## Beta feedback

- Bug reports: `https://github.com/agentprey/agentprey/issues/new?template=bug-report.md`
- False-positive reports: `https://github.com/agentprey/agentprey/issues/new?template=false-positive-report.md`
- Include command, version, and JSON/HTML artifacts when filing reports.

# agentprey

`agentprey` is a developer-first security scanner for AI agents.

This repository currently contains the Day 5 vertical slice:

- Rust CLI with `scan` and `vectors list` commands
- Project config initialization via `init`
- HTTP endpoint testing with YAML-defined prompt-injection vectors
- Config + CLI merged scan settings (CLI overrides config)
- Category filtering for vector listing and scans
- Per-vector terminal output with confidence and indicator matches
- JSON artifact output via `--json-out`
- HTML artifact output via `--html-out`
- Retry/backoff, rate limiting, and bounded concurrency controls
- Response redaction defaults to on
- Meaningful exit codes

## Beta install and verify (15 minutes)

Option A: use a beta release binary.

```bash
# 1) download and extract a release archive from:
# https://github.com/agentprey/agentprey/releases

# 2) run from the extracted directory
./agentprey --help
./agentprey init
```

Option B: install from crates.io.

```bash
cargo install agentprey
agentprey --help
agentprey init
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

## Exit codes

- `0`: no vulnerabilities found
- `2`: one or more vulnerabilities detected
- `1`: runtime/tooling error

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

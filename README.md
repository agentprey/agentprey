# agentprey

`agentprey` is a developer-first security scanner for AI agents.

This repository currently contains the Day 2 vertical slice:

- Rust CLI with `scan` and `vectors list` commands
- HTTP endpoint testing with YAML-defined prompt-injection vectors
- Category filtering for vector listing and scans
- Per-vector terminal output with confidence and indicator matches
- JSON artifact output via `--json-out`
- Meaningful exit codes

## Quickstart

Start a local mock target:

```bash
python3 scripts/mock_agent.py --mode vulnerable --port 8787
```

Inspect available vectors:

```bash
cargo run --manifest-path cli/Cargo.toml -- vectors list --category prompt-injection
```

Run the scanner:

```bash
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat --category prompt-injection
```

Write JSON output for CI or scripting:

```bash
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat --category prompt-injection --json-out ./scan.json
```

Try a resistant mock:

```bash
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
- Prompt-injection vectors only (10 vectors)

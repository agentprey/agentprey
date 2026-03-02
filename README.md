# agentprey

`agentprey` is a developer-first security scanner for AI agents.

This repository currently contains the Day 1 vertical slice:

- Rust CLI with `scan` command
- HTTP endpoint testing with one prompt-injection payload
- Basic response analysis (`vulnerable` vs `resistant`)
- Terminal output and meaningful exit codes

## Quickstart

Start a local mock target:

```bash
python3 scripts/mock_agent.py --mode vulnerable --port 8787
```

Run the scanner:

```bash
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat
```

Try a resistant mock:

```bash
python3 scripts/mock_agent.py --mode resistant --port 8787
cargo run --manifest-path cli/Cargo.toml -- scan --target http://127.0.0.1:8787/chat
```

## Exit codes

- `0`: target appears resistant for tested vector
- `2`: vulnerability detected
- `1`: runtime/tooling error

## Day 1 limitations

- One built-in vector only
- HTTP target only
- Terminal output only

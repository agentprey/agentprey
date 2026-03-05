# agentprey

`agentprey` is a developer-first AI agent security scanner CLI.

## Install

```bash
cargo install agentprey --locked
```

## Update

```bash
cargo install agentprey --locked --force
```

## Quickstart

```bash
agentprey init
agentprey auth activate --key apy_example_key
agentprey auth status
agentprey auth refresh
agentprey vectors sync --pro
agentprey auth logout
agentprey vectors list --category prompt-injection
agentprey scan --target http://127.0.0.1:8787/chat --category prompt-injection
```

## Notes

- The published binary includes bundled free vectors for out-of-the-box scans.
- You can still point to a custom vector directory with `--vectors-dir`.
- Entitlement API URL defaults to `https://brilliant-meerkat-569.convex.site` and can be overridden with `AGENTPREY_API_URL` or `.agentprey.toml` `[auth].api_url`.
- Project repository: `https://github.com/agentprey/agentprey`

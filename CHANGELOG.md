# Changelog

All notable changes to this project are documented in this file.

## v0.5.0

### Added

- Added scan artifact comparison foundations with stable comparison models, `agentprey compare`, JSON output, and HTML compare reports
- Added a redesigned operator-console TUI with stronger control-center framing, clearer completion states, and focused regression coverage for finalization artifact reporting

### Changed

- TUI completion metadata now only marks JSON and HTML artifacts as written after successful finalization writes
- README install guidance now points to the `v0.5.0` release line

## v0.4.0

### Added

- Added OpenClaw-focused `tool-misuse` findings for dangerous tool + egress combinations, unsafe fallback guidance, and unsafe default execution policy
- Added `approval-bypass` findings for approval-disabled risky defaults, prompt-guided approval bypass, and fallback path approval avoidance
- Added unsafe remote-fallback escalation coverage to expand release-gating evidence for tool-using agents
- Added stronger HTML report surfacing for higher-risk findings and clearer remediation scanning

### Changed

- OpenClaw scans now provide a more credible post-MCP release-gating story for tool-using agents
- Public docs and release-facing surfaces now better reflect the shipped `tool-misuse` and `approval-bypass` foundations
- The current released value now maps to the intended `0.4.0` approval-bypass milestone rather than the older `0.2.0` MCP-only public state

## v0.2.0

### Added

- Added MCP descriptor scanning with an initial `mcp-security` ruleset
- Added MCP inventory metadata in scan artifacts, including tool inventory and capability counts
- Added additive MCP evidence fields in `agentprey.scan.v1` for downstream-compatible richer findings

### Changed

- MCP dangerous-tool approval checks now focus on high-confidence dangerous capabilities to reduce heuristic noise
- MCP promptability metadata detection now avoids partial-phrase matches and ignores non-dangerous tools even when they contain prompt/policy-related text
- Release and product docs now describe MCP support alongside HTTP and OpenClaw scanning

## v0.1.6

### Added

- Added a POSIX shell installer at `https://agentprey.com/install` for Linux x86_64 and Apple Silicon macOS
- Added release checksum sidecars so the installer can verify downloaded archives before extraction

### Changed

- Release packaging now publishes checksum files alongside each binary archive
- README and release docs now lead with the shell installer while keeping Cargo as the cross-platform fallback

## v0.1.5

### Added

- Added `agentprey center` as a public interactive control center for configuring and launching scans
- Added shared scan-input/config seeding so `scan` and `center` resolve the same runtime settings
- Added `agentprey.scan.v1` downstream contract documentation and a contract-lock integration test

### Changed

- Interactive `scan` now defaults to the TUI automatically while non-interactive output remains plain for CI/CD
- The main scan TUI now uses a single operator-console layout with stronger completion-state handling
- README now documents the control-center flow alongside the direct scan flow

## v0.1.4

### Added

- OpenClaw local-path scanning support
- TUI scan mode via `agentprey scan --ui tui`
- API-key authenticated scan upload with returned share identifiers and optional share URLs
- Public-by-link report pages for uploaded scans
- OpenClaw and release-candidate smoke scripts

### Changed

- README and docs now reflect the shipped HTTP, OpenClaw, TUI, upload, and share-link flows
- Release-candidate hardening now includes fuller smoke coverage and launch checklists

## v0.1.3

### Added

- Added a new free prompt-injection vector for Base64 decode-and-comply instruction recovery attacks

### Changed

- Prompt-injection vector catalog now includes 21 bundled free vectors

## v0.1.2

### Changed

- Improved top-level CLI help output with richer command descriptions and usage examples for scan, auth, and vectors workflows

## v0.1.1

### Added

- Custom scan request shaping via `--request-template` with `{{payload}}` JSON-string injection
- Expanded `.agentprey.toml` `[target]` support for `endpoint`, `method`, `request_template`, `response_path`, and `headers`
- Rich terminal scan output with an ASCII banner, progress tracking, streamed status lines, and a final report card

### Changed

- Default entitlement API URL now comes from a top-level compile-time constant placeholder for easier pre-publish swapping
- Scan output now stays non-interactive when not attached to a TTY so logs remain CI/CD friendly

## v0.1.0-beta.1

### Added

- HTTP-first CLI scanning flow with vector-driven prompt-injection execution
- JSON and HTML scan artifact outputs
- Config initialization and CLI-over-config precedence
- Retry/backoff, rate limiting, and bounded concurrency controls
- Default-on response redaction for scan outputs
- 20 curated prompt-injection vectors across direct, indirect, and multi-turn categories
- Beta smoke script for vulnerable/resistant baseline verification

### Changed

- Scoring now penalizes execution errors and avoids optimistic grades when scans fail heavily
- Detection heuristics improved for contradictory refusal-plus-disclosure responses

### Known Gaps

- HTTP-only target support
- Prompt-injection-only vector category
- Single-turn payload execution per vector

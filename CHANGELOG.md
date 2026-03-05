# Changelog

All notable changes to this project are documented in this file.

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

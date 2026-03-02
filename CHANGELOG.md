# Changelog

All notable changes to this project are documented in this file.

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

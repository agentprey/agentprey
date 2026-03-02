# Known Limitations (Beta)

These limitations are expected in `v0.1.0-beta` and are tracked for post-beta work.

## Scope Limits

- HTTP endpoint scanning only
- Prompt-injection vectors only
- Single-turn execution path (first payload per vector)

## Reporting Limits

- HTML and JSON artifacts only (no PDF export)
- Report layout is static and not customizable yet

## Platform Limits

- No dashboard/cloud upload in release candidate workflows
- No team or enterprise feature set
- No billing or license enforcement path in beta

## Detection Limits

- Heuristic detection model with regex/phrase indicators
- No semantic classifier model integration yet
- False positives/negatives are still possible on custom agent schemas

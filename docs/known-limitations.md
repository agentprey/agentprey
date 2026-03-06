# Known Limitations

These limits reflect the shipped product after the current upload and share-link work.

## Product surface

- `agentprey center` is interactive-only. It requires a real terminal and is not intended for CI/CD or piped automation.
- The website on Vercel does not run live scans. It hosts docs, checkout/recovery flows, replay demos, and public share pages for uploaded artifacts.
- Cloud support is currently upload plus public-by-link report viewing. There is no full browser dashboard or richer web auth/product loop yet.
- Share pages are read-only and artifact-driven. There are no edit controls, trend charts, dashboard lists, or team workspaces.

## Scan coverage

- HTTP scans and local-path OpenClaw scans are shipped. OpenClaw requires a checked-out local project path, not a URL.
- Detection still relies on heuristic indicators and scoring. False positives and false negatives are still possible on custom agent schemas.
- The scanner does not ship an MCP adapter today.

## Reporting and telemetry

- Reports are JSON, HTML, and uploaded share pages. There is no PDF export.
- Upload is opt-in with `--upload`. The CLI does not send telemetry by default when upload is omitted.
- Share links depend on stored uploaded artifacts. If a stored artifact is malformed, the share page renders a stable error state instead of a full report.

# AgentPrey Architecture

AgentPrey now builds as a small Cargo workspace with the current CLI package kept at `cli/` and shared logic extracted into focused crates:

- `agentprey-core`: shared scan/result types, score model, MCP metadata types, and narrow cross-crate traits.
- `agentprey-vectors`: vector model, parser, validator, loader, catalog, storage, and built-in catalog embedding.
- `agentprey-report`: JSON/HTML report generation plus compare and runtime artifact rendering.
- `agentprey-analyzer`: heuristic detection plus structured OpenClaw analysis for supported source languages.
- `agentprey-sandbox`: Linux-first runtime execution with isolated tempdirs, workspace-copy modes, timeout handling, and normalized runtime events.
- `cli/`: command parsing, config/auth/cloud flows, target execution orchestration, MCP scan runtime, and the TUI.

## Current execution flow

1. The CLI resolves config and flags into `ResolvedScanSettings`.
2. Vectors load through `agentprey-vectors`.
3. Target execution runs from the CLI package.
4. OpenClaw scans now have two analysis lanes:
   - structured static analysis from `agentprey-analyzer` for supported TypeScript and Python code
   - heuristic corpus scanning as the fallback for current vectors and unsupported files
5. Findings and runtime outcomes normalize into `agentprey-core` types and render through `agentprey-report`.

## Crate boundaries

- New structured analyzers belong in `agentprey-analyzer`. Detection logic, rule kinds, and language-specific source-span extraction live there, not in the report crate or the CLI.
- Artifact schema and rendering changes belong in `agentprey-report`. Scan, compare, and runtime JSON/HTML output shape plus golden fixture expectations should stay concentrated there.
- Runtime sandbox work belongs in `agentprey-sandbox`. Isolation, workspace-copy behavior, timeout enforcement, and normalized runtime events should land there before deeper trace/policy work widens the surface.
- Shared result contracts belong in `agentprey-core`. Cross-crate finding types, runtime outcome types, MCP metadata, scoring, and future execution/policy traits should remain the seam between analyzers, runtimes, and presentation.
- CLI wiring belongs in `cli/`. Command parsing, target-specific orchestration, OpenClaw scan assembly, and cloud/auth/config flows should use the focused crates instead of re-implementing their logic.

## Artifact compatibility

- The public CLI surface stays stable while the workspace split lands.
- Scan artifact compatibility stays on `agentprey.scan.v1`.
- Runtime execution uses a dedicated artifact schema, `agentprey.runtime.v1`.
- New artifact fields must be additive-only so downstream consumers can keep parsing older required keys without breakage.
- Renderer updates should preserve current report structure unless a deterministic correctness bug requires a narrow fix.

## Runtime and policy seams

- Linux-first runtime work lives in `agentprey-sandbox`, with `agentprey run` as the first user-facing runtime entrypoint.
- `RuntimeExecutor`, `TraceCollector`, and `PolicyEvaluator` are defined in `agentprey-core` as future seams for runtime, trace, and policy crates.
- Future runtime and policy crates should plug in beside the existing workspace crates, with the CLI orchestrating them and `agentprey-report` consuming only normalized findings and runtime events.

## Adding an OpenClaw structured rule

1. Add the rule kind, matching logic, and source-span extraction in `agentprey-analyzer`.
2. Add or update the vector definition under `cli/vectors/` so the rule has a shipped contract and severity/category metadata.
3. Wire the rule output into the OpenClaw target flow in [`cli/src/targets/openclaw.rs`](/home/senku/Projects/agentprey/cli/src/targets/openclaw.rs) so findings become `agentprey-core` outcomes with additive evidence like `source_spans`.
4. Add artifact assertions in report and contract tests so JSON/HTML outputs keep `agentprey.scan.v1` compatibility while exposing the new structured evidence.

## Near-term direction

- Expand structured OpenClaw analysis beyond shell execution to filesystem, network, and approval-gate flows.
- Grow `agentprey-sandbox` from first-slice command execution into deeper Linux isolation, tracing, and policy enforcement.
- Keep compare/report behavior stable while new additive evidence such as `source_spans` and runtime events land.

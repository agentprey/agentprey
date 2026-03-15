# AgentPrey Architecture

AgentPrey now builds as a small Cargo workspace with the current CLI package kept at `cli/` and shared logic extracted into focused crates:

- `agentprey-core`: shared scan/result types, score model, MCP metadata types, and narrow cross-crate traits.
- `agentprey-vectors`: vector model, parser, validator, loader, catalog, storage, and built-in catalog embedding.
- `agentprey-report`: JSON/HTML report generation plus compare artifact parsing and rendering.
- `agentprey-analyzer`: heuristic detection plus structured OpenClaw analysis for supported source languages.
- `agentprey-sandbox`: Linux-first runtime execution prototype with isolated tempdirs, timeout handling, and normalized runtime events.
- `cli/`: command parsing, config/auth/cloud flows, target execution orchestration, MCP scan runtime, and the TUI.

## Current execution flow

1. The CLI resolves config and flags into `ResolvedScanSettings`.
2. Vectors load through `agentprey-vectors`.
3. Target execution runs from the CLI package.
4. OpenClaw scans now have two analysis lanes:
   - structured static analysis from `agentprey-analyzer` for supported TypeScript and Python code
   - heuristic corpus scanning as the fallback for current vectors and unsupported files
5. Findings normalize into `agentprey-core` types and render through `agentprey-report`.

## Deliberate boundaries

- The public CLI surface stays stable while the workspace split lands.
- Artifact compatibility stays on `agentprey.scan.v1`; new fields must be additive.
- Linux-first runtime work lives in `agentprey-sandbox`; it does not change the released CLI surface until the runtime command model is ready.
- `RuntimeExecutor`, `TraceCollector`, and `PolicyEvaluator` are defined in `agentprey-core` as future seams, but only the pieces needed today are wired into execution.

## Near-term direction

- Expand structured OpenClaw analysis beyond shell execution to filesystem, network, and approval-gate flows.
- Grow `agentprey-sandbox` from prototype supervision into enforced Linux isolation.
- Keep compare/report behavior stable while new additive evidence such as `source_spans` and runtime events land.

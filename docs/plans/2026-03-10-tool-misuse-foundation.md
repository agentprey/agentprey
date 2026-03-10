# Tool Misuse Foundation Implementation Plan

> For Hermes: follow strict TDD and keep the first slice bounded, deterministic, and OpenClaw-first.

Goal: ship the first credible `tool-misuse` foundation toward `0.3.0` without broadening scope into heuristic mush.

Architecture: start with OpenClaw static-audit support for a new `tool-misuse` category because the current repo already has deterministic local corpus scanning there. Reuse the existing vector execution path, allow OpenClaw targets to run both `openclaw` and `tool-misuse` categories, and add one high-signal rule family around dangerous tool + egress combinations.

Tech stack: Rust CLI, existing vector YAML model, OpenClaw static corpus executor, JSON/HTML artifacts, cargo test.

---

## Scope lock

In scope:
- new `tool-misuse` vector category
- OpenClaw target compatibility for `tool-misuse`
- 1 deterministic first rule family with actionable evidence
- tests for category validation/filtering and fixture behavior

Out of scope for this PR:
- `approval-bypass`
- trace/runtime action ingestion
- broad evidence schema expansion
- web/dashboard work

---

## First slice

Rule family: dangerous tool + outbound channel combination

Why this slice:
- deterministic on static config
- easy to explain to users
- maps directly to “unsafe combinations of read/write/exec/egress in a single run context” from the roadmap
- naturally supports remediation guidance

Detection idea:
- vulnerable when a project grants high-risk tools (for example shell/file-write/root/admin) and also configures outbound sinks or remote egress channels
- resistant when only one side appears or the project stays read-only/local-first

---

## Tasks

### Task 1: Add red tests for target/category behavior
- prove OpenClaw accepts `tool-misuse`
- prove HTTP rejects `tool-misuse`
- prove default OpenClaw filtering includes `tool-misuse`

### Task 2: Add red integration test for risky vs safe OpenClaw fixture
- risky fixture should trigger at least one `tool-misuse` finding
- safe fixture should not trigger that rule family
- finding should include actionable evidence summary/recommendation

### Task 3: Implement category support
- add `tool-misuse` category constant
- update category validation and compatibility filtering

### Task 4: Add first built-in vectors
- create bounded `tool-misuse` vectors under `cli/vectors/tool-misuse/...`
- start with dangerous tool + egress combination
- optionally add a second low-noise rule only if tests stay crisp

### Task 5: Improve OpenClaw evidence synthesis for the new slice if needed
- keep changes additive and minimal
- include evidence snippets useful for reproduction/remediation

### Task 6: Verify
- run targeted tests first
- run full cargo test
- inspect CI workflow commands relevant to this surface

---

## Ship bar for this PR
- `tool-misuse` is a real shipped category, not just roadmap text
- at least one deterministic high-value misuse rule family is demoable
- risky vs safe fixture behavior is covered by tests
- no existing scan paths regress

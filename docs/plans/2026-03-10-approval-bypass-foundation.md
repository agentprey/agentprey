# Approval Bypass Foundation Implementation Plan

> For Hermes: keep this bounded, deterministic, and adjacent to the shipped OpenClaw tool-misuse work. Do not drift into runtime tracing or ambiguous social-intent heuristics in the first slice.

Goal: define the first credible `approval-bypass` foundation toward `0.4.0` with deterministic findings and release-gating value.

Architecture: start with OpenClaw static-audit support because the repo already has deterministic local config/prompt scanning there. Reuse the existing vector execution path, add an `approval-bypass` category for OpenClaw-compatible scans, and ship one clear rule family around approval-required behavior being avoided, disabled, or diluted by default configuration and prompt guidance.

Tech stack: Rust CLI, vector YAML model, OpenClaw static corpus executor, JSON/HTML artifacts, cargo test.

---

## Scope lock

In scope:
- new `approval-bypass` vector category
- OpenClaw target compatibility for `approval-bypass`
- 1 deterministic first rule family with actionable evidence
- bounded tests for category validation/filtering and risky vs safe fixture behavior

Out of scope for first slice:
- runtime action logs / actual tool invocation traces
- user-intent laundering heuristics
- stale approval replay simulation
- nested handoff or multi-agent approval semantics
- MCP runtime approval bypass execution

---

## First slice

Rule family: approval avoidance via no-approval defaults on risky tool surfaces

Why this slice:
- directly matches the roadmap phrase “attempts to avoid approval-required tools”
- deterministic on static config and prompt assets
- commercially legible to buyers and security reviewers
- bridges naturally from shipped tool-misuse rules into explicit approval-bypass coverage

Detection idea:
- vulnerable when risky tool surfaces coexist with approval-disabled defaults or prompt/config guidance that normalizes bypassing confirmation
- resistant when sensitive actions are explicitly approval-gated or constrained to read-only behavior

Candidate markers:
- `approval_policy = "never"`
- `auto_approve = true`
- `always_run = true`
- prompt guidance like “skip approval”, “ignore confirmation”, “don’t wait for user approval”

---

## Tasks

### Task 1: Add red tests for target/category behavior
- prove OpenClaw accepts `approval-bypass`
- prove HTTP rejects `approval-bypass`
- prove default OpenClaw filtering includes `approval-bypass` once vectors exist

### Task 2: Add red integration test for risky vs safe OpenClaw fixture
- risky fixture should trigger at least one vulnerable `approval-bypass` finding
- safe fixture should not trigger that rule family
- evidence should show both the risky surface and the bypass marker when available

### Task 3: Implement category support
- add `approval-bypass` category constant
- update category validation and target compatibility filtering

### Task 4: Add first built-in vector family
- create bounded vectors under `cli/vectors/approval-bypass/...`
- start with approval-disabled risky default execution policy
- optionally add one prompt-guidance slice only if it remains crisp and non-overlapping

### Task 5: Keep evidence/reporting actionable
- reuse existing finding output fields
- ensure evidence summaries are concise and reproducible
- avoid broad schema changes unless absolutely required

### Task 6: Verify
- targeted approval-bypass tests first
- full cargo test
- fmt, clippy, and smoke scripts

---

## Ship bar for this PR
- `approval-bypass` is a real shipped category, not just roadmap text
- at least one deterministic bypass scenario is demoable
- findings clearly explain why approval controls are being bypassed or diluted
- existing scan paths and current tool-misuse rules do not regress

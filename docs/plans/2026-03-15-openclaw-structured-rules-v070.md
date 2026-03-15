# OpenClaw Structured Rules v0.7.0 Implementation Plan

> For Hermes/Codex: implement this plan on a feature branch, run the listed tests, and stop before commit/push so Hermes can review first.

Goal: expand OpenClaw structured static analysis beyond shell execution by adding precise TypeScript/Python detections for unsafe filesystem writes and outbound network egress, then surface them through scan findings with source-span evidence.

Architecture: keep the current tree-sitter based analyzer as the single structured-analysis entrypoint, but refactor it so multiple finding kinds can be emitted from one project scan. In the CLI OpenClaw target, replace the single hard-coded structured rule special case with a small mapping layer from vector IDs to structured findings so new rules stay additive and the heuristic fallback path remains intact.

Tech stack: Rust workspace, tree-sitter-typescript, tree-sitter-python, existing agentprey-core FindingEvidence/SourceSpan types, existing OpenClaw scan integration tests.

Suggested branch: feat/openclaw-structured-rules-v070
Suggested PR title: feat: expand structured openclaw analysis for filesystem and egress risks

---

## Scope for this PR

Implement exactly these structured capabilities:
- keep existing tm-openclaw-005 shell-exec structured rule working
- add a new structured rule for unsafe filesystem write without approval
- add a new structured rule for outbound network egress without approval
- emit source spans, evidence kind, attack surface, observed capabilities, repro steps, and mitigation tags for the new findings
- expose the new rules through scan results using built-in vectors
- preserve heuristic/text fallback behavior for everything not covered by structured findings

Do not implement in this PR:
- sandbox/run/trace commands
- eBPF or runtime event collection
- full capability graph visualization
- SARIF
- broad HTML redesign

---

## Task 1: Refactor the structured analyzer to support multiple finding kinds

Objective: make `analyze_openclaw_project` capable of producing more than one structured finding type without duplicating traversal logic.

Files:
- Modify: `crates/agentprey-analyzer/src/structured.rs`
- Modify: `crates/agentprey-analyzer/src/lib.rs` only if export changes are needed
- Test: `crates/agentprey-analyzer/src/structured.rs`

Step 1: extend the finding enum and helper model
- Add `UnsafeFilesystemWrite`
- Add `OutboundNetworkEgress`
- Keep `UnsafeShellExecution`
- If useful, add a small metadata helper on `StructuredFindingKind` for default summary, attack surface, observed capabilities, and mitigation tags

Step 2: replace the single `matches` collector with a collector that can gather spans per finding kind
- Prefer a `BTreeMap<StructuredFindingKind, Vec<SourceSpan>>` or similar
- Traverse each parsed file once and append matches for any structured rule that fires
- Deduplicate identical source spans per finding kind before returning the final report

Step 3: keep the approval-gate suppression behavior generic
- Reuse the existing approval gate heuristics for shell exec
- Apply the same gate suppression logic to filesystem-write and network-egress detections
- Keep the current ancestor lookback behavior unless a clearly small improvement is needed for correctness

Step 4: write/adjust analyzer unit tests before implementation
Add tests in `crates/agentprey-analyzer/src/structured.rs` for:
- existing shell-exec behavior still works
- one TypeScript filesystem-write case is detected with a source span
- one Python filesystem-write case with an inline approval marker is ignored
- one TypeScript network-egress case is detected with a source span
- one Python network-egress case with an inline approval marker is ignored
- a mixed project can return more than one finding kind from a single scan

Suggested detection coverage for this PR:
- TypeScript filesystem write: `fs.writeFile`, `fs.writeFileSync`, `fs.appendFile`, `fs.appendFileSync`, `createWriteStream`
- Python filesystem write: `open(..., "w"|"a"|"wb"|"ab")`, `Path.write_text`, `Path.write_bytes`
- TypeScript network egress: `fetch(`, `axios.`, `http.request`, `https.request`
- Python network egress: `requests.get/post/put`, `httpx.`, `urllib.request.urlopen`

Run:
- `cargo test -p agentprey-analyzer structured -- --nocapture`
Expected: pass

---

## Task 2: Add built-in vectors for the new structured rules

Objective: create explicit vector IDs for the new structured findings so they show up cleanly in scan output instead of overloading unrelated heuristic vectors.

Files:
- Create: `cli/vectors/tool-misuse/openclaw/unsafe-filesystem-write-without-approval.yaml`
- Create: `cli/vectors/tool-misuse/openclaw/outbound-network-egress-without-approval.yaml`
- Modify: `crates/agentprey-vectors/src/builtin.rs`
- Optional mirror only if needed by repo conventions: `vectors/tool-misuse/execution/...` or matching root-vector paths if there is a deliberate duplication policy to preserve
- Test: `crates/agentprey-vectors/src/builtin.rs`

Step 1: create the new vector YAMLs
Use the current `tm-openclaw-005` file as the template shape:
- new IDs should be sequential and stable, e.g. `tm-openclaw-006` and `tm-openclaw-007`
- category: `tool-misuse`
- subcategory: `openclaw`
- payload name/prompt should clearly indicate `structured-static`
- detection should use a sentinel `contains_any` marker because the structured path will short-circuit the heuristic path when it has evidence
- remediation should be specific to approval gating and least privilege for each capability

Step 2: update builtin-vector tests
- assert the new vector IDs load from the embedded catalog

Run:
- `cargo test -p agentprey-vectors builtin -- --nocapture`
Expected: pass

---

## Task 3: Replace the one-off shell-exec special case in the OpenClaw target with a structured mapping layer

Objective: make `cli/src/targets/openclaw.rs` able to translate any structured finding into a `FindingOutcome` without copy-pasted per-vector special cases.

Files:
- Modify: `cli/src/targets/openclaw.rs`
- Test: `cli/tests/openclaw_scan.rs`
- Optional: `cli/tests/scan_json_contract.rs` only if a contract test needs a new evidence assertion

Step 1: extract a helper that maps vector IDs to structured finding kinds
Minimum mapping for this PR:
- `tm-openclaw-005` -> `UnsafeShellExecution`
- `tm-openclaw-006` -> `UnsafeFilesystemWrite`
- `tm-openclaw-007` -> `OutboundNetworkEgress`

Step 2: extract a helper that builds a `FindingOutcome` from a structured finding
Populate:
- vulnerable status when the structured finding exists
- `evidence_kind = structured-static`
- `source_spans`
- `observed_capabilities`
- `attack_surface`
- `repro_steps` derived from source spans
- rule-appropriate mitigation tags

Step 3: preserve fallback behavior
- if a vector maps to a structured finding kind but that finding is absent, fall back to the current heuristic/text path and return a normal resistant or heuristic result
- do not make structured vectors error out when no finding exists

Step 4: keep the response/evidence summaries readable
- evidence summary should mention the files/lines from structured spans
- response text should identify the target path and the capability detected

Run:
- `cargo test -p agentprey --test openclaw_scan -- --nocapture`
Expected: pass

---

## Task 4: Extend the OpenClaw integration fixture to prove the new rules work end-to-end

Objective: ensure the structured analyzer beats text-only matching in a realistic project scan and that safe fixtures stay resistant.

Files:
- Modify: `cli/tests/openclaw_scan.rs`

Step 1: extend the risky fixture
Add code examples that should trigger the new structured findings:
- one risky filesystem write in TS or Python with no approval marker
- one risky outbound network call in TS or Python with no approval marker

Step 2: extend the safe fixture
Add safe examples that include the same APIs but place them behind an obvious approval marker consistent with current heuristics.

Step 3: assert end-to-end finding details
For each new vector ID:
- finding exists in risky scan
- status is `Vulnerable`
- `evidence_kind == Some("structured-static")`
- `source_spans` includes the expected file
- `observed_capabilities` is non-empty

For the safe fixture:
- the corresponding finding exists
- status is `Resistant`
- `source_spans` is empty

Step 4: guard against regressions in the existing shell rule
- keep the existing tm-openclaw-005 assertions intact

Run:
- `cargo test -p agentprey --test openclaw_scan -- --nocapture`
Expected: pass

---

## Task 5: Run focused and full verification

Objective: make sure the new structured rules compile cleanly and do not break the workspace.

Files:
- No code changes required unless fixes are needed

Run in this order:
1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test -p agentprey-analyzer structured -- --nocapture`
4. `cargo test -p agentprey-vectors builtin -- --nocapture`
5. `cargo test -p agentprey --test openclaw_scan -- --nocapture`
6. `cargo test --workspace`

Expected:
- all green
- no new warnings

Stop after verification. Do not commit, push, or open a PR yet.

---

## Review checklist for Hermes before commit

Spec compliance:
- [ ] exactly two new structured rule kinds were added
- [ ] existing shell-exec rule still works
- [ ] new vector IDs are present in builtins
- [ ] OpenClaw scan emits structured evidence for the new vectors
- [ ] safe fixtures remain resistant

Code quality:
- [ ] no copy-pasted giant `if vector.id == ...` blocks remain in `openclaw.rs`
- [ ] structured detection helpers are readable and rule-specific
- [ ] tests cover both risky and approved/safe cases
- [ ] no heuristic regressions or broken workspace tests

Commit message after Hermes review:
- `feat: expand structured openclaw analysis for filesystem and egress risks`

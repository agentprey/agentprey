# Golden Artifacts And Architecture Docs Implementation Plan

> For Hermes/Codex: implement this plan on a feature branch, run the listed tests, and stop before commit/push so Hermes can review first.

Goal: stabilize AgentPrey artifact outputs by introducing dedicated golden fixtures for representative JSON and HTML reports, add explicit source-span coverage in artifact tests, and tighten the architecture doc so future analyzer/runtime work lands in the right crate.

Architecture: keep the existing report renderers unchanged unless a test reveals a deterministic rendering issue. Add a small set of committed fixture artifacts under test fixture directories, then make report tests compare rendered outputs against those fixtures after normalizing only the non-deterministic timestamp field in JSON.

Tech stack: Rust workspace, existing `agentprey-report` unit tests, CLI integration tests, committed fixture files under the repo, markdown docs.

Suggested branch: chore/golden-artifacts-and-architecture-docs
Suggested PR title: chore: add golden artifact fixtures and architecture cleanup

---

## Scope for this PR

Implement exactly these improvements:
- add committed golden JSON and HTML artifact fixtures for representative scan outputs
- add explicit test coverage that `source_spans` survive JSON rendering and appear in HTML output
- keep artifact compatibility on `agentprey.scan.v1`
- tighten `ARCHITECTURE.md` so contributors know where analyzer, report, sandbox, and future runtime/policy work belongs

Do not implement in this PR:
- new analyzer rules
- sandbox/run/trace commands
- SARIF
- policy engine
- broad report redesign

---

## Task 1: Create reusable sample outcomes for report tests

Objective: reduce duplication in report tests and make fixture generation deterministic enough for golden comparisons.

Files:
- Modify: `crates/agentprey-report/src/json.rs`
- Modify: `crates/agentprey-report/src/html.rs`
- Optional helper extraction if it stays test-only inside one file

Step 1: identify current inline `ScanOutcome` constructors in report tests
- JSON report tests already build a sample HTTP outcome
- HTML report tests already build one HTTP outcome and one OpenClaw/MCP-heavy outcome

Step 2: replace duplicated test setup with named helper constructors per file
Suggested helpers:
- `sample_http_outcome()`
- `sample_openclaw_outcome_with_source_spans()`

Step 3: ensure at least one sample finding includes additive evidence fields
Required in the OpenClaw-focused sample:
- `evidence_kind`
- `observed_capabilities`
- `mitigation_tags`
- `source_spans`

Step 4: keep helpers test-only
- do not introduce production abstractions for this
- avoid changing renderer behavior unless needed for determinism/correctness

Run:
- `cargo test -p agentprey-report json::tests::render_scan_json_preserves_schema_version -- --nocapture`
- `cargo test -p agentprey-report html::tests::writes_html_report_with_mcp_and_openclaw_focus_sections -- --nocapture`
Expected: pass

---

## Task 2: Add committed golden JSON artifact fixtures

Objective: compare rendered JSON against committed expected output instead of only spot-checking a few fields.

Files:
- Create: `crates/agentprey-report/tests/fixtures/scan_http.golden.json`
- Create: `crates/agentprey-report/tests/fixtures/scan_openclaw_structured.golden.json`
- Modify: `crates/agentprey-report/src/json.rs`

Step 1: choose fixture strategy
Use report-unit-test-owned fixture files under:
- `crates/agentprey-report/tests/fixtures/`

Step 2: render deterministic comparisons
Because `generated_at_ms` is time-based, normalize it in the test before comparison:
- parse rendered JSON and golden JSON as `serde_json::Value`
- replace/remove `generated_at_ms` in both values before equality assertion
- keep `schema_version` intact and asserted

Step 3: golden coverage requirements
The structured OpenClaw golden JSON fixture must include at least one finding with:
- `evidence_kind: "structured-static"`
- non-empty `source_spans`
- non-empty `observed_capabilities`
- non-empty `mitigation_tags`

Step 4: add a dedicated source-span assertion test if the straight golden comparison feels too opaque
- assert specific path/line values under `scan.findings[*].source_spans`

Run:
- `cargo test -p agentprey-report json -- --nocapture`
Expected: pass

---

## Task 3: Add committed golden HTML artifact fixtures

Objective: lock in the current report structure for representative outputs without relying only on substring assertions.

Files:
- Create: `crates/agentprey-report/tests/fixtures/scan_http.golden.html`
- Create: `crates/agentprey-report/tests/fixtures/scan_openclaw_structured.golden.html`
- Modify: `crates/agentprey-report/src/html.rs`

Step 1: generate representative HTML from the same sample outcomes used in Task 1
- one simple HTTP scan fixture
- one OpenClaw/MCP-rich fixture with additive finding evidence and source spans

Step 2: compare full file contents where feasible
- prefer exact comparison to the committed golden fixture
- if any field is inherently non-deterministic in the HTML output, normalize it before comparison
- if nothing is non-deterministic, compare exact strings directly

Step 3: keep a small number of focused semantic assertions too
Required assertions for the structured OpenClaw HTML fixture:
- rendered source span file path appears
- rendered line number appears
- `structured-static` appears
- OpenClaw/TM/approval sections still appear

Step 4: do not rewrite large portions of HTML rendering just to satisfy the test
- only make small deterministic cleanup changes if necessary

Run:
- `cargo test -p agentprey-report html -- --nocapture`
Expected: pass

---

## Task 4: Add CLI-level contract coverage for additive source-span fields

Objective: make sure downstream-facing artifact contract tests explicitly cover structured findings, not only MCP additive fields.

Files:
- Modify: `cli/tests/scan_json_contract.rs`
- Optional: `cli/tests/reporting.rs`

Step 1: update the JSON contract sample outcome to include one finding with source-span evidence
Add to a sample finding:
- `evidence_kind: Some("structured-static")`
- `source_spans` with one path/line pair
- at least one observed capability and mitigation tag

Step 2: strengthen assertions
Explicitly assert the rendered JSON contract preserves:
- `schema_version`
- `evidence_kind`
- `source_spans[0].file`
- `source_spans[0].line`
- `observed_capabilities`
- `mitigation_tags`

Step 3: if needed, add one focused HTML integration assertion in `cli/tests/reporting.rs`
- use an OpenClaw-like sample and assert source span text is visible to end users

Run:
- `cargo test -p agentprey --test scan_json_contract -- --nocapture`
- `cargo test -p agentprey --test reporting -- --nocapture`
Expected: pass

---

## Task 5: Tighten ARCHITECTURE.md for contributor clarity

Objective: make it obvious where future work belongs so the repo does not regress into a single-crate hairball.

Files:
- Modify: `ARCHITECTURE.md`

Step 1: keep the current workspace overview but make boundaries more operational
Add short sections for:
- where new structured analyzers should live
- where artifact schema/rendering changes should live
- where runtime sandbox work should live
- where future trace/policy crates are expected to plug in

Step 2: add a "how to add a new OpenClaw structured rule" subsection
Should mention:
- analyzer rule kind and detection logic in `agentprey-analyzer`
- vector definition in `cli/vectors/`
- CLI mapping/wiring in `cli/src/targets/openclaw.rs`
- artifact assertions in report/contract tests

Step 3: add a short note on artifact compatibility
- `agentprey.scan.v1` is additive-only
- new fields must not break downstream consumers

Run:
- no standalone doc test required, but include this in final verification

---

## Task 6: Full verification

Objective: prove the fixture-based tests and docs cleanup did not destabilize the workspace.

Run in this order:
1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test -p agentprey-report json -- --nocapture`
4. `cargo test -p agentprey-report html -- --nocapture`
5. `cargo test -p agentprey --test scan_json_contract -- --nocapture`
6. `cargo test -p agentprey --test reporting -- --nocapture`
7. `cargo test --workspace`

Expected:
- all green
- no schema version regressions
- source-span evidence present in both JSON and HTML golden coverage

Stop after verification. Do not commit, push, or open a PR yet.

---

## Review checklist for Hermes before commit

Spec compliance:
- [ ] committed golden JSON fixtures exist
- [ ] committed golden HTML fixtures exist
- [ ] source-span evidence is explicitly covered in tests
- [ ] `ARCHITECTURE.md` explains crate boundaries and structured-rule extension flow
- [ ] artifact schema remains `agentprey.scan.v1`

Code quality:
- [ ] tests avoid brittle timestamp comparisons by normalizing only nondeterministic fields
- [ ] helper sample outcomes reduce duplication instead of increasing it
- [ ] no unnecessary renderer redesign slipped in
- [ ] full workspace verification passes

Commit message after Hermes review:
- `chore: add golden artifact fixtures and architecture guidance`

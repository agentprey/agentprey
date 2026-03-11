use std::{fs, path::PathBuf, process::Command};

use agentprey::{
    compare::compare_artifact_files,
    output::compare_html::{render_compare_html, write_compare_html},
};
use tempfile::tempdir;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("compare")
        .join(name)
}

#[test]
fn compare_html_report_contains_required_sections() {
    let comparison = compare_artifact_files(
        &fixture_path("baseline.json"),
        &fixture_path("candidate.json"),
    )
    .expect("fixtures should compare");

    let html = render_compare_html(&comparison);

    assert!(html.contains("AgentPrey Compare Report"));
    assert!(html.contains(">Safer<"));
    assert!(html.contains("Baseline grade B"));
    assert!(html.contains("Candidate grade A"));
    assert!(html.contains("Score Delta"));
    assert!(html.contains("Release Gating"));
    assert!(html.contains("New Blocker Findings"));
    assert!(html.contains("Resolved Blocker Findings"));
    assert!(html.contains("Category Delta Overview"));
    assert!(html.contains("Prompt Injection"));
    assert!(html.contains("Tool Misuse"));
    assert!(!html.contains("Approval Bypass</div>"));
    assert!(html.contains("Added Findings"));
    assert!(html.contains("Removed Findings"));
    assert!(html.contains("Changed Findings"));
    assert!(html.contains("vector-leakage-001"));
    assert!(html.contains("tool-misuse-001"));
    assert!(html.contains("prompt-injection-001"));
    assert!(html.contains("Baseline rationale"));
    assert!(html.contains("Candidate rationale"));
}

#[test]
fn compare_html_report_writes_file_and_is_deterministic() {
    let temp = tempdir().expect("tempdir should be created");
    let output = temp.path().join("reports/compare.html");
    let comparison = compare_artifact_files(
        &fixture_path("baseline.json"),
        &fixture_path("candidate.json"),
    )
    .expect("fixtures should compare");

    write_compare_html(&output, &comparison).expect("html report should be written");
    let first = fs::read_to_string(&output).expect("html report should exist");

    write_compare_html(&output, &comparison).expect("html report should be rewritten");
    let second = fs::read_to_string(&output).expect("html report should still exist");

    assert_eq!(first, second);
    assert!(first.contains("Candidate keeps blockers flat at 2"));
}

#[test]
fn compare_command_writes_compare_html_report() {
    let temp = tempdir().expect("tempdir should be created");
    let output_path = temp.path().join("reports/compare.html");

    let output = Command::new(env!("CARGO_BIN_EXE_agentprey"))
        .arg("compare")
        .arg("--baseline")
        .arg(fixture_path("baseline.json"))
        .arg("--candidate")
        .arg(fixture_path("candidate.json"))
        .arg("--html-out")
        .arg(&output_path)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("compare command should execute");

    assert!(
        output.status.success(),
        "compare command should succeed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let html = fs::read_to_string(&output_path).expect("compare HTML should exist");

    assert!(stdout.contains("HTML Output:"));
    assert!(stdout.contains(&output_path.display().to_string()));
    assert!(!stderr.contains("not implemented yet"));
    assert!(html.contains("AgentPrey Compare Report"));
    assert!(html.contains("Added Findings"));
    assert!(html.contains("Changed Findings"));
}

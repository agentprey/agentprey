use std::{path::PathBuf, process::Command};

use agentprey::{
    cli::{Cli, Commands},
    output::compare_json::COMPARE_ARTIFACT_SCHEMA_VERSION,
};
use clap::Parser;
use serde_json::Value;
use tempfile::tempdir;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("compare")
        .join(name)
}

#[test]
fn compare_command_parses_public_flags() {
    let cli = Cli::try_parse_from([
        "agentprey",
        "compare",
        "--baseline",
        "baseline.json",
        "--candidate",
        "candidate.json",
        "--json-out",
        "compare.json",
        "--html-out",
        "compare.html",
    ])
    .expect("compare command should parse");

    match cli.command {
        Commands::Compare(args) => {
            assert_eq!(args.baseline, PathBuf::from("baseline.json"));
            assert_eq!(args.candidate, PathBuf::from("candidate.json"));
            assert_eq!(args.json_out, Some(PathBuf::from("compare.json")));
            assert_eq!(args.html_out, Some(PathBuf::from("compare.html")));
        }
        other => panic!("expected compare command, got {other:?}"),
    }
}

#[test]
fn compare_command_writes_compare_json_schema() {
    let temp = tempdir().expect("tempdir should be created");
    let output_path = temp.path().join("reports/compare.json");

    let output = Command::new(env!("CARGO_BIN_EXE_agentprey"))
        .arg("compare")
        .arg("--baseline")
        .arg(fixture_path("baseline.json"))
        .arg("--candidate")
        .arg(fixture_path("candidate.json"))
        .arg("--json-out")
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

    let contents = std::fs::read_to_string(&output_path).expect("compare JSON should exist");
    let parsed: Value = serde_json::from_str(&contents).expect("compare JSON should parse");

    assert_eq!(parsed["schema_version"], COMPARE_ARTIFACT_SCHEMA_VERSION);
    assert!(parsed["generated_at_ms"].is_u64());

    assert_eq!(
        parsed["baseline"]["path"],
        fixture_path("baseline.json").display().to_string()
    );
    assert_eq!(
        parsed["candidate"]["path"],
        fixture_path("candidate.json").display().to_string()
    );
    assert_eq!(parsed["baseline"]["target"], "https://baseline.example/api");
    assert_eq!(
        parsed["candidate"]["target"],
        "https://candidate.example/api"
    );

    let summary = &parsed["summary"];
    assert_eq!(summary["baseline_grade"], "B");
    assert_eq!(summary["candidate_grade"], "A");
    assert_eq!(summary["baseline_score"], 82);
    assert_eq!(summary["candidate_score"], 91);
    assert_eq!(summary["total_finding_delta"], 0);
    assert_eq!(summary["vulnerable_delta"], 0);
    assert_eq!(summary["resistant_delta"], 0);
    assert_eq!(summary["error_delta"], 0);
    assert_eq!(
        summary["blocker_summary_sentence"],
        "Candidate keeps blockers flat at 2, with vulnerable findings +0 and errors +0 versus baseline."
    );

    assert_eq!(parsed["category_deltas"].as_array().map(Vec::len), Some(3));
    assert_eq!(parsed["added_findings"].as_array().map(Vec::len), Some(1));
    assert_eq!(parsed["removed_findings"].as_array().map(Vec::len), Some(1));
    assert_eq!(parsed["changed_findings"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        parsed["added_findings"][0]["identity"]["rule_id"],
        "vector-leakage-001"
    );
    assert_eq!(
        parsed["removed_findings"][0]["identity"]["rule_id"],
        "tool-misuse-001"
    );
    assert_eq!(
        parsed["changed_findings"][0]["identity"]["rule_id"],
        "prompt-injection-001"
    );
}

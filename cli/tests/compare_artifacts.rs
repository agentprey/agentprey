use std::path::Path;

use agentprey::compare::{compare_artifact_files, parse_artifact_file, ArtifactFindingStatus};

fn fixture_path(name: &str) -> &'static Path {
    match name {
        "baseline.json" => Path::new("tests/fixtures/compare/baseline.json"),
        "candidate.json" => Path::new("tests/fixtures/compare/candidate.json"),
        "unknown-schema.json" => Path::new("tests/fixtures/compare/unknown-schema.json"),
        _ => panic!("unknown fixture"),
    }
}

#[test]
fn compare_artifact_files_reports_stable_deltas_and_finding_changes() {
    let comparison = compare_artifact_files(
        fixture_path("baseline.json"),
        fixture_path("candidate.json"),
    )
    .expect("fixtures should compare");

    assert_eq!(comparison.baseline.target_type.to_string(), "http");
    assert_eq!(comparison.baseline.target, "https://baseline.example/api");
    assert_eq!(comparison.baseline.score.score, 82);
    assert_eq!(comparison.baseline.counts.total_vectors, 3);
    assert_eq!(comparison.baseline.counts.findings, 3);
    assert_eq!(comparison.candidate.target, "https://candidate.example/api");
    assert_eq!(comparison.candidate.score.score, 91);
    assert_eq!(comparison.candidate.counts.total_vectors, 4);

    assert!(comparison.overall_delta.target_changed);
    assert!(!comparison.overall_delta.target_type_changed);
    assert!(comparison.overall_delta.grade_changed);
    assert_eq!(comparison.overall_delta.score_delta, 9);
    assert_eq!(comparison.overall_delta.total_vectors_delta, 1);
    assert_eq!(comparison.overall_delta.findings_delta, 0);
    assert_eq!(comparison.overall_delta.vulnerable_delta, 0);
    assert_eq!(comparison.overall_delta.resistant_delta, 0);
    assert_eq!(comparison.overall_delta.error_delta, 0);

    assert_eq!(comparison.category_deltas.len(), 3);
    assert_eq!(comparison.category_deltas[0].category, "prompt-injection");
    assert_eq!(comparison.category_deltas[0].baseline.total, 2);
    assert_eq!(comparison.category_deltas[0].candidate.total, 2);
    assert_eq!(comparison.category_deltas[0].delta.vulnerable, -1);
    assert_eq!(comparison.category_deltas[0].delta.resistant, 1);
    assert_eq!(comparison.category_deltas[1].category, "tool-misuse");
    assert_eq!(comparison.category_deltas[1].delta.total, -1);
    assert_eq!(comparison.category_deltas[2].category, "vector-leakage");
    assert_eq!(comparison.category_deltas[2].delta.total, 1);

    assert_eq!(comparison.added_findings.len(), 1);
    assert_eq!(
        comparison.added_findings[0].identity.rule_id,
        "vector-leakage-001"
    );
    assert_eq!(
        comparison.added_findings[0].status,
        ArtifactFindingStatus::Vulnerable
    );

    assert_eq!(comparison.removed_findings.len(), 1);
    assert_eq!(
        comparison.removed_findings[0].identity.rule_id,
        "tool-misuse-001"
    );

    assert_eq!(comparison.changed_findings.len(), 1);
    let changed = &comparison.changed_findings[0];
    assert_eq!(changed.identity.rule_id, "prompt-injection-001");
    assert_eq!(changed.baseline.status, ArtifactFindingStatus::Vulnerable);
    assert_eq!(changed.candidate.status, ArtifactFindingStatus::Resistant);
    assert_eq!(changed.baseline.severity.as_str(), "high");
    assert_eq!(changed.candidate.severity.as_str(), "low");
    assert_eq!(changed.baseline.rationale, "Baseline rationale");
    assert_eq!(changed.candidate.rationale, "Candidate rationale");
    assert_eq!(
        changed.baseline.evidence_summary,
        "Baseline evidence summary"
    );
    assert_eq!(
        changed.candidate.evidence_summary,
        "Candidate evidence summary"
    );
    assert_eq!(changed.baseline.recommendation, "Baseline recommendation");
    assert_eq!(changed.candidate.recommendation, "Candidate recommendation");
}

#[test]
fn parse_artifact_file_rejects_unknown_schema_versions() {
    let error = parse_artifact_file(fixture_path("unknown-schema.json"))
        .expect_err("unknown schema version should be rejected");

    assert!(error
        .to_string()
        .contains("unsupported scan artifact schema_version 'agentprey.scan.v2'"));
}

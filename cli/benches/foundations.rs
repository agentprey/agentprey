use std::fs;

use agentprey::{
    cli::TargetType,
    output::{html::write_scan_html, json::render_scan_json},
    scan::{FindingOutcome, FindingOutcomeInput, FindingStatus, ScanOutcome},
    scorer::{Grade, ScoreSummary, SeverityCounts},
    vectors::loader::load_vectors,
    vectors::model::Severity,
};
use criterion::{criterion_group, criterion_main, Criterion};
use tempfile::tempdir;

fn sample_outcome() -> ScanOutcome {
    ScanOutcome {
        target_type: TargetType::Openclaw,
        target: "./fixtures/openclaw-risky".to_string(),
        mcp: None,
        total_vectors: 1,
        vulnerable_count: 1,
        resistant_count: 0,
        error_count: 0,
        score: ScoreSummary {
            score: 90,
            grade: Grade::B,
            vulnerable_severities: SeverityCounts {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                info: 0,
            },
            error_count: 0,
        },
        findings: vec![FindingOutcome::new(FindingOutcomeInput {
            rule_id: "tm-openclaw-001".to_string(),
            vector_id: "tm-openclaw-001".to_string(),
            vector_name: "Structured shell exec".to_string(),
            category: "tool-misuse".to_string(),
            subcategory: "execution".to_string(),
            severity: Severity::High,
            payload_name: "static".to_string(),
            payload_prompt: "static".to_string(),
            status: FindingStatus::Vulnerable,
            status_code: None,
            response: "child_process.exec detected".to_string(),
            analysis: None,
            duration_ms: 4,
            rationale: "Shell execution without approval expands agent attack surface.".to_string(),
            evidence_summary: "src/agent.ts: child_process.exec(input)".to_string(),
            recommendation: "Require approval before shell execution.".to_string(),
        })],
        duration_ms: 5,
    }
}

fn bench_vector_loading(c: &mut Criterion) {
    c.bench_function("vector_loading_builtin_catalog", |b| {
        b.iter(|| load_vectors(std::path::Path::new("vectors")).expect("vectors should load"))
    });
}

fn bench_json_render(c: &mut Criterion) {
    let outcome = sample_outcome();
    c.bench_function("report_render_scan_json", |b| {
        b.iter(|| render_scan_json(&outcome).expect("scan json should render"))
    });
}

fn bench_html_write(c: &mut Criterion) {
    let outcome = sample_outcome();
    c.bench_function("report_write_scan_html", |b| {
        b.iter(|| {
            let temp = tempdir().expect("tempdir should be created");
            let output = temp.path().join("scan.html");
            write_scan_html(&output, &outcome).expect("scan html should write");
            fs::metadata(&output).expect("html report should exist");
        })
    });
}

criterion_group!(
    foundations,
    bench_vector_loading,
    bench_json_render,
    bench_html_write
);
criterion_main!(foundations);

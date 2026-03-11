use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::compare::{ArtifactComparison, ArtifactGrade};

pub const COMPARE_ARTIFACT_SCHEMA_VERSION: &str = "agentprey.compare.v1";

#[derive(Debug, Serialize)]
struct CompareJsonArtifact<'a> {
    schema_version: &'static str,
    generated_at_ms: u128,
    baseline: &'a crate::compare::ArtifactMetadata,
    candidate: &'a crate::compare::ArtifactMetadata,
    summary: CompareSummary,
    category_deltas: &'a [crate::compare::CategoryDelta],
    added_findings: &'a [crate::compare::ComparedFinding],
    removed_findings: &'a [crate::compare::ComparedFinding],
    changed_findings: &'a [crate::compare::ChangedFinding],
}

#[derive(Debug, Serialize)]
struct CompareSummary {
    baseline_grade: ArtifactGrade,
    candidate_grade: ArtifactGrade,
    baseline_score: u8,
    candidate_score: u8,
    total_finding_delta: i64,
    vulnerable_delta: i64,
    resistant_delta: i64,
    error_delta: i64,
    blocker_summary_sentence: String,
}

pub fn render_compare_json(comparison: &ArtifactComparison) -> Result<String> {
    let artifact = CompareJsonArtifact {
        schema_version: COMPARE_ARTIFACT_SCHEMA_VERSION,
        generated_at_ms: now_ms(),
        baseline: &comparison.baseline,
        candidate: &comparison.candidate,
        summary: CompareSummary::from(comparison),
        category_deltas: &comparison.category_deltas,
        added_findings: &comparison.added_findings,
        removed_findings: &comparison.removed_findings,
        changed_findings: &comparison.changed_findings,
    };

    serde_json::to_string_pretty(&artifact).context("failed to serialize compare results as JSON")
}

pub fn write_compare_json(path: &Path, comparison: &ArtifactComparison) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create compare JSON output directory '{}'",
                    parent.display()
                )
            })?;
        }
    }

    let json = render_compare_json(comparison)?;
    fs::write(path, json).with_context(|| {
        format!(
            "failed to write compare JSON output file '{}'",
            path.display()
        )
    })?;

    Ok(())
}

impl From<&ArtifactComparison> for CompareSummary {
    fn from(comparison: &ArtifactComparison) -> Self {
        Self {
            baseline_grade: comparison.baseline.score.grade,
            candidate_grade: comparison.candidate.score.grade,
            baseline_score: comparison.baseline.score.score,
            candidate_score: comparison.candidate.score.score,
            total_finding_delta: comparison.overall_delta.findings_delta,
            vulnerable_delta: comparison.overall_delta.vulnerable_delta,
            resistant_delta: comparison.overall_delta.resistant_delta,
            error_delta: comparison.overall_delta.error_delta,
            blocker_summary_sentence: blocker_summary_sentence(comparison),
        }
    }
}

fn blocker_summary_sentence(comparison: &ArtifactComparison) -> String {
    let baseline_blockers =
        comparison.baseline.counts.vulnerable + comparison.baseline.counts.errors;
    let candidate_blockers =
        comparison.candidate.counts.vulnerable + comparison.candidate.counts.errors;
    let blocker_delta = candidate_blockers as i64 - baseline_blockers as i64;

    match blocker_delta.cmp(&0) {
        std::cmp::Ordering::Less => format!(
            "Candidate reduces blockers from {baseline_blockers} to {candidate_blockers} ({blocker_delta:+}), with vulnerable findings {:+} and errors {:+} versus baseline.",
            comparison.overall_delta.vulnerable_delta,
            comparison.overall_delta.error_delta,
        ),
        std::cmp::Ordering::Equal => format!(
            "Candidate keeps blockers flat at {candidate_blockers}, with vulnerable findings {:+} and errors {:+} versus baseline.",
            comparison.overall_delta.vulnerable_delta,
            comparison.overall_delta.error_delta,
        ),
        std::cmp::Ordering::Greater => format!(
            "Candidate increases blockers from {baseline_blockers} to {candidate_blockers} ({blocker_delta:+}), with vulnerable findings {:+} and errors {:+} versus baseline.",
            comparison.overall_delta.vulnerable_delta,
            comparison.overall_delta.error_delta,
        ),
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

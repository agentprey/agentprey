use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    cli::TargetType, output::json::SCAN_ARTIFACT_SCHEMA_VERSION, vectors::model::Severity,
};

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactComparison {
    pub baseline: ArtifactMetadata,
    pub candidate: ArtifactMetadata,
    pub overall_delta: OverallDelta,
    pub category_deltas: Vec<CategoryDelta>,
    pub added_findings: Vec<ComparedFinding>,
    pub removed_findings: Vec<ComparedFinding>,
    pub changed_findings: Vec<ChangedFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactMetadata {
    pub path: PathBuf,
    pub target_type: TargetType,
    pub target: String,
    pub score: ArtifactScore,
    pub counts: ScanCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactScore {
    pub score: u8,
    pub grade: ArtifactGrade,
    pub vulnerable_severities: ArtifactSeverityCounts,
    pub error_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanCounts {
    pub total_vectors: usize,
    pub findings: usize,
    pub vulnerable: usize,
    pub resistant: usize,
    pub errors: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverallDelta {
    pub target_type_changed: bool,
    pub target_changed: bool,
    pub grade_changed: bool,
    pub score_delta: i64,
    pub total_vectors_delta: i64,
    pub findings_delta: i64,
    pub vulnerable_delta: i64,
    pub resistant_delta: i64,
    pub error_delta: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryDelta {
    pub category: String,
    pub baseline: CategoryCounts,
    pub candidate: CategoryCounts,
    pub delta: CategoryCountDelta,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CategoryCounts {
    pub total: usize,
    pub vulnerable: usize,
    pub resistant: usize,
    pub errors: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryCountDelta {
    pub total: i64,
    pub vulnerable: i64,
    pub resistant: i64,
    pub errors: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FindingIdentity {
    pub rule_id: String,
    pub vector_id: String,
    pub payload_name: String,
    pub category: String,
    pub subcategory: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparedFinding {
    pub identity: FindingIdentity,
    pub status: ArtifactFindingStatus,
    pub severity: Severity,
    pub rationale: String,
    pub evidence_summary: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangedFinding {
    pub identity: FindingIdentity,
    pub baseline: ComparedFinding,
    pub candidate: ComparedFinding,
}

#[derive(Debug, Clone)]
pub struct ComparableScanArtifact {
    pub metadata: ArtifactMetadata,
    pub findings: Vec<ComparedFinding>,
}

pub fn compare_artifact_files(
    baseline_path: &Path,
    candidate_path: &Path,
) -> Result<ArtifactComparison> {
    let baseline = parse_artifact_file(baseline_path)?;
    let candidate = parse_artifact_file(candidate_path)?;
    Ok(compare_artifacts(&baseline, &candidate))
}

pub fn parse_artifact_file(path: &Path) -> Result<ComparableScanArtifact> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read scan artifact '{}'", path.display()))?;
    parse_artifact_str(path, &contents)
}

pub fn compare_artifacts(
    baseline: &ComparableScanArtifact,
    candidate: &ComparableScanArtifact,
) -> ArtifactComparison {
    let baseline_index = index_findings(&baseline.findings);
    let candidate_index = index_findings(&candidate.findings);

    let mut added_findings = Vec::new();
    let mut removed_findings = Vec::new();
    let mut changed_findings = Vec::new();

    for (identity, candidate_finding) in &candidate_index {
        match baseline_index.get(identity) {
            Some(baseline_finding) if finding_changed(baseline_finding, candidate_finding) => {
                changed_findings.push(ChangedFinding {
                    identity: identity.clone(),
                    baseline: baseline_finding.clone(),
                    candidate: candidate_finding.clone(),
                });
            }
            Some(_) => {}
            None => added_findings.push(candidate_finding.clone()),
        }
    }

    for (identity, baseline_finding) in &baseline_index {
        if !candidate_index.contains_key(identity) {
            removed_findings.push(baseline_finding.clone());
        }
    }

    ArtifactComparison {
        baseline: baseline.metadata.clone(),
        candidate: candidate.metadata.clone(),
        overall_delta: build_overall_delta(&baseline.metadata, &candidate.metadata),
        category_deltas: build_category_deltas(&baseline.findings, &candidate.findings),
        added_findings,
        removed_findings,
        changed_findings,
    }
}

fn parse_artifact_str(path: &Path, contents: &str) -> Result<ComparableScanArtifact> {
    let artifact: RawArtifact = serde_json::from_str(contents)
        .with_context(|| format!("failed to parse scan artifact '{}'", path.display()))?;

    if artifact.schema_version != SCAN_ARTIFACT_SCHEMA_VERSION {
        bail!(
            "unsupported scan artifact schema_version '{}' in '{}'; expected '{}'",
            artifact.schema_version,
            path.display(),
            SCAN_ARTIFACT_SCHEMA_VERSION
        );
    }

    let findings = artifact
        .scan
        .findings
        .into_iter()
        .map(ComparedFinding::from)
        .collect::<Vec<_>>();

    Ok(ComparableScanArtifact {
        metadata: ArtifactMetadata {
            path: path.to_path_buf(),
            target_type: artifact.scan.target_type,
            target: artifact.scan.target,
            score: artifact.scan.score.into(),
            counts: ScanCounts {
                total_vectors: artifact.scan.total_vectors,
                findings: findings.len(),
                vulnerable: artifact.scan.vulnerable_count,
                resistant: artifact.scan.resistant_count,
                errors: artifact.scan.error_count,
            },
        },
        findings,
    })
}

fn index_findings(findings: &[ComparedFinding]) -> BTreeMap<FindingIdentity, ComparedFinding> {
    findings
        .iter()
        .cloned()
        .map(|finding| (finding.identity.clone(), finding))
        .collect()
}

fn finding_changed(baseline: &ComparedFinding, candidate: &ComparedFinding) -> bool {
    baseline.status != candidate.status
        || baseline.severity.as_str() != candidate.severity.as_str()
        || baseline.rationale != candidate.rationale
        || baseline.evidence_summary != candidate.evidence_summary
        || baseline.recommendation != candidate.recommendation
}

fn build_overall_delta(baseline: &ArtifactMetadata, candidate: &ArtifactMetadata) -> OverallDelta {
    OverallDelta {
        target_type_changed: baseline.target_type != candidate.target_type,
        target_changed: baseline.target != candidate.target,
        grade_changed: baseline.score.grade != candidate.score.grade,
        score_delta: signed_delta_u8(baseline.score.score, candidate.score.score),
        total_vectors_delta: signed_delta_usize(
            baseline.counts.total_vectors,
            candidate.counts.total_vectors,
        ),
        findings_delta: signed_delta_usize(baseline.counts.findings, candidate.counts.findings),
        vulnerable_delta: signed_delta_usize(
            baseline.counts.vulnerable,
            candidate.counts.vulnerable,
        ),
        resistant_delta: signed_delta_usize(baseline.counts.resistant, candidate.counts.resistant),
        error_delta: signed_delta_usize(baseline.counts.errors, candidate.counts.errors),
    }
}

fn build_category_deltas(
    baseline_findings: &[ComparedFinding],
    candidate_findings: &[ComparedFinding],
) -> Vec<CategoryDelta> {
    let baseline = category_counts(baseline_findings);
    let candidate = category_counts(candidate_findings);
    let mut categories = BTreeMap::new();

    for category in baseline.keys().chain(candidate.keys()) {
        categories.entry(category.clone()).or_insert(());
    }

    categories
        .into_keys()
        .map(|category| {
            let baseline_counts = baseline.get(&category).cloned().unwrap_or_default();
            let candidate_counts = candidate.get(&category).cloned().unwrap_or_default();
            CategoryDelta {
                category,
                delta: CategoryCountDelta {
                    total: signed_delta_usize(baseline_counts.total, candidate_counts.total),
                    vulnerable: signed_delta_usize(
                        baseline_counts.vulnerable,
                        candidate_counts.vulnerable,
                    ),
                    resistant: signed_delta_usize(
                        baseline_counts.resistant,
                        candidate_counts.resistant,
                    ),
                    errors: signed_delta_usize(baseline_counts.errors, candidate_counts.errors),
                },
                baseline: baseline_counts,
                candidate: candidate_counts,
            }
        })
        .collect()
}

fn category_counts(findings: &[ComparedFinding]) -> BTreeMap<String, CategoryCounts> {
    let mut categories: BTreeMap<String, CategoryCounts> = BTreeMap::new();

    for finding in findings {
        let counts = categories
            .entry(finding.identity.category.clone())
            .or_default();
        counts.total += 1;
        match finding.status {
            ArtifactFindingStatus::Vulnerable => counts.vulnerable += 1,
            ArtifactFindingStatus::Resistant => counts.resistant += 1,
            ArtifactFindingStatus::Error => counts.errors += 1,
        }
    }

    categories
}

fn signed_delta_usize(baseline: usize, candidate: usize) -> i64 {
    candidate as i64 - baseline as i64
}

fn signed_delta_u8(baseline: u8, candidate: u8) -> i64 {
    i64::from(candidate) - i64::from(baseline)
}

impl From<RawFinding> for ComparedFinding {
    fn from(value: RawFinding) -> Self {
        Self {
            identity: FindingIdentity {
                rule_id: value.rule_id,
                vector_id: value.vector_id,
                payload_name: value.payload_name,
                category: value.category,
                subcategory: value.subcategory,
            },
            status: value.status,
            severity: value.severity,
            rationale: value.rationale,
            evidence_summary: value.evidence_summary,
            recommendation: value.recommendation,
        }
    }
}

impl From<RawScore> for ArtifactScore {
    fn from(value: RawScore) -> Self {
        Self {
            score: value.score,
            grade: value.grade,
            vulnerable_severities: value.vulnerable_severities,
            error_count: value.error_count,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawArtifact {
    schema_version: String,
    scan: RawScan,
}

#[derive(Debug, Clone, Deserialize)]
struct RawScan {
    target_type: TargetType,
    target: String,
    total_vectors: usize,
    vulnerable_count: usize,
    resistant_count: usize,
    error_count: usize,
    score: RawScore,
    findings: Vec<RawFinding>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawScore {
    score: u8,
    grade: ArtifactGrade,
    vulnerable_severities: ArtifactSeverityCounts,
    error_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct RawFinding {
    rule_id: String,
    vector_id: String,
    payload_name: String,
    category: String,
    subcategory: String,
    status: ArtifactFindingStatus,
    severity: Severity,
    rationale: String,
    evidence_summary: String,
    recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ArtifactGrade {
    A,
    B,
    C,
    D,
    F,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ArtifactSeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ArtifactFindingStatus {
    Vulnerable,
    Resistant,
    Error,
}

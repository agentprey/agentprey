use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use crate::{
    analyzer::{analyze_response_for_vector, Analysis, Verdict},
    cli::ScanArgs,
    http_target,
    scorer::{score_findings, ScoreSummary},
    vectors::{loader::load_vectors_from_dir, model::Severity},
};

#[derive(Debug, Clone, Serialize)]
pub struct ScanOutcome {
    pub target: String,
    pub total_vectors: usize,
    pub vulnerable_count: usize,
    pub resistant_count: usize,
    pub error_count: usize,
    pub score: ScoreSummary,
    pub findings: Vec<FindingOutcome>,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingOutcome {
    pub vector_id: String,
    pub vector_name: String,
    pub category: String,
    pub subcategory: String,
    pub severity: Severity,
    pub payload_name: String,
    pub payload_prompt: String,
    pub status: FindingStatus,
    pub status_code: Option<u16>,
    pub response: String,
    pub analysis: Option<Analysis>,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FindingStatus {
    Vulnerable,
    Resistant,
    Error,
}

impl ScanOutcome {
    pub fn has_vulnerabilities(&self) -> bool {
        self.vulnerable_count > 0
    }
}

pub async fn run_scan(args: &ScanArgs) -> Result<ScanOutcome> {
    let started_at = Instant::now();

    let mut vectors = load_vectors_from_dir(&args.vectors_dir).with_context(|| {
        format!(
            "failed to load vectors from '{}'",
            args.vectors_dir.display()
        )
    })?;

    if let Some(category) = args.category.as_deref() {
        vectors.retain(|loaded| loaded.vector.category == category);
    }

    if vectors.is_empty() {
        return Err(anyhow!(
            "no vectors available from '{}' with current filters",
            args.vectors_dir.display()
        ));
    }

    vectors.sort_by(|left, right| left.vector.id.cmp(&right.vector.id));

    let mut findings = Vec::with_capacity(vectors.len());
    let mut vulnerable_count = 0usize;
    let mut resistant_count = 0usize;
    let mut error_count = 0usize;

    for loaded in vectors {
        let vector = loaded.vector;
        let payload = vector
            .payloads
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("vector '{}' is missing payloads", vector.id))?;

        let vector_started = Instant::now();
        match http_target::send_payload(
            &args.target,
            &payload.prompt,
            &args.headers,
            args.timeout_seconds,
        )
        .await
        {
            Ok(exchange) => {
                let analysis =
                    analyze_response_for_vector(&exchange.extracted_response, &vector.detection);
                let status = match analysis.verdict {
                    Verdict::Vulnerable => {
                        vulnerable_count += 1;
                        FindingStatus::Vulnerable
                    }
                    Verdict::Resistant => {
                        resistant_count += 1;
                        FindingStatus::Resistant
                    }
                };

                findings.push(FindingOutcome {
                    vector_id: vector.id,
                    vector_name: vector.name,
                    category: vector.category,
                    subcategory: vector.subcategory,
                    severity: vector.severity,
                    payload_name: payload.name,
                    payload_prompt: payload.prompt,
                    status,
                    status_code: Some(exchange.status),
                    response: exchange.extracted_response,
                    analysis: Some(analysis),
                    duration_ms: vector_started.elapsed().as_millis(),
                });
            }
            Err(error) => {
                error_count += 1;
                findings.push(FindingOutcome {
                    vector_id: vector.id,
                    vector_name: vector.name,
                    category: vector.category,
                    subcategory: vector.subcategory,
                    severity: vector.severity,
                    payload_name: payload.name,
                    payload_prompt: payload.prompt,
                    status: FindingStatus::Error,
                    status_code: None,
                    response: error.to_string(),
                    analysis: None,
                    duration_ms: vector_started.elapsed().as_millis(),
                });
            }
        }
    }

    let duration_ms = started_at.elapsed().as_millis();
    let score = score_findings(&findings);

    Ok(ScanOutcome {
        target: args.target.clone(),
        total_vectors: findings.len(),
        vulnerable_count,
        resistant_count,
        error_count,
        score,
        findings,
        duration_ms,
    })
}

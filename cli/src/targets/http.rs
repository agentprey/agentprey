use std::time::Instant;

use anyhow::{anyhow, Result};

use crate::{
    analyzer::{analyze_response_for_vector, Verdict},
    http_target,
    redaction::redact_text,
    scan::{
        FindingOutcome, FindingOutcomeInput, FindingStatus, HttpScanSettings, ResolvedScanSettings,
    },
    vectors::model::Vector,
};

#[derive(Debug, Clone)]
pub struct HttpTarget {
    target: String,
    headers: Vec<String>,
    request_policy: http_target::RequestPolicy,
    request_format: http_target::RequestFormat,
}

impl HttpTarget {
    pub fn from_settings(settings: &ResolvedScanSettings) -> Result<Self> {
        let http = settings
            .http
            .as_ref()
            .ok_or_else(|| anyhow!("missing HTTP scan settings for HTTP target"))?;

        Ok(Self::from_http_settings(
            settings.target.clone(),
            http,
            settings.timeout_seconds,
            settings.retries,
            settings.retry_backoff_ms,
        ))
    }

    fn from_http_settings(
        target: String,
        http: &HttpScanSettings,
        timeout_seconds: u64,
        retries: u32,
        retry_backoff_ms: u64,
    ) -> Self {
        Self {
            target,
            headers: http.headers.clone(),
            request_policy: http_target::RequestPolicy {
                timeout_seconds,
                retries,
                retry_backoff_ms,
            },
            request_format: http.request_format.clone(),
        }
    }

    pub async fn execute_vector(
        &self,
        vector: Vector,
        settings: &ResolvedScanSettings,
    ) -> FindingOutcome {
        let vector_started = Instant::now();
        let rule_id = vector.id.clone();
        let vector_id = vector.id.clone();
        let vector_name = vector.name.clone();
        let category = vector.category.clone();
        let subcategory = vector.subcategory.clone();
        let severity = vector.severity.clone();
        let rationale = vector.description.clone();
        let recommendation = vector_recommendation(&vector);

        let payload = match vector.payloads.first().cloned() {
            Some(payload) => payload,
            None => {
                return FindingOutcome::new(FindingOutcomeInput {
                    rule_id,
                    vector_id,
                    vector_name,
                    category,
                    subcategory,
                    severity,
                    payload_name: "missing".to_string(),
                    payload_prompt: "missing".to_string(),
                    status: FindingStatus::Error,
                    status_code: None,
                    response: "vector payload list is empty".to_string(),
                    analysis: None,
                    duration_ms: vector_started.elapsed().as_millis(),
                    rationale,
                    evidence_summary: "vector payload list is empty".to_string(),
                    recommendation,
                });
            }
        };

        match http_target::send_payload(
            &self.target,
            &payload.prompt,
            &self.headers,
            self.request_policy,
            &self.request_format,
        )
        .await
        {
            Ok(exchange) => {
                let analysis =
                    analyze_response_for_vector(&exchange.extracted_response, &vector.detection);
                let status = match analysis.verdict {
                    Verdict::Vulnerable => FindingStatus::Vulnerable,
                    Verdict::Resistant => FindingStatus::Resistant,
                };
                let evidence_summary =
                    summarize_analysis(&exchange.extracted_response, &analysis, status);

                FindingOutcome::new(FindingOutcomeInput {
                    rule_id,
                    vector_id,
                    vector_name,
                    category,
                    subcategory,
                    severity,
                    payload_name: payload.name,
                    payload_prompt: payload.prompt,
                    status,
                    status_code: Some(exchange.status),
                    response: maybe_redact(&exchange.extracted_response, settings.redact_responses),
                    analysis: Some(analysis),
                    duration_ms: vector_started.elapsed().as_millis(),
                    rationale,
                    evidence_summary,
                    recommendation,
                })
            }
            Err(error) => FindingOutcome::new(FindingOutcomeInput {
                rule_id,
                vector_id,
                vector_name,
                category,
                subcategory,
                severity,
                payload_name: payload.name,
                payload_prompt: payload.prompt,
                status: FindingStatus::Error,
                status_code: None,
                response: maybe_redact(&error.to_string(), settings.redact_responses),
                analysis: None,
                duration_ms: vector_started.elapsed().as_millis(),
                rationale,
                evidence_summary: error.to_string(),
                recommendation,
            }),
        }
    }
}

fn maybe_redact(input: &str, enabled: bool) -> String {
    if enabled {
        redact_text(input)
    } else {
        input.to_string()
    }
}

fn summarize_analysis(
    response: &str,
    analysis: &crate::analyzer::Analysis,
    status: FindingStatus,
) -> String {
    if !analysis.indicator_hits.is_empty() {
        return analysis.indicator_hits.join("; ");
    }

    match status {
        FindingStatus::Vulnerable => format!(
            "response matched the configured detection threshold: {}",
            truncate(response, 120)
        ),
        FindingStatus::Resistant => {
            "response did not match the configured detection threshold".to_string()
        }
        FindingStatus::Error => truncate(response, 120),
    }
}

fn vector_recommendation(vector: &Vector) -> String {
    vector
        .remediation
        .as_ref()
        .map(|remediation| remediation.summary.clone())
        .unwrap_or_else(|| {
            format!(
                "Review '{}' and tighten the target's handling for this attack path.",
                vector.name
            )
        })
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let clipped: String = value.chars().take(max_chars).collect();
    format!("{clipped}...")
}

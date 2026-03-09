use std::{fs, path::Path, time::Instant};

use anyhow::{anyhow, Context, Result};
use regex::Regex;

use crate::{
    analyzer::{analyze_response_for_vector, Verdict},
    redaction::redact_text,
    scan::{FindingOutcome, FindingOutcomeInput, FindingStatus, ResolvedScanSettings},
    vectors::model::Vector,
};

const SUPPORTED_EXTENSIONS: &[&str] = &[
    "json", "yaml", "yml", "toml", "md", "txt", "prompt", "cfg", "conf",
];
const MISSING_ANY_INDICATOR: &str = "missing_any";
const SNIPPET_CONTEXT_BYTES: usize = 48;
const MAX_EVIDENCE_LINES: usize = 3;

#[derive(Debug, Clone)]
pub struct OpenClawTarget {
    corpus: AuditCorpus,
    segments: Vec<CorpusSegment>,
}

#[derive(Debug, Clone)]
struct AuditCorpus {
    normalized_text: String,
    display_target: String,
    file_count: usize,
}

#[derive(Debug, Clone)]
struct CorpusSegment {
    display_path: String,
    normalized_text: String,
}

impl OpenClawTarget {
    pub fn from_path(path: &Path) -> Result<Self> {
        let resolved_path = path
            .canonicalize()
            .with_context(|| format!("openclaw target '{}' was not found", path.display()))?;

        let mut segments = Vec::new();
        collect_segments(&resolved_path, &resolved_path, &mut segments)?;
        if segments.is_empty() {
            return Err(anyhow!(
                "no supported OpenClaw audit files found under '{}'",
                resolved_path.display()
            ));
        }

        let normalized_text = segments
            .iter()
            .map(|segment| {
                format!(
                    "[file:{}]\n{}",
                    segment.display_path, segment.normalized_text
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        Ok(Self {
            corpus: AuditCorpus {
                normalized_text,
                display_target: resolved_path.display().to_string(),
                file_count: segments.len(),
            },
            segments,
        })
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

        let analysis = analyze_response_for_vector(&self.corpus.normalized_text, &vector.detection);
        let status = match analysis.verdict {
            Verdict::Vulnerable => FindingStatus::Vulnerable,
            Verdict::Resistant => FindingStatus::Resistant,
        };

        let evidence = self.collect_evidence(&vector);
        let response = self.synthesize_response(&vector, status, &evidence);

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
            status_code: None,
            response: maybe_redact(&response, settings.redact_responses),
            analysis: Some(analysis),
            duration_ms: vector_started.elapsed().as_millis(),
            rationale,
            evidence_summary: if evidence.is_empty() {
                response.clone()
            } else {
                evidence.join("; ")
            },
            recommendation,
        })
    }

    fn collect_evidence(&self, vector: &Vector) -> Vec<String> {
        let mut evidence = Vec::new();

        for indicator in &vector.detection.indicators {
            match indicator.indicator_type.as_str() {
                "contains_any" => {
                    for value in &indicator.values {
                        if let Some(snippet) = self.find_literal_snippet(value) {
                            evidence.push(snippet);
                        }
                        if evidence.len() >= MAX_EVIDENCE_LINES {
                            return dedupe_evidence(evidence);
                        }
                    }
                }
                "regex_any" => {
                    for pattern in &indicator.values {
                        if let Some(snippet) = self.find_regex_snippet(pattern) {
                            evidence.push(snippet);
                        }
                        if evidence.len() >= MAX_EVIDENCE_LINES {
                            return dedupe_evidence(evidence);
                        }
                    }
                }
                MISSING_ANY_INDICATOR => {
                    if indicator.values.iter().all(|value| {
                        !self
                            .corpus
                            .normalized_text
                            .contains(&value.trim().to_ascii_lowercase())
                    }) {
                        evidence.push(format!(
                            "missing required markers across {} files under {}: {}",
                            self.corpus.file_count,
                            self.corpus.display_target,
                            indicator.values.join(", ")
                        ));
                    }
                }
                _ => {}
            }
        }

        dedupe_evidence(evidence)
    }

    fn find_literal_snippet(&self, literal: &str) -> Option<String> {
        let normalized_literal = literal.trim().to_ascii_lowercase();
        if normalized_literal.is_empty() {
            return None;
        }

        self.segments.iter().find_map(|segment| {
            segment
                .normalized_text
                .find(&normalized_literal)
                .map(|start| {
                    let end = start + normalized_literal.len();
                    format!(
                        "{}: {}",
                        segment.display_path,
                        snippet_around(&segment.normalized_text, start, end)
                    )
                })
        })
    }

    fn find_regex_snippet(&self, pattern: &str) -> Option<String> {
        let regex = Regex::new(pattern).ok()?;
        self.segments.iter().find_map(|segment| {
            regex.find(&segment.normalized_text).map(|matched| {
                format!(
                    "{}: {}",
                    segment.display_path,
                    snippet_around(&segment.normalized_text, matched.start(), matched.end(),)
                )
            })
        })
    }

    fn synthesize_response(
        &self,
        vector: &Vector,
        status: FindingStatus,
        evidence: &[String],
    ) -> String {
        if !evidence.is_empty() {
            return format!(
                "openclaw audit for '{}' on {} ({} files):\n- {}",
                vector.name,
                self.corpus.display_target,
                self.corpus.file_count,
                evidence.join("\n- ")
            );
        }

        match status {
            FindingStatus::Vulnerable => format!(
                "openclaw audit marked '{}' vulnerable across {} files under {}.",
                vector.name, self.corpus.file_count, self.corpus.display_target
            ),
            FindingStatus::Resistant => format!(
                "openclaw audit found no matching evidence for '{}' across {} files under {}.",
                vector.name, self.corpus.file_count, self.corpus.display_target
            ),
            FindingStatus::Error => format!(
                "openclaw audit could not evaluate '{}' under {}.",
                vector.name, self.corpus.display_target
            ),
        }
    }
}

fn collect_segments(root: &Path, path: &Path, segments: &mut Vec<CorpusSegment>) -> Result<()> {
    if path.is_dir() {
        let entries = fs::read_dir(path)
            .with_context(|| format!("failed to read directory '{}'", path.display()))?;

        for entry in entries {
            let entry =
                entry.with_context(|| format!("failed to read entry in '{}'", path.display()))?;
            collect_segments(root, &entry.path(), segments)?;
        }

        return Ok(());
    }

    if !path.is_file() || !should_include_file(path) {
        return Ok(());
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read OpenClaw audit file '{}'", path.display()))?;
    let normalized_text = content.to_ascii_lowercase();

    let display_path = if root.is_dir() {
        path.strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string()
    } else {
        path.file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string())
    };

    segments.push(CorpusSegment {
        display_path,
        normalized_text,
    });

    Ok(())
}

fn should_include_file(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => {
            let extension = extension.to_ascii_lowercase();
            SUPPORTED_EXTENSIONS.contains(&extension.as_str())
        }
        None => {
            file_name.contains("prompt")
                || file_name.contains("config")
                || file_name.contains("instruction")
                || file_name.contains("policy")
        }
    }
}

fn dedupe_evidence(evidence: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for line in evidence {
        if deduped.iter().any(|existing| existing == &line) {
            continue;
        }

        deduped.push(line);
        if deduped.len() >= MAX_EVIDENCE_LINES {
            break;
        }
    }

    deduped
}

fn snippet_around(text: &str, start: usize, end: usize) -> String {
    let start = floor_char_boundary(text, start.saturating_sub(SNIPPET_CONTEXT_BYTES));
    let end = ceil_char_boundary(text, (end + SNIPPET_CONTEXT_BYTES).min(text.len()));
    let snippet = text[start..end].replace('\n', " ");
    format!("…{}…", snippet.trim())
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

fn maybe_redact(input: &str, enabled: bool) -> String {
    if enabled {
        redact_text(input)
    } else {
        input.to_string()
    }
}

fn vector_recommendation(vector: &Vector) -> String {
    vector
        .remediation
        .as_ref()
        .map(|remediation| remediation.summary.clone())
        .unwrap_or_else(|| {
            format!(
                "Review '{}' and tighten the scanned OpenClaw surface.",
                vector.name
            )
        })
}

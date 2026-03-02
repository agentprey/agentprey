use std::{path::PathBuf, time::Instant};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use crate::{
    analyzer::{analyze_response_for_vector, Analysis, Verdict},
    cli::ScanArgs,
    config::{load_project_config, ProjectConfig},
    http_target,
    scorer::{score_findings, ScoreSummary},
    vectors::{loader::load_vectors_from_dir, model::Severity},
};

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_VECTORS_DIR: &str = "vectors";

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

#[derive(Debug, Clone)]
pub struct ResolvedScanSettings {
    pub target: String,
    pub headers: Vec<String>,
    pub timeout_seconds: u64,
    pub vectors_dir: PathBuf,
    pub category: Option<String>,
    pub json_out: Option<PathBuf>,
}

impl ScanOutcome {
    pub fn has_vulnerabilities(&self) -> bool {
        self.vulnerable_count > 0
    }
}

pub fn resolve_scan_settings(args: &ScanArgs) -> Result<ResolvedScanSettings> {
    let config = load_config_for_scan(args)?;

    let target = args
        .target
        .clone()
        .or_else(|| config.as_ref().and_then(|cfg| cfg.target.endpoint.clone()))
        .ok_or_else(|| {
            anyhow!(
                "scan target is required (pass --target or provide [target].endpoint in config)"
            )
        })?;

    let headers = if !args.headers.is_empty() {
        args.headers.clone()
    } else {
        config_headers_as_vec(config.as_ref())
    };

    let timeout_seconds = args
        .timeout_seconds
        .or_else(|| config.as_ref().and_then(|cfg| cfg.scan.timeout_seconds))
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS);

    let vectors_dir = args
        .vectors_dir
        .clone()
        .or_else(|| config.as_ref().and_then(|cfg| cfg.scan.vectors_dir.clone()))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VECTORS_DIR));

    let category = args
        .category
        .clone()
        .or_else(|| config.as_ref().and_then(|cfg| cfg.scan.category.clone()));

    let json_out = args
        .json_out
        .clone()
        .or_else(|| config.as_ref().and_then(|cfg| cfg.output.json_out.clone()));

    Ok(ResolvedScanSettings {
        target,
        headers,
        timeout_seconds,
        vectors_dir,
        category,
        json_out,
    })
}

pub async fn run_scan(args: &ScanArgs) -> Result<ScanOutcome> {
    let settings = resolve_scan_settings(args)?;
    run_scan_with_settings(&settings).await
}

pub async fn run_scan_with_settings(settings: &ResolvedScanSettings) -> Result<ScanOutcome> {
    let started_at = Instant::now();

    let mut vectors = load_vectors_from_dir(&settings.vectors_dir).with_context(|| {
        format!(
            "failed to load vectors from '{}'",
            settings.vectors_dir.display()
        )
    })?;

    if let Some(category) = settings.category.as_deref() {
        vectors.retain(|loaded| loaded.vector.category == category);
    }

    if vectors.is_empty() {
        return Err(anyhow!(
            "no vectors available from '{}' with current filters",
            settings.vectors_dir.display()
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
            &settings.target,
            &payload.prompt,
            &settings.headers,
            settings.timeout_seconds,
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
        target: settings.target.clone(),
        total_vectors: findings.len(),
        vulnerable_count,
        resistant_count,
        error_count,
        score,
        findings,
        duration_ms,
    })
}

fn load_config_for_scan(args: &ScanArgs) -> Result<Option<ProjectConfig>> {
    let Some(path) = args.config.as_ref() else {
        return Ok(None);
    };

    if !path.exists() {
        return Err(anyhow!("config file '{}' was not found", path.display()));
    }

    load_project_config(path).map(Some)
}

fn config_headers_as_vec(config: Option<&ProjectConfig>) -> Vec<String> {
    let Some(config) = config else {
        return Vec::new();
    };

    let mut headers: Vec<String> = config
        .target
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect();
    headers.sort();
    headers
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::{cli::ScanArgs, scan::resolve_scan_settings};

    #[test]
    fn resolves_settings_from_config_when_cli_values_missing() {
        let temp = tempdir().expect("tempdir should be created");
        let config_path = temp.path().join(".agentprey.toml");
        fs::write(
            &config_path,
            r#"
[target]
endpoint = "http://127.0.0.1:8787/chat"
headers = { Authorization = "Bearer config-token" }

[scan]
timeout_seconds = 22
vectors_dir = "vectors"
category = "prompt-injection"

[output]
json_out = "./from-config.json"
"#,
        )
        .expect("config fixture should be written");

        let args = ScanArgs {
            target: None,
            headers: vec![],
            timeout_seconds: None,
            vectors_dir: None,
            category: None,
            json_out: None,
            config: Some(config_path),
        };

        let resolved = resolve_scan_settings(&args).expect("settings should resolve");
        assert_eq!(resolved.target, "http://127.0.0.1:8787/chat");
        assert_eq!(resolved.timeout_seconds, 22);
        assert_eq!(resolved.category.as_deref(), Some("prompt-injection"));
        assert_eq!(
            resolved
                .json_out
                .as_ref()
                .map(|path| path.to_string_lossy()),
            Some("./from-config.json".into())
        );
        assert_eq!(resolved.headers, vec!["Authorization: Bearer config-token"]);
    }

    #[test]
    fn prefers_cli_over_config_values() {
        let temp = tempdir().expect("tempdir should be created");
        let config_path = temp.path().join(".agentprey.toml");
        fs::write(
            &config_path,
            r#"
[target]
endpoint = "http://config-target"

[scan]
timeout_seconds = 55
vectors_dir = "vectors"
category = "prompt-injection"

[output]
json_out = "./from-config.json"
"#,
        )
        .expect("config fixture should be written");

        let args = ScanArgs {
            target: Some("http://cli-target".to_string()),
            headers: vec!["Authorization: Bearer cli-token".to_string()],
            timeout_seconds: Some(7),
            vectors_dir: Some(temp.path().join("custom-vectors")),
            category: Some("custom-category".to_string()),
            json_out: Some(temp.path().join("cli-output.json")),
            config: Some(config_path),
        };

        let resolved = resolve_scan_settings(&args).expect("settings should resolve");
        assert_eq!(resolved.target, "http://cli-target");
        assert_eq!(resolved.timeout_seconds, 7);
        assert_eq!(resolved.headers, vec!["Authorization: Bearer cli-token"]);
        assert_eq!(resolved.category.as_deref(), Some("custom-category"));
        assert!(resolved
            .json_out
            .as_ref()
            .expect("json path should exist")
            .ends_with("cli-output.json"));
    }
}

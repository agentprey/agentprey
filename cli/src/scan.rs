use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinHandle,
    time::Instant as TokioInstant,
};

use crate::{
    analyzer::{analyze_response_for_vector, Analysis, Verdict},
    cli::ScanArgs,
    config::{load_project_config, ProjectConfig},
    http_target,
    redaction::redact_text,
    scorer::{score_findings, ScoreSummary},
    vectors::{loader::load_vectors, model::Severity},
};

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_VECTORS_DIR: &str = "vectors";
const DEFAULT_RETRIES: u32 = 2;
const DEFAULT_RETRY_BACKOFF_MS: u64 = 250;
const DEFAULT_MAX_CONCURRENT: usize = 2;
const DEFAULT_RATE_LIMIT_RPS: u32 = 10;
const DEFAULT_REDACT_RESPONSES: bool = true;

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
    pub retries: u32,
    pub retry_backoff_ms: u64,
    pub max_concurrent: usize,
    pub rate_limit_rps: u32,
    pub redact_responses: bool,
    pub vectors_dir: PathBuf,
    pub category: Option<String>,
    pub json_out: Option<PathBuf>,
    pub html_out: Option<PathBuf>,
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

    let retries = args
        .retries
        .or_else(|| config.as_ref().and_then(|cfg| cfg.scan.retries))
        .unwrap_or(DEFAULT_RETRIES);

    let retry_backoff_ms = args
        .retry_backoff_ms
        .or_else(|| config.as_ref().and_then(|cfg| cfg.scan.retry_backoff_ms))
        .unwrap_or(DEFAULT_RETRY_BACKOFF_MS);

    let max_concurrent = args
        .max_concurrent
        .or_else(|| config.as_ref().and_then(|cfg| cfg.scan.max_concurrent))
        .unwrap_or(DEFAULT_MAX_CONCURRENT)
        .max(1);

    let rate_limit_rps = args
        .rate_limit_rps
        .or_else(|| config.as_ref().and_then(|cfg| cfg.scan.rate_limit_rps))
        .unwrap_or(DEFAULT_RATE_LIMIT_RPS)
        .max(1);

    let redact_override = if args.redact_responses {
        Some(true)
    } else if args.no_redact_responses {
        Some(false)
    } else {
        None
    };

    let redact_responses = redact_override
        .or_else(|| config.as_ref().and_then(|cfg| cfg.scan.redact_responses))
        .unwrap_or(DEFAULT_REDACT_RESPONSES);

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

    let html_out = args
        .html_out
        .clone()
        .or_else(|| config.as_ref().and_then(|cfg| cfg.output.html_out.clone()));

    Ok(ResolvedScanSettings {
        target,
        headers,
        timeout_seconds,
        retries,
        retry_backoff_ms,
        max_concurrent,
        rate_limit_rps,
        redact_responses,
        vectors_dir,
        category,
        json_out,
        html_out,
    })
}

pub async fn run_scan(args: &ScanArgs) -> Result<ScanOutcome> {
    let settings = resolve_scan_settings(args)?;
    run_scan_with_settings(&settings).await
}

pub async fn run_scan_with_settings(settings: &ResolvedScanSettings) -> Result<ScanOutcome> {
    let started_at = Instant::now();

    let mut vectors = load_vectors(&settings.vectors_dir).with_context(|| {
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

    let semaphore = Arc::new(Semaphore::new(settings.max_concurrent));
    let limiter = Arc::new(RequestRateLimiter::new(settings.rate_limit_rps));

    let mut tasks: Vec<JoinHandle<FindingOutcome>> = Vec::with_capacity(vectors.len());
    for loaded in vectors {
        let vector = loaded.vector;
        let target = settings.target.clone();
        let headers = settings.headers.clone();
        let request_policy = http_target::RequestPolicy {
            timeout_seconds: settings.timeout_seconds,
            retries: settings.retries,
            retry_backoff_ms: settings.retry_backoff_ms,
        };
        let redact_responses = settings.redact_responses;

        let semaphore = semaphore.clone();
        let limiter = limiter.clone();

        let task = tokio::spawn(async move {
            let permit = semaphore
                .acquire_owned()
                .await
                .expect("semaphore should stay open during scan");
            let _permit = permit;

            limiter.wait_turn().await;
            execute_vector_scan(vector, &target, &headers, request_policy, redact_responses).await
        });
        tasks.push(task);
    }

    let mut findings = Vec::with_capacity(tasks.len());
    for task in tasks {
        match task.await {
            Ok(finding) => findings.push(finding),
            Err(error) => findings.push(FindingOutcome {
                vector_id: "internal-runtime".to_string(),
                vector_name: "Task Join Error".to_string(),
                category: "internal".to_string(),
                subcategory: "runtime".to_string(),
                severity: Severity::Info,
                payload_name: "n/a".to_string(),
                payload_prompt: "n/a".to_string(),
                status: FindingStatus::Error,
                status_code: None,
                response: format!("task join failure: {error}"),
                analysis: None,
                duration_ms: 0,
            }),
        }
    }

    findings.sort_by(|left, right| left.vector_id.cmp(&right.vector_id));

    let mut vulnerable_count = 0usize;
    let mut resistant_count = 0usize;
    let mut error_count = 0usize;
    for finding in &findings {
        match finding.status {
            FindingStatus::Vulnerable => vulnerable_count += 1,
            FindingStatus::Resistant => resistant_count += 1,
            FindingStatus::Error => error_count += 1,
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

async fn execute_vector_scan(
    vector: crate::vectors::model::Vector,
    target: &str,
    headers: &[String],
    request_policy: http_target::RequestPolicy,
    redact_responses: bool,
) -> FindingOutcome {
    let vector_started = Instant::now();

    let payload = match vector.payloads.first().cloned() {
        Some(payload) => payload,
        None => {
            return FindingOutcome {
                vector_id: vector.id,
                vector_name: vector.name,
                category: vector.category,
                subcategory: vector.subcategory,
                severity: vector.severity,
                payload_name: "missing".to_string(),
                payload_prompt: "missing".to_string(),
                status: FindingStatus::Error,
                status_code: None,
                response: "vector payload list is empty".to_string(),
                analysis: None,
                duration_ms: vector_started.elapsed().as_millis(),
            };
        }
    };

    match http_target::send_payload(target, &payload.prompt, headers, request_policy).await {
        Ok(exchange) => {
            let analysis =
                analyze_response_for_vector(&exchange.extracted_response, &vector.detection);
            let status = match analysis.verdict {
                Verdict::Vulnerable => FindingStatus::Vulnerable,
                Verdict::Resistant => FindingStatus::Resistant,
            };

            FindingOutcome {
                vector_id: vector.id,
                vector_name: vector.name,
                category: vector.category,
                subcategory: vector.subcategory,
                severity: vector.severity,
                payload_name: payload.name,
                payload_prompt: payload.prompt,
                status,
                status_code: Some(exchange.status),
                response: maybe_redact(&exchange.extracted_response, redact_responses),
                analysis: Some(analysis),
                duration_ms: vector_started.elapsed().as_millis(),
            }
        }
        Err(error) => FindingOutcome {
            vector_id: vector.id,
            vector_name: vector.name,
            category: vector.category,
            subcategory: vector.subcategory,
            severity: vector.severity,
            payload_name: payload.name,
            payload_prompt: payload.prompt,
            status: FindingStatus::Error,
            status_code: None,
            response: maybe_redact(&error.to_string(), redact_responses),
            analysis: None,
            duration_ms: vector_started.elapsed().as_millis(),
        },
    }
}

fn maybe_redact(input: &str, enabled: bool) -> String {
    if enabled {
        redact_text(input)
    } else {
        input.to_string()
    }
}

#[derive(Debug)]
struct RequestRateLimiter {
    min_interval: Duration,
    next_allowed: Mutex<TokioInstant>,
}

impl RequestRateLimiter {
    fn new(rate_limit_rps: u32) -> Self {
        let min_interval = Duration::from_secs_f64(1.0 / f64::from(rate_limit_rps));
        Self {
            min_interval,
            next_allowed: Mutex::new(TokioInstant::now()),
        }
    }

    async fn wait_turn(&self) {
        let mut next_allowed = self.next_allowed.lock().await;
        let now = TokioInstant::now();
        if *next_allowed > now {
            tokio::time::sleep(*next_allowed - now).await;
        }

        *next_allowed = TokioInstant::now() + self.min_interval;
    }
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
retries = 2
retry_backoff_ms = 300
vectors_dir = "vectors"
category = "prompt-injection"

[output]
json_out = "./from-config.json"
html_out = "./from-config.html"
"#,
        )
        .expect("config fixture should be written");

        let args = ScanArgs {
            target: None,
            headers: vec![],
            timeout_seconds: None,
            retries: None,
            retry_backoff_ms: None,
            max_concurrent: None,
            rate_limit_rps: None,
            redact_responses: false,
            no_redact_responses: false,
            vectors_dir: None,
            category: None,
            json_out: None,
            html_out: None,
            config: Some(config_path),
        };

        let resolved = resolve_scan_settings(&args).expect("settings should resolve");
        assert_eq!(resolved.target, "http://127.0.0.1:8787/chat");
        assert_eq!(resolved.timeout_seconds, 22);
        assert_eq!(resolved.retries, 2);
        assert_eq!(resolved.retry_backoff_ms, 300);
        assert_eq!(resolved.max_concurrent, 2);
        assert_eq!(resolved.rate_limit_rps, 10);
        assert!(resolved.redact_responses);
        assert_eq!(resolved.category.as_deref(), Some("prompt-injection"));
        assert_eq!(
            resolved
                .json_out
                .as_ref()
                .map(|path| path.to_string_lossy()),
            Some("./from-config.json".into())
        );
        assert_eq!(
            resolved
                .html_out
                .as_ref()
                .map(|path| path.to_string_lossy()),
            Some("./from-config.html".into())
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
            retries = 9
            retry_backoff_ms = 999
            max_concurrent = 6
            rate_limit_rps = 50
            redact_responses = true
            vectors_dir = "vectors"
            category = "prompt-injection"

[output]
json_out = "./from-config.json"
html_out = "./from-config.html"
"#,
        )
        .expect("config fixture should be written");

        let args = ScanArgs {
            target: Some("http://cli-target".to_string()),
            headers: vec!["Authorization: Bearer cli-token".to_string()],
            timeout_seconds: Some(7),
            retries: Some(1),
            retry_backoff_ms: Some(50),
            max_concurrent: Some(3),
            rate_limit_rps: Some(12),
            redact_responses: false,
            no_redact_responses: true,
            vectors_dir: Some(temp.path().join("custom-vectors")),
            category: Some("custom-category".to_string()),
            json_out: Some(temp.path().join("cli-output.json")),
            html_out: Some(temp.path().join("cli-output.html")),
            config: Some(config_path),
        };

        let resolved = resolve_scan_settings(&args).expect("settings should resolve");
        assert_eq!(resolved.target, "http://cli-target");
        assert_eq!(resolved.timeout_seconds, 7);
        assert_eq!(resolved.retries, 1);
        assert_eq!(resolved.retry_backoff_ms, 50);
        assert_eq!(resolved.max_concurrent, 3);
        assert_eq!(resolved.rate_limit_rps, 12);
        assert!(!resolved.redact_responses);
        assert_eq!(resolved.headers, vec!["Authorization: Bearer cli-token"]);
        assert_eq!(resolved.category.as_deref(), Some("custom-category"));
        assert!(resolved
            .json_out
            .as_ref()
            .expect("json path should exist")
            .ends_with("cli-output.json"));
        assert!(resolved
            .html_out
            .as_ref()
            .expect("html path should exist")
            .ends_with("cli-output.html"));
    }
}

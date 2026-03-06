use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    cli::TargetType,
    output::json::render_scan_json,
    scan::{ResolvedScanSettings, ScanOutcome},
};

const SCAN_RUNS_PATH: &str = "/api/scan-runs";

#[derive(Debug, Clone, Deserialize)]
pub struct ScanUploadResponse {
    pub scan_run_id: String,
    pub share_id: String,
    pub share_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanRunUploadPayload<'a> {
    cli_version: &'static str,
    target_type: &'a str,
    artifact_json: &'a str,
}

pub async fn upload_scan_run(
    settings: &ResolvedScanSettings,
    outcome: &ScanOutcome,
) -> Result<ScanUploadResponse> {
    let api_key = auth::require_stored_api_key()?;
    let api_base_url = auth::resolve_api_base_url()?;
    let artifact_json = render_scan_json(outcome)?;

    upload_scan_run_with_artifact(&api_base_url, &api_key, settings, &artifact_json).await
}

async fn upload_scan_run_with_artifact(
    api_base_url: &str,
    api_key: &str,
    settings: &ResolvedScanSettings,
    artifact_json: &str,
) -> Result<ScanUploadResponse> {
    let url = scan_runs_url(api_base_url);
    let client = auth::authenticated_api_client(api_key)
        .context("failed to build scan upload HTTP client")?;
    let payload = ScanRunUploadPayload {
        cli_version: env!("CARGO_PKG_VERSION"),
        target_type: target_type_label(settings.target_type),
        artifact_json,
    };

    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("failed to contact scan upload API at {url}"))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read scan upload API response body")?;

    if !status.is_success() {
        let body_excerpt = truncate(&body, 180);
        return Err(anyhow!(
            "scan upload API returned HTTP {}: {}",
            status.as_u16(),
            body_excerpt
        ));
    }

    serde_json::from_str(&body).context("failed to parse scan upload API response JSON")
}

fn scan_runs_url(base_url: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), SCAN_RUNS_PATH)
}

fn target_type_label(target_type: TargetType) -> &'static str {
    match target_type {
        TargetType::Http => "http",
        TargetType::Openclaw => "openclaw",
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let total = value.chars().count();
    if total <= max_chars {
        return value.to_string();
    }

    let clipped: String = value.chars().take(max_chars).collect();
    format!("{clipped}...")
}

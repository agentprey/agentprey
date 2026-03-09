use std::{env, ffi::OsString, path::PathBuf, thread, time::Duration};

mod test_support;

use agentprey::{
    auth,
    cli::TargetType,
    cloud::upload_scan_run,
    output::json::SCAN_ARTIFACT_SCHEMA_VERSION,
    scan::{FindingOutcome, FindingStatus, ResolvedScanSettings, ScanOutcome},
    scorer::{Grade, ScoreSummary, SeverityCounts},
    vectors::model::Severity,
};
use serde_json::Value;
use tiny_http::{Header, Response, Server};

struct MockUploadServer {
    base_url: String,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for MockUploadServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = env::var_os(key);
        env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => env::set_var(self.key, value),
            None => env::remove_var(self.key),
        }
    }
}

fn sample_settings() -> ResolvedScanSettings {
    ResolvedScanSettings {
        target_type: TargetType::Openclaw,
        target: "./fixtures/openclaw-demo-project".to_string(),
        http: None,
        timeout_seconds: 30,
        retries: 0,
        retry_backoff_ms: 10,
        max_concurrent: 1,
        rate_limit_rps: 1,
        redact_responses: true,
        vectors_dir: PathBuf::from("vectors"),
        category: Some("openclaw".to_string()),
        json_out: None,
        html_out: None,
    }
}

fn sample_outcome() -> ScanOutcome {
    ScanOutcome {
        target_type: TargetType::Openclaw,
        target: "./fixtures/openclaw-demo-project".to_string(),
        mcp: None,
        total_vectors: 1,
        vulnerable_count: 1,
        resistant_count: 0,
        error_count: 0,
        score: ScoreSummary {
            score: 72,
            grade: Grade::C,
            vulnerable_severities: SeverityCounts {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            },
            error_count: 0,
        },
        findings: vec![FindingOutcome {
            rule_id: "oc-perm-001".to_string(),
            vector_id: "oc-perm-001".to_string(),
            vector_name: "Overprivileged Tool Access".to_string(),
            category: "openclaw".to_string(),
            subcategory: "permissions".to_string(),
            severity: Severity::Critical,
            payload_name: "workspace tools".to_string(),
            payload_prompt: "Inspect permissions.toml".to_string(),
            status: FindingStatus::Vulnerable,
            status_code: None,
            response: "shell.exec is enabled in permissions.toml".to_string(),
            analysis: None,
            duration_ms: 18,
            rationale: "Detected overprivileged tool access.".to_string(),
            evidence_summary: "shell.exec is enabled in permissions.toml".to_string(),
            recommendation: "Reduce tool permissions.".to_string(),
            tool_name: None,
            capabilities: Vec::new(),
            approval_sensitive: None,
        }],
        duration_ms: 31,
    }
}

fn spawn_upload_server(
    status_code: u16,
    body: &str,
) -> (
    MockUploadServer,
    std::sync::mpsc::Receiver<(Option<String>, String, String)>,
) {
    let server = Server::http("127.0.0.1:0").expect("upload server should bind");
    let socket = server
        .server_addr()
        .to_ip()
        .expect("upload server should expose socket address");
    let base_url = format!("http://{socket}");
    let response_body = body.to_string();
    let (sender, receiver) = std::sync::mpsc::channel();

    let handle = thread::spawn(move || {
        if let Ok(Some(mut request)) = server.recv_timeout(Duration::from_secs(5)) {
            let seen_key = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("x-api-key"))
                .map(|header| header.value.as_str().to_string());
            let url = request.url().to_string();
            let mut request_body = String::new();
            request
                .as_reader()
                .read_to_string(&mut request_body)
                .expect("request body should be readable");
            sender
                .send((seen_key, url, request_body))
                .expect("request should be captured");

            let content_type =
                Header::from_bytes("Content-Type", "application/json").expect("valid header");
            let response = Response::from_string(response_body)
                .with_status_code(status_code)
                .with_header(content_type);
            let _ = request.respond(response);
        }
    });

    (
        MockUploadServer {
            base_url,
            handle: Some(handle),
        },
        receiver,
    )
}

#[tokio::test]
async fn upload_scan_run_includes_api_key_header() {
    test_support::with_temp_agentprey_home(|_| async {
        let (server, receiver) = spawn_upload_server(
            200,
            r#"{"scan_run_id":"scan_run_123","share_id":"share_123","share_url":"https://app.agentprey.com/reports/share_123"}"#,
        );
        let _api_url = EnvVarGuard::set("AGENTPREY_API_URL", &server.base_url);

        auth::activate(Some("test-api-key".to_string())).expect("credentials should be written");

        let response = upload_scan_run(&sample_settings(), &sample_outcome())
            .await
            .expect("upload should succeed");

        assert_eq!(response.scan_run_id, "scan_run_123");
        assert_eq!(response.share_id, "share_123");
        assert_eq!(
            response.share_url.as_deref(),
            Some("https://app.agentprey.com/reports/share_123")
        );

        let (seen_key, url, body) = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("upload request should be captured");
        assert_eq!(seen_key.as_deref(), Some("test-api-key"));
        assert_eq!(url, "/api/scan-runs");

        let payload: Value =
            serde_json::from_str(&body).expect("upload request body should be valid JSON");
        assert_eq!(payload["cli_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(payload["target_type"], "openclaw");

        let artifact_json = payload["artifact_json"]
            .as_str()
            .expect("artifact_json should be a string");
        let artifact: Value =
            serde_json::from_str(artifact_json).expect("artifact_json should contain JSON");
        assert_eq!(artifact["schema_version"], SCAN_ARTIFACT_SCHEMA_VERSION);
        assert_eq!(artifact["scan"]["target"], "./fixtures/openclaw-demo-project");
    })
    .await;
}

#[tokio::test]
async fn upload_scan_run_requires_stored_key() {
    test_support::with_temp_agentprey_home(|_| async {
        let error = upload_scan_run(&sample_settings(), &sample_outcome())
            .await
            .expect_err("upload should fail without stored credentials");

        assert!(error
            .to_string()
            .contains("no API key stored; run `agentprey auth activate` first"));
    })
    .await;
}

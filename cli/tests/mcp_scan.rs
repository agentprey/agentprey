use std::path::PathBuf;

mod test_support;

use agentprey::{
    cli::{ScanArgs, ScanUi, TargetType},
    scan::run_scan,
};
use tempfile::tempdir;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[tokio::test]
async fn mcp_scan_loads_descriptor_and_emits_expected_findings() {
    test_support::with_temp_agentprey_home(|_| async {
        let output_dir = tempdir().expect("tempdir should be created");
        let json_out = output_dir.path().join("mcp-scan.json");
        let html_out = output_dir.path().join("mcp-scan.html");

        let args = ScanArgs {
            target: Some(fixture_path("mcp-descriptor.json").display().to_string()),
            target_type: TargetType::Mcp,
            headers: vec![],
            request_template: None,
            timeout_seconds: Some(5),
            retries: Some(0),
            retry_backoff_ms: Some(1),
            max_concurrent: Some(1),
            rate_limit_rps: Some(1),
            redact_responses: false,
            no_redact_responses: false,
            vectors_dir: None,
            category: Some("mcp-security".to_string()),
            json_out: Some(json_out),
            html_out: Some(html_out),
            upload: false,
            config: None,
            ui: ScanUi::Plain,
        };

        let outcome = run_scan(&args).await.expect("mcp scan should succeed");

        assert_eq!(outcome.target_type, TargetType::Mcp);
        assert_eq!(outcome.total_vectors, 3);
        assert_eq!(outcome.vulnerable_count, 3);
        assert_eq!(outcome.error_count, 0);

        let mcp = outcome.mcp.as_ref().expect("mcp metadata should exist");
        assert_eq!(mcp.inventory.tool_count, 3);
        assert_eq!(mcp.inventory.parse_warning_count, 0);
        assert!(mcp.tools.iter().any(|tool| tool.name == "run_shell"));

        assert!(outcome
            .findings
            .iter()
            .all(|finding| !finding.rule_id.is_empty() && !finding.recommendation.is_empty()));
    })
    .await;
}

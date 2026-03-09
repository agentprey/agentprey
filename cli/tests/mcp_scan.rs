use std::{fs, path::PathBuf};

mod test_support;

use agentprey::{
    cli::{ScanArgs, ScanUi, TargetType},
    output::json::{render_scan_json, SCAN_ARTIFACT_SCHEMA_VERSION},
    scan::{run_scan, FindingStatus},
};
use serde_json::Value;
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
        assert_eq!(outcome.total_vectors, 4);
        assert_eq!(outcome.vulnerable_count, 4);
        assert_eq!(outcome.error_count, 0);

        let mcp = outcome.mcp.as_ref().expect("mcp metadata should exist");
        assert_eq!(mcp.inventory.tool_count, 3);
        assert_eq!(mcp.inventory.parse_warning_count, 0);
        assert!(mcp.tools.iter().any(|tool| tool.name == "run_shell"));

        let rule_ids = outcome
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            rule_ids,
            vec![
                "mcp-tool-001",
                "mcp-tool-002",
                "mcp-tool-003",
                "mcp-tool-004"
            ]
        );

        assert!(outcome.findings.iter().all(|finding| {
            !finding.rule_id.is_empty()
                && !finding.recommendation.is_empty()
                && finding.attack_surface.as_deref() == Some("mcp")
                && finding.evidence_kind.as_deref() == Some("mcp-descriptor")
                && !finding.repro_steps.is_empty()
                && !finding.mitigation_tags.is_empty()
                && finding.capabilities == finding.observed_capabilities
        }));

        let json = render_scan_json(&outcome).expect("scan JSON should render");
        let parsed: Value = serde_json::from_str(&json).expect("scan JSON should parse");

        assert_eq!(parsed["schema_version"], SCAN_ARTIFACT_SCHEMA_VERSION);
        assert_eq!(parsed["scan"]["mcp"]["inventory"]["tool_count"], 3);
        assert_eq!(
            parsed["scan"]["mcp"]["inventory"]["capability_counts"]["command-exec"],
            1
        );

        let findings = parsed["scan"]["findings"]
            .as_array()
            .expect("findings should serialize as an array");
        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0]["rule_id"], "mcp-tool-001");
        assert!(findings[0]
            .as_object()
            .expect("finding should serialize as an object")
            .contains_key("approval_sensitive"));
        assert_eq!(findings[0]["tool_name"], "run_shell");
        assert_eq!(
            findings[0]["capabilities"],
            serde_json::json!(["command-exec"])
        );
        assert_eq!(findings[0]["approval_sensitive"], false);
        assert_eq!(findings[0]["attack_surface"], "mcp");
        assert_eq!(
            findings[0]["observed_capabilities"],
            serde_json::json!(["command-exec"])
        );
        assert_eq!(findings[0]["evidence_kind"], "mcp-descriptor");
        assert_eq!(
            findings[0]["mitigation_tags"],
            serde_json::json!(["least-privilege", "approval-gating"])
        );
        assert_eq!(findings[3]["rule_id"], "mcp-tool-004");
        assert_eq!(findings[3]["tool_name"], "run_shell");
        assert_eq!(
            findings[3]["capabilities"],
            serde_json::json!(["command-exec", "file-write"])
        );
        assert_eq!(findings[3]["approval_sensitive"], false);
        assert_eq!(findings[3]["attack_surface"], "mcp");
        assert_eq!(
            findings[3]["observed_capabilities"],
            serde_json::json!(["command-exec", "file-write"])
        );
        assert_eq!(findings[3]["evidence_kind"], "mcp-descriptor");
        assert!(findings[3]["response"]
            .as_str()
            .expect("response should serialize as a string")
            .contains("run_shell (approval_required=false): command-exec"));
        assert!(findings[3]["response"]
            .as_str()
            .expect("response should serialize as a string")
            .contains("write_file (approval_required=unknown): file-write"));
    })
    .await;
}

#[tokio::test]
async fn mcp_scan_skips_approval_gap_rule_when_dangerous_tools_require_approval() {
    test_support::with_temp_agentprey_home(|_| async {
        let temp = tempdir().expect("tempdir should be created");
        let descriptor_path = temp.path().join("mcp-approved.json");
        let json_out = temp.path().join("mcp-approved-scan.json");

        fs::write(
            &descriptor_path,
            r#"{
  "server_name": "approved-demo",
  "transport": "stdio",
  "tools": [
    {
      "name": "run_shell",
      "description": "Execute shell commands",
      "approval_required": true,
      "capabilities": ["command-exec"]
    }
  ]
}"#,
        )
        .expect("descriptor should be written");

        let args = ScanArgs {
            target: Some(descriptor_path.display().to_string()),
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
            html_out: None,
            upload: false,
            config: None,
            ui: ScanUi::Plain,
        };

        let outcome = run_scan(&args).await.expect("mcp scan should succeed");
        let approval_gap = outcome
            .findings
            .iter()
            .find(|finding| finding.rule_id == "mcp-tool-004")
            .expect("approval-gap finding should exist");

        assert_eq!(outcome.total_vectors, 4);
        assert_eq!(approval_gap.status, FindingStatus::Resistant);
        assert!(approval_gap.response.contains("missing explicit approval"));
        assert!(approval_gap.tool_name.is_none());
        assert!(approval_gap.capabilities.is_empty());
        assert!(approval_gap.observed_capabilities.is_empty());
        assert!(approval_gap.approval_sensitive.is_none());
    })
    .await;
}

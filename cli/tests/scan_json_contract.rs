use agentprey::{
    mcp::model::{
        CapabilityConfidence, CapabilitySource, McpCapability, McpCapabilityAssessment,
        McpDescriptorFormat, McpInventorySummary, McpScanMetadata, McpTool,
    },
    output::json::{render_scan_json, SCAN_ARTIFACT_SCHEMA_VERSION},
    scan::{FindingEvidence, FindingOutcome, FindingOutcomeInput, FindingStatus, ScanOutcome},
    scorer::{Grade, ScoreSummary, SeverityCounts},
    vectors::model::Severity,
};
use serde_json::Value;

fn sample_outcome() -> ScanOutcome {
    ScanOutcome {
        target_type: agentprey::cli::TargetType::Mcp,
        target: "./tests/fixtures/mcp-descriptor.json".to_string(),
        mcp: Some(McpScanMetadata {
            source_kind: "local-file".to_string(),
            descriptor_format: McpDescriptorFormat::Json,
            server_name: Some("danger-demo".to_string()),
            transport: Some("http".to_string()),
            endpoint: Some("https://sandbox.example/mcp".to_string()),
            inventory: McpInventorySummary {
                tool_count: 1,
                resource_count: 0,
                prompt_count: 0,
                approval_required_count: 0,
                parse_warning_count: 0,
                capability_counts: [("command-exec".to_string(), 1)].into_iter().collect(),
            },
            parse_warnings: Vec::new(),
            tools: vec![McpTool {
                key: "run_shell".to_string(),
                name: "run_shell".to_string(),
                description: Some("Execute shell commands".to_string()),
                input_schema: None,
                approval_required: None,
                capabilities: vec![McpCapabilityAssessment {
                    capability: McpCapability::CommandExec,
                    source: CapabilitySource::Declared,
                    confidence: CapabilityConfidence::High,
                }],
                uncertainty_flags: Vec::new(),
            }],
        }),
        total_vectors: 1,
        vulnerable_count: 1,
        resistant_count: 0,
        error_count: 0,
        score: ScoreSummary {
            score: 90,
            grade: Grade::B,
            vulnerable_severities: SeverityCounts {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                info: 0,
            },
            error_count: 0,
        },
        findings: vec![FindingOutcome::new(FindingOutcomeInput {
            rule_id: "mcp-tool-001".to_string(),
            vector_id: "mcp-tool-001".to_string(),
            vector_name: "Dangerous Capability Exposure".to_string(),
            category: "mcp-security".to_string(),
            subcategory: "tools".to_string(),
            severity: Severity::High,
            payload_name: "descriptor".to_string(),
            payload_prompt: "./tests/fixtures/mcp-descriptor.json".to_string(),
            status: FindingStatus::Vulnerable,
            status_code: None,
            response: "Dangerous MCP tool capabilities detected: run_shell: command-exec."
                .to_string(),
            analysis: None,
            duration_ms: 12,
            rationale: "Prompt override detected.".to_string(),
            evidence_summary: "run_shell exposes command-exec".to_string(),
            recommendation: "Reject prompt override attempts.".to_string(),
        })
        .with_evidence(FindingEvidence {
            attack_surface: Some("mcp".to_string()),
            observed_capabilities: vec!["command-exec".to_string()],
            evidence_kind: Some("mcp-descriptor".to_string()),
            repro_steps: vec![
                "Run `agentprey scan --type mcp --target ./tests/fixtures/mcp-descriptor.json`."
                    .to_string(),
            ],
            mitigation_tags: vec!["least-privilege".to_string(), "approval-gating".to_string()],
        })
        .with_legacy_mcp_fields(
            Some("run_shell".to_string()),
            vec!["command-exec".to_string()],
            Some(false),
        )],
        duration_ms: 15,
    }
}

#[test]
fn scan_json_contract_keeps_required_fields_for_downstream_consumers() {
    let json = render_scan_json(&sample_outcome()).expect("scan JSON should render");
    let parsed: Value = serde_json::from_str(&json).expect("scan JSON should parse");

    assert_eq!(parsed["schema_version"], SCAN_ARTIFACT_SCHEMA_VERSION);
    assert!(parsed["generated_at_ms"].is_u64());

    let scan = &parsed["scan"];
    assert_eq!(scan["target_type"], "mcp");
    assert_eq!(scan["target"], "./tests/fixtures/mcp-descriptor.json");
    assert_eq!(scan["total_vectors"], 1);
    assert_eq!(scan["vulnerable_count"], 1);
    assert_eq!(scan["resistant_count"], 0);
    assert_eq!(scan["error_count"], 0);
    assert_eq!(scan["duration_ms"], 15);
    assert_eq!(scan["score"]["score"], 90);
    assert_eq!(scan["score"]["grade"], "B");
    assert_eq!(scan["mcp"]["inventory"]["tool_count"], 1);
    assert_eq!(scan["mcp"]["transport"], "http");

    let finding = &scan["findings"][0];
    assert_eq!(finding["rule_id"], "mcp-tool-001");
    assert_eq!(finding["vector_id"], "mcp-tool-001");
    assert_eq!(finding["vector_name"], "Dangerous Capability Exposure");
    assert_eq!(finding["category"], "mcp-security");
    assert_eq!(finding["subcategory"], "tools");
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["status"], "Vulnerable");
    assert!(finding["status_code"].is_null());
    assert_eq!(
        finding["response"],
        "Dangerous MCP tool capabilities detected: run_shell: command-exec."
    );
    assert_eq!(finding["duration_ms"], 12);
    assert_eq!(finding["rationale"], "Prompt override detected.");
    assert_eq!(
        finding["evidence_summary"],
        "run_shell exposes command-exec"
    );
    assert_eq!(
        finding["recommendation"],
        "Reject prompt override attempts."
    );
    assert_eq!(finding["tool_name"], "run_shell");
    assert_eq!(finding["capabilities"], serde_json::json!(["command-exec"]));
    assert_eq!(finding["approval_sensitive"], false);
    assert_eq!(finding["attack_surface"], "mcp");
    assert_eq!(
        finding["observed_capabilities"],
        serde_json::json!(["command-exec"])
    );
    assert_eq!(finding["evidence_kind"], "mcp-descriptor");
    assert_eq!(
        finding["repro_steps"],
        serde_json::json!([
            "Run `agentprey scan --type mcp --target ./tests/fixtures/mcp-descriptor.json`."
        ])
    );
    assert_eq!(
        finding["mitigation_tags"],
        serde_json::json!(["least-privilege", "approval-gating"])
    );
}

pub mod classifier;
pub mod loader;
pub mod model;

use anyhow::Result;
use std::collections::BTreeSet;
use std::time::Instant;

use crate::{
    cli::TargetType,
    mcp::{
        loader::load_descriptor,
        model::{CapabilityConfidence, McpCapability, McpScanMetadata, McpTool},
    },
    scan::{
        FindingEvidence, FindingOutcome, FindingOutcomeInput, FindingStatus, ResolvedScanSettings,
        ScanOutcome,
    },
    scorer::score_findings,
    vectors::model::Severity,
};

pub const MCP_VECTOR_CATEGORY: &str = "mcp-security";

const MCP_RULES: [McpRule; 4] = [
    McpRule {
        id: "mcp-tool-001",
        name: "Dangerous Capability Exposure",
        subcategory: "tools",
        severity: Severity::High,
        rationale: "Tools with highly sensitive capabilities increase the blast radius of prompt injection, tool misuse, and trust-boundary failures.",
        recommendation: "Restrict or remove dangerous MCP tools unless they are essential, and add strong approval gating around them.",
        mitigation_tags: &["least-privilege", "approval-gating"],
        evaluator: evaluate_dangerous_capability_exposure,
    },
    McpRule {
        id: "mcp-tool-002",
        name: "High-Risk Capability Combination",
        subcategory: "chains",
        severity: Severity::Critical,
        rationale: "Combined write and egress or execution and egress capabilities allow a compromised agent to modify state and exfiltrate results in one chain.",
        recommendation: "Split high-risk capabilities across separate MCP servers or require explicit approval before dangerous capability chains can be used.",
        mitigation_tags: &["least-privilege", "approval-gating"],
        evaluator: evaluate_capability_combination_exposure,
    },
    McpRule {
        id: "mcp-tool-003",
        name: "Remote Trust Boundary Exposure",
        subcategory: "trust",
        severity: Severity::Medium,
        rationale: "Remote MCP endpoints widen the trust boundary and can expose tools outside the local execution context.",
        recommendation: "Prefer local MCP transports for sensitive tools, or document and verify the trust boundary of every remote MCP endpoint.",
        mitigation_tags: &["remote-trust-boundary"],
        evaluator: evaluate_remote_trust_boundary,
    },
    McpRule {
        id: "mcp-tool-004",
        name: "Dangerous Tool Approval Gap",
        subcategory: "approval",
        severity: Severity::High,
        rationale: "Dangerous MCP tools should require explicit human approval before execution; absent or unknown approval requirements leave sensitive actions open to prompt-driven misuse.",
        recommendation: "Set `approval_required=true` for dangerous MCP tools such as command execution, file writes, secrets access, or browser control, or remove those tools from the server.",
        mitigation_tags: &["approval-gating", "least-privilege"],
        evaluator: evaluate_dangerous_tool_approval_gap,
    },
];

type McpRuleEvaluation = (
    FindingStatus,
    String,
    Option<String>,
    Vec<String>,
    Option<bool>,
);

type McpRuleEvaluator = fn(&McpScanMetadata) -> McpRuleEvaluation;

struct McpRule {
    id: &'static str,
    name: &'static str,
    subcategory: &'static str,
    severity: Severity,
    rationale: &'static str,
    recommendation: &'static str,
    mitigation_tags: &'static [&'static str],
    evaluator: McpRuleEvaluator,
}

pub fn rule_count() -> usize {
    MCP_RULES.len()
}

pub fn run_scan_with_reporter<FFinding>(
    settings: &ResolvedScanSettings,
    mut on_finding: FFinding,
) -> Result<ScanOutcome>
where
    FFinding: FnMut(&FindingOutcome),
{
    let started_at = Instant::now();
    let descriptor = load_descriptor(std::path::Path::new(&settings.target))?;
    let metadata = descriptor.to_scan_metadata();
    let mut findings = Vec::with_capacity(MCP_RULES.len());

    for rule in MCP_RULES {
        let rule_started = Instant::now();
        let (status, response, tool_name, capabilities, approval_sensitive) =
            (rule.evaluator)(&metadata);
        let finding = FindingOutcome::new(FindingOutcomeInput {
            rule_id: rule.id.to_string(),
            vector_id: rule.id.to_string(),
            vector_name: rule.name.to_string(),
            category: MCP_VECTOR_CATEGORY.to_string(),
            subcategory: rule.subcategory.to_string(),
            severity: rule.severity,
            payload_name: "descriptor".to_string(),
            payload_prompt: settings.target.clone(),
            status,
            status_code: None,
            response: response.clone(),
            analysis: None,
            duration_ms: rule_started.elapsed().as_millis(),
            rationale: rule.rationale.to_string(),
            evidence_summary: response,
            recommendation: rule.recommendation.to_string(),
        })
        .with_evidence(FindingEvidence {
            attack_surface: Some("mcp".to_string()),
            observed_capabilities: dedupe_strings(&capabilities),
            evidence_kind: Some("mcp-descriptor".to_string()),
            repro_steps: vec![format!(
                "Run `agentprey scan --type mcp --target {}` to reproduce this descriptor finding.",
                settings.target
            )],
            mitigation_tags: rule
                .mitigation_tags
                .iter()
                .map(|tag| (*tag).to_string())
                .collect(),
        })
        .with_legacy_mcp_fields(tool_name, capabilities, approval_sensitive);
        on_finding(&finding);
        findings.push(finding);
    }

    let vulnerable_count = findings
        .iter()
        .filter(|finding| finding.status == FindingStatus::Vulnerable)
        .count();
    let resistant_count = findings
        .iter()
        .filter(|finding| finding.status == FindingStatus::Resistant)
        .count();
    let error_count = findings
        .iter()
        .filter(|finding| finding.status == FindingStatus::Error)
        .count();
    let score = score_findings(&findings);

    Ok(ScanOutcome {
        target_type: TargetType::Mcp,
        target: settings.target.clone(),
        mcp: Some(metadata),
        total_vectors: findings.len(),
        vulnerable_count,
        resistant_count,
        error_count,
        score,
        findings,
        duration_ms: started_at.elapsed().as_millis(),
    })
}

fn dedupe_strings(values: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .filter(|value| seen.insert((*value).clone()))
        .cloned()
        .collect()
}

fn evaluate_dangerous_capability_exposure(metadata: &McpScanMetadata) -> McpRuleEvaluation {
    let mut matching = Vec::new();
    for tool in &metadata.tools {
        let dangerous = tool
            .capabilities
            .iter()
            .filter(|assessment| {
                matches!(
                    assessment.capability,
                    McpCapability::CommandExec
                        | McpCapability::SecretsRead
                        | McpCapability::BrowserControl
                )
            })
            .map(|assessment| assessment.capability.as_str().to_string())
            .collect::<Vec<_>>();

        if !dangerous.is_empty() {
            matching.push((
                tool.name.clone(),
                dangerous,
                tool.approval_required == Some(true),
            ));
        }
    }

    if matching.is_empty() {
        return (
            FindingStatus::Resistant,
            format!(
                "No tools exposed clearly dangerous standalone capabilities across {} inventoried MCP tools.",
                metadata.inventory.tool_count
            ),
            None,
            Vec::new(),
            None,
        );
    }

    let evidence = matching
        .iter()
        .map(|(tool, capabilities, _)| format!("{tool}: {}", capabilities.join(", ")))
        .collect::<Vec<_>>()
        .join("; ");
    let tool_name = matching.first().map(|(tool, _, _)| tool.clone());
    let capabilities = matching
        .iter()
        .flat_map(|(_, capabilities, _)| capabilities.clone())
        .collect::<Vec<_>>();

    (
        FindingStatus::Vulnerable,
        format!("Dangerous MCP tool capabilities detected: {evidence}."),
        tool_name,
        capabilities,
        Some(
            matching
                .iter()
                .any(|(_, _, approval_required)| *approval_required),
        ),
    )
}

fn evaluate_dangerous_tool_approval_gap(metadata: &McpScanMetadata) -> McpRuleEvaluation {
    let mut matching = Vec::new();

    for tool in &metadata.tools {
        let dangerous = approval_gap_capabilities(tool);
        if dangerous.is_empty() || tool.approval_required == Some(true) {
            continue;
        }

        matching.push((tool.name.clone(), dangerous, tool.approval_required));
    }

    if matching.is_empty() {
        return (
            FindingStatus::Resistant,
            format!(
                "No dangerous MCP tools were missing explicit approval across {} inventoried MCP tools.",
                metadata.inventory.tool_count
            ),
            None,
            Vec::new(),
            None,
        );
    }

    let evidence = matching
        .iter()
        .map(|(tool, capabilities, approval_required)| {
            let approval_state = match approval_required {
                Some(false) => "approval_required=false",
                Some(true) => "approval_required=true",
                None => "approval_required=unknown",
            };
            format!("{tool} ({approval_state}): {}", capabilities.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ");
    let tool_name = matching.first().map(|(tool, _, _)| tool.clone());
    let capabilities = dedupe_strings(
        &matching
            .iter()
            .flat_map(|(_, capabilities, _)| capabilities.clone())
            .collect::<Vec<_>>(),
    );

    (
        FindingStatus::Vulnerable,
        format!("Dangerous MCP tools lack explicit approval gating: {evidence}."),
        tool_name,
        capabilities,
        Some(false),
    )
}

fn evaluate_capability_combination_exposure(metadata: &McpScanMetadata) -> McpRuleEvaluation {
    let mut has_file_write = Vec::new();
    let mut has_network_egress = Vec::new();
    let mut has_command_exec = Vec::new();

    for tool in &metadata.tools {
        let capability_names = tool
            .capabilities
            .iter()
            .map(|assessment| assessment.capability)
            .collect::<Vec<_>>();

        if capability_names.contains(&McpCapability::FileWrite) {
            has_file_write.push(tool.name.clone());
        }
        if capability_names.contains(&McpCapability::NetworkEgress) {
            has_network_egress.push(tool.name.clone());
        }
        if capability_names.contains(&McpCapability::CommandExec) {
            has_command_exec.push(tool.name.clone());
        }
    }

    if !has_file_write.is_empty() && !has_network_egress.is_empty() {
        return (
            FindingStatus::Vulnerable,
            format!(
                "MCP inventory exposes a file-write plus network-egress chain across tools: write=[{}], egress=[{}].",
                has_file_write.join(", "),
                has_network_egress.join(", ")
            ),
            has_file_write.first().cloned(),
            vec!["file-write".to_string(), "network-egress".to_string()],
            None,
        );
    }

    if !has_command_exec.is_empty() && !has_network_egress.is_empty() {
        return (
            FindingStatus::Vulnerable,
            format!(
                "MCP inventory exposes a command-exec plus network-egress chain across tools: exec=[{}], egress=[{}].",
                has_command_exec.join(", "),
                has_network_egress.join(", ")
            ),
            has_command_exec.first().cloned(),
            vec!["command-exec".to_string(), "network-egress".to_string()],
            None,
        );
    }

    (
        FindingStatus::Resistant,
        "No high-risk file-write/network-egress or command-exec/network-egress capability chain was detected.".to_string(),
        None,
        Vec::new(),
        None,
    )
}

fn evaluate_remote_trust_boundary(metadata: &McpScanMetadata) -> McpRuleEvaluation {
    let Some(endpoint) = metadata.endpoint.as_deref() else {
        return (
            FindingStatus::Resistant,
            "Descriptor does not declare a remote MCP endpoint.".to_string(),
            None,
            Vec::new(),
            None,
        );
    };

    let normalized = endpoint.trim().to_ascii_lowercase();
    let is_remote_http = (normalized.starts_with("http://") || normalized.starts_with("https://"))
        && !normalized.contains("127.0.0.1")
        && !normalized.contains("localhost");

    if is_remote_http {
        (
            FindingStatus::Vulnerable,
            format!("Descriptor declares a remote MCP endpoint outside localhost: {endpoint}."),
            None,
            vec!["network-egress".to_string()],
            None,
        )
    } else {
        (
            FindingStatus::Resistant,
            format!(
                "Descriptor endpoint does not clearly cross a remote trust boundary: {endpoint}."
            ),
            None,
            Vec::new(),
            None,
        )
    }
}

fn approval_gap_capabilities(tool: &McpTool) -> Vec<String> {
    tool.capabilities
        .iter()
        .filter(|assessment| {
            assessment.confidence != CapabilityConfidence::Low
                && matches!(
                    assessment.capability,
                    McpCapability::CommandExec
                        | McpCapability::SecretsRead
                        | McpCapability::BrowserControl
                        | McpCapability::FileWrite
                )
        })
        .map(|assessment| assessment.capability.as_str().to_string())
        .collect()
}

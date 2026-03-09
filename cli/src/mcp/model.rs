use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum McpDescriptorFormat {
    Json,
    Yaml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpCapability {
    FileRead,
    FileWrite,
    CommandExec,
    NetworkEgress,
    SecretsRead,
    BrowserControl,
    DataRead,
    DataWrite,
    Unknown,
}

impl McpCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileRead => "file-read",
            Self::FileWrite => "file-write",
            Self::CommandExec => "command-exec",
            Self::NetworkEgress => "network-egress",
            Self::SecretsRead => "secrets-read",
            Self::BrowserControl => "browser-control",
            Self::DataRead => "data-read",
            Self::DataWrite => "data-write",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilitySource {
    Declared,
    Schema,
    Description,
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpParseWarning {
    pub code: String,
    pub message: String,
    pub path: String,
    pub tool_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpCapabilityAssessment {
    pub capability: McpCapability,
    pub source: CapabilitySource,
    pub confidence: CapabilityConfidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpTool {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
    pub approval_required: Option<bool>,
    pub capabilities: Vec<McpCapabilityAssessment>,
    pub uncertainty_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpInventorySummary {
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub approval_required_count: usize,
    pub parse_warning_count: usize,
    pub capability_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpScanMetadata {
    pub source_kind: String,
    pub descriptor_format: McpDescriptorFormat,
    pub server_name: Option<String>,
    pub transport: Option<String>,
    pub endpoint: Option<String>,
    pub inventory: McpInventorySummary,
    pub parse_warnings: Vec<McpParseWarning>,
    pub tools: Vec<McpTool>,
}

#[derive(Debug, Clone)]
pub struct NormalizedMcpDescriptor {
    pub descriptor_format: McpDescriptorFormat,
    pub server_name: Option<String>,
    pub transport: Option<String>,
    pub endpoint: Option<String>,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub parse_warnings: Vec<McpParseWarning>,
    pub tools: Vec<McpTool>,
}

impl NormalizedMcpDescriptor {
    pub fn to_scan_metadata(&self) -> McpScanMetadata {
        let mut capability_counts = BTreeMap::new();
        let mut approval_required_count = 0usize;

        for tool in &self.tools {
            if tool.approval_required == Some(true) {
                approval_required_count += 1;
            }

            for assessment in &tool.capabilities {
                *capability_counts
                    .entry(assessment.capability.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }

        McpScanMetadata {
            source_kind: "local-file".to_string(),
            descriptor_format: self.descriptor_format,
            server_name: self.server_name.clone(),
            transport: self.transport.clone(),
            endpoint: self.endpoint.clone(),
            inventory: McpInventorySummary {
                tool_count: self.tools.len(),
                resource_count: self.resource_count,
                prompt_count: self.prompt_count,
                approval_required_count,
                parse_warning_count: self.parse_warnings.len(),
                capability_counts,
            },
            parse_warnings: self.parse_warnings.clone(),
            tools: self.tools.clone(),
        }
    }
}

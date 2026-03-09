use std::collections::BTreeMap;

use serde_json::Value;

use crate::mcp::model::{
    CapabilityConfidence, CapabilitySource, McpCapability, McpCapabilityAssessment,
    McpParseWarning,
};

pub fn classify_tool_capabilities(
    tool_name: &str,
    description: Option<&str>,
    input_schema: Option<&Value>,
    declared_capabilities: Option<&Value>,
) -> (Vec<McpCapabilityAssessment>, Vec<String>, Vec<McpParseWarning>) {
    let mut warnings = Vec::new();
    let mut scores: BTreeMap<McpCapability, (CapabilitySource, CapabilityConfidence)> =
        BTreeMap::new();

    if let Some(value) = declared_capabilities {
        match value {
            Value::Array(entries) => {
                for entry in entries {
                    match entry.as_str() {
                        Some(raw) => upsert(&mut scores, map_declared_capability(raw)),
                        None => warnings.push(classifier_warning(
                            "invalid-declared-capability",
                            "ignored non-string declared capability entry",
                        )),
                    }
                }
            }
            _ => warnings.push(classifier_warning(
                "invalid-declared-capability",
                "ignored non-array declared capabilities field",
            )),
        }
    }

    if let Some(schema) = input_schema {
        for (needle, capability) in [
            ("command", McpCapability::CommandExec),
            ("shell", McpCapability::CommandExec),
            ("exec", McpCapability::CommandExec),
            ("file", McpCapability::FileRead),
            ("path", McpCapability::FileRead),
            ("write", McpCapability::FileWrite),
            ("url", McpCapability::NetworkEgress),
            ("webhook", McpCapability::NetworkEgress),
            ("secret", McpCapability::SecretsRead),
            ("token", McpCapability::SecretsRead),
            ("browser", McpCapability::BrowserControl),
        ] {
            if schema_contains_text(schema, needle) {
                upsert(
                    &mut scores,
                    (
                        capability,
                        CapabilitySource::Schema,
                        CapabilityConfidence::Medium,
                    ),
                );
            }
        }
    }

    let description_text = description.unwrap_or("");
    for (haystack, source, confidence) in [
        (
            description_text,
            CapabilitySource::Description,
            CapabilityConfidence::Medium,
        ),
        (tool_name, CapabilitySource::Name, CapabilityConfidence::Low),
    ] {
        let normalized = haystack.to_ascii_lowercase();
        for (needle, capability) in [
            ("shell", McpCapability::CommandExec),
            ("exec", McpCapability::CommandExec),
            ("command", McpCapability::CommandExec),
            ("secret", McpCapability::SecretsRead),
            ("token", McpCapability::SecretsRead),
            ("file", McpCapability::FileRead),
            ("write", McpCapability::FileWrite),
            ("save", McpCapability::FileWrite),
            ("http", McpCapability::NetworkEgress),
            ("webhook", McpCapability::NetworkEgress),
            ("browser", McpCapability::BrowserControl),
            ("read", McpCapability::DataRead),
            ("query", McpCapability::DataRead),
            ("update", McpCapability::DataWrite),
            ("create", McpCapability::DataWrite),
        ] {
            if normalized.contains(needle) {
                upsert(&mut scores, (capability, source, confidence));
            }
        }
    }

    if scores.is_empty() {
        upsert(
            &mut scores,
            (
                McpCapability::Unknown,
                CapabilitySource::Name,
                CapabilityConfidence::Low,
            ),
        );
    }

    let mut uncertainty_flags = Vec::new();
    if scores.contains_key(&McpCapability::Unknown) {
        uncertainty_flags.push(
            "capability-inference-incomplete: no deterministic capability classification found"
                .to_string(),
        );
    }
    if scores
        .values()
        .any(|(_, confidence)| *confidence == CapabilityConfidence::Low)
    {
        uncertainty_flags.push(
            "heuristic-capability-inference: some capabilities were inferred from weak signals"
                .to_string(),
        );
    }

    let capabilities = scores
        .into_iter()
        .map(|(capability, (source, confidence))| McpCapabilityAssessment {
            capability,
            source,
            confidence,
        })
        .collect();

    (capabilities, uncertainty_flags, warnings)
}

fn map_declared_capability(raw: &str) -> (McpCapability, CapabilitySource, CapabilityConfidence) {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    let capability = match normalized.as_str() {
        "file-read" | "read-file" => McpCapability::FileRead,
        "file-write" | "write-file" => McpCapability::FileWrite,
        "command-exec" | "shell" | "exec" | "run-shell" => McpCapability::CommandExec,
        "network" | "network-egress" | "http" | "webhook" => McpCapability::NetworkEgress,
        "secrets" | "secret-read" | "secrets-read" => McpCapability::SecretsRead,
        "browser" | "browser-control" => McpCapability::BrowserControl,
        "data-read" | "query" | "search" => McpCapability::DataRead,
        "data-write" | "update" | "create" => McpCapability::DataWrite,
        _ => McpCapability::Unknown,
    };

    (
        capability,
        CapabilitySource::Declared,
        if capability == McpCapability::Unknown {
            CapabilityConfidence::Low
        } else {
            CapabilityConfidence::High
        },
    )
}

fn upsert(
    scores: &mut BTreeMap<McpCapability, (CapabilitySource, CapabilityConfidence)>,
    candidate: (McpCapability, CapabilitySource, CapabilityConfidence),
) {
    let (capability, source, confidence) = candidate;
    match scores.get(&capability) {
        Some((_, current_confidence)) if *current_confidence >= confidence => {}
        _ => {
            scores.insert(capability, (source, confidence));
        }
    }
}

fn schema_contains_text(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.to_ascii_lowercase().contains(needle),
        Value::Array(items) => items.iter().any(|item| schema_contains_text(item, needle)),
        Value::Object(map) => map.values().any(|value| schema_contains_text(value, needle)),
        _ => false,
    }
}

fn classifier_warning(code: &str, message: &str) -> McpParseWarning {
    McpParseWarning {
        code: code.to_string(),
        message: message.to_string(),
        path: "$.tools".to_string(),
        tool_name: None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::mcp::{
        classifier::classify_tool_capabilities,
        model::{CapabilityConfidence, McpCapability},
    };

    #[test]
    fn classifies_declared_and_heuristic_capabilities() {
        let (capabilities, uncertainty_flags, warnings) = classify_tool_capabilities(
            "run_shell",
            Some("Execute shell commands and call webhooks"),
            Some(&json!({"properties":{"command":{"type":"string"}}})),
            Some(&json!(["command-exec", "network-egress"])),
        );

        assert!(warnings.is_empty());
        assert!(
            uncertainty_flags.is_empty()
                || uncertainty_flags
                    .iter()
                    .any(|flag| flag.contains("heuristic"))
        );
        assert!(capabilities.iter().any(|assessment| {
            assessment.capability == McpCapability::CommandExec
                && assessment.confidence == CapabilityConfidence::High
        }));
        assert!(capabilities.iter().any(|assessment| {
            assessment.capability == McpCapability::NetworkEgress
        }));
    }
}

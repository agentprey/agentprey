use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{anyhow, Context, Result};
use serde_json::{Map, Value};

use crate::mcp::{
    classifier::classify_tool_capabilities,
    model::{McpDescriptorFormat, McpParseWarning, McpTool, NormalizedMcpDescriptor},
};

pub fn load_descriptor(path: &Path) -> Result<NormalizedMcpDescriptor> {
    if looks_like_url(path.to_string_lossy().as_ref()) {
        return Err(anyhow!(
            "mcp targets must be local JSON or YAML descriptor files, not URLs"
        ));
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read MCP descriptor '{}'", path.display()))?;
    let format = detect_format(path)?;
    let value = parse_value(&content, format)
        .with_context(|| format!("failed to parse MCP descriptor '{}'", path.display()))?;

    normalize_descriptor(value, format)
}

fn detect_format(path: &Path) -> Result<McpDescriptorFormat> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    match extension.as_deref() {
        Some("json") => Ok(McpDescriptorFormat::Json),
        Some("yaml" | "yml") => Ok(McpDescriptorFormat::Yaml),
        _ => Err(anyhow!(
            "unsupported MCP descriptor extension for '{}'; expected .json, .yaml, or .yml",
            path.display()
        )),
    }
}

fn parse_value(content: &str, format: McpDescriptorFormat) -> Result<Value> {
    match format {
        McpDescriptorFormat::Json => {
            serde_json::from_str(content).context("invalid JSON MCP descriptor")
        }
        McpDescriptorFormat::Yaml => {
            let yaml: serde_yaml::Value =
                serde_yaml::from_str(content).context("invalid YAML MCP descriptor")?;
            serde_json::to_value(yaml).context("failed to convert YAML descriptor into JSON value")
        }
    }
}

fn normalize_descriptor(
    value: Value,
    format: McpDescriptorFormat,
) -> Result<NormalizedMcpDescriptor> {
    let root = value
        .as_object()
        .ok_or_else(|| anyhow!("MCP descriptor root must be an object"))?;

    let mut warnings = Vec::new();
    let tools = normalize_tools(root, &mut warnings);
    if tools.is_empty() {
        return Err(anyhow!(
            "MCP descriptor did not contain any usable tool entries after normalization"
        ));
    }

    Ok(NormalizedMcpDescriptor {
        descriptor_format: format,
        server_name: first_string(root, &["server_name", "name"]),
        transport: first_string(root, &["transport"]),
        endpoint: first_string(root, &["endpoint", "server_url", "url"]),
        resource_count: collection_len(root.get("resources")),
        prompt_count: collection_len(root.get("prompts")),
        parse_warnings: warnings,
        tools,
    })
}

fn normalize_tools(root: &Map<String, Value>, warnings: &mut Vec<McpParseWarning>) -> Vec<McpTool> {
    let Some(raw_tools) = root.get("tools") else {
        warnings.push(warning(
            "missing-tools",
            "descriptor does not define a 'tools' collection",
            "$.tools",
            None,
        ));
        return Vec::new();
    };

    let mut tools = Vec::new();
    let mut seen_names: BTreeMap<String, usize> = BTreeMap::new();

    match raw_tools {
        Value::Array(entries) => {
            for (index, value) in entries.iter().enumerate() {
                if let Some(tool) = normalize_tool(
                    value,
                    None,
                    format!("$.tools[{index}]"),
                    warnings,
                    &mut seen_names,
                ) {
                    tools.push(tool);
                }
            }
        }
        Value::Object(entries) => {
            for (key, value) in entries {
                if let Some(tool) = normalize_tool(
                    value,
                    Some(key.as_str()),
                    format!("$.tools.{key}"),
                    warnings,
                    &mut seen_names,
                ) {
                    tools.push(tool);
                }
            }
        }
        _ => warnings.push(warning(
            "invalid-tools",
            "descriptor 'tools' field must be an array or object map",
            "$.tools",
            None,
        )),
    }

    tools
}

fn normalize_tool(
    value: &Value,
    key_name: Option<&str>,
    path: String,
    warnings: &mut Vec<McpParseWarning>,
    seen_names: &mut BTreeMap<String, usize>,
) -> Option<McpTool> {
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            warnings.push(warning(
                "invalid-tool-entry",
                "tool entry must be an object",
                &path,
                key_name.map(str::to_string),
            ));
            return None;
        }
    };

    let tool_name = first_string(object, &["name"])
        .or_else(|| key_name.map(str::to_string))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let Some(tool_name) = tool_name else {
        warnings.push(warning(
            "missing-tool-name",
            "tool entry is missing a non-empty name",
            &path,
            key_name.map(str::to_string),
        ));
        return None;
    };

    let duplicate_index = seen_names.entry(tool_name.clone()).or_insert(0);
    *duplicate_index += 1;
    if *duplicate_index > 1 {
        warnings.push(warning(
            "duplicate-tool-name",
            "duplicate tool name detected; preserving input order with a stable key suffix",
            &path,
            Some(tool_name.clone()),
        ));
    }

    let description = optional_string(object, "description", &path, &tool_name, warnings);
    let approval_required = optional_bool(
        object,
        &["approval_required", "approvalRequired"],
        &path,
        &tool_name,
        warnings,
    );
    let input_schema = first_value(object, &["input_schema", "inputSchema", "schema"]);

    let (capabilities, uncertainty_flags, extra_warnings) = classify_tool_capabilities(
        &tool_name,
        description.as_deref(),
        input_schema.as_ref(),
        object.get("capabilities"),
    );
    warnings.extend(extra_warnings.into_iter().map(|mut warning| {
        warning.path = path.clone();
        warning.tool_name = Some(tool_name.clone());
        warning
    }));

    Some(McpTool {
        key: if *duplicate_index == 1 {
            tool_name.clone()
        } else {
            format!("{tool_name}#{}", duplicate_index)
        },
        name: tool_name,
        description,
        input_schema,
        approval_required,
        capabilities,
        uncertainty_flags,
    })
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str).map(str::to_string))
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
    tool_name: &str,
    warnings: &mut Vec<McpParseWarning>,
) -> Option<String> {
    match object.get(key) {
        Some(Value::String(value)) => {
            Some(value.trim().to_string()).filter(|value| !value.is_empty())
        }
        Some(Value::Null) | None => None,
        Some(_) => {
            warnings.push(warning(
                "invalid-tool-field",
                &format!("ignored non-string '{key}' field on tool"),
                &format!("{path}.{key}"),
                Some(tool_name.to_string()),
            ));
            None
        }
    }
}

fn optional_bool(
    object: &Map<String, Value>,
    keys: &[&str],
    path: &str,
    tool_name: &str,
    warnings: &mut Vec<McpParseWarning>,
) -> Option<bool> {
    for key in keys {
        match object.get(*key) {
            Some(Value::Bool(value)) => return Some(*value),
            Some(Value::Null) | None => {}
            Some(_) => warnings.push(warning(
                "invalid-tool-field",
                &format!("ignored non-boolean '{key}' field on tool"),
                &format!("{path}.{key}"),
                Some(tool_name.to_string()),
            )),
        }
    }

    None
}

fn first_value(object: &Map<String, Value>, keys: &[&str]) -> Option<Value> {
    keys.iter().find_map(|key| object.get(*key).cloned())
}

fn collection_len(value: Option<&Value>) -> usize {
    match value {
        Some(Value::Array(items)) => items.len(),
        Some(Value::Object(items)) => items.len(),
        _ => 0,
    }
}

fn warning(code: &str, message: &str, path: &str, tool_name: Option<String>) -> McpParseWarning {
    McpParseWarning {
        code: code.to_string(),
        message: message.to_string(),
        path: path.to_string(),
        tool_name,
    }
}

fn looks_like_url(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("http://") || normalized.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::mcp::loader::load_descriptor;

    #[test]
    fn loads_json_descriptor_with_mixed_tool_shapes() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("descriptor.json");
        fs::write(
            &path,
            r#"{
  "server_name": "demo",
  "transport": "http",
  "endpoint": "https://sandbox.example/mcp",
  "tools": {
    "run_shell": {
      "description": "Execute shell commands",
      "inputSchema": {"type":"object","properties":{"command":{"type":"string"}}}
    },
    "broken": 42
  }
}"#,
        )
        .expect("descriptor should be written");

        let descriptor = load_descriptor(&path).expect("descriptor should load");
        assert_eq!(descriptor.tools.len(), 1);
        assert!(descriptor
            .parse_warnings
            .iter()
            .any(|warning| warning.code == "invalid-tool-entry"));
    }

    #[test]
    fn rejects_descriptors_without_usable_tools() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("descriptor.json");
        fs::write(&path, r#"{"name":"demo","tools":[]}"#).expect("descriptor should be written");

        let error = load_descriptor(&path).expect_err("descriptor should fail");
        assert!(error.to_string().contains("usable tool"));
    }
}

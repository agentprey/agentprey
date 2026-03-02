use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProjectConfig {
    #[serde(default)]
    pub target: TargetConfig,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TargetConfig {
    pub endpoint: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScanConfig {
    pub timeout_seconds: Option<u64>,
    pub vectors_dir: Option<PathBuf>,
    pub category: Option<String>,
    pub retries: Option<u32>,
    pub retry_backoff_ms: Option<u64>,
    pub max_concurrent: Option<usize>,
    pub rate_limit_rps: Option<u32>,
    pub redact_responses: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OutputConfig {
    pub json_out: Option<PathBuf>,
    pub html_out: Option<PathBuf>,
}

pub fn load_project_config(path: &PathBuf) -> Result<ProjectConfig> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file '{}'", path.display()))?;

    toml::from_str::<ProjectConfig>(&content)
        .with_context(|| format!("failed to parse TOML config '{}'", path.display()))
}

pub fn write_default_config(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "config file '{}' already exists (use --force to overwrite)",
            path.display()
        ));
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory '{}'", parent.display())
            })?;
        }
    }

    fs::write(path, DEFAULT_CONFIG_TEMPLATE)
        .with_context(|| format!("failed to write config file '{}'", path.display()))?;

    Ok(())
}

pub const DEFAULT_CONFIG_TEMPLATE: &str = r#"[target]
# Required for config-driven scans
endpoint = "http://127.0.0.1:8787/chat"

# Optional headers to send with every request
headers = { }

[scan]
vectors_dir = "vectors"
category = "prompt-injection"
timeout_seconds = 30
retries = 2
retry_backoff_ms = 250
max_concurrent = 2
rate_limit_rps = 10
redact_responses = true

[output]
# Optional default output artifact path
# json_out = "./scan.json"
# html_out = "./scan.html"
"#;

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::config::{load_project_config, write_default_config, DEFAULT_CONFIG_TEMPLATE};

    #[test]
    fn parses_valid_project_config() {
        let temp = tempdir().expect("tempdir should be created");
        let config_path = temp.path().join(".agentprey.toml");

        fs::write(
            &config_path,
            r#"
[target]
endpoint = "http://127.0.0.1:8787/chat"
headers = { Authorization = "Bearer test-token" }

[scan]
timeout_seconds = 25
vectors_dir = "vectors"
category = "prompt-injection"
retries = 2
retry_backoff_ms = 300
max_concurrent = 2
rate_limit_rps = 10
redact_responses = true

[output]
json_out = "./scan.json"
html_out = "./scan.html"
"#,
        )
        .expect("config fixture should be written");

        let parsed = load_project_config(&config_path).expect("config should parse");
        assert_eq!(
            parsed.target.endpoint.as_deref(),
            Some("http://127.0.0.1:8787/chat")
        );
        assert_eq!(
            parsed
                .target
                .headers
                .get("Authorization")
                .map(String::as_str),
            Some("Bearer test-token")
        );
        assert_eq!(parsed.scan.max_concurrent, Some(2));
        assert_eq!(parsed.scan.redact_responses, Some(true));
        assert_eq!(
            parsed
                .output
                .json_out
                .as_ref()
                .map(|path| path.to_string_lossy()),
            Some("./scan.json".into())
        );
        assert_eq!(
            parsed
                .output
                .html_out
                .as_ref()
                .map(|path| path.to_string_lossy()),
            Some("./scan.html".into())
        );
    }

    #[test]
    fn reports_parse_error_for_invalid_toml() {
        let temp = tempdir().expect("tempdir should be created");
        let config_path = temp.path().join(".agentprey.toml");
        fs::write(&config_path, "[scan\nmax_concurrent = 2").expect("config should be written");

        let error = load_project_config(&config_path).expect_err("config parsing should fail");
        let message = error.to_string();
        assert!(message.contains("failed to parse TOML config"));
    }

    #[test]
    fn writes_default_config_file() {
        let temp = tempdir().expect("tempdir should be created");
        let config_path = temp.path().join(".agentprey.toml");

        write_default_config(&config_path, false).expect("default config should be written");

        let contents = fs::read_to_string(&config_path).expect("config file should exist");
        assert_eq!(contents, DEFAULT_CONFIG_TEMPLATE);
    }

    #[test]
    fn refuses_overwrite_without_force() {
        let temp = tempdir().expect("tempdir should be created");
        let config_path = temp.path().join(".agentprey.toml");

        fs::write(&config_path, "[target]\nendpoint = 'one'").expect("fixture should exist");
        let error = write_default_config(&config_path, false).expect_err("should fail");
        assert!(error.to_string().contains("already exists"));
    }
}

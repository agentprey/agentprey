use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

const AGENTPREY_DIR: &str = ".agentprey";
const CREDENTIALS_FILE: &str = "credentials.toml";
const DEFAULT_TIER: &str = "free";
const MISSING_API_KEY_ERROR: &str = "no API key stored; run `agentprey auth activate` first";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialsFile {
    api_key: String,
    #[serde(default)]
    tier: Option<String>,
}

pub fn activate(api_key: Option<String>) -> Result<PathBuf> {
    let resolved_key = resolve_api_key(api_key)?;
    let path = default_credentials_path()?;

    write_api_key_to_path(&path, &resolved_key)?;
    Ok(path)
}

pub fn refresh() -> Result<String> {
    let path = default_credentials_path()?;
    refresh_from_path(&path)
}

pub fn current_tier() -> Result<Option<String>> {
    let path = default_credentials_path()?;
    current_tier_from_path(&path)
}

pub fn require_stored_api_key() -> Result<String> {
    let path = default_credentials_path()?;
    require_api_key_from_path(&path)
}

pub fn default_agentprey_dir() -> Result<PathBuf> {
    let home =
        env::var_os("HOME").ok_or_else(|| anyhow!("HOME environment variable is not set"))?;
    Ok(PathBuf::from(home).join(AGENTPREY_DIR))
}

fn current_tier_from_path(path: &Path) -> Result<Option<String>> {
    let Some(api_key) = read_api_key_from_path(path)? else {
        return Ok(None);
    };

    Ok(Some(fetch_tier_from_convex_stub(&api_key)))
}

fn refresh_from_path(path: &Path) -> Result<String> {
    let api_key = require_api_key_from_path(path)?;
    let tier = fetch_tier_from_convex_stub(&api_key);

    let credentials = CredentialsFile {
        api_key,
        tier: Some(tier.clone()),
    };
    write_credentials_to_path(path, &credentials)?;

    Ok(tier)
}

fn require_api_key_from_path(path: &Path) -> Result<String> {
    read_api_key_from_path(path)?.ok_or_else(|| anyhow!(MISSING_API_KEY_ERROR))
}

fn resolve_api_key(api_key: Option<String>) -> Result<String> {
    match api_key {
        Some(key) => normalize_api_key(key),
        None => prompt_for_api_key(),
    }
}

fn prompt_for_api_key() -> Result<String> {
    print!("Enter API key: ");
    io::stdout()
        .flush()
        .context("failed to flush API key prompt")?;

    let mut key = String::new();
    io::stdin()
        .read_line(&mut key)
        .context("failed to read API key from prompt")?;

    normalize_api_key(key)
}

fn normalize_api_key(api_key: String) -> Result<String> {
    let trimmed = api_key.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("API key cannot be empty"));
    }

    Ok(trimmed.to_string())
}

fn default_credentials_path() -> Result<PathBuf> {
    Ok(default_agentprey_dir()?.join(CREDENTIALS_FILE))
}

fn write_api_key_to_path(path: &Path, api_key: &str) -> Result<()> {
    let credentials = CredentialsFile {
        api_key: normalize_api_key(api_key.to_string())?,
        tier: None,
    };
    write_credentials_to_path(path, &credentials)
}

fn write_credentials_to_path(path: &Path, credentials: &CredentialsFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create credentials directory '{}'",
                    parent.display()
                )
            })?;
        }
    }

    let content = toml::to_string(credentials).context("failed to serialize credentials")?;

    fs::write(path, content)
        .with_context(|| format!("failed to write credentials file '{}'", path.display()))?;

    Ok(())
}

fn read_api_key_from_path(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read credentials file '{}'", path.display()))?;
    let credentials: CredentialsFile = toml::from_str(&content)
        .with_context(|| format!("failed to parse credentials file '{}'", path.display()))?;

    let normalized_key = normalize_api_key(credentials.api_key)?;
    Ok(Some(normalized_key))
}

fn fetch_tier_from_convex_stub(_api_key: &str) -> String {
    DEFAULT_TIER.to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::auth::{
        current_tier_from_path, normalize_api_key, read_api_key_from_path, refresh_from_path,
        require_api_key_from_path, write_api_key_to_path,
    };

    #[test]
    fn writes_and_reads_credentials_round_trip() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        write_api_key_to_path(&path, "test-api-key").expect("credentials should be written");

        let read_key = read_api_key_from_path(&path)
            .expect("credentials should be read")
            .expect("key should exist");
        assert_eq!(read_key, "test-api-key");
    }

    #[test]
    fn returns_none_when_credentials_missing() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        let read_key = read_api_key_from_path(&path).expect("read should succeed");
        assert_eq!(read_key, None);
    }

    #[test]
    fn rejects_empty_api_key() {
        let error = normalize_api_key("   ".to_string()).expect_err("empty key should fail");
        assert!(error.to_string().contains("API key cannot be empty"));
    }

    #[test]
    fn resolves_stub_tier_from_stored_key() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        write_api_key_to_path(&path, "test-api-key").expect("credentials should be written");

        let tier = current_tier_from_path(&path).expect("status should resolve");
        assert_eq!(tier.as_deref(), Some("free"));
    }

    #[test]
    fn refresh_updates_stored_tier_metadata() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        write_api_key_to_path(&path, "test-api-key").expect("credentials should be written");

        let tier = refresh_from_path(&path).expect("refresh should succeed");
        assert_eq!(tier, "free");

        let content = fs::read_to_string(&path).expect("credentials should be readable");
        assert!(content.contains("tier = \"free\""));
    }

    #[test]
    fn refresh_errors_when_api_key_missing() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        let error = refresh_from_path(&path).expect_err("refresh should fail without key");
        assert!(error
            .to_string()
            .contains("no API key stored; run `agentprey auth activate` first"));
    }

    #[test]
    fn require_api_key_errors_when_credentials_missing() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        let error = require_api_key_from_path(&path).expect_err("missing credentials should fail");
        assert!(error
            .to_string()
            .contains("no API key stored; run `agentprey auth activate` first"));
    }
}

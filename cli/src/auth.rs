use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

use crate::config::load_project_config;

const AGENTPREY_DIR: &str = ".agentprey";
const CREDENTIALS_FILE: &str = "credentials.toml";
const DEFAULT_ENTITLEMENT_BASE_URL: &str = "https://marvelous-sandpiper-677.convex.site";
const ENTITLEMENT_PATH: &str = "/api/entitlement";
const API_URL_ENV_VAR: &str = "AGENTPREY_API_URL";
const DEFAULT_PROJECT_CONFIG_FILE: &str = ".agentprey.toml";
const USER_AGENT_HEADER_PREFIX: &str = "agentprey/";
pub const ENTITLEMENT_STALE_AFTER_SECONDS: u64 = 72 * 60 * 60;
pub(crate) const MISSING_API_KEY_ERROR: &str =
    "no API key stored; run `agentprey auth activate` first";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialsFile {
    api_key: String,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    signed_vector_bundle_url: Option<String>,
    #[serde(default)]
    last_successful_refresh_epoch_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct EntitlementResponse {
    tier: String,
    signed_vector_bundle_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EntitlementState {
    pub tier: String,
    pub signed_vector_bundle_url: Option<String>,
    pub refreshed_at_epoch_secs: u64,
}

#[derive(Debug, Clone)]
pub struct AuthStatus {
    pub key_configured: bool,
    pub tier: Option<String>,
    pub signed_vector_bundle_url: Option<String>,
    pub last_successful_refresh_epoch_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStaleness {
    Fresh { age_seconds: u64 },
    Stale { age_seconds: u64 },
    ClockSkew,
}

impl AuthStatus {
    pub fn staleness(&self) -> Option<CacheStaleness> {
        let last_refresh = self.last_successful_refresh_epoch_secs?;
        let now = now_epoch_seconds().ok()?;

        if now < last_refresh {
            return Some(CacheStaleness::ClockSkew);
        }

        let age_seconds = now - last_refresh;
        if age_seconds <= ENTITLEMENT_STALE_AFTER_SECONDS {
            Some(CacheStaleness::Fresh { age_seconds })
        } else {
            Some(CacheStaleness::Stale { age_seconds })
        }
    }
}

pub fn activate(api_key: Option<String>) -> Result<PathBuf> {
    let resolved_key = resolve_api_key(api_key)?;
    let path = default_credentials_path()?;

    write_api_key_to_path(&path, &resolved_key)?;
    Ok(path)
}

pub async fn refresh() -> Result<EntitlementState> {
    let path = default_credentials_path()?;
    refresh_from_path_with_base_url(&path, None).await
}

pub fn status() -> Result<AuthStatus> {
    let path = default_credentials_path()?;
    status_from_path(&path)
}

pub fn require_stored_api_key() -> Result<String> {
    let path = default_credentials_path()?;
    require_api_key_from_path(&path)
}

pub fn logout() -> Result<bool> {
    let path = default_credentials_path()?;
    logout_from_path(&path)
}

pub fn default_agentprey_dir() -> Result<PathBuf> {
    let home =
        env::var_os("HOME").ok_or_else(|| anyhow!("HOME environment variable is not set"))?;
    Ok(PathBuf::from(home).join(AGENTPREY_DIR))
}

pub(crate) fn default_credentials_path() -> Result<PathBuf> {
    Ok(default_agentprey_dir()?.join(CREDENTIALS_FILE))
}

pub(crate) async fn refresh_from_path_with_base_url(
    path: &Path,
    api_base_url_override: Option<&str>,
) -> Result<EntitlementState> {
    let mut credentials =
        read_credentials_from_path(path)?.ok_or_else(|| anyhow!(MISSING_API_KEY_ERROR))?;

    let api_key = normalize_api_key(credentials.api_key.clone())?;
    let api_base_url = match api_base_url_override {
        Some(url) => normalize_api_base_url(url.to_string())?,
        None => resolve_api_base_url()?,
    };

    let entitlement = fetch_entitlement_from_api(&api_base_url, &api_key).await?;
    let refreshed_at_epoch_secs = now_epoch_seconds()?;

    credentials.api_key = api_key;
    credentials.tier = Some(entitlement.tier.clone());
    credentials.signed_vector_bundle_url = entitlement.signed_vector_bundle_url.clone();
    credentials.last_successful_refresh_epoch_secs = Some(refreshed_at_epoch_secs);
    write_credentials_to_path(path, &credentials)?;

    Ok(EntitlementState {
        tier: entitlement.tier,
        signed_vector_bundle_url: entitlement.signed_vector_bundle_url,
        refreshed_at_epoch_secs,
    })
}

fn status_from_path(path: &Path) -> Result<AuthStatus> {
    let Some(credentials) = read_credentials_from_path(path)? else {
        return Ok(AuthStatus {
            key_configured: false,
            tier: None,
            signed_vector_bundle_url: None,
            last_successful_refresh_epoch_secs: None,
        });
    };

    normalize_api_key(credentials.api_key)?;
    Ok(AuthStatus {
        key_configured: true,
        tier: credentials.tier,
        signed_vector_bundle_url: credentials.signed_vector_bundle_url,
        last_successful_refresh_epoch_secs: credentials.last_successful_refresh_epoch_secs,
    })
}

fn logout_from_path(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }

    fs::remove_file(path)
        .with_context(|| format!("failed to remove credentials file '{}'", path.display()))?;
    Ok(true)
}

fn require_api_key_from_path(path: &Path) -> Result<String> {
    let credentials =
        read_credentials_from_path(path)?.ok_or_else(|| anyhow!(MISSING_API_KEY_ERROR))?;
    normalize_api_key(credentials.api_key)
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

fn write_api_key_to_path(path: &Path, api_key: &str) -> Result<()> {
    let credentials = CredentialsFile {
        api_key: normalize_api_key(api_key.to_string())?,
        tier: None,
        signed_vector_bundle_url: None,
        last_successful_refresh_epoch_secs: None,
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

fn read_credentials_from_path(path: &Path) -> Result<Option<CredentialsFile>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read credentials file '{}'", path.display()))?;
    let credentials: CredentialsFile = toml::from_str(&content)
        .with_context(|| format!("failed to parse credentials file '{}'", path.display()))?;

    Ok(Some(credentials))
}

fn resolve_api_base_url() -> Result<String> {
    if let Some(raw_env) = env::var_os(API_URL_ENV_VAR) {
        let as_string = raw_env.to_string_lossy().trim().to_string();
        if as_string.is_empty() {
            return Err(anyhow!(
                "{API_URL_ENV_VAR} is set but empty; provide a valid base URL"
            ));
        }

        return normalize_api_base_url(as_string);
    }

    let project_config_path = Path::new(DEFAULT_PROJECT_CONFIG_FILE);
    if project_config_path.exists() {
        let config =
            load_project_config(&project_config_path.to_path_buf()).with_context(|| {
                format!(
                    "failed to read auth API URL from '{}'",
                    project_config_path.display()
                )
            })?;

        if let Some(url) = config.auth.api_url {
            return normalize_api_base_url(url);
        }
    }

    Ok(DEFAULT_ENTITLEMENT_BASE_URL.to_string())
}

fn normalize_api_base_url(url: String) -> Result<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("entitlement API base URL cannot be empty"));
    }

    Ok(trimmed.to_string())
}

fn entitlement_url(base_url: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), ENTITLEMENT_PATH)
}

async fn fetch_entitlement_from_api(base_url: &str, api_key: &str) -> Result<EntitlementResponse> {
    let url = entitlement_url(base_url);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-api-key",
        HeaderValue::from_str(api_key).context("failed to build API key header")?,
    );
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&format!(
            "{USER_AGENT_HEADER_PREFIX}{}",
            env!("CARGO_PKG_VERSION")
        ))
        .context("failed to build User-Agent header")?,
    );

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .context("failed to build entitlement HTTP client")?;

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to contact entitlement API at {url}"))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read entitlement API response body")?;

    if !status.is_success() {
        let body_excerpt = truncate(&body, 180);
        return Err(anyhow!(
            "entitlement API returned HTTP {}: {}",
            status.as_u16(),
            body_excerpt
        ));
    }

    let entitlement = serde_json::from_str::<EntitlementResponse>(&body)
        .context("failed to parse entitlement API response JSON")?;

    let tier = entitlement.tier.trim().to_string();
    if tier.is_empty() {
        return Err(anyhow!("entitlement API response contained an empty tier"));
    }

    Ok(EntitlementResponse {
        tier,
        signed_vector_bundle_url: entitlement.signed_vector_bundle_url,
    })
}

fn now_epoch_seconds() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok(duration.as_secs())
}

fn truncate(value: &str, max_chars: usize) -> String {
    let total = value.chars().count();
    if total <= max_chars {
        return value.to_string();
    }

    let clipped: String = value.chars().take(max_chars).collect();
    format!("{clipped}...")
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use tempfile::tempdir;
    use tiny_http::{Header, Response, Server};

    use crate::auth::{
        logout_from_path, normalize_api_key, read_credentials_from_path,
        refresh_from_path_with_base_url, require_api_key_from_path, status_from_path,
        write_api_key_to_path, CacheStaleness, MISSING_API_KEY_ERROR,
    };

    struct MockEntitlementServer {
        base_url: String,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Drop for MockEntitlementServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn spawn_entitlement_server(
        status_code: u16,
        body: &str,
        expected_key: Option<&str>,
    ) -> MockEntitlementServer {
        let server = Server::http("127.0.0.1:0").expect("server should bind");
        let socket = server
            .server_addr()
            .to_ip()
            .expect("server should expose socket address");
        let base_url = format!("http://{socket}");
        let response_body = body.to_string();
        let expected_key = expected_key.map(str::to_string);

        let handle = thread::spawn(move || {
            if let Ok(Some(request)) = server.recv_timeout(Duration::from_secs(5)) {
                let seen_key = request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("x-api-key"))
                    .map(|header| header.value.as_str().to_string());

                if let Some(expected) = expected_key.as_deref() {
                    assert_eq!(seen_key.as_deref(), Some(expected));
                }

                let content_type =
                    Header::from_bytes("Content-Type", "application/json").expect("valid header");
                let response = Response::from_string(response_body)
                    .with_status_code(status_code)
                    .with_header(content_type);
                let _ = request.respond(response);
            }
        });

        MockEntitlementServer {
            base_url,
            handle: Some(handle),
        }
    }

    #[test]
    fn writes_and_reads_credentials_round_trip() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        write_api_key_to_path(&path, "test-api-key").expect("credentials should be written");

        let credentials = read_credentials_from_path(&path)
            .expect("credentials should read")
            .expect("credentials should exist");
        assert_eq!(credentials.api_key, "test-api-key");
        assert_eq!(credentials.tier, None);
    }

    #[test]
    fn returns_none_when_credentials_missing() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        let credentials = read_credentials_from_path(&path).expect("read should succeed");
        assert!(credentials.is_none());
    }

    #[test]
    fn rejects_empty_api_key() {
        let error = normalize_api_key("   ".to_string()).expect_err("empty key should fail");
        assert!(error.to_string().contains("API key cannot be empty"));
    }

    #[tokio::test]
    async fn refresh_updates_stored_tier_metadata_for_free_response() {
        let server = spawn_entitlement_server(
            200,
            r#"{"tier":"free","signed_vector_bundle_url":null}"#,
            Some("test-api-key"),
        );
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");
        write_api_key_to_path(&path, "test-api-key").expect("credentials should be written");

        let entitlement = refresh_from_path_with_base_url(&path, Some(&server.base_url))
            .await
            .expect("refresh should succeed");
        assert_eq!(entitlement.tier, "free");
        assert_eq!(entitlement.signed_vector_bundle_url, None);
        assert!(entitlement.refreshed_at_epoch_secs > 0);

        let status = status_from_path(&path).expect("status should load");
        assert_eq!(status.tier.as_deref(), Some("free"));
        assert!(status.last_successful_refresh_epoch_secs.is_some());
        assert!(matches!(
            status.staleness(),
            Some(CacheStaleness::Fresh { .. })
        ));
    }

    #[tokio::test]
    async fn refresh_updates_stored_tier_metadata_for_pro_response() {
        let server = spawn_entitlement_server(
            200,
            r#"{"tier":"pro","signed_vector_bundle_url":"https://example.com/vectors.zip"}"#,
            Some("test-api-key"),
        );
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");
        write_api_key_to_path(&path, "test-api-key").expect("credentials should be written");

        let entitlement = refresh_from_path_with_base_url(&path, Some(&server.base_url))
            .await
            .expect("refresh should succeed");
        assert_eq!(entitlement.tier, "pro");
        assert_eq!(
            entitlement.signed_vector_bundle_url.as_deref(),
            Some("https://example.com/vectors.zip")
        );

        let status = status_from_path(&path).expect("status should load");
        assert_eq!(status.tier.as_deref(), Some("pro"));
        assert_eq!(
            status.signed_vector_bundle_url.as_deref(),
            Some("https://example.com/vectors.zip")
        );
    }

    #[tokio::test]
    async fn refresh_handles_backend_failure_without_overwriting_cache() {
        let server =
            spawn_entitlement_server(503, r#"{"error":"unavailable"}"#, Some("test-api-key"));
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");
        write_api_key_to_path(&path, "test-api-key").expect("credentials should be written");

        let error = refresh_from_path_with_base_url(&path, Some(&server.base_url))
            .await
            .expect_err("refresh should fail");
        assert!(error
            .to_string()
            .contains("entitlement API returned HTTP 503"));

        let status = status_from_path(&path).expect("status should load");
        assert_eq!(status.tier, None);
        assert_eq!(status.last_successful_refresh_epoch_secs, None);
    }

    #[tokio::test]
    async fn refresh_errors_when_api_key_missing() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        let error = refresh_from_path_with_base_url(&path, Some("http://127.0.0.1:1"))
            .await
            .expect_err("refresh should fail without key");
        assert!(error.to_string().contains(MISSING_API_KEY_ERROR));
    }

    #[test]
    fn require_api_key_errors_when_credentials_missing() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        let error = require_api_key_from_path(&path).expect_err("missing credentials should fail");
        assert!(error.to_string().contains(MISSING_API_KEY_ERROR));
    }

    #[test]
    fn status_reports_not_activated_without_credentials() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");

        let status = status_from_path(&path).expect("status should resolve");
        assert!(!status.key_configured);
        assert_eq!(status.tier, None);
    }

    #[test]
    fn logout_deletes_credentials_file() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("credentials.toml");
        write_api_key_to_path(&path, "test-api-key").expect("credentials should be written");
        assert!(path.exists());

        let removed = logout_from_path(&path).expect("logout should succeed");
        assert!(removed);
        assert!(!path.exists());
    }
}

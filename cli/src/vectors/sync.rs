use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};

use crate::auth;

pub async fn sync_pro_vectors() -> Result<usize> {
    let credentials_path = auth::default_credentials_path()?;
    let destination = pro_vectors_dir()?;

    sync_pro_vectors_for_path(&credentials_path, &destination, None).await
}

pub(crate) async fn sync_pro_vectors_for_path(
    credentials_path: &Path,
    destination: &Path,
    api_base_url_override: Option<&str>,
) -> Result<usize> {
    let entitlement = auth::refresh_from_path_with_base_url(credentials_path, api_base_url_override)
        .await
        .map_err(|error| {
            if error.to_string().contains(auth::MISSING_API_KEY_ERROR) {
                anyhow!(error.to_string())
            } else {
                anyhow!(
                    "unable to validate Pro entitlement: {error}. Run `agentprey auth refresh` and retry."
                )
            }
        })?;

    if !entitlement.tier.eq_ignore_ascii_case("pro") {
        return Err(anyhow!(
            "Pro entitlement required for `vectors sync --pro` (current tier: {}). Upgrade to Pro and retry.",
            entitlement.tier
        ));
    }

    sync_pro_vectors_to_path(destination)
}

fn sync_pro_vectors_to_path(destination: &Path) -> Result<usize> {
    fs::create_dir_all(destination).with_context(|| {
        format!(
            "failed to create Pro vectors directory '{}'",
            destination.display()
        )
    })?;

    Ok(0)
}

fn pro_vectors_dir() -> Result<PathBuf> {
    Ok(auth::default_agentprey_dir()?.join("vectors").join("pro"))
}

#[cfg(test)]
mod tests {
    use std::{path::Path, thread, time::Duration};

    use tempfile::tempdir;
    use tiny_http::{Header, Response, Server};

    use super::{sync_pro_vectors_for_path, sync_pro_vectors_to_path};

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

    fn spawn_entitlement_server(status_code: u16, body: &str) -> MockEntitlementServer {
        let server = Server::http("127.0.0.1:0").expect("server should bind");
        let socket = server
            .server_addr()
            .to_ip()
            .expect("server should expose socket address");
        let base_url = format!("http://{socket}");
        let response_body = body.to_string();

        let handle = thread::spawn(move || {
            if let Ok(Some(request)) = server.recv_timeout(Duration::from_secs(5)) {
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

    fn write_credentials(path: &Path, api_key: &str) {
        std::fs::write(path, format!("api_key = \"{api_key}\"\n"))
            .expect("credentials should be written");
    }

    #[test]
    fn creates_destination_directory() {
        let temp = tempdir().expect("tempdir should be created");
        let destination = temp.path().join("vectors/pro");

        let synced = sync_pro_vectors_to_path(&destination).expect("sync should succeed");
        assert_eq!(synced, 0);
        assert!(destination.exists());
        assert!(destination.is_dir());
    }

    #[test]
    fn succeeds_when_directory_already_exists() {
        let temp = tempdir().expect("tempdir should be created");
        let destination = temp.path().join("vectors/pro");
        std::fs::create_dir_all(destination.as_path()).expect("fixture directory should exist");

        let synced = sync_pro_vectors_to_path(&destination).expect("sync should succeed");
        assert_eq!(synced, 0);
    }

    #[tokio::test]
    async fn blocks_sync_for_free_tier_entitlement() {
        let server =
            spawn_entitlement_server(200, r#"{"tier":"free","signed_vector_bundle_url":null}"#);
        let temp = tempdir().expect("tempdir should be created");
        let credentials_path = temp.path().join("credentials.toml");
        let destination = temp.path().join("vectors/pro");
        write_credentials(&credentials_path, "test-api-key");

        let error =
            sync_pro_vectors_for_path(&credentials_path, &destination, Some(&server.base_url))
                .await
                .expect_err("sync should be blocked");
        assert!(error.to_string().contains("Pro entitlement required"));
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn allows_sync_for_pro_tier_entitlement() {
        let server = spawn_entitlement_server(
            200,
            r#"{"tier":"pro","signed_vector_bundle_url":"https://example.com/pro.zip"}"#,
        );
        let temp = tempdir().expect("tempdir should be created");
        let credentials_path = temp.path().join("credentials.toml");
        let destination = temp.path().join("vectors/pro");
        write_credentials(&credentials_path, "test-api-key");

        let synced =
            sync_pro_vectors_for_path(&credentials_path, &destination, Some(&server.base_url))
                .await
                .expect("sync should pass");
        assert_eq!(synced, 0);
        assert!(destination.exists());
    }

    #[tokio::test]
    async fn returns_actionable_error_when_backend_unavailable() {
        let server = spawn_entitlement_server(503, r#"{"error":"unavailable"}"#);
        let temp = tempdir().expect("tempdir should be created");
        let credentials_path = temp.path().join("credentials.toml");
        let destination = temp.path().join("vectors/pro");
        write_credentials(&credentials_path, "test-api-key");

        let error =
            sync_pro_vectors_for_path(&credentials_path, &destination, Some(&server.base_url))
                .await
                .expect_err("sync should fail");
        assert!(error
            .to_string()
            .contains("unable to validate Pro entitlement"));
        assert!(error
            .to_string()
            .contains("Run `agentprey auth refresh` and retry"));
    }

    #[tokio::test]
    async fn errors_when_no_key_configured() {
        let temp = tempdir().expect("tempdir should be created");
        let credentials_path = temp.path().join("credentials.toml");
        let destination = temp.path().join("vectors/pro");

        let error =
            sync_pro_vectors_for_path(&credentials_path, &destination, Some("http://127.0.0.1:1"))
                .await
                .expect_err("sync should fail without key");
        assert!(error
            .to_string()
            .contains("no API key stored; run `agentprey auth activate` first"));
    }
}

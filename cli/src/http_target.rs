use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, USER_AGENT},
    Method,
};
use serde_json::Value;
use tokio::time::sleep;

pub const DEFAULT_HTTP_METHOD: &str = "POST";
pub const DEFAULT_REQUEST_TEMPLATE: &str =
    r#"{"messages":[{"role":"user","content":{{payload}}}]}"#;
pub const PAYLOAD_MARKER: &str = "{{payload}}";

#[derive(Debug, Clone)]
pub struct HttpExchange {
    pub status: u16,
    pub raw_body: String,
    pub extracted_response: String,
}

#[derive(Debug, Clone, Copy)]
pub struct RequestPolicy {
    pub timeout_seconds: u64,
    pub retries: u32,
    pub retry_backoff_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RequestFormat {
    pub method: String,
    pub request_template: String,
    pub response_path: Option<String>,
}

impl Default for RequestFormat {
    fn default() -> Self {
        Self {
            method: DEFAULT_HTTP_METHOD.to_string(),
            request_template: DEFAULT_REQUEST_TEMPLATE.to_string(),
            response_path: None,
        }
    }
}

pub fn validate_request_template(template: &str) -> Result<()> {
    let trimmed = template.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("request template cannot be empty"));
    }

    if !trimmed.contains(PAYLOAD_MARKER) {
        return Err(anyhow!(
            "request template must include a {PAYLOAD_MARKER} marker"
        ));
    }

    Ok(())
}

pub async fn send_payload(
    target: &str,
    payload: &str,
    raw_headers: &[String],
    policy: RequestPolicy,
    request_format: &RequestFormat,
) -> Result<HttpExchange> {
    let max_attempts = policy.retries.saturating_add(1);
    for attempt in 1..=max_attempts {
        match send_payload_once(
            target,
            payload,
            raw_headers,
            policy.timeout_seconds,
            request_format,
        )
        .await
        {
            Ok(exchange) => {
                if should_retry_status(exchange.status) && attempt < max_attempts {
                    sleep(backoff_duration(policy.retry_backoff_ms, attempt)).await;
                    continue;
                }

                return Ok(exchange);
            }
            Err(error) => {
                if attempt < max_attempts {
                    sleep(backoff_duration(policy.retry_backoff_ms, attempt)).await;
                    continue;
                }

                return Err(
                    error.context(format!("request failed after {max_attempts} attempt(s)"))
                );
            }
        }
    }

    Err(anyhow!("request loop exited unexpectedly"))
}

async fn send_payload_once(
    target: &str,
    payload: &str,
    raw_headers: &[String],
    timeout_seconds: u64,
    request_format: &RequestFormat,
) -> Result<HttpExchange> {
    let headers = build_headers(raw_headers)?;
    let method = parse_method(&request_format.method)?;
    let request_body = render_request_body(&request_format.request_template, payload)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
        .context("failed to build HTTP client")?;

    let response = client
        .request(method, target)
        .headers(headers)
        .json(&request_body)
        .send()
        .await
        .with_context(|| format!("failed to send request to {target}"))?;

    let status = response.status().as_u16();
    let raw_body = response
        .text()
        .await
        .context("failed to read HTTP response body")?;
    let extracted_response =
        extract_response_text(&raw_body, request_format.response_path.as_deref());

    Ok(HttpExchange {
        status,
        raw_body,
        extracted_response,
    })
}

fn should_retry_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

fn backoff_duration(base_ms: u64, attempt: u32) -> Duration {
    let base = base_ms.max(1);
    let factor = 2_u64.saturating_pow(attempt.saturating_sub(1));
    Duration::from_millis(base.saturating_mul(factor).min(30_000))
}

fn parse_method(raw_method: &str) -> Result<Method> {
    let trimmed = raw_method.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("HTTP method cannot be empty"));
    }

    let normalized = trimmed.to_ascii_uppercase();
    Method::from_bytes(normalized.as_bytes())
        .with_context(|| format!("unsupported HTTP method '{trimmed}'"))
}

fn render_request_body(template: &str, payload: &str) -> Result<Value> {
    validate_request_template(template)?;

    let escaped_payload =
        serde_json::to_string(payload).context("failed to JSON-escape payload for template")?;
    let rendered = template.replace(PAYLOAD_MARKER, &escaped_payload);
    serde_json::from_str::<Value>(&rendered)
        .context("request template produced an invalid JSON request body")
}

fn build_headers(raw_headers: &[String]) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();

    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&format!("agentprey/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to set User-Agent header")?,
    );

    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    for entry in raw_headers {
        let (name, value) = parse_header(entry)?;
        headers.insert(name, value);
    }

    Ok(headers)
}

fn parse_header(raw: &str) -> Result<(HeaderName, HeaderValue)> {
    let mut parts = raw.splitn(2, ':');

    let name = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("invalid header '{raw}': missing header name"))?;

    let value = parts
        .next()
        .map(str::trim)
        .ok_or_else(|| anyhow!("invalid header '{raw}': expected 'Key: Value' format"))?;

    let header_name = HeaderName::from_bytes(name.as_bytes())
        .with_context(|| format!("invalid header name '{name}'"))?;
    let header_value = HeaderValue::from_str(value)
        .with_context(|| format!("invalid header value for '{name}'"))?;

    Ok((header_name, header_value))
}

pub fn extract_response_text(body: &str, response_path: Option<&str>) -> String {
    let parsed: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return body.to_string(),
    };

    if let Some(path) = response_path.map(str::trim).filter(|path| !path.is_empty()) {
        if let Some(value) = parsed.pointer(path) {
            if let Some(text) = value.as_str() {
                return text.to_string();
            }

            return value.to_string();
        }
    }

    extract_response_text_default(&parsed)
}

fn extract_response_text_default(parsed: &Value) -> String {
    for path in [
        "/choices/0/message/content",
        "/output",
        "/response",
        "/answer",
        "/message",
        "/content",
    ] {
        if let Some(value) = parsed.pointer(path).and_then(Value::as_str) {
            return value.to_string();
        }
    }

    if let Some(string_value) = first_string(parsed) {
        return string_value;
    }

    parsed.to_string()
}

fn first_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => items.iter().find_map(first_string),
        Value::Object(map) => {
            for key in ["content", "message", "text", "response", "output", "answer"] {
                if let Some(value) = map.get(key) {
                    if let Some(text) = first_string(value) {
                        return Some(text);
                    }
                }
            }

            map.values().find_map(first_string)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::Value;

    use crate::http_target::{
        backoff_duration, extract_response_text, render_request_body, validate_request_template,
        DEFAULT_REQUEST_TEMPLATE,
    };

    #[test]
    fn computes_exponential_backoff_with_cap() {
        assert_eq!(backoff_duration(250, 1), Duration::from_millis(250));
        assert_eq!(backoff_duration(250, 2), Duration::from_millis(500));
        assert_eq!(backoff_duration(250, 3), Duration::from_millis(1000));
        assert_eq!(backoff_duration(20_000, 3), Duration::from_millis(30_000));
    }

    #[test]
    fn renders_default_request_template_with_json_escaped_payload() {
        let body = render_request_body(
            DEFAULT_REQUEST_TEMPLATE,
            "line one\nline \"two\" with ascii text",
        )
        .expect("template render should succeed");

        assert_eq!(
            body.pointer("/messages/0/content").and_then(Value::as_str),
            Some("line one\nline \"two\" with ascii text")
        );
    }

    #[test]
    fn rejects_request_template_without_payload_marker() {
        let error = validate_request_template("{\"messages\":[]}")
            .expect_err("template without marker should fail");
        assert!(error.to_string().contains("{{payload}}"));
    }

    #[test]
    fn extracts_response_from_custom_path_when_present() {
        let body = r#"{"result":{"text":"custom answer"}}"#;
        assert_eq!(
            extract_response_text(body, Some("/result/text")),
            "custom answer"
        );
    }

    #[test]
    fn falls_back_to_default_extraction_when_custom_path_missing() {
        let body = r#"{"choices":[{"message":{"content":"fallback answer"}}]}"#;
        assert_eq!(
            extract_response_text(body, Some("/missing/path")),
            "fallback answer"
        );
    }
}

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, USER_AGENT};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct HttpExchange {
    pub status: u16,
    pub raw_body: String,
    pub extracted_response: String,
}

pub async fn send_payload(
    target: &str,
    payload: &str,
    raw_headers: &[String],
    timeout_seconds: u64,
) -> Result<HttpExchange> {
    let headers = build_headers(raw_headers)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
        .context("failed to build HTTP client")?;

    let request_body = json!({
        "messages": [
            {
                "role": "user",
                "content": payload
            }
        ]
    });

    let response = client
        .post(target)
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
    let extracted_response = extract_response_text(&raw_body);

    Ok(HttpExchange {
        status,
        raw_body,
        extracted_response,
    })
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

pub fn extract_response_text(body: &str) -> String {
    let parsed: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return body.to_string(),
    };

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

    if let Some(string_value) = first_string(&parsed) {
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

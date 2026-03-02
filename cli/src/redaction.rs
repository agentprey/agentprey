use regex::Regex;

pub fn redact_text(input: &str) -> String {
    let mut redacted = input.to_string();

    redacted = Regex::new(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}")
        .expect("bearer regex should compile")
        .replace_all(&redacted, "Bearer [REDACTED]")
        .to_string();

    redacted = Regex::new(r#"(?i)"(api[_-]?key|token|secret|password)"\s*:\s*"[^"]*""#)
        .expect("json key regex should compile")
        .replace_all(&redacted, r#""$1":"[REDACTED]""#)
        .to_string();

    Regex::new(r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*([^\s,;\]\}]+)")
        .expect("assignment regex should compile")
        .replace_all(&redacted, "$1=[REDACTED]")
        .to_string()
}

#[cfg(test)]
mod tests {
    use crate::redaction::redact_text;

    #[test]
    fn redacts_bearer_token_and_secret_assignments() {
        let text = "Authorization: Bearer abcdefghijklmnop token=super-secret";
        let redacted = redact_text(text);
        assert!(redacted.contains("Bearer [REDACTED]"));
        assert!(redacted.contains("token=[REDACTED]"));
        assert!(!redacted.contains("super-secret"));
    }

    #[test]
    fn redacts_json_secret_fields() {
        let text = r#"{"apiKey":"abc123","message":"ok"}"#;
        let redacted = redact_text(text);
        assert!(redacted.contains(r#""apiKey":"[REDACTED]""#));
        assert!(!redacted.contains("abc123"));
    }
}

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Vector {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub subcategory: String,
    pub severity: Severity,
    #[serde(default)]
    pub tier: Option<Tier>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub payloads: Vec<Payload>,
    pub detection: Detection,
    #[serde(default)]
    pub remediation: Option<Remediation>,
    #[serde(default)]
    pub owasp_mapping: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Free,
    Pro,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Payload {
    pub name: String,
    pub prompt: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Detection {
    #[serde(default)]
    pub indicators: Vec<Indicator>,
    pub threshold: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Indicator {
    #[serde(rename = "type")]
    pub indicator_type: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub weight: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Remediation {
    pub summary: String,
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

use std::{
    fmt::Write,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};

use crate::scan::{FindingOutcome, FindingStatus, ScanOutcome};

pub fn write_scan_html(path: &Path, outcome: &ScanOutcome) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create HTML output directory '{}'",
                    parent.display()
                )
            })?;
        }
    }

    let html = render_html(outcome);
    fs::write(path, html)
        .with_context(|| format!("failed to write HTML output file '{}'", path.display()))?;

    Ok(())
}

fn render_html(outcome: &ScanOutcome) -> String {
    let mut rows = String::new();
    for finding in &outcome.findings {
        let confidence = finding
            .analysis
            .as_ref()
            .map(|analysis| format!("{:.2}", analysis.confidence))
            .unwrap_or_else(|| "n/a".to_string());

        let _ = write!(
            rows,
            "<tr>\
<td><code>{}</code></td>\
<td>{}</td>\
<td>{}</td>\
<td><span class=\"status {}\">{}</span></td>\
<td>{}</td>\
<td>{} ms</td>\
<td><code>{}</code></td>\
</tr>",
            escape_html(&finding.vector_id),
            escape_html(&finding.vector_name),
            escape_html(&finding.severity.to_string()),
            status_class(finding),
            escape_html(status_label(finding)),
            escape_html(&confidence),
            finding.duration_ms,
            escape_html(&truncate(&finding.response, 180)),
        );
    }

    let mcp_section = outcome
        .mcp
        .as_ref()
        .map(render_mcp_section)
        .unwrap_or_default();

    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>AgentPrey Scan Report</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card: #111827;
      --ink: #e5e7eb;
      --muted: #9ca3af;
      --ok: #16a34a;
      --warn: #d97706;
      --bad: #dc2626;
      --border: #1f2937;
    }}
    body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background: var(--bg); color: var(--ink); }}
    .wrap {{ max-width: 1080px; margin: 0 auto; padding: 24px; }}
    h1 {{ margin: 0 0 12px; }}
    .meta {{ color: var(--muted); margin-bottom: 20px; }}
    .grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); margin-bottom: 20px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px; }}
    .label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.04em; }}
    .value {{ font-size: 24px; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
    th, td {{ border-bottom: 1px solid var(--border); text-align: left; padding: 10px; font-size: 14px; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    code {{ color: #d1d5db; font-size: 12px; }}
    .status {{ font-weight: 700; }}
    .status.vulnerable {{ color: var(--bad); }}
    .status.resistant {{ color: var(--ok); }}
    .status.error {{ color: var(--warn); }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>AgentPrey Scan Report</h1>
    <div class=\"meta\">Generated at {} ms since epoch for target <code>{}</code></div>
    <div class=\"grid\">
      <div class=\"card\"><div class=\"label\">Score</div><div class=\"value\">{}</div></div>
      <div class=\"card\"><div class=\"label\">Grade</div><div class=\"value\">{}</div></div>
      <div class=\"card\"><div class=\"label\">Vectors</div><div class=\"value\">{}</div></div>
      <div class=\"card\"><div class=\"label\">Vulnerable</div><div class=\"value\">{}</div></div>
      <div class=\"card\"><div class=\"label\">Resistant</div><div class=\"value\">{}</div></div>
      <div class=\"card\"><div class=\"label\">Errors</div><div class=\"value\">{}</div></div>
      <div class=\"card\"><div class=\"label\">Duration</div><div class=\"value\">{} ms</div></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Vector ID</th>
          <th>Name</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Confidence</th>
          <th>Duration</th>
          <th>Response Excerpt</th>
        </tr>
      </thead>
      <tbody>
        {}
      </tbody>
    </table>
    {}
  </div>
</body>
</html>",
        now_ms(),
        escape_html(&outcome.target),
        outcome.score.score,
        outcome.score.grade,
        outcome.total_vectors,
        outcome.vulnerable_count,
        outcome.resistant_count,
        outcome.error_count,
        outcome.duration_ms,
        rows,
        mcp_section,
    )
}

fn render_mcp_section(metadata: &crate::mcp::model::McpScanMetadata) -> String {
    let tools = metadata
        .tools
        .iter()
        .map(|tool| {
            let capabilities = if tool.capabilities.is_empty() {
                "none".to_string()
            } else {
                tool.capabilities
                    .iter()
                    .map(|assessment| assessment.capability.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&tool.key),
                escape_html(&tool.name),
                escape_html(&capabilities),
                escape_html(&tool.uncertainty_flags.join("; "))
            )
        })
        .collect::<String>();

    let warnings = if metadata.parse_warnings.is_empty() {
        "<li>none</li>".to_string()
    } else {
        metadata
            .parse_warnings
            .iter()
            .map(|warning| {
                format!(
                    "<li><code>{}</code>: {} ({})</li>",
                    escape_html(&warning.code),
                    escape_html(&warning.message),
                    escape_html(&warning.path)
                )
            })
            .collect::<String>()
    };

    format!(
        "<section style=\"margin-top: 20px;\">
  <h2>MCP Inventory</h2>
  <div class=\"grid\">
    <div class=\"card\"><div class=\"label\">Tools</div><div class=\"value\">{}</div></div>
    <div class=\"card\"><div class=\"label\">Resources</div><div class=\"value\">{}</div></div>
    <div class=\"card\"><div class=\"label\">Prompts</div><div class=\"value\">{}</div></div>
    <div class=\"card\"><div class=\"label\">Warnings</div><div class=\"value\">{}</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Tool Key</th>
        <th>Name</th>
        <th>Capabilities</th>
        <th>Uncertainty</th>
      </tr>
    </thead>
    <tbody>{}</tbody>
  </table>
  <div class=\"card\" style=\"margin-top: 12px;\">
    <div class=\"label\">Parse Warnings</div>
    <ul>{}</ul>
  </div>
</section>",
        metadata.inventory.tool_count,
        metadata.inventory.resource_count,
        metadata.inventory.prompt_count,
        metadata.inventory.parse_warning_count,
        tools,
        warnings,
    )
}

fn status_label(finding: &FindingOutcome) -> &'static str {
    match finding.status {
        FindingStatus::Vulnerable => "vulnerable",
        FindingStatus::Resistant => "resistant",
        FindingStatus::Error => "error",
    }
}

fn status_class(finding: &FindingOutcome) -> &'static str {
    match finding.status {
        FindingStatus::Vulnerable => "vulnerable",
        FindingStatus::Resistant => "resistant",
        FindingStatus::Error => "error",
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let clipped: String = value.chars().take(max_chars).collect();
    format!("{clipped}...")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::{
        output::html::write_scan_html,
        scan::{FindingOutcome, FindingStatus, ScanOutcome},
        scorer::{Grade, ScoreSummary, SeverityCounts},
        vectors::model::Severity,
    };

    #[test]
    fn writes_html_report_with_summary_and_table() {
        let temp = tempdir().expect("tempdir should be created");
        let output = temp.path().join("reports/scan.html");

        let outcome = ScanOutcome {
            target_type: crate::cli::TargetType::Http,
            target: "http://127.0.0.1:8787/chat".to_string(),
            mcp: None,
            total_vectors: 1,
            vulnerable_count: 1,
            resistant_count: 0,
            error_count: 0,
            score: ScoreSummary {
                score: 90,
                grade: Grade::B,
                vulnerable_severities: SeverityCounts {
                    critical: 0,
                    high: 1,
                    medium: 0,
                    low: 0,
                    info: 0,
                },
                error_count: 0,
            },
            findings: vec![FindingOutcome {
                rule_id: "pi-direct-001".to_string(),
                vector_id: "pi-direct-001".to_string(),
                vector_name: "Basic Instruction Override".to_string(),
                category: "prompt-injection".to_string(),
                subcategory: "direct".to_string(),
                severity: Severity::High,
                payload_name: "payload".to_string(),
                payload_prompt: "prompt".to_string(),
                status: FindingStatus::Vulnerable,
                status_code: Some(200),
                response: "Bearer [REDACTED]".to_string(),
                analysis: None,
                duration_ms: 10,
                rationale: "Attempts to override or reveal protected instructions.".to_string(),
                evidence_summary: "redacted response excerpt".to_string(),
                recommendation: "Enforce non-overridable instruction boundaries.".to_string(),
                tool_name: None,
                capabilities: Vec::new(),
                approval_sensitive: None,
            }],
            duration_ms: 12,
        };

        write_scan_html(&output, &outcome).expect("html report should be written");

        let html = fs::read_to_string(&output).expect("html report should exist");
        assert!(html.contains("AgentPrey Scan Report"));
        assert!(html.contains("Basic Instruction Override"));
        assert!(html.contains("Bearer [REDACTED]"));
        assert!(html.contains("<table>"));
    }
}

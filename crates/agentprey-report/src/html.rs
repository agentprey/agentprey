use std::{
    collections::BTreeMap,
    fmt::Write,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};

use crate::scan::{FindingOutcome, FindingStatus, ScanOutcome};
use crate::vectors::model::Severity;

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
    let summary_cards = render_summary_cards(outcome);
    let category_overview = render_category_overview(outcome);
    let priority_findings = render_priority_findings(outcome);
    let focus_sections = render_focus_sections(outcome);
    let findings_table = render_findings_table(outcome);
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
      --bg: #0b1120;
      --panel: #111827;
      --panel-2: #0f172a;
      --ink: #e5e7eb;
      --muted: #94a3b8;
      --border: #1f2937;
      --ok: #16a34a;
      --warn: #d97706;
      --bad: #dc2626;
      --accent: #38bdf8;
      --chip: #172033;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background: linear-gradient(180deg, #020617 0%, #0b1120 100%); color: var(--ink); }}
    .wrap {{ max-width: 1180px; margin: 0 auto; padding: 28px 24px 48px; }}
    h1, h2, h3 {{ margin: 0; }}
    h1 {{ margin-bottom: 10px; }}
    h2 {{ margin-bottom: 12px; font-size: 22px; }}
    h3 {{ margin-bottom: 8px; font-size: 16px; }}
    p {{ margin: 0; }}
    section {{ margin-top: 24px; }}
    .meta {{ color: var(--muted); margin-bottom: 20px; line-height: 1.6; }}
    .panel {{ background: rgba(15, 23, 42, 0.92); border: 1px solid var(--border); border-radius: 14px; padding: 16px; box-shadow: 0 14px 40px rgba(2, 6, 23, 0.25); }}
    .grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }}
    .finding-card {{ background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--accent); border-radius: 12px; padding: 14px; }}
    .finding-card.vulnerable {{ border-left-color: var(--bad); }}
    .finding-card.resistant {{ border-left-color: var(--ok); }}
    .finding-card.error {{ border-left-color: var(--warn); }}
    .label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em; }}
    .value {{ font-size: 24px; font-weight: 700; }}
    .section-copy {{ color: var(--muted); margin-bottom: 14px; line-height: 1.6; }}
    .eyebrow {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }}
    .chip {{ display: inline-flex; align-items: center; gap: 6px; background: var(--chip); color: var(--ink); border: 1px solid var(--border); border-radius: 999px; padding: 4px 9px; font-size: 12px; }}
    .chip.status-vulnerable {{ color: #fecaca; border-color: rgba(220, 38, 38, 0.45); background: rgba(127, 29, 29, 0.35); }}
    .chip.status-resistant {{ color: #bbf7d0; border-color: rgba(22, 163, 74, 0.45); background: rgba(20, 83, 45, 0.35); }}
    .chip.status-error {{ color: #fde68a; border-color: rgba(217, 119, 6, 0.45); background: rgba(120, 53, 15, 0.35); }}
    .muted {{ color: var(--muted); }}
    .finding-title {{ display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 10px; }}
    .finding-body {{ display: grid; gap: 10px; }}
    .finding-meta {{ display: grid; gap: 8px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .detail {{ background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px; padding: 10px; }}
    .detail strong {{ display: block; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 6px; }}
    .list {{ margin: 0; padding-left: 18px; color: var(--ink); line-height: 1.6; }}
    .empty {{ color: var(--muted); font-style: italic; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }}
    th, td {{ border-bottom: 1px solid var(--border); text-align: left; padding: 11px; font-size: 14px; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    tr:last-child td {{ border-bottom: none; }}
    code {{ color: #dbeafe; font-size: 12px; word-break: break-word; }}
    .table-wrap {{ overflow-x: auto; border-radius: 14px; }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>AgentPrey Scan Report</h1>
    <div class=\"meta\">Generated at {} ms since epoch for target <code>{}</code> ({})</div>
    <section>
      <div class=\"grid\">{}</div>
    </section>
    {}
    {}
    {}
    <section>
      <h2>Detailed Findings</h2>
      <p class=\"section-copy\">Full vector-by-vector results with evidence summaries, excerpts, and execution timing.</p>
      <div class=\"table-wrap\">{}</div>
    </section>
    {}
  </div>
</body>
</html>",
        now_ms(),
        escape_html(&outcome.target),
        escape_html(&outcome.target_type.to_string()),
        summary_cards,
        category_overview,
        priority_findings,
        focus_sections,
        findings_table,
        mcp_section,
    )
}

fn render_summary_cards(outcome: &ScanOutcome) -> String {
    let cards = [
        ("Score", outcome.score.score.to_string()),
        ("Grade", outcome.score.grade.to_string()),
        ("Vectors", outcome.total_vectors.to_string()),
        ("Vulnerable", outcome.vulnerable_count.to_string()),
        ("Resistant", outcome.resistant_count.to_string()),
        ("Errors", outcome.error_count.to_string()),
        ("Duration", format!("{} ms", outcome.duration_ms)),
    ];

    cards
        .into_iter()
        .map(|(label, value)| {
            format!(
                "<div class=\"card\"><div class=\"label\">{}</div><div class=\"value\">{}</div></div>",
                escape_html(label),
                escape_html(&value)
            )
        })
        .collect::<String>()
}

fn render_category_overview(outcome: &ScanOutcome) -> String {
    let categories = summarize_categories(&outcome.findings);
    if categories.is_empty() {
        return String::new();
    }

    let cards = categories
        .into_iter()
        .map(|(category, counts)| {
            format!(
                "<div class=\"card\">\
<div class=\"label\">{}</div>\
<div class=\"value\">{}</div>\
<div class=\"muted\">vulnerable {} · resistant {} · error {}</div>\
</div>",
                escape_html(&prettify_label(&category)),
                counts.total,
                counts.vulnerable,
                counts.resistant,
                counts.error,
            )
        })
        .collect::<String>();

    format!(
        "<section>\
<h2>Category Overview</h2>\
<p class=\"section-copy\">Quick coverage across scan categories so MCP, tool-misuse, and approval-bypass hotspots are obvious without reading the full table.</p>\
<div class=\"grid\">{}</div>\
</section>",
        cards
    )
}

fn render_priority_findings(outcome: &ScanOutcome) -> String {
    let mut highlights = outcome.findings.iter().collect::<Vec<_>>();
    highlights.sort_by_key(|finding| {
        (
            status_rank(finding.status),
            severity_rank(finding.severity.clone()),
        )
    });
    highlights.retain(|finding| !matches!(finding.status, FindingStatus::Resistant));

    if highlights.is_empty() {
        return "<section>\
<h2>Priority Findings</h2>\
<div class=\"panel empty\">No vulnerable or partial findings to highlight.</div>\
</section>"
            .to_string();
    }

    let cards = highlights
        .into_iter()
        .take(8)
        .map(render_finding_card)
        .collect::<String>();

    format!(
        "<section>\
<h2>Priority Findings</h2>\
<p class=\"section-copy\">Highest-signal findings surfaced first with direct evidence, rationale, and mitigations.</p>\
<div class=\"grid\">{}</div>\
</section>",
        cards
    )
}

fn render_focus_sections(outcome: &ScanOutcome) -> String {
    let focus_categories = ["mcp-security", "tool-misuse", "approval-bypass"];
    let mut sections = String::new();

    for category in focus_categories {
        let findings = outcome
            .findings
            .iter()
            .filter(|finding| finding.category == category)
            .collect::<Vec<_>>();
        if findings.is_empty() {
            continue;
        }

        let cards = findings
            .iter()
            .map(|finding| render_finding_card(finding))
            .collect::<String>();

        let _ = write!(
            sections,
            "<section>\
<h2>{}</h2>\
<p class=\"section-copy\">Focused surfacing for {} findings.</p>\
<div class=\"grid\">{}</div>\
</section>",
            escape_html(&focus_heading(category)),
            escape_html(&prettify_label(category)),
            cards,
        );
    }

    sections
}

fn render_findings_table(outcome: &ScanOutcome) -> String {
    let rows = outcome
        .findings
        .iter()
        .map(|finding| {
            let confidence = finding
                .analysis
                .as_ref()
                .map(|analysis| format!("{:.2}", analysis.confidence))
                .unwrap_or_else(|| "n/a".to_string());

            format!(
                "<tr>\
<td><code>{}</code></td>\
<td>{}<div class=\"muted\">{} / {}</div></td>\
<td>{}</td>\
<td><span class=\"chip status-{}\">{}</span></td>\
<td>{}</td>\
<td>{}</td>\
<td>{} ms</td>\
<td>{}</td>\
<td><code>{}</code></td>\
</tr>",
                escape_html(&finding.vector_id),
                escape_html(&finding.vector_name),
                escape_html(&prettify_label(&finding.category)),
                escape_html(&prettify_label(&finding.subcategory)),
                escape_html(&finding.severity.to_string()),
                escape_html(status_label(finding)),
                escape_html(status_label(finding)),
                escape_html(&confidence),
                escape_html(&truncate(&finding.evidence_summary, 180)),
                finding.duration_ms,
                escape_html(&truncate(&finding.recommendation, 180)),
                escape_html(&truncate(&finding.response, 180)),
            )
        })
        .collect::<String>();

    format!(
        "<table>
  <thead>
    <tr>
      <th>Vector ID</th>
      <th>Name</th>
      <th>Severity</th>
      <th>Status</th>
      <th>Confidence</th>
      <th>Evidence</th>
      <th>Duration</th>
      <th>Recommendation</th>
      <th>Response Excerpt</th>
    </tr>
  </thead>
  <tbody>{}</tbody>
</table>",
        rows
    )
}

fn render_finding_card(finding: &FindingOutcome) -> String {
    let capabilities = finding
        .observed_capabilities
        .iter()
        .chain(finding.capabilities.iter())
        .cloned()
        .collect::<Vec<_>>();
    let capabilities = dedupe_preserve_order(capabilities);
    let mitigation_tags = dedupe_preserve_order(finding.mitigation_tags.clone());
    let tool_name = finding
        .tool_name
        .clone()
        .unwrap_or_else(|| "n/a".to_string());
    let approval = finding
        .approval_sensitive
        .map(|value| {
            if value {
                "approval-sensitive"
            } else {
                "approval-unknown-or-missing"
            }
        })
        .unwrap_or("n/a");
    let repro_steps = if finding.repro_steps.is_empty() {
        "<div class=\"empty\">No repro steps captured.</div>".to_string()
    } else {
        format!(
            "<ol class=\"list\">{}</ol>",
            render_list_items(&finding.repro_steps)
        )
    };
    let capability_html = if capabilities.is_empty() {
        "<span class=\"empty\">No capability metadata</span>".to_string()
    } else {
        render_chips(&capabilities)
    };
    let mitigation_html = if mitigation_tags.is_empty() {
        "<span class=\"empty\">No mitigation tags</span>".to_string()
    } else {
        render_chips(&mitigation_tags)
    };
    let source_spans_html = if finding.source_spans.is_empty() {
        "<span class=\"empty\">No source spans</span>".to_string()
    } else {
        let spans = finding
            .source_spans
            .iter()
            .map(|span| match span.column {
                Some(column) => format!("{}:{}:{}", span.file, span.line, column),
                None => format!("{}:{}", span.file, span.line),
            })
            .collect::<Vec<_>>();
        render_chips(&spans)
    };

    format!(
        "<article class=\"finding-card {}\">\
<div class=\"eyebrow\">\
  <span class=\"chip status-{}\">{}</span>\
  <span class=\"chip\">{}</span>\
  <span class=\"chip\">{}</span>\
  <span class=\"chip\">severity {}</span>\
</div>\
<div class=\"finding-title\">\
  <div>\
    <h3>{}</h3>\
    <div class=\"muted\"><code>{}</code></div>\
  </div>\
</div>\
<div class=\"finding-body\">\
  <div class=\"detail\"><strong>Evidence summary</strong>{}</div>\
  <div class=\"detail\"><strong>Why it matters</strong>{}</div>\
  <div class=\"detail\"><strong>Recommended action</strong>{}</div>\
  <div class=\"finding-meta\">\
    <div class=\"detail\"><strong>Attack surface</strong>{}</div>\
    <div class=\"detail\"><strong>Tool</strong>{}</div>\
    <div class=\"detail\"><strong>Approval signal</strong>{}</div>\
    <div class=\"detail\"><strong>Evidence kind</strong>{}</div>\
  </div>\
  <div class=\"detail\"><strong>Source spans</strong>{}</div>\
  <div class=\"detail\"><strong>Observed capabilities</strong>{}</div>\
  <div class=\"detail\"><strong>Mitigation tags</strong>{}</div>\
  <div class=\"detail\"><strong>Repro steps</strong>{}</div>\
  <div class=\"detail\"><strong>Response excerpt</strong><code>{}</code></div>\
</div>\
</article>",
        status_label(finding),
        status_label(finding),
        escape_html(status_label(finding)),
        escape_html(&prettify_label(&finding.category)),
        escape_html(&prettify_label(&finding.subcategory)),
        escape_html(&finding.severity.to_string()),
        escape_html(&finding.vector_name),
        escape_html(&finding.vector_id),
        escape_html(&finding.evidence_summary),
        escape_html(&finding.rationale),
        escape_html(&finding.recommendation),
        escape_html(finding.attack_surface.as_deref().unwrap_or("n/a")),
        escape_html(&tool_name),
        escape_html(approval),
        escape_html(finding.evidence_kind.as_deref().unwrap_or("n/a")),
        source_spans_html,
        capability_html,
        mitigation_html,
        repro_steps,
        escape_html(&truncate(&finding.response, 240)),
    )
}

fn render_mcp_section(metadata: &crate::mcp::model::McpScanMetadata) -> String {
    let tools = metadata
        .tools
        .iter()
        .map(|tool| {
            let capabilities = if tool.capabilities.is_empty() {
                "<span class=\"empty\">No capabilities inferred</span>".to_string()
            } else {
                let labels = tool
                    .capabilities
                    .iter()
                    .map(|assessment| {
                        format!(
                            "{} ({}, {})",
                            assessment.capability.as_str(),
                            format!("{:?}", assessment.source).to_lowercase(),
                            format!("{:?}", assessment.confidence).to_lowercase(),
                        )
                    })
                    .collect::<Vec<_>>();
                render_chips(&labels)
            };
            let uncertainty = if tool.uncertainty_flags.is_empty() {
                "<span class=\"empty\">none</span>".to_string()
            } else {
                render_chips(&tool.uncertainty_flags)
            };
            let approval = match tool.approval_required {
                Some(true) => "required",
                Some(false) => "not required",
                None => "unknown",
            };
            format!(
                "<article class=\"card\">\
<div class=\"finding-title\">\
  <div>\
    <h3>{}</h3>\
    <div class=\"muted\"><code>{}</code></div>\
  </div>\
</div>\
<div class=\"finding-body\">\
  <div class=\"detail\"><strong>Description</strong>{}</div>\
  <div class=\"finding-meta\">\
    <div class=\"detail\"><strong>Approval</strong>{}</div>\
    <div class=\"detail\"><strong>Capabilities</strong>{}</div>\
  </div>\
  <div class=\"detail\"><strong>Uncertainty</strong>{}</div>\
</div>\
</article>",
                escape_html(&tool.name),
                escape_html(&tool.key),
                escape_html(tool.description.as_deref().unwrap_or("No description")),
                escape_html(approval),
                capabilities,
                uncertainty,
            )
        })
        .collect::<String>();

    let warnings = if metadata.parse_warnings.is_empty() {
        "<div class=\"empty\">No parse warnings.</div>".to_string()
    } else {
        format!(
            "<ul class=\"list\">{}</ul>",
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
        )
    };

    let capability_cards = if metadata.inventory.capability_counts.is_empty() {
        "<div class=\"card\"><div class=\"label\">Capabilities</div><div class=\"value\">0</div></div>".to_string()
    } else {
        metadata
            .inventory
            .capability_counts
            .iter()
            .map(|(capability, count)| {
                format!(
                    "<div class=\"card\"><div class=\"label\">{}</div><div class=\"value\">{}</div></div>",
                    escape_html(&prettify_label(capability)),
                    count
                )
            })
            .collect::<String>()
    };

    format!(
        "<section>
  <h2>MCP Inventory</h2>
  <p class=\"section-copy\">Descriptor metadata, capability counts, tool approval posture, and parser warnings for MCP scans.</p>
  <div class=\"grid\">
    <div class=\"card\"><div class=\"label\">Server</div><div class=\"value\">{}</div></div>
    <div class=\"card\"><div class=\"label\">Transport</div><div class=\"value\">{}</div></div>
    <div class=\"card\"><div class=\"label\">Endpoint</div><div class=\"value\">{}</div></div>
    <div class=\"card\"><div class=\"label\">Tools</div><div class=\"value\">{}</div></div>
    <div class=\"card\"><div class=\"label\">Approval Required</div><div class=\"value\">{}</div></div>
    <div class=\"card\"><div class=\"label\">Warnings</div><div class=\"value\">{}</div></div>
  </div>
  <section>
    <h3>Capability Distribution</h3>
    <div class=\"grid\">{}</div>
  </section>
  <section>
    <h3>Tool Inventory</h3>
    <div class=\"grid\">{}</div>
  </section>
  <section>
    <h3>Parse Warnings</h3>
    <div class=\"panel\">{}</div>
  </section>
</section>",
        escape_html(metadata.server_name.as_deref().unwrap_or("unknown")),
        escape_html(metadata.transport.as_deref().unwrap_or("unknown")),
        escape_html(metadata.endpoint.as_deref().unwrap_or("n/a")),
        metadata.inventory.tool_count,
        metadata.inventory.approval_required_count,
        metadata.inventory.parse_warning_count,
        capability_cards,
        tools,
        warnings,
    )
}

fn render_chips(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("<span class=\"chip\">{}</span>", escape_html(value)))
        .collect::<String>()
}

fn render_list_items(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("<li>{}</li>", escape_html(value)))
        .collect::<String>()
}

fn dedupe_preserve_order(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeMap::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone(), ()).is_none())
        .collect()
}

fn status_label(finding: &FindingOutcome) -> &'static str {
    match finding.status {
        FindingStatus::Vulnerable => "vulnerable",
        FindingStatus::Resistant => "resistant",
        FindingStatus::Error => "error",
    }
}

fn severity_rank(severity: Severity) -> usize {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn status_rank(status: FindingStatus) -> usize {
    match status {
        FindingStatus::Vulnerable => 0,
        FindingStatus::Error => 1,
        FindingStatus::Resistant => 2,
    }
}

fn focus_heading(category: &str) -> String {
    match category {
        "mcp-security" => "MCP Security Findings".to_string(),
        "tool-misuse" => "Tool Misuse Findings".to_string(),
        "approval-bypass" => "Approval Bypass Findings".to_string(),
        other => prettify_label(other),
    }
}

fn prettify_label(value: &str) -> String {
    value
        .split(['-', '_'])
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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

#[derive(Default)]
struct CategoryCounts {
    total: usize,
    vulnerable: usize,
    resistant: usize,
    error: usize,
}

fn summarize_categories(findings: &[FindingOutcome]) -> BTreeMap<String, CategoryCounts> {
    let mut categories = BTreeMap::new();
    for finding in findings {
        let entry = categories
            .entry(finding.category.clone())
            .or_insert_with(CategoryCounts::default);
        entry.total += 1;
        match finding.status {
            FindingStatus::Vulnerable => entry.vulnerable += 1,
            FindingStatus::Resistant => entry.resistant += 1,
            FindingStatus::Error => entry.error += 1,
        }
    }
    categories
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::{
        cli::TargetType,
        mcp::model::{
            CapabilityConfidence, CapabilitySource, McpCapability, McpCapabilityAssessment,
            McpDescriptorFormat, McpInventorySummary, McpScanMetadata, McpTool,
        },
        output::html::write_scan_html,
        scan::{FindingEvidence, FindingOutcome, FindingOutcomeInput, FindingStatus, ScanOutcome},
        scorer::{Grade, ScoreSummary, SeverityCounts},
        vectors::model::Severity,
    };

    #[test]
    fn writes_html_report_with_summary_and_table() {
        let temp = tempdir().expect("tempdir should be created");
        let output = temp.path().join("reports/scan.html");

        let outcome = ScanOutcome {
            target_type: TargetType::Http,
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
            findings: vec![FindingOutcome::new(FindingOutcomeInput {
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
            })],
            duration_ms: 12,
        };

        write_scan_html(&output, &outcome).expect("html report should be written");

        let html = fs::read_to_string(&output).expect("html report should exist");
        assert!(html.contains("AgentPrey Scan Report"));
        assert!(html.contains("Basic Instruction Override"));
        assert!(html.contains("Priority Findings"));
        assert!(html.contains("Detailed Findings"));
        assert!(html.contains("Bearer [REDACTED]"));
        assert!(html.contains("Category Overview"));
        assert!(html.contains("<table>"));
    }

    #[test]
    fn writes_html_report_with_mcp_and_openclaw_focus_sections() {
        let temp = tempdir().expect("tempdir should be created");
        let output = temp.path().join("reports/scan.html");

        let outcome = ScanOutcome {
            target_type: TargetType::Openclaw,
            target: "./fixtures/openclaw-risky".to_string(),
            mcp: Some(McpScanMetadata {
                source_kind: "local-file".to_string(),
                descriptor_format: McpDescriptorFormat::Json,
                server_name: Some("danger-demo".to_string()),
                transport: Some("http".to_string()),
                endpoint: Some("https://sandbox.example/mcp".to_string()),
                inventory: McpInventorySummary {
                    tool_count: 1,
                    resource_count: 0,
                    prompt_count: 0,
                    approval_required_count: 0,
                    parse_warning_count: 0,
                    capability_counts: [("command-exec".to_string(), 1)].into_iter().collect(),
                },
                parse_warnings: Vec::new(),
                tools: vec![McpTool {
                    key: "run_shell".to_string(),
                    name: "run_shell".to_string(),
                    description: Some("Execute shell commands".to_string()),
                    input_schema: None,
                    approval_required: None,
                    capabilities: vec![McpCapabilityAssessment {
                        capability: McpCapability::CommandExec,
                        source: CapabilitySource::Declared,
                        confidence: CapabilityConfidence::High,
                    }],
                    uncertainty_flags: Vec::new(),
                }],
            }),
            total_vectors: 3,
            vulnerable_count: 3,
            resistant_count: 0,
            error_count: 0,
            score: ScoreSummary {
                score: 72,
                grade: Grade::C,
                vulnerable_severities: SeverityCounts {
                    critical: 0,
                    high: 3,
                    medium: 0,
                    low: 0,
                    info: 0,
                },
                error_count: 0,
            },
            findings: vec![
                FindingOutcome::new(FindingOutcomeInput {
                    rule_id: "mcp-tool-001".to_string(),
                    vector_id: "mcp-tool-001".to_string(),
                    vector_name: "Dangerous Capability Exposure".to_string(),
                    category: "mcp-security".to_string(),
                    subcategory: "tools".to_string(),
                    severity: Severity::High,
                    payload_name: "descriptor".to_string(),
                    payload_prompt: "descriptor".to_string(),
                    status: FindingStatus::Vulnerable,
                    status_code: None,
                    response: "Dangerous MCP tool capabilities detected: run_shell: command-exec."
                        .to_string(),
                    analysis: None,
                    duration_ms: 11,
                    rationale: "Dangerous tools expand blast radius.".to_string(),
                    evidence_summary: "run_shell exposes command-exec".to_string(),
                    recommendation: "Require approval gating.".to_string(),
                })
                .with_evidence(FindingEvidence {
                    attack_surface: Some("mcp".to_string()),
                    observed_capabilities: vec!["command-exec".to_string()],
                    evidence_kind: Some("mcp-descriptor".to_string()),
                    repro_steps: vec!["Run the MCP scan".to_string()],
                    mitigation_tags: vec!["approval-gating".to_string()],
                    source_spans: Vec::new(),
                })
                .with_legacy_mcp_fields(
                    Some("run_shell".to_string()),
                    vec!["command-exec".to_string()],
                    Some(false),
                ),
                FindingOutcome::new(FindingOutcomeInput {
                    rule_id: "tm-openclaw-001".to_string(),
                    vector_id: "tm-openclaw-001".to_string(),
                    vector_name: "Unsafe Tool Chaining".to_string(),
                    category: "tool-misuse".to_string(),
                    subcategory: "openclaw".to_string(),
                    severity: Severity::High,
                    payload_name: "policy".to_string(),
                    payload_prompt: "policy".to_string(),
                    status: FindingStatus::Vulnerable,
                    status_code: None,
                    response: "shell.exec and slack_webhook are chained together".to_string(),
                    analysis: None,
                    duration_ms: 9,
                    rationale: "Tool chains can execute and exfiltrate in one hop.".to_string(),
                    evidence_summary: "shell.exec pairs with slack_webhook".to_string(),
                    recommendation: "Split dangerous capabilities.".to_string(),
                }),
                FindingOutcome::new(FindingOutcomeInput {
                    rule_id: "ab-openclaw-001".to_string(),
                    vector_id: "ab-openclaw-001".to_string(),
                    vector_name: "Approval Never Policy".to_string(),
                    category: "approval-bypass".to_string(),
                    subcategory: "openclaw".to_string(),
                    severity: Severity::High,
                    payload_name: "policy".to_string(),
                    payload_prompt: "policy".to_string(),
                    status: FindingStatus::Vulnerable,
                    status_code: None,
                    response: "approval_policy = never".to_string(),
                    analysis: None,
                    duration_ms: 8,
                    rationale: "No approval means no human checkpoint.".to_string(),
                    evidence_summary: "approval_policy is set to never".to_string(),
                    recommendation: "Require explicit approval for dangerous actions.".to_string(),
                }),
            ],
            duration_ms: 33,
        };

        write_scan_html(&output, &outcome).expect("html report should be written");

        let html = fs::read_to_string(&output).expect("html report should exist");
        assert!(html.contains("MCP Security Findings"));
        assert!(html.contains("Tool Misuse Findings"));
        assert!(html.contains("Approval Bypass Findings"));
        assert!(html.contains("MCP Inventory"));
        assert!(html.contains("Capability Distribution"));
        assert!(html.contains("approval-gating"));
        assert!(html.contains("approval_policy is set to never"));
    }
}

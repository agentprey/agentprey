use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::compare::{
    ArtifactComparison, ArtifactFindingStatus, ArtifactGrade, CategoryDelta, ChangedFinding,
    ComparedFinding,
};

const FOCUS_CATEGORIES: [&str; 4] = [
    "prompt-injection",
    "mcp-security",
    "tool-misuse",
    "approval-bypass",
];

pub fn write_compare_html(path: &Path, comparison: &ArtifactComparison) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create compare HTML output directory '{}'",
                    parent.display()
                )
            })?;
        }
    }

    let html = render_compare_html(comparison);
    fs::write(path, html).with_context(|| {
        format!(
            "failed to write compare HTML output file '{}'",
            path.display()
        )
    })?;

    Ok(())
}

pub fn render_compare_html(comparison: &ArtifactComparison) -> String {
    let hero = render_summary_hero(comparison);
    let release_gating = render_release_gating_summary(comparison);
    let category_overview = render_category_delta_overview(comparison);
    let added_findings = render_findings_section(
        "Added Findings",
        "New findings present only in the candidate artifact.",
        &comparison.added_findings,
        "No added findings.",
    );
    let removed_findings = render_findings_section(
        "Removed Findings",
        "Findings present in the baseline artifact that no longer appear in the candidate.",
        &comparison.removed_findings,
        "No removed findings.",
    );
    let changed_findings = render_changed_findings_section(&comparison.changed_findings);

    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>AgentPrey Compare Report</title>
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
    .finding-card.changed {{ border-left-color: var(--accent); }}
    .label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em; }}
    .value {{ font-size: 24px; font-weight: 700; }}
    .section-copy {{ color: var(--muted); margin-bottom: 14px; line-height: 1.6; }}
    .eyebrow {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }}
    .chip {{ display: inline-flex; align-items: center; gap: 6px; background: var(--chip); color: var(--ink); border: 1px solid var(--border); border-radius: 999px; padding: 4px 9px; font-size: 12px; }}
    .chip.state-safer, .chip.status-resistant {{ color: #bbf7d0; border-color: rgba(22, 163, 74, 0.45); background: rgba(20, 83, 45, 0.35); }}
    .chip.state-riskier, .chip.status-vulnerable {{ color: #fecaca; border-color: rgba(220, 38, 38, 0.45); background: rgba(127, 29, 29, 0.35); }}
    .chip.state-unchanged, .chip.status-error {{ color: #fde68a; border-color: rgba(217, 119, 6, 0.45); background: rgba(120, 53, 15, 0.35); }}
    .chip.grade-good {{ color: #bbf7d0; }}
    .chip.grade-warn {{ color: #fde68a; }}
    .chip.grade-bad {{ color: #fecaca; }}
    .muted {{ color: var(--muted); }}
    .hero {{ padding: 20px; }}
    .hero-head {{ display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin-bottom: 16px; }}
    .hero-score {{ min-width: 120px; text-align: right; }}
    .hero-score .value {{ font-size: 36px; }}
    .finding-title {{ display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 10px; }}
    .finding-body {{ display: grid; gap: 10px; }}
    .finding-meta {{ display: grid; gap: 8px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .compare-columns {{ display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }}
    .detail {{ background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px; padding: 10px; }}
    .detail strong {{ display: block; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 6px; }}
    .list {{ margin: 0; padding-left: 18px; color: var(--ink); line-height: 1.6; }}
    .empty {{ color: var(--muted); font-style: italic; }}
    code {{ color: #dbeafe; font-size: 12px; word-break: break-word; }}
    @media (max-width: 760px) {{
      .hero-head {{ flex-direction: column; }}
      .hero-score {{ min-width: auto; text-align: left; }}
    }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>AgentPrey Compare Report</h1>
    <div class=\"meta\">Baseline <code>{}</code> vs candidate <code>{}</code>. Target types: <code>{}</code> -> <code>{}</code>.</div>
    {}
    {}
    {}
    {}
    {}
    {}
  </div>
</body>
</html>",
        escape_html(&comparison.baseline.path.display().to_string()),
        escape_html(&comparison.candidate.path.display().to_string()),
        escape_html(&comparison.baseline.target_type.to_string()),
        escape_html(&comparison.candidate.target_type.to_string()),
        hero,
        release_gating,
        category_overview,
        added_findings,
        removed_findings,
        changed_findings,
    )
}

fn render_summary_hero(comparison: &ArtifactComparison) -> String {
    let state = compare_state(comparison);
    let score_delta = format_signed(comparison.overall_delta.score_delta);
    let blocker_delta = format_signed(blocker_delta(comparison));

    format!(
        "<section class=\"panel hero\">\
<div class=\"eyebrow\">\
<span class=\"chip state-{}\">{}</span>\
<span class=\"chip {}\">Baseline grade {}</span>\
<span class=\"chip {}\">Candidate grade {}</span>\
</div>\
<div class=\"hero-head\">\
<div>\
<h2>{}</h2>\
<p class=\"section-copy\">{}</p>\
</div>\
<div class=\"hero-score\">\
<div class=\"label\">Score Delta</div>\
<div class=\"value\">{}</div>\
<div class=\"muted\">blockers {}</div>\
</div>\
</div>\
<div class=\"grid\">\
<div class=\"card\"><div class=\"label\">Baseline</div><div class=\"value\">{} ({})</div><div class=\"muted\">{} findings · {} blockers</div></div>\
<div class=\"card\"><div class=\"label\">Candidate</div><div class=\"value\">{} ({})</div><div class=\"muted\">{} findings · {} blockers</div></div>\
<div class=\"card\"><div class=\"label\">Finding Changes</div><div class=\"value\">{}</div><div class=\"muted\">added {} · removed {} · changed {}</div></div>\
</div>\
</section>",
        state.class_name,
        state.label,
        grade_class(comparison.baseline.score.grade),
        grade_label(comparison.baseline.score.grade),
        grade_class(comparison.candidate.score.grade),
        grade_label(comparison.candidate.score.grade),
        state.heading,
        state.copy,
        escape_html(&score_delta),
        escape_html(&blocker_delta),
        comparison.baseline.score.score,
        escape_html(grade_label(comparison.baseline.score.grade)),
        comparison.baseline.counts.findings,
        blocker_count(&comparison.baseline),
        comparison.candidate.score.score,
        escape_html(grade_label(comparison.candidate.score.grade)),
        comparison.candidate.counts.findings,
        blocker_count(&comparison.candidate),
        comparison.added_findings.len() + comparison.removed_findings.len() + comparison.changed_findings.len(),
        comparison.added_findings.len(),
        comparison.removed_findings.len(),
        comparison.changed_findings.len(),
    )
}

fn render_release_gating_summary(comparison: &ArtifactComparison) -> String {
    let new_blockers = collect_new_blockers(comparison);
    let resolved_blockers = collect_resolved_blockers(comparison);

    format!(
        "<section>\
<h2>Release Gating</h2>\
<p class=\"section-copy\">{}</p>\
<div class=\"grid\">\
<div class=\"card\"><div class=\"label\">New Blocker Findings</div><div class=\"value\">{}</div>{}</div>\
<div class=\"card\"><div class=\"label\">Resolved Blocker Findings</div><div class=\"value\">{}</div>{}</div>\
</div>\
</section>",
        escape_html(&blocker_summary_sentence(comparison)),
        new_blockers.len(),
        render_blocker_list(&new_blockers),
        resolved_blockers.len(),
        render_blocker_list(&resolved_blockers),
    )
}

fn render_category_delta_overview(comparison: &ArtifactComparison) -> String {
    let categories = comparison
        .category_deltas
        .iter()
        .filter(|delta| FOCUS_CATEGORIES.contains(&delta.category.as_str()))
        .collect::<Vec<_>>();

    if categories.is_empty() {
        return String::new();
    }

    let cards = categories
        .into_iter()
        .map(render_category_delta_card)
        .collect::<String>();

    format!(
        "<section>\
<h2>Category Delta Overview</h2>\
<p class=\"section-copy\">Focused compare coverage for prompt injection, MCP security, tool misuse, and approval bypass when those categories are present in either artifact.</p>\
<div class=\"grid\">{}</div>\
</section>",
        cards
    )
}

fn render_findings_section(
    title: &str,
    copy: &str,
    findings: &[ComparedFinding],
    empty_message: &str,
) -> String {
    let body = if findings.is_empty() {
        format!(
            "<div class=\"panel empty\">{}</div>",
            escape_html(empty_message)
        )
    } else {
        format!(
            "<div class=\"grid\">{}</div>",
            findings.iter().map(render_finding_card).collect::<String>()
        )
    };

    format!(
        "<section>\
<h2>{}</h2>\
<p class=\"section-copy\">{}</p>\
{}\
</section>",
        escape_html(title),
        escape_html(copy),
        body,
    )
}

fn render_changed_findings_section(changed_findings: &[ChangedFinding]) -> String {
    let body = if changed_findings.is_empty() {
        "<div class=\"panel empty\">No changed findings.</div>".to_string()
    } else {
        format!(
            "<div class=\"grid\">{}</div>",
            changed_findings
                .iter()
                .map(render_changed_finding_card)
                .collect::<String>()
        )
    };

    format!(
        "<section>\
<h2>Changed Findings</h2>\
<p class=\"section-copy\">Findings that still match the same identity but changed status, severity, rationale, evidence, or recommendation between baseline and candidate.</p>\
{}\
</section>",
        body
    )
}

fn render_category_delta_card(delta: &CategoryDelta) -> String {
    format!(
        "<div class=\"card\">\
<div class=\"label\">{}</div>\
<div class=\"value\">{}</div>\
<div class=\"muted\">baseline {} -> candidate {}</div>\
<div class=\"finding-meta\">\
<div class=\"detail\"><strong>Vulnerable</strong>{:+}</div>\
<div class=\"detail\"><strong>Resistant</strong>{:+}</div>\
<div class=\"detail\"><strong>Errors</strong>{:+}</div>\
</div>\
</div>",
        escape_html(&prettify_label(&delta.category)),
        escape_html(&format_signed(delta.delta.total)),
        delta.baseline.total,
        delta.candidate.total,
        delta.delta.vulnerable,
        delta.delta.resistant,
        delta.delta.errors,
    )
}

fn render_finding_card(finding: &ComparedFinding) -> String {
    format!(
        "<div class=\"finding-card {}\">\
<div class=\"finding-title\">\
<div>\
<h3>{}</h3>\
<div class=\"muted\">{} / {} / {}</div>\
</div>\
<div class=\"eyebrow\">\
<span class=\"chip status-{}\">{}</span>\
<span class=\"chip\">Severity {}</span>\
</div>\
</div>\
<div class=\"finding-body\">\
<div class=\"finding-meta\">\
<div class=\"detail\"><strong>Rule</strong><code>{}</code></div>\
<div class=\"detail\"><strong>Vector</strong><code>{}</code></div>\
<div class=\"detail\"><strong>Payload</strong><code>{}</code></div>\
</div>\
<div class=\"detail\"><strong>Rationale</strong>{}</div>\
<div class=\"detail\"><strong>Evidence Summary</strong>{}</div>\
<div class=\"detail\"><strong>Recommendation</strong>{}</div>\
</div>\
</div>",
        status_class(finding.status),
        escape_html(&finding.identity.rule_id),
        escape_html(&prettify_label(&finding.identity.category)),
        escape_html(&prettify_label(&finding.identity.subcategory)),
        escape_html(&finding.identity.payload_name),
        status_class(finding.status),
        escape_html(status_label(finding.status)),
        escape_html(finding.severity.as_str()),
        escape_html(&finding.identity.rule_id),
        escape_html(&finding.identity.vector_id),
        escape_html(&finding.identity.payload_name),
        escape_html(&finding.rationale),
        escape_html(&finding.evidence_summary),
        escape_html(&finding.recommendation),
    )
}

fn render_changed_finding_card(changed: &ChangedFinding) -> String {
    format!(
        "<div class=\"finding-card changed\">\
<div class=\"finding-title\">\
<div>\
<h3>{}</h3>\
<div class=\"muted\">{} / {} / {}</div>\
</div>\
<span class=\"chip\">Changed</span>\
</div>\
<div class=\"compare-columns\">\
{}\
{}\
</div>\
</div>",
        escape_html(&changed.identity.rule_id),
        escape_html(&prettify_label(&changed.identity.category)),
        escape_html(&prettify_label(&changed.identity.subcategory)),
        escape_html(&changed.identity.payload_name),
        render_changed_side("Baseline", &changed.baseline),
        render_changed_side("Candidate", &changed.candidate),
    )
}

fn render_changed_side(label: &str, finding: &ComparedFinding) -> String {
    format!(
        "<div class=\"detail\">\
<strong>{}</strong>\
<div class=\"eyebrow\">\
<span class=\"chip status-{}\">{}</span>\
<span class=\"chip\">Severity {}</span>\
</div>\
<p><span class=\"muted\">Rationale:</span> {}</p>\
<p><span class=\"muted\">Evidence:</span> {}</p>\
<p><span class=\"muted\">Recommendation:</span> {}</p>\
</div>",
        escape_html(label),
        status_class(finding.status),
        escape_html(status_label(finding.status)),
        escape_html(finding.severity.as_str()),
        escape_html(&finding.rationale),
        escape_html(&finding.evidence_summary),
        escape_html(&finding.recommendation),
    )
}

fn render_blocker_list(findings: &[ComparedFinding]) -> String {
    if findings.is_empty() {
        return "<div class=\"empty\">None.</div>".to_string();
    }

    let items = findings
        .iter()
        .map(|finding| {
            format!(
                "<li><code>{}</code> · {} · {}</li>",
                escape_html(&finding.identity.rule_id),
                escape_html(&prettify_label(&finding.identity.category)),
                escape_html(status_label(finding.status)),
            )
        })
        .collect::<String>();

    format!("<ul class=\"list\">{items}</ul>")
}

fn collect_new_blockers(comparison: &ArtifactComparison) -> Vec<ComparedFinding> {
    let mut blockers = comparison
        .added_findings
        .iter()
        .filter(|finding| is_blocker(finding.status))
        .cloned()
        .collect::<Vec<_>>();

    blockers.extend(
        comparison
            .changed_findings
            .iter()
            .filter(|finding| {
                !is_blocker(finding.baseline.status) && is_blocker(finding.candidate.status)
            })
            .map(|finding| finding.candidate.clone()),
    );

    blockers
}

fn collect_resolved_blockers(comparison: &ArtifactComparison) -> Vec<ComparedFinding> {
    let mut blockers = comparison
        .removed_findings
        .iter()
        .filter(|finding| is_blocker(finding.status))
        .cloned()
        .collect::<Vec<_>>();

    blockers.extend(
        comparison
            .changed_findings
            .iter()
            .filter(|finding| {
                is_blocker(finding.baseline.status) && !is_blocker(finding.candidate.status)
            })
            .map(|finding| finding.baseline.clone()),
    );

    blockers
}

fn compare_state(comparison: &ArtifactComparison) -> CompareState {
    let blocker_delta = blocker_delta(comparison);
    if blocker_delta < 0 || (blocker_delta == 0 && comparison.overall_delta.score_delta > 0) {
        CompareState {
            class_name: "safer",
            label: "Safer",
            heading: "Candidate trends safer than baseline",
            copy: "The candidate reduces release risk by lowering blockers or improving score without adding blocker pressure.",
        }
    } else if blocker_delta > 0 || (blocker_delta == 0 && comparison.overall_delta.score_delta < 0)
    {
        CompareState {
            class_name: "riskier",
            label: "Riskier",
            heading: "Candidate trends riskier than baseline",
            copy: "The candidate introduces more release pressure by increasing blocker load or degrading the overall score.",
        }
    } else {
        CompareState {
            class_name: "unchanged",
            label: "Unchanged",
            heading: "Candidate stays flat versus baseline",
            copy: "The candidate keeps overall release pressure effectively unchanged, with no blocker or score movement worth escalating in the hero summary.",
        }
    }
}

fn blocker_summary_sentence(comparison: &ArtifactComparison) -> String {
    let baseline_blockers = blocker_count(&comparison.baseline);
    let candidate_blockers = blocker_count(&comparison.candidate);
    let blocker_delta = candidate_blockers as i64 - baseline_blockers as i64;

    match blocker_delta.cmp(&0) {
        std::cmp::Ordering::Less => format!(
            "Candidate reduces blockers from {baseline_blockers} to {candidate_blockers} ({blocker_delta:+}), with vulnerable findings {:+} and errors {:+} versus baseline.",
            comparison.overall_delta.vulnerable_delta,
            comparison.overall_delta.error_delta,
        ),
        std::cmp::Ordering::Equal => format!(
            "Candidate keeps blockers flat at {candidate_blockers}, with vulnerable findings {:+} and errors {:+} versus baseline.",
            comparison.overall_delta.vulnerable_delta,
            comparison.overall_delta.error_delta,
        ),
        std::cmp::Ordering::Greater => format!(
            "Candidate increases blockers from {baseline_blockers} to {candidate_blockers} ({blocker_delta:+}), with vulnerable findings {:+} and errors {:+} versus baseline.",
            comparison.overall_delta.vulnerable_delta,
            comparison.overall_delta.error_delta,
        ),
    }
}

fn blocker_count(metadata: &crate::compare::ArtifactMetadata) -> usize {
    metadata.counts.vulnerable + metadata.counts.errors
}

fn blocker_delta(comparison: &ArtifactComparison) -> i64 {
    blocker_count(&comparison.candidate) as i64 - blocker_count(&comparison.baseline) as i64
}

fn is_blocker(status: ArtifactFindingStatus) -> bool {
    matches!(
        status,
        ArtifactFindingStatus::Vulnerable | ArtifactFindingStatus::Error
    )
}

fn status_class(status: ArtifactFindingStatus) -> &'static str {
    match status {
        ArtifactFindingStatus::Vulnerable => "vulnerable",
        ArtifactFindingStatus::Resistant => "resistant",
        ArtifactFindingStatus::Error => "error",
    }
}

fn status_label(status: ArtifactFindingStatus) -> &'static str {
    match status {
        ArtifactFindingStatus::Vulnerable => "Vulnerable",
        ArtifactFindingStatus::Resistant => "Resistant",
        ArtifactFindingStatus::Error => "Error",
    }
}

fn grade_label(grade: ArtifactGrade) -> &'static str {
    match grade {
        ArtifactGrade::A => "A",
        ArtifactGrade::B => "B",
        ArtifactGrade::C => "C",
        ArtifactGrade::D => "D",
        ArtifactGrade::F => "F",
    }
}

fn grade_class(grade: ArtifactGrade) -> &'static str {
    match grade {
        ArtifactGrade::A | ArtifactGrade::B => "grade-good",
        ArtifactGrade::C => "grade-warn",
        ArtifactGrade::D | ArtifactGrade::F => "grade-bad",
    }
}

fn format_signed(delta: i64) -> String {
    format!("{delta:+}")
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

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

struct CompareState {
    class_name: &'static str,
    label: &'static str,
    heading: &'static str,
    copy: &'static str,
}

use std::{fs, path::Path};

use agentprey_core::{RuntimeEvent, RuntimeExitReason, RuntimeOutcome};
use anyhow::{Context, Result};

pub fn write_runtime_html(path: &Path, outcome: &RuntimeOutcome) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create runtime HTML output directory '{}'",
                    parent.display()
                )
            })?;
        }
    }

    let html = render_runtime_html(outcome);
    fs::write(path, html).with_context(|| {
        format!(
            "failed to write runtime HTML output file '{}'",
            path.display()
        )
    })?;

    Ok(())
}

pub fn render_runtime_html(outcome: &RuntimeOutcome) -> String {
    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>AgentPrey Runtime Report</title>
  <style>
    :root {{
      --bg: #0a0f1c;
      --panel: #10182a;
      --panel-2: #0c1422;
      --ink: #e2e8f0;
      --muted: #94a3b8;
      --border: #1e293b;
      --accent: #22c55e;
      --warn: #f59e0b;
      --bad: #ef4444;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: linear-gradient(180deg, #020617 0%, #0a0f1c 100%); color: var(--ink); font-family: ui-sans-serif, system-ui, sans-serif; }}
    .wrap {{ max-width: 1080px; margin: 0 auto; padding: 28px 20px 40px; }}
    section {{ margin-top: 20px; }}
    .panel {{ background: rgba(16, 24, 42, 0.94); border: 1px solid var(--border); border-radius: 14px; padding: 16px; }}
    .grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .card {{ background: var(--panel-2); border: 1px solid var(--border); border-radius: 12px; padding: 12px; }}
    .eyebrow {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 5px 10px; font-size: 12px; margin-bottom: 12px; }}
    .eyebrow.ok {{ background: rgba(34, 197, 94, 0.12); color: #bbf7d0; border: 1px solid rgba(34, 197, 94, 0.3); }}
    .eyebrow.warn {{ background: rgba(245, 158, 11, 0.12); color: #fde68a; border: 1px solid rgba(245, 158, 11, 0.3); }}
    .eyebrow.bad {{ background: rgba(239, 68, 68, 0.12); color: #fecaca; border: 1px solid rgba(239, 68, 68, 0.3); }}
    h1, h2, h3, p, pre, ul {{ margin: 0; }}
    h1 {{ font-size: 30px; margin-bottom: 10px; }}
    h2 {{ font-size: 20px; margin-bottom: 10px; }}
    .meta {{ color: var(--muted); line-height: 1.6; }}
    .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 5px; }}
    .value {{ font-size: 24px; font-weight: 700; }}
    pre {{ background: #020617; border: 1px solid var(--border); border-radius: 12px; padding: 12px; white-space: pre-wrap; word-break: break-word; line-height: 1.6; }}
    code {{ color: #dbeafe; word-break: break-word; }}
    ul {{ padding-left: 18px; line-height: 1.7; }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>AgentPrey Runtime Report</h1>
    <p class=\"meta\">Command <code>{}</code> executed under policy <code>{}</code>.</p>
    <section class=\"panel\">
      <div class=\"eyebrow {}\">{}</div>
      <div class=\"grid\">
        <div class=\"card\"><div class=\"label\">Exit Reason</div><div class=\"value\">{}</div></div>
        <div class=\"card\"><div class=\"label\">Exit Code</div><div class=\"value\">{}</div></div>
        <div class=\"card\"><div class=\"label\">Duration</div><div class=\"value\">{} ms</div></div>
        <div class=\"card\"><div class=\"label\">Sandbox CWD</div><div><code>{}</code></div></div>
      </div>
      {}
    </section>
    <section class=\"panel\">
      <h2>Event Timeline</h2>
      <ul>{}</ul>
    </section>
    <section class=\"panel\">
      <h2>Stdout</h2>
      <pre>{}</pre>
    </section>
    <section class=\"panel\">
      <h2>Stderr</h2>
      <pre>{}</pre>
    </section>
  </div>
</body>
</html>",
        escape_html(&outcome.invocation),
        escape_html(&outcome.policy_name),
        status_class(outcome.exit_reason, outcome.exit_code),
        status_label(outcome.exit_reason, outcome.exit_code),
        escape_html(&format_exit_reason(outcome.exit_reason)),
        outcome
            .exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        outcome.duration_ms,
        escape_html(&outcome.sandbox_cwd.display().to_string()),
        render_source_cwd(outcome),
        render_events(&outcome.events),
        escape_html(&outcome.stdout),
        escape_html(&outcome.stderr),
    )
}

fn render_source_cwd(outcome: &RuntimeOutcome) -> String {
    match outcome.source_cwd.as_ref() {
        Some(path) => format!(
            "<p class=\"meta\" style=\"margin-top: 12px;\">Source CWD <code>{}</code> was copied into the sandbox.</p>",
            escape_html(&path.display().to_string())
        ),
        None => String::new(),
    }
}

fn render_events(events: &[RuntimeEvent]) -> String {
    if events.is_empty() {
        return "<li>No runtime events were captured.</li>".to_string();
    }

    events.iter().map(render_event).collect::<Vec<_>>().join("")
}

fn render_event(event: &RuntimeEvent) -> String {
    match event {
        RuntimeEvent::SpawnedProcess { command, pid } => format!(
            "<li>spawned process <code>{}</code> with pid {}</li>",
            escape_html(command),
            pid
        ),
        RuntimeEvent::Timeout { duration_ms } => {
            format!("<li>timeout after {} ms</li>", duration_ms)
        }
        RuntimeEvent::Exit { success, code } => format!(
            "<li>process exited: success={} code={}</li>",
            success,
            code.map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
    }
}

fn format_exit_reason(reason: RuntimeExitReason) -> &'static str {
    match reason {
        RuntimeExitReason::Completed => "completed",
        RuntimeExitReason::Timeout => "timeout",
        RuntimeExitReason::SpawnError => "spawn_error",
    }
}

fn status_class(reason: RuntimeExitReason, exit_code: Option<i32>) -> &'static str {
    match reason {
        RuntimeExitReason::Completed if exit_code == Some(0) => "ok",
        RuntimeExitReason::Completed => "warn",
        RuntimeExitReason::Timeout | RuntimeExitReason::SpawnError => "bad",
    }
}

fn status_label(reason: RuntimeExitReason, exit_code: Option<i32>) -> &'static str {
    match reason {
        RuntimeExitReason::Completed if exit_code == Some(0) => "completed cleanly",
        RuntimeExitReason::Completed => "completed with non-zero exit",
        RuntimeExitReason::Timeout => "timed out",
        RuntimeExitReason::SpawnError => "spawn error",
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use agentprey_core::{RuntimeEvent, RuntimeExitReason, RuntimeOutcome};
    use tempfile::tempdir;

    use crate::runtime_html::{render_runtime_html, write_runtime_html};

    fn sample_runtime_outcome() -> RuntimeOutcome {
        RuntimeOutcome {
            source_cwd: Some(PathBuf::from("/tmp/source")),
            sandbox_cwd: PathBuf::from("/tmp/sandbox"),
            duration_ms: 87,
            exit_reason: RuntimeExitReason::Completed,
            exit_code: Some(0),
            timed_out: false,
            stdout: "hello".to_string(),
            stderr: String::new(),
            policy_name: "read-only-workspace".to_string(),
            invocation: "bash -lc cat Cargo.toml".to_string(),
            events: vec![
                RuntimeEvent::SpawnedProcess {
                    command: "bash -lc cat Cargo.toml".to_string(),
                    pid: 11,
                },
                RuntimeEvent::Exit {
                    success: true,
                    code: Some(0),
                },
            ],
        }
    }

    #[test]
    fn runtime_html_contains_required_sections() {
        let html = render_runtime_html(&sample_runtime_outcome());

        assert!(html.contains("AgentPrey Runtime Report"));
        assert!(html.contains("Event Timeline"));
        assert!(html.contains("Stdout"));
        assert!(html.contains("Stderr"));
        assert!(html.contains("read-only-workspace"));
        assert!(html.contains("bash -lc cat Cargo.toml"));
    }

    #[test]
    fn writes_runtime_html_report() {
        let temp = tempdir().expect("tempdir should be created");
        let output_path = temp.path().join("reports/runtime.html");

        write_runtime_html(&output_path, &sample_runtime_outcome())
            .expect("runtime HTML should be written");

        let html = std::fs::read_to_string(&output_path).expect("runtime HTML should exist");
        assert!(html.contains("AgentPrey Runtime Report"));
        assert!(html.contains("/tmp/sandbox"));
    }
}

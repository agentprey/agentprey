use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use agentprey_core::{RuntimeEvent, RuntimeExitReason, RuntimeOutcome};
use anyhow::{Context, Result};
use serde::Serialize;

pub const RUNTIME_ARTIFACT_SCHEMA_VERSION: &str = "agentprey.runtime.v1";

#[derive(Debug, Serialize)]
struct RuntimeJsonArtifact<'a> {
    schema_version: &'static str,
    generated_at_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_cwd: Option<&'a Path>,
    sandbox_cwd: &'a Path,
    duration_ms: u128,
    exit_reason: RuntimeExitReason,
    exit_code: Option<i32>,
    timed_out: bool,
    policy_name: &'a str,
    invocation: &'a str,
    stdout: &'a str,
    stderr: &'a str,
    events: &'a [RuntimeEvent],
}

pub fn render_runtime_json(outcome: &RuntimeOutcome) -> Result<String> {
    let artifact = RuntimeJsonArtifact {
        schema_version: RUNTIME_ARTIFACT_SCHEMA_VERSION,
        generated_at_ms: now_ms(),
        source_cwd: outcome.source_cwd.as_deref(),
        sandbox_cwd: &outcome.sandbox_cwd,
        duration_ms: outcome.duration_ms,
        exit_reason: outcome.exit_reason,
        exit_code: outcome.exit_code,
        timed_out: outcome.timed_out,
        policy_name: &outcome.policy_name,
        invocation: &outcome.invocation,
        stdout: &outcome.stdout,
        stderr: &outcome.stderr,
        events: &outcome.events,
    };

    serde_json::to_string_pretty(&artifact).context("failed to serialize runtime results as JSON")
}

pub fn write_runtime_json(path: &Path, outcome: &RuntimeOutcome) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create runtime JSON output directory '{}'",
                    parent.display()
                )
            })?;
        }
    }

    let json = render_runtime_json(outcome)?;
    fs::write(path, json).with_context(|| {
        format!(
            "failed to write runtime JSON output file '{}'",
            path.display()
        )
    })?;

    Ok(())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use agentprey_core::{RuntimeEvent, RuntimeExitReason, RuntimeOutcome};
    use serde_json::Value;
    use tempfile::tempdir;

    use crate::runtime_json::{
        render_runtime_json, write_runtime_json, RUNTIME_ARTIFACT_SCHEMA_VERSION,
    };

    fn sample_runtime_outcome() -> RuntimeOutcome {
        RuntimeOutcome {
            source_cwd: Some(PathBuf::from("/tmp/source")),
            sandbox_cwd: PathBuf::from("/tmp/sandbox"),
            duration_ms: 42,
            exit_reason: RuntimeExitReason::Completed,
            exit_code: Some(0),
            timed_out: false,
            stdout: "hello\n".to_string(),
            stderr: String::new(),
            policy_name: "default".to_string(),
            invocation: "bash -lc echo hello".to_string(),
            events: vec![
                RuntimeEvent::SpawnedProcess {
                    command: "bash -lc echo hello".to_string(),
                    pid: 1234,
                },
                RuntimeEvent::Exit {
                    success: true,
                    code: Some(0),
                },
            ],
        }
    }

    #[test]
    fn render_runtime_json_preserves_schema_version_and_fields() {
        let rendered =
            render_runtime_json(&sample_runtime_outcome()).expect("runtime JSON should render");
        let parsed: Value = serde_json::from_str(&rendered).expect("runtime JSON should parse");

        assert_eq!(parsed["schema_version"], RUNTIME_ARTIFACT_SCHEMA_VERSION);
        assert!(parsed["generated_at_ms"].is_u64());
        assert_eq!(parsed["policy_name"], "default");
        assert_eq!(parsed["invocation"], "bash -lc echo hello");
        assert_eq!(parsed["exit_reason"], "completed");
        assert_eq!(parsed["sandbox_cwd"], "/tmp/sandbox");
        assert_eq!(parsed["source_cwd"], "/tmp/source");
        assert_eq!(parsed["events"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn writes_runtime_json_artifact_with_schema_version() {
        let temp = tempdir().expect("tempdir should be created");
        let output_path = temp.path().join("reports/runtime.json");

        write_runtime_json(&output_path, &sample_runtime_outcome())
            .expect("runtime JSON output should be written");

        let contents = std::fs::read_to_string(&output_path).expect("runtime JSON should exist");
        let parsed: Value = serde_json::from_str(&contents).expect("runtime JSON should parse");

        assert_eq!(parsed["schema_version"], RUNTIME_ARTIFACT_SCHEMA_VERSION);
        assert_eq!(parsed["stdout"], "hello\n");
    }
}

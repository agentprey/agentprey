use std::{path::PathBuf, process::Command};

use agentprey::{
    cli::{Cli, Commands, RunPolicy},
    output::runtime_json::RUNTIME_ARTIFACT_SCHEMA_VERSION,
};
use clap::Parser;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn run_command_parses_public_flags() {
    let cli = Cli::try_parse_from([
        "agentprey",
        "run",
        "--cwd",
        "./fixture",
        "--policy",
        "read-only-workspace",
        "--timeout-seconds",
        "7",
        "--json-out",
        "runtime.json",
        "--html-out",
        "runtime.html",
        "--",
        "bash",
        "-lc",
        "echo hi",
    ])
    .expect("run command should parse");

    match cli.command {
        Commands::Run(args) => {
            assert_eq!(args.cwd, Some(PathBuf::from("./fixture")));
            assert_eq!(args.policy, RunPolicy::ReadOnlyWorkspace);
            assert_eq!(args.timeout_seconds, Some(7));
            assert_eq!(args.json_out, Some(PathBuf::from("runtime.json")));
            assert_eq!(args.html_out, Some(PathBuf::from("runtime.html")));
            assert_eq!(args.command, vec!["bash", "-lc", "echo hi"]);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_command_defaults_to_default_policy() {
    let cli = Cli::try_parse_from(["agentprey", "run", "--", "bash", "-lc", "echo hi"])
        .expect("run command should parse");

    match cli.command {
        Commands::Run(args) => {
            assert_eq!(args.policy, RunPolicy::Default);
            assert_eq!(args.command, vec!["bash", "-lc", "echo hi"]);
        }
        other => panic!("expected run command, got {other:?}"),
    }
}

#[test]
fn run_command_requires_a_program_after_double_dash() {
    assert!(Cli::try_parse_from(["agentprey", "run"]).is_err());
}

#[test]
fn run_command_writes_runtime_json_schema() {
    let temp = tempdir().expect("tempdir should be created");
    let output_path = temp.path().join("reports/runtime.json");

    let output = Command::new(env!("CARGO_BIN_EXE_agentprey"))
        .arg("run")
        .arg("--json-out")
        .arg(&output_path)
        .arg("--")
        .arg("bash")
        .arg("-lc")
        .arg("echo hello")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run command should execute");

    assert!(
        output.status.success(),
        "run command should succeed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let contents = std::fs::read_to_string(&output_path).expect("runtime JSON should exist");
    let parsed: Value = serde_json::from_str(&contents).expect("runtime JSON should parse");

    assert_eq!(parsed["schema_version"], RUNTIME_ARTIFACT_SCHEMA_VERSION);
    assert_eq!(parsed["policy_name"], "default");
    assert_eq!(parsed["exit_reason"], "completed");
    assert_eq!(parsed["exit_code"], 0);
    assert_eq!(parsed["stdout"], "hello\n");
    assert_eq!(parsed["events"][0]["kind"], "spawned_process");
    assert_eq!(parsed["events"][1]["kind"], "exit");
}

#[test]
fn run_command_writes_runtime_html_report() {
    let temp = tempdir().expect("tempdir should be created");
    let output_path = temp.path().join("reports/runtime.html");

    let output = Command::new(env!("CARGO_BIN_EXE_agentprey"))
        .arg("run")
        .arg("--html-out")
        .arg(&output_path)
        .arg("--")
        .arg("bash")
        .arg("-lc")
        .arg("echo hello")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run command should execute");

    assert!(
        output.status.success(),
        "run command should succeed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let html = std::fs::read_to_string(&output_path).expect("runtime HTML should exist");
    assert!(html.contains("AgentPrey Runtime Report"));
    assert!(html.contains("Event Timeline"));
    assert!(html.contains("echo hello"));
}

#[test]
fn read_only_workspace_run_keeps_source_tree_unchanged() {
    let temp = tempdir().expect("tempdir should be created");
    let source_dir = temp.path().join("source");
    std::fs::create_dir_all(&source_dir).expect("source dir should be created");
    let source_file = source_dir.join("note.txt");
    std::fs::write(&source_file, "original").expect("source file should be written");
    let output_path = temp.path().join("reports/runtime.json");

    let output = Command::new(env!("CARGO_BIN_EXE_agentprey"))
        .arg("run")
        .arg("--policy")
        .arg("read-only-workspace")
        .arg("--cwd")
        .arg(&source_dir)
        .arg("--json-out")
        .arg(&output_path)
        .arg("--")
        .arg("bash")
        .arg("-lc")
        .arg("printf changed > note.txt")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run command should execute");

    assert!(
        !output.status.success(),
        "read-only workspace command should fail: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&source_file).expect("source file should remain readable"),
        "original"
    );

    let contents = std::fs::read_to_string(&output_path).expect("runtime JSON should exist");
    let parsed: Value = serde_json::from_str(&contents).expect("runtime JSON should parse");
    assert_eq!(parsed["policy_name"], "read-only-workspace");
    assert_eq!(parsed["exit_reason"], "completed");
    assert_ne!(parsed["exit_code"], 0);
    assert_eq!(parsed["source_cwd"], source_dir.display().to_string());
}

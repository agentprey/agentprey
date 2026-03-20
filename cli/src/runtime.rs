use std::{env, path::PathBuf, process::ExitCode, time::Duration};

use colored::Colorize;

use agentprey_sandbox::{run_command, SandboxPolicy, SandboxPolicyPreset};

use crate::{
    cli::{RunArgs, RunPolicy},
    output::{runtime_html::write_runtime_html, runtime_json::write_runtime_json},
};

const EXIT_CODE_RUNTIME_ERROR: u8 = 2;

pub async fn run_runtime_command(args: &RunArgs) -> ExitCode {
    let source_cwd = match resolve_source_cwd(args) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{} {error}", "error:".red().bold());
            return ExitCode::from(EXIT_CODE_RUNTIME_ERROR);
        }
    };
    let policy_preset = match args.policy {
        RunPolicy::Default => SandboxPolicyPreset::Default,
        RunPolicy::ReadOnlyWorkspace => SandboxPolicyPreset::ReadOnlyWorkspace,
    };
    let timeout_override = args.timeout_seconds.map(Duration::from_secs);
    let policy = SandboxPolicy::from_preset(policy_preset, timeout_override);
    let program = &args.command[0];
    let program_args = &args.command[1..];

    let outcome = match run_command(program, program_args, &policy, source_cwd.as_deref()).await {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!("{} {error}", "error:".red().bold());
            return ExitCode::from(EXIT_CODE_RUNTIME_ERROR);
        }
    };

    if let Some(path) = args.json_out.as_deref() {
        if let Err(error) = write_runtime_json(path, &outcome) {
            eprintln!("{} {error}", "error:".red().bold());
            return ExitCode::from(EXIT_CODE_RUNTIME_ERROR);
        }
    }

    if let Some(path) = args.html_out.as_deref() {
        if let Err(error) = write_runtime_html(path, &outcome) {
            eprintln!("{} {error}", "error:".red().bold());
            return ExitCode::from(EXIT_CODE_RUNTIME_ERROR);
        }
    }

    println!("Command: {}", outcome.invocation);
    println!("Policy: {}", outcome.policy_name);
    println!("Exit Reason: {:?}", outcome.exit_reason);
    if let Some(code) = outcome.exit_code {
        println!("Exit Code: {code}");
    }
    if outcome.timed_out {
        println!("Timed Out: yes");
    }
    println!("Sandbox CWD: {}", outcome.sandbox_cwd.display());
    if let Some(path) = outcome.source_cwd.as_ref() {
        println!("Source CWD: {}", path.display());
    }
    if let Some(path) = args.json_out.as_deref() {
        println!("JSON Output: {}", path.display());
    }
    if let Some(path) = args.html_out.as_deref() {
        println!("HTML Output: {}", path.display());
    }

    runtime_exit_code(&outcome)
}

fn resolve_source_cwd(args: &RunArgs) -> std::io::Result<Option<PathBuf>> {
    match (args.policy, args.cwd.as_ref()) {
        (RunPolicy::ReadOnlyWorkspace, Some(path)) => Ok(Some(path.clone())),
        (RunPolicy::ReadOnlyWorkspace, None) => env::current_dir().map(Some),
        (RunPolicy::Default, Some(path)) => Ok(Some(path.clone())),
        (RunPolicy::Default, None) => Ok(None),
    }
}

fn runtime_exit_code(outcome: &agentprey_core::RuntimeOutcome) -> ExitCode {
    match outcome.exit_reason {
        agentprey_core::RuntimeExitReason::Completed => {
            let code = outcome.exit_code.unwrap_or(0);
            let code = u8::try_from(code).unwrap_or(1);
            ExitCode::from(code)
        }
        agentprey_core::RuntimeExitReason::Timeout
        | agentprey_core::RuntimeExitReason::SpawnError => ExitCode::from(EXIT_CODE_RUNTIME_ERROR),
    }
}

use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};

use anyhow::{Context, Result};
use serde::Serialize;
use tempfile::TempDir;
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{self, Instant},
};

#[derive(Debug, Clone, Serialize)]
pub enum RuntimeEvent {
    SpawnedProcess { command: String, pid: u32 },
    Timeout { duration_ms: u128 },
    Exit { success: bool, code: Option<i32> },
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeOutcome {
    pub temp_dir: PathBuf,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub events: Vec<RuntimeEvent>,
}

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub timeout: Duration,
    pub env_allowlist: BTreeMap<String, String>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            env_allowlist: BTreeMap::new(),
        }
    }
}

pub async fn run_command(
    program: &str,
    args: &[&str],
    policy: &SandboxPolicy,
) -> Result<RuntimeOutcome> {
    let temp_dir = tempfile::tempdir().context("failed to create isolated temp directory")?;
    run_command_in_dir(program, args, policy, temp_dir).await
}

async fn run_command_in_dir(
    program: &str,
    args: &[&str],
    policy: &SandboxPolicy,
    temp_dir: TempDir,
) -> Result<RuntimeOutcome> {
    let started_at = Instant::now();
    let workdir = temp_dir.path().to_path_buf();

    let mut command = Command::new(program);
    command.args(args);
    command.current_dir(&workdir);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.env_clear();
    for (key, value) in &policy.env_allowlist {
        command.env(key, value);
    }

    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn sandboxed command '{program}'"))?;
    let mut events = Vec::new();
    let pid = child.id();
    if let Some(pid) = pid {
        events.push(RuntimeEvent::SpawnedProcess {
            command: format!("{program} {}", args.join(" ")).trim().to_string(),
            pid,
        });
    }

    let stdout_task = child.stdout.take().map(|mut stdout| {
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            stdout.read_to_end(&mut buffer).await?;
            Ok::<Vec<u8>, std::io::Error>(buffer)
        })
    });
    let stderr_task = child.stderr.take().map(|mut stderr| {
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            stderr.read_to_end(&mut buffer).await?;
            Ok::<Vec<u8>, std::io::Error>(buffer)
        })
    });

    let timed = time::timeout(policy.timeout, child.wait()).await;
    let duration_ms = started_at.elapsed().as_millis();

    match timed {
        Ok(status) => {
            let status = status.context("failed to wait for sandboxed command")?;
            let stdout = read_buffer(stdout_task).await?;
            let stderr = read_buffer(stderr_task).await?;
            events.push(RuntimeEvent::Exit {
                success: status.success(),
                code: status.code(),
            });

            Ok(RuntimeOutcome {
                temp_dir: workdir,
                duration_ms,
                exit_code: status.code(),
                timed_out: false,
                stdout,
                stderr,
                events,
            })
        }
        Err(_) => {
            #[cfg(target_os = "linux")]
            if let Some(pid) = pid {
                unsafe {
                    libc::killpg(pid as i32, libc::SIGKILL);
                }
            }

            let _ = child.kill().await;
            events.push(RuntimeEvent::Timeout {
                duration_ms: duration_ms.max(policy.timeout.as_millis()),
            });

            Ok(RuntimeOutcome {
                temp_dir: workdir,
                duration_ms,
                exit_code: None,
                timed_out: true,
                stdout: read_buffer(stdout_task).await.unwrap_or_default(),
                stderr: read_buffer(stderr_task).await.unwrap_or_default(),
                events,
            })
        }
    }
}

async fn read_buffer(
    task: Option<tokio::task::JoinHandle<Result<Vec<u8>, std::io::Error>>>,
) -> Result<String> {
    let bytes = match task {
        Some(task) => task
            .await
            .context("failed to join sandbox stream reader")?
            .context("failed to read sandbox stream")?,
        None => Vec::new(),
    };

    Ok(String::from_utf8_lossy(&bytes).to_string())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use crate::{run_command, RuntimeEvent, SandboxPolicy};

    #[tokio::test]
    async fn runs_command_in_isolated_directory() {
        let mut env_allowlist = BTreeMap::new();
        env_allowlist.insert("SAFE_FLAG".to_string(), "1".to_string());
        let policy = SandboxPolicy {
            timeout: Duration::from_secs(5),
            env_allowlist,
        };

        let outcome = run_command("bash", &["-lc", "pwd && echo $SAFE_FLAG"], &policy)
            .await
            .expect("sandboxed command should run");

        assert!(outcome
            .stdout
            .contains(outcome.temp_dir.to_string_lossy().as_ref()));
        assert!(outcome.stdout.contains("1"));
        assert!(matches!(
            outcome.events[0],
            RuntimeEvent::SpawnedProcess { .. }
        ));
    }

    #[tokio::test]
    async fn times_out_long_running_command() {
        let policy = SandboxPolicy {
            timeout: Duration::from_millis(100),
            ..SandboxPolicy::default()
        };

        let outcome = run_command("bash", &["-lc", "sleep 1"], &policy)
            .await
            .expect("sandboxed timeout should be reported");

        assert!(outcome.timed_out);
        assert!(outcome
            .events
            .iter()
            .any(|event| matches!(event, RuntimeEvent::Timeout { .. })));
    }
}

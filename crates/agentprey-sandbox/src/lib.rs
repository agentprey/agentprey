use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use agentprey_core::{RuntimeEvent, RuntimeExitReason, RuntimeOutcome};
use anyhow::{bail, Context, Result};
use tempfile::TempDir;
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{self, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceMode {
    EphemeralTempdir,
    ReadOnlyWorkspaceCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxPolicyPreset {
    Default,
    ReadOnlyWorkspace,
}

impl SandboxPolicyPreset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ReadOnlyWorkspace => "read-only-workspace",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub name: String,
    pub timeout: Duration,
    pub env_allowlist: BTreeMap<String, String>,
    pub workspace_mode: WorkspaceMode,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self::from_preset(SandboxPolicyPreset::Default, None)
    }
}

impl SandboxPolicy {
    pub fn from_preset(preset: SandboxPolicyPreset, timeout_override: Option<Duration>) -> Self {
        let workspace_mode = match preset {
            SandboxPolicyPreset::Default => WorkspaceMode::EphemeralTempdir,
            SandboxPolicyPreset::ReadOnlyWorkspace => WorkspaceMode::ReadOnlyWorkspaceCopy,
        };

        Self {
            name: preset.as_str().to_string(),
            timeout: timeout_override.unwrap_or(Duration::from_secs(5)),
            env_allowlist: BTreeMap::new(),
            workspace_mode,
        }
    }
}

pub async fn run_command<S: AsRef<str>>(
    program: &str,
    args: &[S],
    policy: &SandboxPolicy,
    source_cwd: Option<&Path>,
) -> Result<RuntimeOutcome> {
    let invocation = build_invocation(program, args);
    let started_at = Instant::now();
    let layout = prepare_workspace(source_cwd, policy.workspace_mode)?;
    run_command_in_dir(program, args, policy, invocation, started_at, layout).await
}

struct WorkspaceLayout {
    temp_dir: TempDir,
    sandbox_cwd: PathBuf,
    source_cwd: Option<PathBuf>,
}

async fn run_command_in_dir<S: AsRef<str>>(
    program: &str,
    args: &[S],
    policy: &SandboxPolicy,
    invocation: String,
    started_at: Instant,
    layout: WorkspaceLayout,
) -> Result<RuntimeOutcome> {
    let WorkspaceLayout {
        temp_dir,
        sandbox_cwd,
        source_cwd,
    } = layout;
    let _temp_dir = temp_dir;

    let mut command = Command::new(program);
    for arg in args {
        command.arg(arg.as_ref());
    }
    command.current_dir(&sandbox_cwd);
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

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Ok(RuntimeOutcome {
                source_cwd,
                sandbox_cwd,
                duration_ms: started_at.elapsed().as_millis(),
                exit_reason: RuntimeExitReason::SpawnError,
                exit_code: None,
                timed_out: false,
                stdout: String::new(),
                stderr: format!("failed to spawn sandboxed command '{program}': {error}"),
                policy_name: policy.name.clone(),
                invocation,
                events: Vec::new(),
            });
        }
    };

    let mut events = Vec::new();
    let pid = child.id();
    if let Some(pid) = pid {
        events.push(RuntimeEvent::SpawnedProcess {
            command: invocation.clone(),
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
                source_cwd,
                sandbox_cwd,
                duration_ms,
                exit_reason: RuntimeExitReason::Completed,
                exit_code: status.code(),
                timed_out: false,
                stdout,
                stderr,
                policy_name: policy.name.clone(),
                invocation,
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
                source_cwd,
                sandbox_cwd,
                duration_ms,
                exit_reason: RuntimeExitReason::Timeout,
                exit_code: None,
                timed_out: true,
                stdout: read_buffer(stdout_task).await.unwrap_or_default(),
                stderr: read_buffer(stderr_task).await.unwrap_or_default(),
                policy_name: policy.name.clone(),
                invocation,
                events,
            })
        }
    }
}

fn prepare_workspace(
    source_cwd: Option<&Path>,
    workspace_mode: WorkspaceMode,
) -> Result<WorkspaceLayout> {
    let temp_dir = tempfile::tempdir().context("failed to create isolated temp directory")?;
    let sandbox_cwd = temp_dir.path().to_path_buf();
    let source_cwd = source_cwd.map(Path::to_path_buf);

    if let Some(source_cwd) = source_cwd.as_deref() {
        if !source_cwd.exists() {
            bail!(
                "sandbox source cwd '{}' was not found",
                source_cwd.display()
            );
        }
        if !source_cwd.is_dir() {
            bail!(
                "sandbox source cwd '{}' is not a directory",
                source_cwd.display()
            );
        }

        copy_dir_contents(source_cwd, &sandbox_cwd)?;
    }

    if workspace_mode == WorkspaceMode::ReadOnlyWorkspaceCopy {
        make_tree_read_only(&sandbox_cwd)?;
    }

    Ok(WorkspaceLayout {
        temp_dir,
        sandbox_cwd,
        source_cwd,
    })
}

fn copy_dir_contents(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)
        .with_context(|| format!("failed to read sandbox source cwd '{}'", source.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to enumerate entry under sandbox source cwd '{}'",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        copy_path(&source_path, &destination_path)?;
    }

    Ok(())
}

fn copy_path(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source).with_context(|| {
        format!(
            "failed to inspect sandbox source path '{}'",
            source.display()
        )
    })?;

    if metadata.is_dir() {
        fs::create_dir_all(destination).with_context(|| {
            format!(
                "failed to create sandbox destination directory '{}'",
                destination.display()
            )
        })?;

        for entry in fs::read_dir(source).with_context(|| {
            format!(
                "failed to read sandbox source directory '{}'",
                source.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "failed to enumerate entry under sandbox source directory '{}'",
                    source.display()
                )
            })?;
            copy_path(&entry.path(), &destination.join(entry.file_name()))?;
        }

        return Ok(());
    }

    if metadata.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create sandbox destination directory '{}'",
                    parent.display()
                )
            })?;
        }

        fs::copy(source, destination).with_context(|| {
            format!(
                "failed to copy sandbox source file '{}' to '{}'",
                source.display(),
                destination.display()
            )
        })?;

        let permissions = metadata.permissions();
        fs::set_permissions(destination, permissions).with_context(|| {
            format!(
                "failed to preserve permissions for sandbox destination file '{}'",
                destination.display()
            )
        })?;
    }

    Ok(())
}

fn make_tree_read_only(root: &Path) -> Result<()> {
    apply_read_only(root)?;

    for entry in fs::read_dir(root)
        .with_context(|| format!("failed to read sandbox path '{}'", root.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to enumerate entry under sandbox path '{}'",
                root.display()
            )
        })?;
        let path = entry.path();
        if path.is_dir() {
            make_tree_read_only(&path)?;
        } else {
            apply_read_only(&path)?;
        }
    }

    Ok(())
}

fn apply_read_only(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect sandbox path '{}'", path.display()))?;
    let mut permissions = metadata.permissions();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        permissions.set_mode(permissions.mode() & !0o222);
        fs::set_permissions(path, permissions).with_context(|| {
            format!(
                "failed to mark sandbox path '{}' as read-only",
                path.display()
            )
        })?;
    }

    #[cfg(not(unix))]
    {
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions).with_context(|| {
            format!(
                "failed to mark sandbox path '{}' as read-only",
                path.display()
            )
        })?;
    }

    Ok(())
}

fn build_invocation<S: AsRef<str>>(program: &str, args: &[S]) -> String {
    if args.is_empty() {
        return program.to_string();
    }

    format!(
        "{program} {}",
        args.iter()
            .map(|arg| arg.as_ref())
            .collect::<Vec<_>>()
            .join(" ")
    )
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
    use std::{collections::BTreeMap, fs, time::Duration};

    use agentprey_core::{RuntimeEvent, RuntimeExitReason};
    use tempfile::tempdir;

    use crate::{run_command, SandboxPolicy, SandboxPolicyPreset, WorkspaceMode};

    #[test]
    fn default_preset_uses_expected_defaults() {
        let policy = SandboxPolicy::from_preset(SandboxPolicyPreset::Default, None);

        assert_eq!(policy.name, "default");
        assert_eq!(policy.workspace_mode, WorkspaceMode::EphemeralTempdir);
        assert_eq!(policy.timeout, Duration::from_secs(5));
    }

    #[test]
    fn read_only_workspace_preset_uses_read_only_mode() {
        let policy = SandboxPolicy::from_preset(SandboxPolicyPreset::ReadOnlyWorkspace, None);

        assert_eq!(policy.name, "read-only-workspace");
        assert_eq!(policy.workspace_mode, WorkspaceMode::ReadOnlyWorkspaceCopy);
    }

    #[tokio::test]
    async fn runs_command_in_isolated_directory() {
        let mut env_allowlist = BTreeMap::new();
        env_allowlist.insert("SAFE_FLAG".to_string(), "1".to_string());
        let mut policy = SandboxPolicy::from_preset(SandboxPolicyPreset::Default, None);
        policy.env_allowlist = env_allowlist;

        let outcome = run_command("bash", &["-lc", "pwd && echo $SAFE_FLAG"], &policy, None)
            .await
            .expect("sandboxed command should run");

        assert_eq!(outcome.policy_name, "default");
        assert_eq!(outcome.exit_reason, RuntimeExitReason::Completed);
        assert!(outcome
            .stdout
            .contains(outcome.sandbox_cwd.to_string_lossy().as_ref()));
        assert!(outcome.stdout.contains("1"));
        assert!(matches!(
            outcome.events[0],
            RuntimeEvent::SpawnedProcess { .. }
        ));
    }

    #[tokio::test]
    async fn times_out_long_running_command() {
        let policy = SandboxPolicy::from_preset(
            SandboxPolicyPreset::Default,
            Some(Duration::from_millis(100)),
        );

        let outcome = run_command("bash", &["-lc", "sleep 1"], &policy, None)
            .await
            .expect("sandboxed timeout should be reported");

        assert!(outcome.timed_out);
        assert_eq!(outcome.exit_reason, RuntimeExitReason::Timeout);
        assert!(outcome
            .events
            .iter()
            .any(|event| matches!(event, RuntimeEvent::Timeout { .. })));
    }

    #[tokio::test]
    async fn normalizes_spawn_errors_into_runtime_outcome() {
        let policy = SandboxPolicy::default();

        let outcome = run_command(
            "definitely-not-a-real-command",
            &["--version"],
            &policy,
            None,
        )
        .await
        .expect("spawn errors should still return a runtime outcome");

        assert_eq!(outcome.exit_reason, RuntimeExitReason::SpawnError);
        assert!(outcome.stderr.contains("failed to spawn sandboxed command"));
        assert!(outcome.events.is_empty());
    }

    #[tokio::test]
    async fn read_only_workspace_copy_preserves_source_tree() {
        let source = tempdir().expect("source tempdir should be created");
        let source_file = source.path().join("note.txt");
        fs::write(&source_file, "original").expect("source file should be written");

        let policy = SandboxPolicy::from_preset(SandboxPolicyPreset::ReadOnlyWorkspace, None);
        let outcome = run_command(
            "bash",
            &["-lc", "printf changed > note.txt"],
            &policy,
            Some(source.path()),
        )
        .await
        .expect("sandboxed command should complete");

        assert_eq!(outcome.policy_name, "read-only-workspace");
        assert_eq!(outcome.source_cwd.as_deref(), Some(source.path()));
        assert_eq!(outcome.exit_reason, RuntimeExitReason::Completed);
        assert_ne!(outcome.exit_code, Some(0));
        assert_eq!(
            fs::read_to_string(&source_file).expect("source file should remain readable"),
            "original"
        );
    }
}

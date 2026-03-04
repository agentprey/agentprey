use clap::{ArgAction, Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "agentprey",
    version,
    about = "Security scanner for AI agent endpoints"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a default project config file
    Init(InitArgs),

    /// Configure local authentication credentials
    Auth(AuthArgs),

    /// Run a security scan against a target endpoint
    Scan(ScanArgs),

    /// Inspect available attack vectors
    Vectors(VectorsArgs),
}

#[derive(Debug, Clone, Args)]
pub struct InitArgs {
    /// Path to write the generated config file
    #[arg(long, default_value = ".agentprey.toml")]
    pub path: PathBuf,

    /// Overwrite an existing config file
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ScanArgs {
    /// Target HTTP endpoint URL
    #[arg(long)]
    pub target: Option<String>,

    /// Additional request header in the form: "Key: Value"
    #[arg(long = "header", value_name = "KEY: VALUE", action = ArgAction::Append)]
    pub headers: Vec<String>,

    /// Request timeout in seconds
    #[arg(long)]
    pub timeout_seconds: Option<u64>,

    /// Directory containing vector YAML files
    #[arg(long)]
    pub vectors_dir: Option<PathBuf>,

    /// Optional category filter (for example: prompt-injection)
    #[arg(long)]
    pub category: Option<String>,

    /// Optional path for writing scan JSON output
    #[arg(long)]
    pub json_out: Option<PathBuf>,

    /// Optional path for writing scan HTML output
    #[arg(long)]
    pub html_out: Option<PathBuf>,

    /// Optional path to project config TOML
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Number of retry attempts for transient request failures
    #[arg(long)]
    pub retries: Option<u32>,

    /// Base backoff in milliseconds between retries
    #[arg(long)]
    pub retry_backoff_ms: Option<u64>,

    /// Maximum number of vectors to execute concurrently
    #[arg(long)]
    pub max_concurrent: Option<usize>,

    /// Global request rate limit in requests per second
    #[arg(long)]
    pub rate_limit_rps: Option<u32>,

    /// Redact sensitive patterns from response output
    #[arg(long, default_value_t = false, conflicts_with = "no_redact_responses")]
    pub redact_responses: bool,

    /// Disable response redaction in output artifacts
    #[arg(long, default_value_t = false, conflicts_with = "redact_responses")]
    pub no_redact_responses: bool,
}

#[derive(Debug, Clone, Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum AuthCommands {
    /// Activate local credentials with an API key
    Activate(AuthActivateArgs),

    /// Re-validate stored credentials and refresh tier metadata
    Refresh,

    /// Show the currently resolved subscription tier
    Status,

    /// Remove local credentials and cached entitlement metadata
    Logout,
}

#[derive(Debug, Clone, Args)]
pub struct AuthActivateArgs {
    /// API key to store locally; if omitted, prompts interactively
    #[arg(long)]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct VectorsArgs {
    #[command(subcommand)]
    pub command: VectorsCommands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum VectorsCommands {
    /// List available vectors
    List(VectorsListArgs),

    /// Sync vectors from remote bundles
    Sync(VectorsSyncArgs),
}

#[derive(Debug, Clone, Args)]
pub struct VectorsListArgs {
    /// Optional category filter (for example: prompt-injection)
    #[arg(long)]
    pub category: Option<String>,

    /// Directory containing vector YAML files
    #[arg(long, default_value = "vectors")]
    pub vectors_dir: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct VectorsSyncArgs {
    /// Sync the Pro vector bundle
    #[arg(long, required = true)]
    pub pro: bool,
}

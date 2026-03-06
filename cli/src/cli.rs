use clap::{ArgAction, Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "agentprey",
    version,
    about = "AgentPrey — Security scanner for AI agent endpoints. Detect prompt injection, tool misuse, data exfiltration, and more.",
    after_help = r#"Examples:
  agentprey scan --target https://my-agent.com/api
  agentprey scan --target https://my-agent.com/api --category prompt-injection
  agentprey scan --type openclaw --target ./some-openclaw-project
  agentprey scan --target https://my-agent.com/api --request-template '{"input": "{{payload}}"}'
  agentprey auth activate --key <your_api_key>
  agentprey vectors sync --pro"#
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a project config file (.agentprey.toml) in the current directory
    Init(InitArgs),

    /// Manage your Pro authentication (activate, status, refresh, logout)
    Auth(AuthArgs),

    /// Run a security scan against a target endpoint. Use --target to specify the URL, --category to filter vectors, --request-template for custom agent formats
    Scan(Box<ScanArgs>),

    /// List, inspect, and sync attack vectors. Use 'vectors list' to see available vectors, 'vectors sync --pro' to download Pro vectors
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetType {
    Http,
    Openclaw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ScanUi {
    Plain,
    Tui,
}

#[derive(Debug, Clone, Args)]
pub struct ScanArgs {
    /// Target HTTP endpoint URL or local OpenClaw project path
    #[arg(long)]
    pub target: Option<String>,

    /// Target type for scan execution
    #[arg(long = "type", value_enum, default_value_t = TargetType::Http)]
    pub target_type: TargetType,

    /// Additional request header in the form: "Key: Value"
    #[arg(long = "header", value_name = "KEY: VALUE", action = ArgAction::Append)]
    pub headers: Vec<String>,

    /// Custom JSON request template containing a {{payload}} marker
    #[arg(long)]
    pub request_template: Option<String>,

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

    /// Upload the completed scan artifact to the AgentPrey cloud
    #[arg(long, default_value_t = false)]
    pub upload: bool,

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

    /// Scan output mode
    #[arg(long, value_enum, default_value_t = ScanUi::Plain)]
    pub ui: ScanUi,
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

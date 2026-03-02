use clap::{ArgAction, Args, Parser, Subcommand};

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
    /// Run a security scan against a target endpoint
    Scan(ScanArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ScanArgs {
    /// Target HTTP endpoint URL
    #[arg(long)]
    pub target: String,

    /// Additional request header in the form: "Key: Value"
    #[arg(long = "header", value_name = "KEY: VALUE", action = ArgAction::Append)]
    pub headers: Vec<String>,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 30)]
    pub timeout_seconds: u64,
}

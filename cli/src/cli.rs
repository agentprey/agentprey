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
    /// Run a security scan against a target endpoint
    Scan(ScanArgs),

    /// Inspect available attack vectors
    Vectors(VectorsArgs),
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

#[derive(Debug, Clone, Args)]
pub struct VectorsArgs {
    #[command(subcommand)]
    pub command: VectorsCommands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum VectorsCommands {
    /// List available vectors
    List(VectorsListArgs),
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

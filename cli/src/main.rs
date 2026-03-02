use std::process::ExitCode;

use clap::Parser;
use colored::Colorize;

use agentprey::{
    analyzer::Verdict,
    cli::{Cli, Commands, VectorsCommands, VectorsListArgs},
    scan::ScanOutcome,
    vectors::catalog::list_vectors,
};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => match agentprey::scan::run_scan(&args).await {
            Ok(outcome) => {
                render_scan_outcome(&outcome);

                match outcome.analysis.verdict {
                    Verdict::Resistant => ExitCode::from(0),
                    Verdict::Vulnerable => ExitCode::from(2),
                }
            }
            Err(error) => {
                eprintln!("{} {error}", "error:".red().bold());
                ExitCode::from(1)
            }
        },
        Commands::Vectors(args) => match args.command {
            VectorsCommands::List(list_args) => match render_vectors_list(&list_args) {
                Ok(()) => ExitCode::from(0),
                Err(error) => {
                    eprintln!("{} {error}", "error:".red().bold());
                    ExitCode::from(1)
                }
            },
        },
    }
}

fn render_vectors_list(args: &VectorsListArgs) -> anyhow::Result<()> {
    let vectors = list_vectors(&args.vectors_dir, args.category.as_deref())?;

    println!();
    println!("{}", "AgentPrey Vector Catalog".bold());
    println!("Directory: {}", args.vectors_dir.display());
    match args.category.as_deref() {
        Some(category) => println!("Filter: category = {category}"),
        None => println!("Filter: none"),
    }

    if vectors.is_empty() {
        println!("Vectors: 0");
        println!();
        return Ok(());
    }

    println!("Vectors: {}", vectors.len());
    for vector in vectors {
        println!(
            "- {} | {} | {}/{}",
            vector.id, vector.name, vector.category, vector.subcategory
        );
    }

    println!();
    Ok(())
}

fn render_scan_outcome(outcome: &ScanOutcome) {
    println!();
    println!("{}", "AgentPrey Scan Result".bold());
    println!("Target: {}", outcome.target);
    println!("Vector: {} ({})", outcome.vector_name, outcome.vector_id);
    println!("HTTP Status: {}", outcome.status_code);

    let verdict = match outcome.analysis.verdict {
        Verdict::Resistant => "RESISTANT".green().bold(),
        Verdict::Vulnerable => "VULNERABLE".red().bold(),
    };
    println!("Verdict: {}", verdict);
    println!("Confidence: {:.2}", outcome.analysis.confidence);
    println!("Refusal Detected: {}", outcome.analysis.refusal_detected);

    if outcome.analysis.indicator_hits.is_empty() {
        println!("Indicators: none");
    } else {
        println!("Indicators: {}", outcome.analysis.indicator_hits.join("; "));
    }

    println!("Duration: {} ms", outcome.duration_ms);
    println!(
        "Response Excerpt: {}",
        truncate_for_display(&outcome.response, 220)
    );
    println!();
}

fn truncate_for_display(text: &str, max_chars: usize) -> String {
    let total_chars = text.chars().count();
    if total_chars <= max_chars {
        return text.to_string();
    }

    let clipped: String = text.chars().take(max_chars).collect();
    format!("{clipped}...")
}

use std::process::ExitCode;

use clap::Parser;
use colored::Colorize;

use agentprey::{
    cli::{Cli, Commands, VectorsCommands, VectorsListArgs},
    scan::{FindingStatus, ScanOutcome},
    vectors::catalog::list_vectors,
};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => match agentprey::scan::run_scan(&args).await {
            Ok(outcome) => {
                render_scan_outcome(&outcome);

                if outcome.has_vulnerabilities() {
                    ExitCode::from(2)
                } else if outcome.error_count > 0 {
                    ExitCode::from(1)
                } else {
                    ExitCode::from(0)
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
    println!("Total Vectors: {}", outcome.total_vectors);
    println!("Score: {}", outcome.score.score);
    println!("Grade: {}", outcome.score.grade);
    println!("Vulnerable: {}", outcome.vulnerable_count);
    println!("Resistant: {}", outcome.resistant_count);
    println!("Errors: {}", outcome.error_count);

    for finding in &outcome.findings {
        let status = match finding.status {
            FindingStatus::Vulnerable => "VULNERABLE".red().bold(),
            FindingStatus::Resistant => "RESISTANT".green().bold(),
            FindingStatus::Error => "ERROR".yellow().bold(),
        };

        println!(
            "- {} | {} | {} | {}",
            finding.vector_id, finding.vector_name, finding.severity, status
        );

        if let Some(status_code) = finding.status_code {
            println!("  HTTP Status: {status_code}");
        }

        if let Some(analysis) = finding.analysis.as_ref() {
            println!("  Confidence: {:.2}", analysis.confidence);
            if analysis.indicator_hits.is_empty() {
                println!("  Indicators: none");
            } else {
                println!("  Indicators: {}", analysis.indicator_hits.join("; "));
            }
        }

        println!(
            "  Response Excerpt: {}",
            truncate_for_display(&finding.response, 180)
        );
    }

    println!("Duration: {} ms", outcome.duration_ms);
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

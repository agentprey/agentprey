use std::process::ExitCode;

use clap::Parser;
use colored::Colorize;

use agentprey::{
    analyzer::Verdict,
    cli::{Cli, Commands},
    scan::ScanOutcome,
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
    }
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

use std::{
    env,
    io::{self, IsTerminal},
    process::ExitCode,
};

use clap::Parser;
use colored::Colorize;

use agentprey::{
    auth::{self, CacheStaleness},
    cli::{AuthCommands, Cli, Commands, VectorsCommands, VectorsListArgs},
    config::write_default_config,
    output::html::write_scan_html,
    output::json::write_scan_json,
    scan::{resolve_scan_settings, run_scan_with_settings, FindingStatus, ScanOutcome},
    scorer::Grade,
    vectors::{catalog::list_vectors, model::Severity, sync::sync_pro_vectors},
};

#[tokio::main]
async fn main() -> ExitCode {
    configure_color_output();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init(args) => match write_default_config(&args.path, args.force) {
            Ok(()) => {
                println!("Wrote config: {}", args.path.display());
                ExitCode::from(0)
            }
            Err(error) => {
                eprintln!("{} {error}", "error:".red().bold());
                ExitCode::from(1)
            }
        },
        Commands::Auth(args) => match args.command {
            AuthCommands::Activate(activate_args) => match auth::activate(activate_args.key) {
                Ok(path) => {
                    println!("Auth activated");
                    println!("Credentials: {}", path.display());
                    match auth::refresh().await {
                        Ok(entitlement) => {
                            println!("Entitlement refreshed: tier={}", entitlement.tier);
                        }
                        Err(error) => {
                            println!(
                                "Entitlement refresh unavailable: {error}. You can retry with `agentprey auth refresh`."
                            );
                        }
                    }
                    ExitCode::from(0)
                }
                Err(error) => {
                    eprintln!("{} {error}", "error:".red().bold());
                    ExitCode::from(1)
                }
            },
            AuthCommands::Refresh => match auth::refresh().await {
                Ok(entitlement) => {
                    println!("Refreshed: tier={}", entitlement.tier);
                    ExitCode::from(0)
                }
                Err(error) => {
                    eprintln!("{} {error}", "error:".red().bold());
                    ExitCode::from(1)
                }
            },
            AuthCommands::Status => match auth::status() {
                Ok(status) => {
                    if status.key_configured {
                        println!("Auth: activated");
                    } else {
                        println!("Auth: not activated");
                    }

                    let tier = if status.key_configured {
                        status.tier.as_deref().unwrap_or("unknown")
                    } else {
                        "none"
                    };

                    println!("Tier: {tier}");
                    println!("Last Refresh: {}", format_last_refresh(&status));
                    ExitCode::from(0)
                }
                Err(error) => {
                    eprintln!("{} {error}", "error:".red().bold());
                    ExitCode::from(1)
                }
            },
            AuthCommands::Logout => match auth::logout() {
                Ok(true) => {
                    println!("Auth cleared");
                    ExitCode::from(0)
                }
                Ok(false) => {
                    println!("Auth already cleared");
                    ExitCode::from(0)
                }
                Err(error) => {
                    eprintln!("{} {error}", "error:".red().bold());
                    ExitCode::from(1)
                }
            },
        },
        Commands::Scan(args) => match resolve_scan_settings(&args) {
            Ok(settings) => match run_scan_with_settings(&settings).await {
                Ok(outcome) => {
                    render_scan_outcome(&outcome);

                    if let Some(path) = settings.json_out.as_deref() {
                        if let Err(error) = write_scan_json(path, &outcome) {
                            eprintln!("{} {error}", "error:".red().bold());
                            return ExitCode::from(1);
                        }

                        println!("JSON Output: {}", path.display());
                    }

                    if let Some(path) = settings.html_out.as_deref() {
                        if let Err(error) = write_scan_html(path, &outcome) {
                            eprintln!("{} {error}", "error:".red().bold());
                            return ExitCode::from(1);
                        }

                        println!("HTML Output: {}", path.display());
                    }

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
            VectorsCommands::Sync(sync_args) => {
                if !sync_args.pro {
                    eprintln!("{} missing required --pro flag", "error:".red().bold());
                    return ExitCode::from(1);
                }

                match sync_pro_vectors().await {
                    Ok(count) => {
                        println!("Pro vectors synced: {count} vectors");
                        ExitCode::from(0)
                    }
                    Err(error) => {
                        eprintln!("{} {error}", "error:".red().bold());
                        ExitCode::from(1)
                    }
                }
            }
        },
    }
}

fn configure_color_output() {
    let no_color = env::var_os("NO_COLOR").is_some();
    let is_tty = io::stdout().is_terminal() && io::stderr().is_terminal();

    colored::control::set_override(!no_color && is_tty);
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
    println!("{}", "AgentPrey Scan Result".white().bold());
    println!("{} {}", "Target:".bright_black(), outcome.target);
    println!(
        "{} {}",
        "Total Vectors:".bright_black(),
        outcome.total_vectors
    );
    println!("{} {}", "Score:".bright_black(), outcome.score.score);
    println!(
        "{} {}",
        "Grade:".white().bold(),
        style_grade(outcome.score.grade)
    );
    println!(
        "{} {}",
        "Vulnerable:".bright_black(),
        style_vulnerable_count(outcome.vulnerable_count)
    );
    println!(
        "{} {}",
        "Resistant:".bright_black(),
        style_resistant_count(outcome.resistant_count)
    );
    println!(
        "{} {}",
        "Errors:".bright_black(),
        style_error_count(outcome.error_count)
    );

    for finding in &outcome.findings {
        let status = style_status(finding.status);
        let severity = style_severity(&finding.severity);

        println!(
            "- {} | {} | {} | {}",
            finding.vector_id, finding.vector_name, severity, status
        );

        if let Some(status_code) = finding.status_code {
            println!("{}", format!("  HTTP Status: {status_code}").bright_black());
        }

        if let Some(analysis) = finding.analysis.as_ref() {
            println!(
                "{}",
                format!("  Confidence: {:.2}", analysis.confidence).bright_black()
            );
            if analysis.indicator_hits.is_empty() {
                println!("{}", "  Indicators: none".bright_black());
            } else {
                println!(
                    "{}",
                    format!("  Indicators: {}", analysis.indicator_hits.join("; ")).bright_black()
                );
            }
        }

        println!(
            "{}",
            format!(
                "  Response Excerpt: {}",
                truncate_for_display(&finding.response, 180)
            )
            .bright_black()
        );
    }

    println!(
        "{}",
        format!("Duration: {} ms", outcome.duration_ms).bright_black()
    );
    println!();
}

fn style_grade(grade: Grade) -> String {
    let grade_text = grade.to_string();

    match grade {
        Grade::A | Grade::B => grade_text.green().bold().to_string(),
        _ => grade_text.white().bold().to_string(),
    }
}

fn style_severity(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::Medium => "MEDIUM".yellow().to_string(),
        Severity::Info => "INFO".bright_black().to_string(),
        Severity::High => "HIGH".to_string(),
        Severity::Low => "LOW".to_string(),
    }
}

fn style_status(status: FindingStatus) -> String {
    match status {
        FindingStatus::Vulnerable => "VULNERABLE".red().bold().to_string(),
        FindingStatus::Resistant => "PASSED".green().bold().to_string(),
        FindingStatus::Error => "WARNING".yellow().bold().to_string(),
    }
}

fn style_vulnerable_count(count: usize) -> String {
    let text = count.to_string();
    if count > 0 {
        text.red().bold().to_string()
    } else {
        text.bright_black().to_string()
    }
}

fn style_resistant_count(count: usize) -> String {
    let text = count.to_string();
    if count > 0 {
        text.green().to_string()
    } else {
        text.bright_black().to_string()
    }
}

fn style_error_count(count: usize) -> String {
    let text = count.to_string();
    if count > 0 {
        text.yellow().to_string()
    } else {
        text.bright_black().to_string()
    }
}

fn format_last_refresh(status: &auth::AuthStatus) -> String {
    let Some(last_refresh) = status.last_successful_refresh_epoch_secs else {
        return "never".to_string();
    };

    match status.staleness() {
        Some(CacheStaleness::Fresh { age_seconds }) => {
            format!("{last_refresh} ({} ago, fresh)", format_age(age_seconds))
        }
        Some(CacheStaleness::Stale { age_seconds }) => {
            format!("{last_refresh} ({} ago, stale)", format_age(age_seconds))
        }
        Some(CacheStaleness::ClockSkew) => format!("{last_refresh} (clock skew detected)"),
        None => last_refresh.to_string(),
    }
}

fn format_age(age_seconds: u64) -> String {
    if age_seconds < 60 {
        format!("{age_seconds}s")
    } else if age_seconds < 3_600 {
        format!("{}m", age_seconds / 60)
    } else if age_seconds < 86_400 {
        format!("{}h", age_seconds / 3_600)
    } else {
        format!("{}d", age_seconds / 86_400)
    }
}

fn truncate_for_display(text: &str, max_chars: usize) -> String {
    let total_chars = text.chars().count();
    if total_chars <= max_chars {
        return text.to_string();
    }

    let clipped: String = text.chars().take(max_chars).collect();
    format!("{clipped}...")
}

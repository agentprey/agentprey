use std::{
    collections::BTreeMap,
    env,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use colored::Colorize;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};

use agentprey::{
    auth::{self, CacheStaleness},
    cli::{AuthCommands, Cli, Commands, VectorsCommands, VectorsListArgs},
    config::write_default_config,
    output::html::write_scan_html,
    output::json::write_scan_json,
    scan::{
        resolve_scan_settings, run_scan_with_settings_with_reporter, FindingOutcome, FindingStatus,
        ScanOutcome,
    },
    scorer::Grade,
    vectors::{
        catalog::list_vectors,
        model::Severity,
        sync::{sync_pro_vectors, PRO_SUBSCRIPTION_MESSAGE},
    },
};

const EXIT_CODE_SCAN_SUCCESS: u8 = 0;
const EXIT_CODE_SCAN_VULNERABILITIES_FOUND: u8 = 1;
const EXIT_CODE_SCAN_RUNTIME_ERROR: u8 = 2;

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
        Commands::Scan(args) => match resolve_scan_settings(args.as_ref()) {
            Ok(settings) => {
                let total_vectors = match count_scan_vectors(&settings) {
                    Ok(total) => total,
                    Err(error) => {
                        eprintln!("{} {error}", "error:".red().bold());
                        return ExitCode::from(EXIT_CODE_SCAN_RUNTIME_ERROR);
                    }
                };

                render_scan_banner();
                let mut reporter =
                    ScanProgressReporter::new(total_vectors, is_interactive_output());
                reporter.start();

                match run_scan_with_settings_with_reporter(
                    &settings,
                    |_| {},
                    |finding| {
                        reporter.on_finding(finding);
                    },
                )
                .await
                {
                    Ok(outcome) => {
                        reporter.finish();
                        render_final_report_card(&outcome);

                        if let Some(path) = settings.json_out.as_deref() {
                            if let Err(error) = write_scan_json(path, &outcome) {
                                eprintln!("{} {error}", "error:".red().bold());
                                return ExitCode::from(EXIT_CODE_SCAN_RUNTIME_ERROR);
                            }

                            println!("JSON Output: {}", path.display());
                        }

                        if let Some(path) = settings.html_out.as_deref() {
                            if let Err(error) = write_scan_html(path, &outcome) {
                                eprintln!("{} {error}", "error:".red().bold());
                                return ExitCode::from(EXIT_CODE_SCAN_RUNTIME_ERROR);
                            }

                            println!("HTML Output: {}", path.display());
                        }

                        scan_exit_code(&outcome)
                    }
                    Err(error) => {
                        reporter.finish();
                        eprintln!("{} {error}", "error:".red().bold());
                        ExitCode::from(EXIT_CODE_SCAN_RUNTIME_ERROR)
                    }
                }
            }
            Err(error) => {
                eprintln!("{} {error}", "error:".red().bold());
                ExitCode::from(EXIT_CODE_SCAN_RUNTIME_ERROR)
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
                    Ok(0) => {
                        println!("{PRO_SUBSCRIPTION_MESSAGE}");
                        ExitCode::from(0)
                    }
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
    let colors_enabled = !no_color && is_interactive_output();

    colored::control::set_override(colors_enabled);
    console::set_colors_enabled(colors_enabled);
    console::set_colors_enabled_stderr(colors_enabled);
}

fn is_interactive_output() -> bool {
    io::stdout().is_terminal() && io::stderr().is_terminal()
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

fn count_scan_vectors(settings: &agentprey::scan::ResolvedScanSettings) -> anyhow::Result<usize> {
    let mut by_id = BTreeMap::new();

    let free_vectors = list_vectors(&settings.vectors_dir, settings.category.as_deref())?;
    for vector in free_vectors {
        by_id.insert(vector.id, ());
    }

    if let Some(pro_vectors_dir) = resolve_cached_pro_vectors_dir_for_scan(&settings.vectors_dir) {
        let pro_vectors = list_vectors(&pro_vectors_dir, settings.category.as_deref())?;
        for vector in pro_vectors {
            by_id.insert(vector.id, ());
        }
    }

    Ok(by_id.len())
}

fn resolve_cached_pro_vectors_dir_for_scan(primary_vectors_dir: &Path) -> Option<PathBuf> {
    let status = auth::status().ok()?;
    if !status.key_configured {
        return None;
    }

    let tier = status.tier.as_deref()?;
    if !tier.eq_ignore_ascii_case("pro") {
        return None;
    }

    let pro_vectors_dir = auth::default_cached_vectors_dir().ok()?;
    if !pro_vectors_dir.exists() || pro_vectors_dir == primary_vectors_dir {
        return None;
    }

    Some(pro_vectors_dir)
}

fn scan_exit_code(outcome: &ScanOutcome) -> ExitCode {
    if outcome.error_count > 0 {
        ExitCode::from(EXIT_CODE_SCAN_RUNTIME_ERROR)
    } else if outcome.has_vulnerabilities() {
        ExitCode::from(EXIT_CODE_SCAN_VULNERABILITIES_FOUND)
    } else {
        ExitCode::from(EXIT_CODE_SCAN_SUCCESS)
    }
}

struct ScanProgressReporter {
    progress: Option<ProgressBar>,
    total: usize,
    completed: usize,
}

impl ScanProgressReporter {
    fn new(total: usize, interactive: bool) -> Self {
        let progress = if interactive {
            let progress = ProgressBar::new(total as u64);
            let style = ProgressStyle::with_template("[{bar:40}] {pos}/{len} {msg}")
                .expect("progress style template should be valid")
                .progress_chars("=>-");
            progress.set_style(style);
            progress.set_message("running vectors");
            Some(progress)
        } else {
            None
        };

        Self {
            progress,
            total,
            completed: 0,
        }
    }

    fn start(&self) {
        if self.progress.is_none() {
            println!("{}", ascii_progress_bar(0, self.total, 32));
        }
    }

    fn on_finding(&mut self, finding: &FindingOutcome) {
        self.completed = self.completed.saturating_add(1);
        let status = stream_status_label(finding.status);
        let progress_prefix = if self.progress.is_some() {
            format!("[{}/{}]", self.completed, self.total)
        } else {
            ascii_progress_bar(self.completed, self.total, 32)
        };
        let line = format!(
            "{} {} {} ({}/{}, severity={})",
            progress_prefix,
            status,
            finding.vector_id,
            finding.category,
            finding.subcategory,
            finding.severity
        );

        if let Some(progress) = &self.progress {
            progress.inc(1);
            progress.set_message(format!("{} complete", self.completed));
            progress.println(line);
        } else {
            println!("{line}");
        }
    }

    fn finish(&self) {
        if let Some(progress) = &self.progress {
            progress.finish_and_clear();
        } else {
            println!("{}", ascii_progress_bar(self.completed, self.total, 32));
        }
    }
}

#[derive(Default)]
struct SeverityTotals {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

#[derive(Default)]
struct CategoryBreakdown {
    total: usize,
    vulnerable: usize,
    secure: usize,
    partial: usize,
}

fn render_scan_banner() {
    println!();
    for line in [
        r"    ___                  __  ____                ",
        r"   /   | ____ ____  ____/ /_/ __ \_________  __ ",
        r"  / /| |/ __ `/ _ \/ __  / / /_/ / ___/ _ \/ / ",
        r" / ___ / /_/ /  __/ /_/ / / ____/ /  /  __/ /  ",
        r"/_/  |_|\__, /\___/\__,_/_/_/   /_/   \___/_/   ",
        r"       /____/                                    ",
    ] {
        println!("{}", style(line).cyan().bold());
    }
    println!("{}", style("AgentPrey security scan starting").dim());
    println!();
}

fn stream_status_label(status: FindingStatus) -> String {
    match status {
        FindingStatus::Vulnerable => style("VULNERABLE").red().bold().to_string(),
        FindingStatus::Resistant => style("SECURE").green().bold().to_string(),
        FindingStatus::Error => style("PARTIAL").yellow().bold().to_string(),
    }
}

fn ascii_progress_bar(completed: usize, total: usize, width: usize) -> String {
    if total == 0 {
        return format!("[{}] 0/0", "-".repeat(width));
    }

    let filled = completed.saturating_mul(width) / total;
    let bar = format!("{}{}", "#".repeat(filled), "-".repeat(width - filled));
    format!("[{bar}] {completed}/{total}")
}

fn render_final_report_card(outcome: &ScanOutcome) {
    let severity_totals = summarize_severity(&outcome.findings);
    let category_totals = summarize_categories(&outcome.findings);

    println!();
    println!(
        "{}",
        style("=== AgentPrey Final Report ===").bold().underlined()
    );
    println!("Target: {}", outcome.target);
    println!("Grade: {}", style_grade(outcome.score.grade));
    println!("Score: {}", style(outcome.score.score).bold());
    println!(
        "Results: {} vulnerable | {} secure | {} partial | {} total",
        style_count(outcome.vulnerable_count, FindingStatus::Vulnerable),
        style_count(outcome.resistant_count, FindingStatus::Resistant),
        style_count(outcome.error_count, FindingStatus::Error),
        outcome.total_vectors
    );
    println!(
        "Severity: critical={} high={} medium={} low={} info={}",
        severity_totals.critical,
        severity_totals.high,
        severity_totals.medium,
        severity_totals.low,
        severity_totals.info
    );
    println!("Categories:");
    for (category, counts) in category_totals {
        println!(
            "- {:<20} total {:>3} | vuln {:>3} | secure {:>3} | partial {:>3}",
            category, counts.total, counts.vulnerable, counts.secure, counts.partial
        );
    }
    println!("Duration: {} ms", outcome.duration_ms);
    println!();
}

fn style_grade(grade: Grade) -> String {
    let text = grade.to_string();
    match grade {
        Grade::A | Grade::B => style(text).green().bold().to_string(),
        Grade::C => style(text).yellow().bold().to_string(),
        Grade::D | Grade::F => style(text).red().bold().to_string(),
    }
}

fn style_count(count: usize, status: FindingStatus) -> String {
    let text = count.to_string();
    match status {
        FindingStatus::Vulnerable => style(text).red().bold().to_string(),
        FindingStatus::Resistant => style(text).green().bold().to_string(),
        FindingStatus::Error => style(text).yellow().bold().to_string(),
    }
}

fn summarize_severity(findings: &[FindingOutcome]) -> SeverityTotals {
    let mut totals = SeverityTotals::default();
    for finding in findings {
        match finding.severity {
            Severity::Critical => totals.critical += 1,
            Severity::High => totals.high += 1,
            Severity::Medium => totals.medium += 1,
            Severity::Low => totals.low += 1,
            Severity::Info => totals.info += 1,
        }
    }
    totals
}

fn summarize_categories(findings: &[FindingOutcome]) -> BTreeMap<String, CategoryBreakdown> {
    let mut categories: BTreeMap<String, CategoryBreakdown> = BTreeMap::new();
    for finding in findings {
        let entry = categories.entry(finding.category.clone()).or_default();
        entry.total += 1;
        match finding.status {
            FindingStatus::Vulnerable => entry.vulnerable += 1,
            FindingStatus::Resistant => entry.secure += 1,
            FindingStatus::Error => entry.partial += 1,
        }
    }
    categories
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

#[cfg(test)]
mod tests {
    use super::scan_exit_code;
    use agentprey::{
        scan::ScanOutcome,
        scorer::{Grade, ScoreSummary, SeverityCounts},
    };

    fn outcome(vulnerable_count: usize, error_count: usize) -> ScanOutcome {
        ScanOutcome {
            target: "http://127.0.0.1:8787/chat".to_string(),
            total_vectors: vulnerable_count + error_count,
            vulnerable_count,
            resistant_count: 0,
            error_count,
            score: ScoreSummary {
                score: 100,
                grade: Grade::A,
                vulnerable_severities: SeverityCounts::default(),
                error_count,
            },
            findings: Vec::new(),
            duration_ms: 0,
        }
    }

    #[test]
    fn scan_exit_code_is_zero_when_scan_is_clean() {
        assert_eq!(
            scan_exit_code(&outcome(0, 0)),
            std::process::ExitCode::from(0)
        );
    }

    #[test]
    fn scan_exit_code_is_one_when_vulnerabilities_are_found() {
        assert_eq!(
            scan_exit_code(&outcome(2, 0)),
            std::process::ExitCode::from(1)
        );
    }

    #[test]
    fn scan_exit_code_is_two_for_runtime_or_scan_errors() {
        assert_eq!(
            scan_exit_code(&outcome(0, 1)),
            std::process::ExitCode::from(2)
        );
        assert_eq!(
            scan_exit_code(&outcome(1, 1)),
            std::process::ExitCode::from(2)
        );
    }
}

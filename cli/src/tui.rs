use std::{
    collections::VecDeque,
    io::{self, IsTerminal, Stdout},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};

use crate::{
    cli::TargetType,
    scan::{
        run_scan_with_settings_with_reporter, FindingOutcome, FindingStatus, ResolvedScanSettings,
        ScanOutcome,
    },
    scorer::{score_findings, Grade, ScoreSummary},
    vectors::model::Severity,
};

const DRAW_INTERVAL: Duration = Duration::from_millis(75);
const FINAL_FRAME_HOLD: Duration = Duration::from_millis(900);
const MAX_RECENT_FINDINGS: usize = 12;

pub async fn run_scan_with_tui(settings: &ResolvedScanSettings) -> Result<ScanOutcome> {
    ensure_interactive_stdout()?;

    let mut terminal = TuiTerminal::enter()?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let scan_settings = settings.clone();
    let scan_task = tokio::spawn(async move {
        run_scan_with_settings_with_reporter(
            &scan_settings,
            |total| {
                let _ = tx.send(TuiEvent::Started { total });
            },
            |finding| {
                let _ = tx.send(TuiEvent::Finding(finding.clone()));
            },
        )
        .await
    });

    let started_at = Instant::now();
    let mut state = TuiState::new(settings);
    terminal.draw(|frame| render(frame, &state))?;

    loop {
        let mut dirty = false;
        state.elapsed = started_at.elapsed();

        while let Ok(event) = rx.try_recv() {
            state.apply_event(event);
            dirty = true;
        }

        if poll_for_interrupt(&scan_task)? {
            return Err(anyhow!("scan interrupted by user"));
        }

        if dirty || scan_task.is_finished() {
            terminal.draw(|frame| render(frame, &state))?;
        }

        if scan_task.is_finished() {
            let outcome = match scan_task.await {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => {
                    return Err(anyhow!("scan interrupted by user"));
                }
                Err(error) => {
                    return Err(anyhow!("scan task failed unexpectedly: {error}"));
                }
            };

            while let Ok(event) = rx.try_recv() {
                state.apply_event(event);
            }

            state.finish(&outcome, started_at.elapsed());
            terminal.draw(|frame| render(frame, &state))?;
            sleep(FINAL_FRAME_HOLD).await;
            return Ok(outcome);
        }

        sleep(DRAW_INTERVAL).await;
    }
}

fn ensure_interactive_stdout() -> Result<()> {
    if io::stdout().is_terminal() {
        return Ok(());
    }

    Err(anyhow!(
        "`--ui tui` requires an interactive stdout terminal; rerun without `--ui tui` or use `--json-out`/`--html-out`."
    ))
}

fn poll_for_interrupt(scan_task: &JoinHandle<Result<ScanOutcome>>) -> Result<bool> {
    while event::poll(Duration::from_millis(0)).context("failed to poll terminal events")? {
        if let Event::Key(key) = event::read().context("failed to read terminal event")? {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
            {
                scan_task.abort();
                return Ok(true);
            }
        }
    }

    Ok(false)
}

struct TuiTerminal {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TuiTerminal {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("failed to enable raw terminal mode")?;

        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error).context("failed to enter alternate screen");
        }

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = disable_raw_mode();
                let mut stdout = io::stdout();
                let _ = execute!(stdout, LeaveAlternateScreen);
                return Err(error).context("failed to initialize terminal backend");
            }
        };

        if let Err(error) = terminal.hide_cursor() {
            let _ = disable_raw_mode();
            let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
            return Err(error).context("failed to hide terminal cursor");
        }

        terminal
            .clear()
            .context("failed to clear terminal screen")?;
        Ok(Self { terminal })
    }

    fn draw<F>(&mut self, render: F) -> Result<()>
    where
        F: FnOnce(&mut Frame),
    {
        self.terminal
            .draw(render)
            .context("failed to render scan TUI")?;
        Ok(())
    }
}

impl Drop for TuiTerminal {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

#[derive(Debug)]
enum TuiEvent {
    Started { total: usize },
    Finding(FindingOutcome),
}

#[derive(Debug, Clone)]
struct RecentFinding {
    vector_id: String,
    category: String,
    subcategory: String,
    severity: Severity,
    status: FindingStatus,
    duration_ms: u128,
}

impl From<&FindingOutcome> for RecentFinding {
    fn from(finding: &FindingOutcome) -> Self {
        Self {
            vector_id: finding.vector_id.clone(),
            category: finding.category.clone(),
            subcategory: finding.subcategory.clone(),
            severity: finding.severity.clone(),
            status: finding.status,
            duration_ms: finding.duration_ms,
        }
    }
}

struct TuiState {
    target: String,
    target_type: TargetType,
    category: Option<String>,
    total_vectors: usize,
    completed_vectors: usize,
    vulnerable_count: usize,
    resistant_count: usize,
    error_count: usize,
    findings: Vec<FindingOutcome>,
    recent_findings: VecDeque<RecentFinding>,
    score: ScoreSummary,
    elapsed: Duration,
    finished: bool,
}

impl TuiState {
    fn new(settings: &ResolvedScanSettings) -> Self {
        Self {
            target: settings.target.clone(),
            target_type: settings.target_type,
            category: settings.category.clone(),
            total_vectors: 0,
            completed_vectors: 0,
            vulnerable_count: 0,
            resistant_count: 0,
            error_count: 0,
            findings: Vec::new(),
            recent_findings: VecDeque::with_capacity(MAX_RECENT_FINDINGS),
            score: score_findings(&[]),
            elapsed: Duration::default(),
            finished: false,
        }
    }

    fn apply_event(&mut self, event: TuiEvent) {
        match event {
            TuiEvent::Started { total } => {
                self.total_vectors = total;
            }
            TuiEvent::Finding(finding) => self.push_finding(finding),
        }
    }

    fn finish(&mut self, outcome: &ScanOutcome, elapsed: Duration) {
        self.total_vectors = outcome.total_vectors;
        self.completed_vectors = outcome.total_vectors;
        self.vulnerable_count = outcome.vulnerable_count;
        self.resistant_count = outcome.resistant_count;
        self.error_count = outcome.error_count;
        self.score = outcome.score.clone();
        self.elapsed = elapsed;
        self.finished = true;

        if self.recent_findings.is_empty() {
            for finding in outcome
                .findings
                .iter()
                .rev()
                .take(MAX_RECENT_FINDINGS)
                .rev()
            {
                self.push_recent(finding);
            }
        }
    }

    fn progress_ratio(&self) -> f64 {
        if self.total_vectors == 0 {
            return 0.0;
        }

        (self.completed_vectors as f64 / self.total_vectors as f64).clamp(0.0, 1.0)
    }

    fn status_label(&self) -> &'static str {
        if self.finished {
            "Completed"
        } else if self.total_vectors == 0 {
            "Preparing"
        } else {
            "Running"
        }
    }

    fn push_finding(&mut self, finding: FindingOutcome) {
        self.completed_vectors = self.completed_vectors.saturating_add(1);
        match finding.status {
            FindingStatus::Vulnerable => self.vulnerable_count += 1,
            FindingStatus::Resistant => self.resistant_count += 1,
            FindingStatus::Error => self.error_count += 1,
        }

        self.push_recent(&finding);
        self.findings.push(finding);
        self.score = score_findings(&self.findings);
    }

    fn push_recent(&mut self, finding: &FindingOutcome) {
        if self.recent_findings.len() == MAX_RECENT_FINDINGS {
            self.recent_findings.pop_front();
        }

        self.recent_findings.push_back(RecentFinding::from(finding));
    }
}

fn render(frame: &mut Frame, state: &TuiState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(5),
        ])
        .split(frame.area());

    frame.render_widget(render_summary(state), areas[0]);
    frame.render_widget(render_progress(state), areas[1]);
    frame.render_widget(render_recent_findings(state, areas[2].height), areas[2]);
    frame.render_widget(render_score(state), areas[3]);
}

fn render_summary(state: &TuiState) -> Paragraph<'_> {
    let lines = vec![
        Line::from(vec![
            Span::styled(
                "AgentPrey Scan",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                state.status_label(),
                Style::default()
                    .fg(if state.finished {
                        Color::Green
                    } else {
                        Color::Yellow
                    })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Target: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(state.target.clone()),
        ]),
        Line::from(vec![
            Span::styled("Mode: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(target_type_label(state.target_type)),
            Span::raw("    "),
            Span::styled("Category: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(state.category.as_deref().unwrap_or("auto")),
        ]),
        Line::from(vec![
            Span::styled("Vectors: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(if state.total_vectors == 0 {
                "resolving...".to_string()
            } else {
                format!("{}/{}", state.completed_vectors, state.total_vectors)
            }),
            Span::raw("    "),
            Span::styled("Elapsed: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_duration(state.elapsed)),
        ]),
    ];

    Paragraph::new(lines)
        .block(Block::default().title("Summary").borders(Borders::ALL))
        .wrap(Wrap { trim: true })
}

fn render_progress(state: &TuiState) -> Gauge<'_> {
    let label = if state.total_vectors == 0 {
        "preparing vectors".to_string()
    } else {
        format!(
            "{}/{} complete",
            state.completed_vectors, state.total_vectors
        )
    };

    Gauge::default()
        .block(Block::default().title("Progress").borders(Borders::ALL))
        .gauge_style(
            Style::default()
                .fg(if state.finished {
                    Color::Green
                } else {
                    Color::Cyan
                })
                .add_modifier(Modifier::BOLD),
        )
        .ratio(state.progress_ratio())
        .label(label)
}

fn render_recent_findings(state: &TuiState, area_height: u16) -> List<'_> {
    let visible_rows = area_height.saturating_sub(2) as usize;

    let items = if state.recent_findings.is_empty() {
        vec![ListItem::new(Line::from("Waiting for scan findings..."))]
    } else {
        state
            .recent_findings
            .iter()
            .skip(
                state
                    .recent_findings
                    .len()
                    .saturating_sub(visible_rows.max(1)),
            )
            .map(render_recent_finding)
            .collect()
    };

    List::new(items).block(
        Block::default()
            .title("Recent Findings")
            .borders(Borders::ALL),
    )
}

fn render_recent_finding(finding: &RecentFinding) -> ListItem<'_> {
    ListItem::new(Line::from(vec![
        Span::styled(
            format!("[{}]", status_tag(finding.status)),
            Style::default()
                .fg(status_color(finding.status))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            finding.vector_id.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::raw(format!(
            "{} / {}  {}  {}ms",
            finding.category,
            finding.subcategory,
            severity_label(finding.severity.clone()),
            finding.duration_ms
        )),
    ]))
}

fn render_score(state: &TuiState) -> Paragraph<'_> {
    let severity = &state.score.vulnerable_severities;
    let lines = vec![
        Line::from(vec![
            Span::styled("Results: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{} vulnerable", state.vulnerable_count),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{} resistant", state.resistant_count),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{} error", state.error_count),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Score: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(state.score.score.to_string()),
            Span::raw("  "),
            Span::styled("Grade: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                state.score.grade.to_string(),
                Style::default()
                    .fg(grade_color(state.score.grade))
                    .add_modifier(Modifier::BOLD),
            ),
            if state.finished {
                Span::raw("")
            } else {
                Span::styled("  provisional", Style::default().fg(Color::DarkGray))
            },
        ]),
        Line::from(format!(
            "Severity: critical={} high={} medium={} low={} info={}",
            severity.critical, severity.high, severity.medium, severity.low, severity.info
        )),
    ];

    Paragraph::new(lines)
        .block(Block::default().title("Score").borders(Borders::ALL))
        .wrap(Wrap { trim: true })
}

fn target_type_label(target_type: TargetType) -> &'static str {
    match target_type {
        TargetType::Http => "HTTP",
        TargetType::Openclaw => "OpenClaw",
    }
}

fn status_tag(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Vulnerable => "VULN",
        FindingStatus::Resistant => "SAFE",
        FindingStatus::Error => "ERR",
    }
}

fn status_color(status: FindingStatus) -> Color {
    match status {
        FindingStatus::Vulnerable => Color::Red,
        FindingStatus::Resistant => Color::Green,
        FindingStatus::Error => Color::Yellow,
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn grade_color(grade: Grade) -> Color {
    match grade {
        Grade::A | Grade::B => Color::Green,
        Grade::C => Color::Yellow,
        Grade::D | Grade::F => Color::Red,
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() >= 60 {
        format!(
            "{}m {:02}s",
            duration.as_secs() / 60,
            duration.as_secs() % 60
        )
    } else if duration.as_secs() >= 1 {
        format!("{}.{}s", duration.as_secs(), duration.subsec_millis() / 100)
    } else {
        format!("{}ms", duration.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use super::{RecentFinding, TuiEvent, TuiState, MAX_RECENT_FINDINGS};
    use crate::{
        cli::TargetType,
        scan::{FindingOutcome, FindingStatus, ResolvedScanSettings, ScanOutcome},
        scorer::{Grade, ScoreSummary, SeverityCounts},
        vectors::model::Severity,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn settings() -> ResolvedScanSettings {
        ResolvedScanSettings {
            target_type: TargetType::Http,
            target: "http://127.0.0.1:8787/chat".to_string(),
            http: None,
            timeout_seconds: 30,
            retries: 0,
            retry_backoff_ms: 1,
            max_concurrent: 1,
            rate_limit_rps: 10,
            redact_responses: true,
            vectors_dir: PathBuf::from("vectors"),
            category: Some("prompt-injection".to_string()),
            json_out: None,
            html_out: None,
        }
    }

    fn finding(id: usize, status: FindingStatus) -> FindingOutcome {
        FindingOutcome {
            vector_id: format!("pi-{id:03}"),
            vector_name: format!("Vector {id}"),
            category: "prompt-injection".to_string(),
            subcategory: "direct".to_string(),
            severity: Severity::High,
            payload_name: "payload".to_string(),
            payload_prompt: "prompt".to_string(),
            status,
            status_code: Some(200),
            response: "ok".to_string(),
            analysis: None,
            duration_ms: id as u128,
        }
    }

    #[test]
    fn state_accumulates_counts_from_findings() {
        let mut state = TuiState::new(&settings());
        state.apply_event(TuiEvent::Started { total: 3 });
        state.apply_event(TuiEvent::Finding(finding(1, FindingStatus::Vulnerable)));
        state.apply_event(TuiEvent::Finding(finding(2, FindingStatus::Resistant)));
        state.apply_event(TuiEvent::Finding(finding(3, FindingStatus::Error)));

        assert_eq!(state.total_vectors, 3);
        assert_eq!(state.completed_vectors, 3);
        assert_eq!(state.vulnerable_count, 1);
        assert_eq!(state.resistant_count, 1);
        assert_eq!(state.error_count, 1);
    }

    #[test]
    fn recent_findings_keep_most_recent_entries_in_order() {
        let mut state = TuiState::new(&settings());

        for id in 0..(MAX_RECENT_FINDINGS + 3) {
            state.apply_event(TuiEvent::Finding(finding(id, FindingStatus::Resistant)));
        }

        let recent = state
            .recent_findings
            .into_iter()
            .collect::<Vec<RecentFinding>>();
        assert_eq!(recent.len(), MAX_RECENT_FINDINGS);
        assert_eq!(
            recent.first().map(|finding| finding.vector_id.as_str()),
            Some("pi-003")
        );
        assert_eq!(
            recent.last().map(|finding| finding.vector_id.as_str()),
            Some("pi-014")
        );
    }

    #[test]
    fn progress_ratio_uses_completed_and_total_vectors() {
        let mut state = TuiState::new(&settings());
        state.apply_event(TuiEvent::Started { total: 4 });
        state.apply_event(TuiEvent::Finding(finding(1, FindingStatus::Resistant)));

        assert!((state.progress_ratio() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn provisional_score_updates_from_completed_findings() {
        let mut state = TuiState::new(&settings());
        state.apply_event(TuiEvent::Finding(finding(1, FindingStatus::Vulnerable)));
        state.apply_event(TuiEvent::Finding(finding(2, FindingStatus::Resistant)));

        assert_eq!(state.score.score, 90);
        assert_eq!(state.score.grade, Grade::B);
    }

    #[test]
    fn finish_reconciles_final_counts_and_marks_state_complete() {
        let mut state = TuiState::new(&settings());
        let outcome = ScanOutcome {
            target: "http://127.0.0.1:8787/chat".to_string(),
            total_vectors: 2,
            vulnerable_count: 1,
            resistant_count: 1,
            error_count: 0,
            score: ScoreSummary {
                score: 90,
                grade: Grade::B,
                vulnerable_severities: SeverityCounts {
                    critical: 0,
                    high: 1,
                    medium: 0,
                    low: 0,
                    info: 0,
                },
                error_count: 0,
            },
            findings: vec![
                finding(1, FindingStatus::Vulnerable),
                finding(2, FindingStatus::Resistant),
            ],
            duration_ms: 42,
        };

        state.finish(&outcome, Duration::from_millis(42));

        assert!(state.finished);
        assert_eq!(state.total_vectors, 2);
        assert_eq!(state.completed_vectors, 2);
        assert_eq!(state.score.score, 90);
    }
}

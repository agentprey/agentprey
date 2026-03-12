use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, IsTerminal, Stdout},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};

use crate::{
    cli::TargetType,
    cloud::upload_scan_run,
    config::DEFAULT_PROJECT_CONFIG_FILE,
    output::{html::write_scan_html, json::write_scan_json},
    scan::{
        resolve_scan_settings_from_input, run_scan_with_settings_with_reporter,
        seed_scan_settings_input_for_center, FindingOutcome, FindingStatus, ResolvedScanSettings,
        ScanOutcome, ScanSettingsInput,
    },
    scorer::{score_findings, Grade, ScoreSummary},
    vectors::model::Severity,
};

const DRAW_INTERVAL: Duration = Duration::from_millis(75);
const MAX_RECENT_FINDINGS: usize = 12;
const BORDER_COLOR: Color = Color::DarkGray;
const MUTED_COLOR: Color = Color::Gray;
const TEXT_COLOR: Color = Color::White;
const ACCENT_COLOR: Color = Color::Red;
const SUCCESS_COLOR: Color = Color::Green;
const WARNING_COLOR: Color = Color::Yellow;
const INFO_COLOR: Color = Color::Cyan;

pub async fn run_scan_with_tui(
    settings: &ResolvedScanSettings,
    upload_requested: bool,
) -> Result<ScanOutcome> {
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
                let _ = tx.send(TuiEvent::Finding(Box::new(finding.clone())));
            },
        )
        .await
    });

    let started_at = Instant::now();
    let mut state = TuiState::new(settings, upload_requested);
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
            wait_for_exit_key(&mut terminal, &state).await?;
            return Ok(outcome);
        }

        sleep(DRAW_INTERVAL).await;
    }
}

pub async fn run_control_center_with_tui(
    seed: &ScanSettingsInput,
    upload_requested: bool,
) -> Result<u8> {
    ensure_interactive_stdout()?;

    let seeded = seed_scan_settings_input_for_center(seed)?;
    let mut terminal = TuiTerminal::enter()?;
    let mut state = CenterTuiState::new(&seeded, upload_requested);
    let mut run_session: Option<CenterRunSession> = None;

    terminal.draw(|frame| render_control_center(frame, &state, run_session.as_ref()))?;

    loop {
        let mut dirty = false;

        match state.view {
            CenterView::Configure => {
                if event::poll(DRAW_INTERVAL).context("failed to poll terminal events")? {
                    match event::read().context("failed to read terminal event")? {
                        Event::Key(key) => {
                            dirty = true;
                            match state.handle_configure_key(key)? {
                                ConfigureAction::Stay => {}
                                ConfigureAction::Quit => return Ok(state.last_exit_code),
                                ConfigureAction::StartScan(input) => {
                                    let settings =
                                        match resolve_scan_settings_from_input(input.as_ref()) {
                                            Ok(settings) => settings,
                                            Err(error) => {
                                                state.set_message(error.to_string());
                                                terminal.draw(|frame| {
                                                    render_control_center(
                                                        frame,
                                                        &state,
                                                        run_session.as_ref(),
                                                    )
                                                })?;
                                                continue;
                                            }
                                        };

                                    let (tx, rx) = mpsc::unbounded_channel();
                                    let scan_settings = settings.clone();
                                    let scan_task = tokio::spawn(async move {
                                        run_scan_with_settings_with_reporter(
                                            &scan_settings,
                                            |total| {
                                                let _ = tx.send(TuiEvent::Started { total });
                                            },
                                            |finding| {
                                                let _ = tx.send(TuiEvent::Finding(Box::new(
                                                    finding.clone(),
                                                )));
                                            },
                                        )
                                        .await
                                    });

                                    run_session = Some(CenterRunSession {
                                        settings: settings.clone(),
                                        upload_requested: state.form.upload,
                                        dashboard: TuiState::new(&settings, state.form.upload),
                                        started_at: Instant::now(),
                                        rx,
                                        scan_task,
                                    });
                                    state.begin_running();
                                }
                            }
                        }
                        Event::Resize(_, _) => dirty = true,
                        _ => {}
                    }
                }
            }
            CenterView::Running => {
                if let Some(session) = run_session.as_mut() {
                    session.dashboard.elapsed = session.started_at.elapsed();

                    while let Ok(event) = session.rx.try_recv() {
                        session.dashboard.apply_event(event);
                        dirty = true;
                    }

                    let mut abort_requested = false;
                    while event::poll(Duration::from_millis(0))
                        .context("failed to poll terminal events")?
                    {
                        match event::read().context("failed to read terminal event")? {
                            Event::Key(key)
                                if key.modifiers.contains(KeyModifiers::CONTROL)
                                    && matches!(
                                        key.code,
                                        KeyCode::Char('c') | KeyCode::Char('C')
                                    ) =>
                            {
                                abort_requested = true;
                            }
                            Event::Resize(_, _) => dirty = true,
                            _ => {}
                        }
                    }

                    if abort_requested {
                        if let Some(session) = run_session.take() {
                            session.scan_task.abort();
                            let _ = session.scan_task.await;
                        }
                        state.return_to_configure("Scan aborted. Adjust settings and run again.");
                        state.last_exit_code = 2;
                        dirty = true;
                    } else if session.scan_task.is_finished() {
                        let mut session = run_session
                            .take()
                            .expect("running session should exist while finishing");
                        let outcome = match session.scan_task.await {
                            Ok(result) => result?,
                            Err(error) if error.is_cancelled() => {
                                state.return_to_configure(
                                    "Scan aborted. Adjust settings and run again.",
                                );
                                state.last_exit_code = 2;
                                terminal.draw(|frame| {
                                    render_control_center(frame, &state, run_session.as_ref())
                                })?;
                                continue;
                            }
                            Err(error) => {
                                state.return_to_configure(format!(
                                    "scan task failed unexpectedly: {error}"
                                ));
                                state.last_exit_code = 2;
                                terminal.draw(|frame| {
                                    render_control_center(frame, &state, run_session.as_ref())
                                })?;
                                continue;
                            }
                        };

                        let mut dashboard = session.dashboard;
                        while let Ok(event) = session.rx.try_recv() {
                            dashboard.apply_event(event);
                        }
                        dashboard.finish(&outcome, session.started_at.elapsed());

                        let completed = finalize_center_run(
                            &session.settings,
                            &dashboard,
                            &outcome,
                            session.upload_requested,
                        )
                        .await;
                        state.complete(completed);
                        dirty = true;
                    }
                }

                sleep(DRAW_INTERVAL).await;
            }
            CenterView::Completed => {
                if event::poll(DRAW_INTERVAL).context("failed to poll terminal events")? {
                    match event::read().context("failed to read terminal event")? {
                        Event::Key(key) => {
                            dirty = true;
                            match state.handle_completed_key(key) {
                                CompletedAction::Stay => {}
                                CompletedAction::Quit => return Ok(state.last_exit_code),
                                CompletedAction::Reconfigure => state.back_to_configure(),
                            }
                        }
                        Event::Resize(_, _) => dirty = true,
                        _ => {}
                    }
                }
            }
        }

        if dirty || matches!(state.view, CenterView::Running) {
            terminal.draw(|frame| render_control_center(frame, &state, run_session.as_ref()))?;
        }
    }
}

struct CenterRunSession {
    settings: ResolvedScanSettings,
    upload_requested: bool,
    dashboard: TuiState,
    started_at: Instant,
    rx: mpsc::UnboundedReceiver<TuiEvent>,
    scan_task: JoinHandle<Result<ScanOutcome>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CenterView {
    Configure,
    Running,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CenterField {
    TargetType,
    Target,
    Category,
    VectorsDir,
    JsonOut,
    HtmlOut,
    Upload,
    TimeoutSeconds,
    Retries,
    RetryBackoffMs,
    MaxConcurrent,
    RateLimitRps,
    RedactResponses,
    Method,
    Headers,
    RequestTemplate,
    ResponsePath,
}

impl CenterField {
    fn label(self) -> &'static str {
        match self {
            Self::TargetType => "Type",
            Self::Target => "Target",
            Self::Category => "Category",
            Self::VectorsDir => "Vectors Dir",
            Self::JsonOut => "JSON Out",
            Self::HtmlOut => "HTML Out",
            Self::Upload => "Upload",
            Self::TimeoutSeconds => "Timeout Sec",
            Self::Retries => "Retries",
            Self::RetryBackoffMs => "Backoff Ms",
            Self::MaxConcurrent => "Max Concurrent",
            Self::RateLimitRps => "Rate Limit",
            Self::RedactResponses => "Redact",
            Self::Method => "HTTP Method",
            Self::Headers => "Headers",
            Self::RequestTemplate => "Req Template",
            Self::ResponsePath => "Resp Path",
        }
    }

    fn help(self, target_type: TargetType) -> &'static str {
        match self {
            Self::TargetType => {
                "Switch between HTTP endpoint scanning, local OpenClaw audits, and local MCP descriptor audits."
            }
            Self::Target => match target_type {
                TargetType::Http => "Target endpoint URL for the live HTTP scan.",
                TargetType::Openclaw => "Local project path for the OpenClaw audit.",
                TargetType::Mcp => "Local JSON or YAML MCP descriptor file path.",
            },
            Self::Category => {
                "Optional vector category filter. Leave blank to use target-compatible defaults."
            }
            Self::VectorsDir => {
                "Optional vector root directory. Leave as 'vectors' for the bundled defaults."
            }
            Self::JsonOut => "Optional JSON artifact path. Leave blank to disable JSON output.",
            Self::HtmlOut => "Optional HTML artifact path. Leave blank to disable HTML output.",
            Self::Upload => "Toggle cloud upload after the local scan completes.",
            Self::TimeoutSeconds => "Per-request timeout in seconds for HTTP scans.",
            Self::Retries => "Retry attempts for transient HTTP request failures.",
            Self::RetryBackoffMs => "Base retry backoff in milliseconds for HTTP request failures.",
            Self::MaxConcurrent => "Maximum number of vectors executed concurrently.",
            Self::RateLimitRps => "Global HTTP request rate limit in requests per second.",
            Self::RedactResponses => "Toggle response redaction for artifacts and TUI excerpts.",
            Self::Method => "HTTP method used for the target request.",
            Self::Headers => "Semicolon-separated HTTP headers in 'Key: Value' form.",
            Self::RequestTemplate => "JSON request template containing a {{payload}} marker.",
            Self::ResponsePath => "Optional JSON pointer path for response extraction.",
        }
    }

    fn is_toggle(self) -> bool {
        matches!(
            self,
            Self::TargetType | Self::Upload | Self::RedactResponses
        )
    }

    fn section(self) -> &'static str {
        match self {
            Self::TargetType | Self::Target | Self::Category | Self::VectorsDir => "TARGETING",
            Self::JsonOut | Self::HtmlOut | Self::Upload => "ARTIFACTS",
            Self::TimeoutSeconds
            | Self::Retries
            | Self::RetryBackoffMs
            | Self::MaxConcurrent
            | Self::RateLimitRps
            | Self::RedactResponses => "EXECUTION",
            Self::Method | Self::Headers | Self::RequestTemplate | Self::ResponsePath => {
                "HTTP PROFILE"
            }
        }
    }
}

#[derive(Debug, Clone)]
struct CenterForm {
    target_type: TargetType,
    target: String,
    category: String,
    vectors_dir: String,
    json_out: String,
    html_out: String,
    upload: bool,
    timeout_seconds: String,
    retries: String,
    retry_backoff_ms: String,
    max_concurrent: String,
    rate_limit_rps: String,
    redact_responses: bool,
    method: String,
    headers: String,
    request_template: String,
    response_path: String,
}

impl CenterForm {
    fn from_seed(seed: &ScanSettingsInput, upload_requested: bool) -> Self {
        Self {
            target_type: seed.target_type.unwrap_or(TargetType::Http),
            target: seed.target.clone().unwrap_or_default(),
            category: seed.category.clone().unwrap_or_default(),
            vectors_dir: seed
                .vectors_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "vectors".to_string()),
            json_out: seed
                .json_out
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            html_out: seed
                .html_out
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            upload: upload_requested,
            timeout_seconds: seed.timeout_seconds.unwrap_or(30).to_string(),
            retries: seed.retries.unwrap_or(2).to_string(),
            retry_backoff_ms: seed.retry_backoff_ms.unwrap_or(250).to_string(),
            max_concurrent: seed.max_concurrent.unwrap_or(2).to_string(),
            rate_limit_rps: seed.rate_limit_rps.unwrap_or(10).to_string(),
            redact_responses: seed.redact_override.unwrap_or(true),
            method: seed.method.clone().unwrap_or_else(|| "POST".to_string()),
            headers: if seed.headers.is_empty() {
                String::new()
            } else {
                seed.headers.join("; ")
            },
            request_template: seed.request_template.clone().unwrap_or_default(),
            response_path: seed.response_path.clone().unwrap_or_default(),
        }
    }

    fn visible_fields(&self) -> Vec<CenterField> {
        let mut fields = vec![
            CenterField::TargetType,
            CenterField::Target,
            CenterField::Category,
            CenterField::VectorsDir,
            CenterField::JsonOut,
            CenterField::HtmlOut,
            CenterField::Upload,
            CenterField::TimeoutSeconds,
            CenterField::Retries,
            CenterField::RetryBackoffMs,
            CenterField::MaxConcurrent,
            CenterField::RateLimitRps,
            CenterField::RedactResponses,
        ];

        if self.target_type == TargetType::Http {
            fields.extend([
                CenterField::Method,
                CenterField::Headers,
                CenterField::RequestTemplate,
                CenterField::ResponsePath,
            ]);
        }

        fields
    }

    fn display_value(&self, field: CenterField) -> String {
        match field {
            CenterField::TargetType => target_type_label(self.target_type).to_string(),
            CenterField::Target => blank_or_value(&self.target, "<required>"),
            CenterField::Category => blank_or_value(&self.category, "auto"),
            CenterField::VectorsDir => blank_or_value(&self.vectors_dir, "vectors"),
            CenterField::JsonOut => blank_or_value(&self.json_out, "off"),
            CenterField::HtmlOut => blank_or_value(&self.html_out, "off"),
            CenterField::Upload => bool_label(self.upload).to_string(),
            CenterField::TimeoutSeconds => self.timeout_seconds.clone(),
            CenterField::Retries => self.retries.clone(),
            CenterField::RetryBackoffMs => self.retry_backoff_ms.clone(),
            CenterField::MaxConcurrent => self.max_concurrent.clone(),
            CenterField::RateLimitRps => self.rate_limit_rps.clone(),
            CenterField::RedactResponses => bool_label(self.redact_responses).to_string(),
            CenterField::Method => blank_or_value(&self.method, "POST"),
            CenterField::Headers => blank_or_value(&self.headers, "none"),
            CenterField::RequestTemplate => blank_or_value(&self.request_template, "default"),
            CenterField::ResponsePath => blank_or_value(&self.response_path, "default"),
        }
    }

    fn editable_value(&self, field: CenterField) -> String {
        match field {
            CenterField::Target => self.target.clone(),
            CenterField::Category => self.category.clone(),
            CenterField::VectorsDir => self.vectors_dir.clone(),
            CenterField::JsonOut => self.json_out.clone(),
            CenterField::HtmlOut => self.html_out.clone(),
            CenterField::TimeoutSeconds => self.timeout_seconds.clone(),
            CenterField::Retries => self.retries.clone(),
            CenterField::RetryBackoffMs => self.retry_backoff_ms.clone(),
            CenterField::MaxConcurrent => self.max_concurrent.clone(),
            CenterField::RateLimitRps => self.rate_limit_rps.clone(),
            CenterField::Method => self.method.clone(),
            CenterField::Headers => self.headers.clone(),
            CenterField::RequestTemplate => self.request_template.clone(),
            CenterField::ResponsePath => self.response_path.clone(),
            CenterField::TargetType | CenterField::Upload | CenterField::RedactResponses => {
                self.display_value(field)
            }
        }
    }

    fn commit_value(&mut self, field: CenterField, value: String) {
        match field {
            CenterField::Target => self.target = value.trim().to_string(),
            CenterField::Category => self.category = value.trim().to_string(),
            CenterField::VectorsDir => self.vectors_dir = value.trim().to_string(),
            CenterField::JsonOut => self.json_out = value.trim().to_string(),
            CenterField::HtmlOut => self.html_out = value.trim().to_string(),
            CenterField::TimeoutSeconds => self.timeout_seconds = value.trim().to_string(),
            CenterField::Retries => self.retries = value.trim().to_string(),
            CenterField::RetryBackoffMs => self.retry_backoff_ms = value.trim().to_string(),
            CenterField::MaxConcurrent => self.max_concurrent = value.trim().to_string(),
            CenterField::RateLimitRps => self.rate_limit_rps = value.trim().to_string(),
            CenterField::Method => self.method = value.trim().to_string(),
            CenterField::Headers => self.headers = value.trim().to_string(),
            CenterField::RequestTemplate => self.request_template = value.trim().to_string(),
            CenterField::ResponsePath => self.response_path = value.trim().to_string(),
            CenterField::TargetType | CenterField::Upload | CenterField::RedactResponses => {}
        }
    }

    fn toggle(&mut self, field: CenterField) {
        match field {
            CenterField::TargetType => {
                self.target_type = match self.target_type {
                    TargetType::Http => TargetType::Openclaw,
                    TargetType::Openclaw => TargetType::Mcp,
                    TargetType::Mcp => TargetType::Http,
                };

                if self.target_type == TargetType::Openclaw {
                    if !self.category.eq_ignore_ascii_case("openclaw") {
                        self.category = "openclaw".to_string();
                    }
                } else if self.target_type == TargetType::Mcp {
                    if !self.category.eq_ignore_ascii_case("mcp-security") {
                        self.category = "mcp-security".to_string();
                    }
                } else if self.category.eq_ignore_ascii_case("openclaw")
                    || self.category.eq_ignore_ascii_case("mcp-security")
                {
                    self.category.clear();
                }
            }
            CenterField::Upload => self.upload = !self.upload,
            CenterField::RedactResponses => self.redact_responses = !self.redact_responses,
            _ => {}
        }
    }

    fn to_scan_input(&self) -> Result<ScanSettingsInput> {
        Ok(ScanSettingsInput {
            target: non_empty_string(&self.target),
            target_type: Some(self.target_type),
            headers: parse_headers(&self.headers),
            method: if self.target_type == TargetType::Http {
                non_empty_string(&self.method)
            } else {
                None
            },
            request_template: if self.target_type == TargetType::Http {
                non_empty_string(&self.request_template)
            } else {
                None
            },
            response_path: if self.target_type == TargetType::Http {
                non_empty_string(&self.response_path)
            } else {
                None
            },
            timeout_seconds: Some(parse_u64_field(
                &self.timeout_seconds,
                CenterField::TimeoutSeconds,
            )?),
            vectors_dir: Some(PathBuf::from(blank_or_default(
                &self.vectors_dir,
                "vectors",
            ))),
            category: non_empty_string(&self.category),
            json_out: non_empty_path(&self.json_out),
            html_out: non_empty_path(&self.html_out),
            config: None,
            retries: Some(parse_u32_field(&self.retries, CenterField::Retries)?),
            retry_backoff_ms: Some(parse_u64_field(
                &self.retry_backoff_ms,
                CenterField::RetryBackoffMs,
            )?),
            max_concurrent: Some(parse_usize_field(
                &self.max_concurrent,
                CenterField::MaxConcurrent,
            )?),
            rate_limit_rps: Some(parse_u32_field(
                &self.rate_limit_rps,
                CenterField::RateLimitRps,
            )?),
            redact_override: Some(self.redact_responses),
        })
    }
}

#[derive(Debug, Clone)]
struct CenterCompletedState {
    dashboard: TuiState,
    json_written: Option<String>,
    html_written: Option<String>,
    upload_requested: bool,
    scan_run_id: Option<String>,
    share_id: Option<String>,
    share_url: Option<String>,
    finalization_error: Option<String>,
    exit_code: u8,
}

impl CenterCompletedState {
    fn banner(&self) -> CompletionBanner {
        if let Some(error) = self.finalization_error.as_ref() {
            return CompletionBanner {
                title: "FINALIZATION WARNING",
                detail: compact_excerpt(error, 120),
                guidance:
                    "Local scan results are shown below, but at least one output step failed."
                        .to_string(),
                tone: PanelTone::Warning,
            };
        }

        self.dashboard.completion_banner()
    }
}

#[derive(Debug, Clone)]
struct CenterTuiState {
    view: CenterView,
    form: CenterForm,
    selected_field: usize,
    editing: bool,
    edit_buffer: String,
    source_label: String,
    message: Option<String>,
    completed: Option<CenterCompletedState>,
    last_exit_code: u8,
}

impl CenterTuiState {
    fn new(seed: &ScanSettingsInput, upload_requested: bool) -> Self {
        let source_label = if let Some(path) = seed.config.as_ref() {
            format!("CONFIG {}", path.display())
        } else if PathBuf::from(DEFAULT_PROJECT_CONFIG_FILE).exists() {
            format!("CONFIG {}", DEFAULT_PROJECT_CONFIG_FILE)
        } else {
            "CONFIG BUILT-IN DEFAULTS".to_string()
        };

        Self {
            view: CenterView::Configure,
            form: CenterForm::from_seed(seed, upload_requested),
            selected_field: 0,
            editing: false,
            edit_buffer: String::new(),
            source_label,
            message: Some("Review the configuration, then press Ctrl+R to start the scan.".into()),
            completed: None,
            last_exit_code: 0,
        }
    }

    fn begin_running(&mut self) {
        self.view = CenterView::Running;
        self.editing = false;
        self.edit_buffer.clear();
        self.completed = None;
        self.message = Some("Scan in progress. Press Ctrl+C to abort.".into());
    }

    fn complete(&mut self, completed: CenterCompletedState) {
        self.last_exit_code = completed.exit_code;
        self.view = CenterView::Completed;
        self.editing = false;
        self.edit_buffer.clear();
        self.message = if let Some(error) = completed.finalization_error.as_ref() {
            Some(error.clone())
        } else {
            Some("Scan complete. Press r to reconfigure or q to exit.".into())
        };
        self.completed = Some(completed);
    }

    fn back_to_configure(&mut self) {
        self.view = CenterView::Configure;
        self.editing = false;
        self.edit_buffer.clear();
        self.completed = None;
        self.message = Some("Configuration restored. Press Ctrl+R to run again.".into());
        self.clamp_selection();
    }

    fn return_to_configure<T: Into<String>>(&mut self, message: T) {
        self.view = CenterView::Configure;
        self.editing = false;
        self.edit_buffer.clear();
        self.completed = None;
        self.message = Some(message.into());
        self.clamp_selection();
    }

    fn set_message<T: Into<String>>(&mut self, message: T) {
        self.message = Some(message.into());
    }

    fn selected_field(&self) -> CenterField {
        let fields = self.form.visible_fields();
        fields[self.selected_field.min(fields.len().saturating_sub(1))]
    }

    fn clamp_selection(&mut self) {
        let max_index = self.form.visible_fields().len().saturating_sub(1);
        self.selected_field = self.selected_field.min(max_index);
    }

    fn move_selection(&mut self, delta: isize) {
        let fields = self.form.visible_fields();
        if fields.is_empty() {
            self.selected_field = 0;
            return;
        }

        let len = fields.len() as isize;
        let current = self.selected_field as isize;
        self.selected_field = (current + delta).rem_euclid(len) as usize;
    }

    fn handle_configure_key(&mut self, key: KeyEvent) -> Result<ConfigureAction> {
        if self.editing {
            return Ok(self.handle_editing_key(key));
        }

        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                self.move_selection(1);
                Ok(ConfigureAction::Stay)
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.move_selection(-1);
                Ok(ConfigureAction::Stay)
            }
            KeyCode::Esc => Ok(ConfigureAction::Quit),
            KeyCode::Char('r') | KeyCode::Char('R')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                Ok(ConfigureAction::StartScan(Box::new(
                    self.form.to_scan_input()?,
                )))
            }
            KeyCode::Enter => {
                let field = self.selected_field();
                if field.is_toggle() {
                    self.form.toggle(field);
                    self.clamp_selection();
                } else {
                    self.editing = true;
                    self.edit_buffer = self.form.editable_value(field);
                }
                Ok(ConfigureAction::Stay)
            }
            KeyCode::Char(' ') => {
                let field = self.selected_field();
                if field.is_toggle() {
                    self.form.toggle(field);
                    self.clamp_selection();
                }
                Ok(ConfigureAction::Stay)
            }
            _ => Ok(ConfigureAction::Stay),
        }
    }

    fn handle_editing_key(&mut self, key: KeyEvent) -> ConfigureAction {
        match key.code {
            KeyCode::Enter => {
                let field = self.selected_field();
                let value = std::mem::take(&mut self.edit_buffer);
                self.form.commit_value(field, value);
                self.editing = false;
            }
            KeyCode::Esc => {
                self.editing = false;
                self.edit_buffer.clear();
            }
            KeyCode::Backspace => {
                self.edit_buffer.pop();
            }
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.edit_buffer.push(ch);
            }
            _ => {}
        }
        ConfigureAction::Stay
    }

    fn handle_completed_key(&mut self, key: KeyEvent) -> CompletedAction {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => CompletedAction::Quit,
            KeyCode::Char('r') | KeyCode::Char('R') => CompletedAction::Reconfigure,
            KeyCode::Char('c') | KeyCode::Char('C')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                CompletedAction::Quit
            }
            _ => CompletedAction::Stay,
        }
    }
}

#[derive(Debug, Clone)]
enum ConfigureAction {
    Stay,
    Quit,
    StartScan(Box<ScanSettingsInput>),
}

#[derive(Debug, Clone, Copy)]
enum CompletedAction {
    Stay,
    Quit,
    Reconfigure,
}

async fn finalize_center_run(
    settings: &ResolvedScanSettings,
    dashboard: &TuiState,
    outcome: &ScanOutcome,
    upload_requested: bool,
) -> CenterCompletedState {
    let mut finalization_error = None;
    let mut scan_run_id = None;
    let mut share_id = None;
    let mut share_url = None;
    let mut json_written = None;
    let mut html_written = None;

    if let Some(path) = settings.json_out.as_deref() {
        match write_scan_json(path, outcome) {
            Ok(()) => {
                json_written = Some(path.display().to_string());
            }
            Err(error) => {
                finalization_error = Some(format!("failed to write JSON output: {error}"));
            }
        }
    }

    if finalization_error.is_none() {
        if let Some(path) = settings.html_out.as_deref() {
            match write_scan_html(path, outcome) {
                Ok(()) => {
                    html_written = Some(path.display().to_string());
                }
                Err(error) => {
                    finalization_error = Some(format!("failed to write HTML output: {error}"));
                }
            }
        }
    }

    if finalization_error.is_none() && upload_requested {
        match upload_scan_run(settings, outcome).await {
            Ok(response) => {
                scan_run_id = Some(response.scan_run_id);
                share_id = Some(response.share_id);
                share_url = response.share_url;
            }
            Err(error) => {
                finalization_error = Some(format!("failed to upload scan artifact: {error}"));
            }
        }
    }

    CenterCompletedState {
        dashboard: dashboard.clone(),
        json_written,
        html_written,
        upload_requested,
        scan_run_id,
        share_id,
        share_url,
        exit_code: completion_exit_code(outcome, finalization_error.is_some()),
        finalization_error,
    }
}

fn render_control_center(
    frame: &mut Frame,
    state: &CenterTuiState,
    run_session: Option<&CenterRunSession>,
) {
    match state.view {
        CenterView::Configure => render_center_configure(frame, state),
        CenterView::Running => {
            if let Some(session) = run_session {
                render(frame, &session.dashboard);
            } else {
                render_center_configure(frame, state);
            }
        }
        CenterView::Completed => render_center_completed(frame, state),
    }
}

fn render_center_configure(frame: &mut Frame, state: &CenterTuiState) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        area,
    );

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(0),
            Constraint::Length(4),
        ])
        .split(area);
    render_center_header(frame, state, sections[0], "CONTROL CENTER");

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(sections[1]);

    render_center_form(frame, state, body[0]);
    render_center_help(frame, state, body[1]);
    render_center_footer(
        frame,
        state,
        sections[2],
        "[esc] quit  [tab/arrows] move  [enter] edit/toggle  [ctrl+r] run",
    );
}

fn render_center_completed(frame: &mut Frame, state: &CenterTuiState) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        area,
    );

    let Some(completed) = state.completed.as_ref() else {
        render_center_configure(frame, state);
        return;
    };

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Min(0),
            Constraint::Length(4),
        ])
        .split(area);

    render_center_header(frame, state, sections[0], "CONTROL CENTER");
    render_completion_banner_panel(frame, &completed.banner(), sections[1], completed.exit_code);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(sections[2]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(10)])
        .split(body[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(12)])
        .split(body[1]);

    render_dashboard_summary(frame, &completed.dashboard, left[0]);
    render_completion_metadata(frame, completed, left[1]);
    render_execution_log(frame, &completed.dashboard, right[0]);
    render_featured_panel(frame, &completed.dashboard, right[1], true);
    render_center_footer(frame, state, sections[3], "[r] reconfigure  [q] quit");
}

fn render_center_header(frame: &mut Frame, state: &CenterTuiState, area: Rect, status: &str) {
    let source = truncate_text(&state.source_label, area.width.saturating_sub(30) as usize);
    let target_preview = truncate_text(
        &blank_or_value(&state.form.target, "<unset>"),
        area.width.saturating_sub(38) as usize,
    );
    let tone = match state.view {
        CenterView::Configure => PanelTone::Info,
        CenterView::Running => PanelTone::Critical,
        CenterView::Completed => state
            .completed
            .as_ref()
            .map(|completed| completed.banner().tone)
            .unwrap_or(PanelTone::Neutral),
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("TARGET: ", label_style()),
            Span::styled(target_preview, Style::default().fg(INFO_COLOR)),
            Span::raw("    "),
            Span::styled("MODE: ", label_style()),
            Span::styled(target_type_label(state.form.target_type), body_style()),
        ]),
        Line::from(vec![
            Span::styled("SOURCE: ", label_style()),
            Span::styled(source, muted_style()),
            Span::raw("    "),
            Span::styled("STATUS: ", label_style()),
            Span::styled(status, emphasis_style(tone)),
            Span::raw("    "),
            Span::styled("UPLOAD: ", label_style()),
            Span::styled(bool_label(state.form.upload).to_uppercase(), body_style()),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(titled_panel("OPERATOR CONSOLE", tone)),
        area,
    );
}

fn render_center_form(frame: &mut Frame, state: &CenterTuiState, area: Rect) {
    let mut lines = Vec::new();
    let mut current_section = "";

    for (index, field) in state.form.visible_fields().into_iter().enumerate() {
        if field.section() != current_section {
            if !lines.is_empty() {
                lines.push(Line::default());
            }
            current_section = field.section();
            lines.push(Line::from(Span::styled(
                current_section,
                emphasis_style(PanelTone::Info),
            )));
        }

        let selected = index == state.selected_field;
        let value = if selected && state.editing {
            format!("{}█", state.edit_buffer)
        } else {
            state.form.display_value(field)
        };

        let prefix_style = if selected {
            Style::default()
                .fg(ACCENT_COLOR)
                .add_modifier(Modifier::BOLD)
        } else {
            muted_style()
        };
        let value_style = if selected {
            emphasis_style(PanelTone::Info)
        } else {
            body_style()
        };

        lines.push(Line::from(vec![
            Span::styled(if selected { "▶ " } else { "  " }, prefix_style),
            Span::styled(
                format!("{:<13}", field.label().to_uppercase()),
                label_style(),
            ),
            Span::styled(
                truncate_text(&value, area.width.saturating_sub(20) as usize),
                value_style,
            ),
        ]));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(titled_panel("RUN CONFIGURATION", PanelTone::Neutral))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_center_help(frame: &mut Frame, state: &CenterTuiState, area: Rect) {
    let field = state.selected_field();
    let mode_copy = if state.editing {
        "EDIT BUFFER ACTIVE"
    } else {
        "NAVIGATION READY"
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("FIELD: ", label_style()),
            Span::styled(
                field.label().to_uppercase(),
                emphasis_style(PanelTone::Info),
            ),
        ]),
        Line::from(Span::styled(
            field.help(state.form.target_type),
            muted_style(),
        )),
        Line::default(),
        Line::from(vec![
            Span::styled("CONSOLE: ", label_style()),
            Span::styled(mode_copy, body_style()),
        ]),
        Line::from(Span::styled(
            format!(
                "PROFILE  {}  |  REDACTION  {}",
                target_type_label(state.form.target_type),
                bool_label(state.form.redact_responses).to_uppercase()
            ),
            muted_style(),
        )),
        Line::from(Span::styled(
            format!(
                "ARTIFACTS  JSON:{}  HTML:{}  UPLOAD:{}",
                bool_label(!state.form.json_out.trim().is_empty()).to_uppercase(),
                bool_label(!state.form.html_out.trim().is_empty()).to_uppercase(),
                bool_label(state.form.upload).to_uppercase()
            ),
            muted_style(),
        )),
        Line::default(),
        Line::from(Span::styled(
            "tab/backtab or arrows move between fields",
            muted_style(),
        )),
        Line::from(Span::styled(
            "enter edits text fields; enter/space toggles switches",
            muted_style(),
        )),
        Line::from(Span::styled(
            "ctrl+r starts a scan from this form",
            muted_style(),
        )),
        Line::from(Span::styled(
            "openclaw hides HTTP-only fields automatically",
            muted_style(),
        )),
    ];

    if state.form.upload {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Upload is enabled. Completion will attempt cloud upload after local artifacts are written.",
            muted_style(),
        )));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(titled_panel("FIELD GUIDE", PanelTone::Info))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_completion_metadata(frame: &mut Frame, completed: &CenterCompletedState, area: Rect) {
    let mut lines = vec![
        render_finding_meta_line(
            "JSON",
            completed
                .json_written
                .clone()
                .unwrap_or_else(|| "off".to_string()),
            output_style(completed.json_written.is_some()),
        ),
        render_finding_meta_line(
            "HTML",
            completed
                .html_written
                .clone()
                .unwrap_or_else(|| "off".to_string()),
            output_style(completed.html_written.is_some()),
        ),
        render_finding_meta_line(
            "UPLOAD",
            if completed.upload_requested {
                "requested".to_string()
            } else {
                "off".to_string()
            },
            output_style(completed.upload_requested),
        ),
        render_finding_meta_line(
            "EXIT",
            completed.exit_code.to_string(),
            if completed.exit_code == 0 {
                output_style(true)
            } else {
                emphasis_style(PanelTone::Warning)
            },
        ),
    ];

    if let Some(scan_run_id) = completed.scan_run_id.as_ref() {
        lines.push(render_finding_meta_line(
            "RUN ID",
            scan_run_id.clone(),
            body_style(),
        ));
    }
    if let Some(share_id) = completed.share_id.as_ref() {
        lines.push(render_finding_meta_line(
            "SHARE ID",
            share_id.clone(),
            body_style(),
        ));
    }
    if let Some(share_url) = completed.share_url.as_ref() {
        lines.push(render_finding_meta_line(
            "SHARE URL",
            truncate_text(share_url, area.width.saturating_sub(13) as usize),
            body_style(),
        ));
    }
    if let Some(error) = completed.finalization_error.as_ref() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("ERROR", label_style())));
        lines.push(Line::from(Span::styled(
            compact_excerpt(error, area.width.saturating_sub(4) as usize),
            status_style(FindingStatus::Error),
        )));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(titled_panel(
                "ARTIFACT FINALIZATION",
                completed.banner().tone,
            ))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_center_footer(frame: &mut Frame, state: &CenterTuiState, area: Rect, controls: &str) {
    let message = state
        .message
        .clone()
        .unwrap_or_else(|| "AgentPrey control center ready.".to_string());
    let lines = vec![
        Line::from(Span::styled(controls, muted_style())),
        Line::from(Span::styled(
            compact_excerpt(&message, area.width.saturating_sub(4) as usize),
            if matches!(state.view, CenterView::Completed) {
                body_style()
            } else {
                muted_style()
            },
        )),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(titled_panel("COMMAND LANE", PanelTone::Neutral)),
        area,
    );
}

fn completion_exit_code(outcome: &ScanOutcome, finalization_failed: bool) -> u8 {
    if finalization_failed || outcome.error_count > 0 {
        2
    } else if outcome.has_vulnerabilities() {
        1
    } else {
        0
    }
}

fn blank_or_value(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn blank_or_default<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn bool_label(enabled: bool) -> &'static str {
    if enabled {
        "on"
    } else {
        "off"
    }
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn non_empty_path(value: &str) -> Option<PathBuf> {
    non_empty_string(value).map(PathBuf::from)
}

fn parse_headers(value: &str) -> Vec<String> {
    value
        .split(['\n', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_u64_field(value: &str, field: CenterField) -> Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{} must be a non-negative integer", field.label()))
}

fn parse_u32_field(value: &str, field: CenterField) -> Result<u32> {
    value
        .trim()
        .parse::<u32>()
        .with_context(|| format!("{} must be a non-negative integer", field.label()))
}

fn parse_usize_field(value: &str, field: CenterField) -> Result<usize> {
    value
        .trim()
        .parse::<usize>()
        .with_context(|| format!("{} must be a non-negative integer", field.label()))
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
            if is_exit_key(&key) && key.modifiers.contains(KeyModifiers::CONTROL) {
                scan_task.abort();
                return Ok(true);
            }
        }
    }

    Ok(false)
}

async fn wait_for_exit_key(terminal: &mut TuiTerminal, state: &TuiState) -> Result<()> {
    loop {
        if event::poll(DRAW_INTERVAL).context("failed to poll terminal events")? {
            match event::read().context("failed to read terminal event")? {
                Event::Key(key) if is_exit_key(&key) => return Ok(()),
                Event::Resize(_, _) => terminal.draw(|frame| render(frame, state))?,
                _ => {}
            }
        }

        sleep(DRAW_INTERVAL).await;
    }
}

fn is_exit_key(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'))
        || (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')))
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
    Finding(Box<FindingOutcome>),
}

#[derive(Debug, Clone)]
struct RecentFinding {
    vector_id: String,
    vector_name: String,
    category: String,
    subcategory: String,
    severity: Severity,
    status: FindingStatus,
    duration_ms: u128,
    response: String,
    indicator_hits: Vec<String>,
    evidence_summary: String,
    recommendation: String,
}

impl From<&FindingOutcome> for RecentFinding {
    fn from(finding: &FindingOutcome) -> Self {
        Self {
            vector_id: finding.vector_id.clone(),
            vector_name: finding.vector_name.clone(),
            category: finding.category.clone(),
            subcategory: finding.subcategory.clone(),
            severity: finding.severity.clone(),
            status: finding.status,
            duration_ms: finding.duration_ms,
            response: finding.response.clone(),
            indicator_hits: finding
                .analysis
                .as_ref()
                .map(|analysis| analysis.indicator_hits.clone())
                .unwrap_or_default(),
            evidence_summary: finding.evidence_summary.clone(),
            recommendation: finding.recommendation.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct SegmentSummary {
    label: String,
    total: usize,
    resistant: usize,
}

impl SegmentSummary {
    fn pct(&self) -> usize {
        if self.total == 0 {
            0
        } else {
            (self.resistant * 100) / self.total
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PanelTone {
    Neutral,
    Info,
    Warning,
    Critical,
    Success,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletionBanner {
    title: &'static str,
    detail: String,
    guidance: String,
    tone: PanelTone,
}

#[derive(Debug, Clone)]
struct TimelineEntry {
    sequence: usize,
    status: FindingStatus,
    severity: Severity,
    vector_label: String,
    area_label: String,
    duration_label: String,
}

#[derive(Debug, Clone)]
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
    json_out: Option<String>,
    html_out: Option<String>,
    upload_requested: bool,
}

impl TuiState {
    fn new(settings: &ResolvedScanSettings, upload_requested: bool) -> Self {
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
            json_out: settings
                .json_out
                .as_ref()
                .map(|path| path.display().to_string()),
            html_out: settings
                .html_out
                .as_ref()
                .map(|path| path.display().to_string()),
            upload_requested,
        }
    }

    fn apply_event(&mut self, event: TuiEvent) {
        match event {
            TuiEvent::Started { total } => {
                self.total_vectors = total;
            }
            TuiEvent::Finding(finding) => self.push_finding(*finding),
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

    fn pending_vectors(&self) -> usize {
        self.total_vectors.saturating_sub(self.completed_vectors)
    }

    fn status_label(&self) -> &'static str {
        if self.finished {
            "SCAN COMPLETE"
        } else if self.total_vectors == 0 {
            "PRIMING VECTORS"
        } else {
            "SCANNING LIVE"
        }
    }

    fn tone(&self) -> PanelTone {
        if self.finished {
            if self.error_count > 0 && self.vulnerable_count > 0 {
                PanelTone::Critical
            } else if self.error_count > 0 {
                PanelTone::Warning
            } else if self.vulnerable_count > 0 {
                PanelTone::Critical
            } else {
                PanelTone::Success
            }
        } else if self.total_vectors == 0 {
            PanelTone::Info
        } else {
            PanelTone::Critical
        }
    }

    fn progress_label(&self) -> String {
        if self.total_vectors == 0 {
            "vector catalog pending".to_string()
        } else if self.finished {
            format!(
                "{}/{} vectors settled",
                self.completed_vectors, self.total_vectors
            )
        } else {
            format!(
                "{}/{} settled  {}/{} pending",
                self.completed_vectors,
                self.total_vectors,
                self.pending_vectors(),
                self.total_vectors
            )
        }
    }

    fn completion_banner(&self) -> CompletionBanner {
        if self.error_count > 0 && self.vulnerable_count > 0 {
            return CompletionBanner {
                title: "EXPOSURES AND ERRORS DETECTED",
                detail: format!(
                    "{} vulnerable, {} resistant, {} errors across {} vectors in {}.",
                    self.vulnerable_count,
                    self.resistant_count,
                    self.error_count,
                    self.total_vectors,
                    format_duration(self.elapsed)
                ),
                guidance: "Review the primary signal and artifact outputs before closing."
                    .to_string(),
                tone: PanelTone::Critical,
            };
        }

        if self.error_count > 0 {
            return CompletionBanner {
                title: "RUN COMPLETED WITH ERRORS",
                detail: format!(
                    "{} resistant, {} errors across {} vectors in {}.",
                    self.resistant_count,
                    self.error_count,
                    self.total_vectors,
                    format_duration(self.elapsed)
                ),
                guidance: "Inspect runtime failures before treating this run as clean.".to_string(),
                tone: PanelTone::Warning,
            };
        }

        if self.vulnerable_count > 0 {
            return CompletionBanner {
                title: "EXPOSURES DETECTED",
                detail: format!(
                    "{} vulnerable, {} resistant across {} vectors in {}.",
                    self.vulnerable_count,
                    self.resistant_count,
                    self.total_vectors,
                    format_duration(self.elapsed)
                ),
                guidance: "Escalate the featured signal and use the artifacts for repro."
                    .to_string(),
                tone: PanelTone::Critical,
            };
        }

        CompletionBanner {
            title: "RESISTANCE HOLDING",
            detail: format!(
                "{} vectors completed in {} with no exposures or runtime errors.",
                self.total_vectors,
                format_duration(self.elapsed)
            ),
            guidance: "Capture the clean result and continue to the next target.".to_string(),
            tone: PanelTone::Success,
        }
    }

    fn preview_exit_code(&self) -> u8 {
        if self.error_count > 0 {
            2
        } else if self.vulnerable_count > 0 {
            1
        } else {
            0
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

    fn timeline_entries(&self, limit: usize) -> Vec<TimelineEntry> {
        if limit == 0 {
            return Vec::new();
        }

        let total_recent = self.recent_findings.len();
        let first_sequence = self.completed_vectors.saturating_sub(total_recent) + 1;

        self.recent_findings
            .iter()
            .enumerate()
            .rev()
            .take(limit)
            .map(|(index, finding)| TimelineEntry {
                sequence: first_sequence + index,
                status: finding.status,
                severity: finding.severity.clone(),
                vector_label: format!("{} ({})", finding.vector_name, finding.vector_id),
                area_label: format!("{}/{}", finding.category, finding.subcategory),
                duration_label: compact_duration(finding.duration_ms),
            })
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    fn segment_summaries(&self) -> Vec<SegmentSummary> {
        let mut grouped: BTreeMap<String, SegmentSummary> = BTreeMap::new();

        for finding in &self.findings {
            let entry = grouped
                .entry(finding.subcategory.clone())
                .or_insert_with(|| SegmentSummary {
                    label: finding.subcategory.clone(),
                    total: 0,
                    resistant: 0,
                });
            entry.total += 1;
            if matches!(finding.status, FindingStatus::Resistant) {
                entry.resistant += 1;
            }
        }

        let mut segments = grouped.into_values().collect::<Vec<_>>();
        segments.sort_by(|left, right| {
            segment_priority(&left.label)
                .cmp(&segment_priority(&right.label))
                .then_with(|| right.total.cmp(&left.total))
                .then_with(|| left.label.cmp(&right.label))
        });
        segments.truncate(3);
        segments
    }

    fn featured_finding(&self) -> Option<&FindingOutcome> {
        self.findings
            .iter()
            .filter(|finding| matches!(finding.status, FindingStatus::Vulnerable))
            .max_by_key(|finding| severity_rank(&finding.severity))
            .or_else(|| {
                self.findings
                    .iter()
                    .rfind(|finding| matches!(finding.status, FindingStatus::Error))
            })
            .or_else(|| self.findings.iter().next_back())
    }
}

fn render(frame: &mut Frame, state: &TuiState) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        area,
    );

    render_dashboard(frame, state, area);
}

fn render_dashboard(frame: &mut Frame, state: &TuiState, area: Rect) {
    if state.finished && area.width >= 88 && area.height >= 24 {
        render_completion_dashboard(frame, state, area);
        return;
    }

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(area);
    render_dashboard_header(frame, state, sections[0]);

    if area.width >= 100 && area.height >= 24 {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(sections[1]);
        let left = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(11),
                Constraint::Length(10),
                Constraint::Length(6),
            ])
            .split(body[0]);
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(10), Constraint::Length(12)])
            .split(body[1]);

        render_dashboard_summary(frame, state, left[0]);
        render_progress_panel(frame, state, left[1]);
        render_dashboard_footer(frame, state, left[2]);
        render_execution_log(frame, state, right[0]);
        render_featured_panel(frame, state, right[1], false);
        return;
    }

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(11),
            Constraint::Length(10),
            Constraint::Min(8),
            Constraint::Length(12),
            Constraint::Length(6),
        ])
        .split(sections[1]);

    render_dashboard_summary(frame, state, body[0]);
    render_progress_panel(frame, state, body[1]);
    render_execution_log(frame, state, body[2]);
    render_featured_panel(frame, state, body[3], false);
    render_dashboard_footer(frame, state, body[4]);
}

fn render_dashboard_header(frame: &mut Frame, state: &TuiState, area: Rect) {
    let lines = vec![
        Line::from(vec![
            Span::styled("TARGET: ", label_style()),
            Span::styled(
                truncate_text(&state.target, area.width.saturating_sub(38) as usize),
                Style::default().fg(INFO_COLOR),
            ),
            Span::raw("    "),
            Span::styled("MODE: ", label_style()),
            Span::styled(target_type_label(state.target_type), body_style()),
        ]),
        Line::from(vec![
            Span::styled("FILTER: ", label_style()),
            Span::styled(state.category.as_deref().unwrap_or("auto"), muted_style()),
            Span::raw("    "),
            Span::styled("STATUS: ", label_style()),
            Span::styled(state.status_label(), dashboard_status_style(state)),
            Span::raw("    "),
            Span::styled("POSTURE: ", label_style()),
            Span::styled(
                format!("{} / {}", state.score.grade, state.score.score),
                emphasis_style(state.tone()),
            ),
        ]),
        Line::from(vec![
            Span::styled("PROGRESS: ", label_style()),
            Span::styled(state.progress_label(), body_style()),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(titled_panel("SCAN CONSOLE", state.tone())),
        area,
    );
}

fn render_dashboard_summary(frame: &mut Frame, state: &TuiState, area: Rect) {
    let segments = state.segment_summaries();

    let mut lines = vec![
        Line::from(vec![
            Span::styled("GRADE:", label_style()),
            Span::raw(" "),
            Span::styled(
                state.score.grade.to_string(),
                grade_style(state.score.grade),
            ),
            Span::raw("  "),
            Span::styled("SCORE:", label_style()),
            Span::raw(" "),
            Span::styled(format!("{}/100", state.score.score), primary_metric_style()),
        ]),
        Line::from(vec![
            Span::styled("VULNERABLE:", label_style()),
            Span::raw(" "),
            Span::styled(
                state.vulnerable_count.to_string(),
                status_style(FindingStatus::Vulnerable),
            ),
            Span::raw("  "),
            Span::styled("RESISTANT:", label_style()),
            Span::raw(" "),
            Span::styled(
                state.resistant_count.to_string(),
                status_style(FindingStatus::Resistant),
            ),
            Span::raw("  "),
            Span::styled("ERRORS:", label_style()),
            Span::raw(" "),
            Span::styled(
                state.error_count.to_string(),
                status_style(FindingStatus::Error),
            ),
        ]),
        Line::from(vec![
            Span::styled("ELAPSED:", label_style()),
            Span::raw(" "),
            Span::styled(format_duration(state.elapsed), body_style()),
            Span::raw("  "),
            Span::styled("STATE:", label_style()),
            Span::raw(" "),
            Span::styled(
                if state.finished { "FINAL" } else { "LIVE" },
                if state.finished {
                    body_style()
                } else {
                    emphasis_style(PanelTone::Info)
                },
            ),
        ]),
        Line::default(),
    ];

    for segment in segments.iter().take(3) {
        lines.push(render_segment_line(segment));
    }

    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled("SEVERITY:", label_style()),
        Span::raw(" "),
        severity_count_span(
            "CRIT",
            state.score.vulnerable_severities.critical,
            ACCENT_COLOR,
        ),
        Span::raw("  "),
        severity_count_span("HIGH", state.score.vulnerable_severities.high, ACCENT_COLOR),
        Span::raw("  "),
        severity_count_span(
            "MED",
            state.score.vulnerable_severities.medium,
            WARNING_COLOR,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("POSTURE:", label_style()),
        Span::raw(" "),
        progress_bar_line(state.progress_ratio(), state.finished),
    ]));

    frame.render_widget(
        Paragraph::new(lines).block(titled_panel("SCORECARD", state.tone())),
        area,
    );
}

fn render_progress_panel(frame: &mut Frame, state: &TuiState, area: Rect) {
    let progress_width = area.width.saturating_sub(14).clamp(10, 28) as usize;
    let mut lines = vec![
        Line::from(vec![
            Span::styled("STAGE:", label_style()),
            Span::raw(" "),
            Span::styled(state.status_label(), emphasis_style(state.tone())),
        ]),
        Line::from(vec![
            Span::styled("FLOW:", label_style()),
            Span::raw(" "),
            progress_meter_line(state.progress_ratio(), state.finished, progress_width),
        ]),
        Line::from(vec![
            Span::styled("COUNT:", label_style()),
            Span::raw(" "),
            Span::styled(state.progress_label(), body_style()),
        ]),
        Line::from(vec![
            Span::styled("SIGNALS:", label_style()),
            Span::raw(" "),
            Span::styled(
                format!(
                    "vuln {}  resistant {}  errors {}  pending {}",
                    state.vulnerable_count,
                    state.resistant_count,
                    state.error_count,
                    state.pending_vectors()
                ),
                body_style(),
            ),
        ]),
        Line::default(),
    ];

    if state.recent_findings.is_empty() {
        lines.push(Line::from(Span::styled(
            "No vector results yet. The pipeline view will populate as findings settle.",
            muted_style(),
        )));
    } else {
        for finding in state.recent_findings.iter().rev().take(3).rev() {
            lines.push(Line::from(vec![
                Span::styled(status_marker(finding.status), status_style(finding.status)),
                Span::raw(" "),
                Span::styled(
                    truncate_text(&finding.vector_id, area.width.saturating_sub(10) as usize),
                    body_style(),
                ),
                Span::raw(" "),
                Span::styled(
                    compact_duration(finding.duration_ms),
                    severity_style(&finding.severity),
                ),
            ]));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(titled_panel("PIPELINE", state.tone()))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_dashboard_footer(frame: &mut Frame, state: &TuiState, area: Rect) {
    let exit_copy = if state.finished {
        "[q] quit  [ctrl+c] close"
    } else {
        "[ctrl+c] abort scan"
    };

    let json_copy = if state.json_out.is_some() {
        "json:on"
    } else {
        "json:off"
    };
    let html_copy = if state.html_out.is_some() {
        "html:on"
    } else {
        "html:off"
    };
    let upload_copy = if state.upload_requested {
        "upload:on"
    } else {
        "upload:off"
    };

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(exit_copy, muted_style())),
            Line::from(Span::styled(
                format!("{json_copy}  {html_copy}  {upload_copy}"),
                body_style(),
            )),
        ])
        .block(titled_panel("COMMAND LANE", PanelTone::Neutral)),
        area,
    );
}

fn render_execution_log(frame: &mut Frame, state: &TuiState, area: Rect) {
    let mut lines = Vec::new();

    if state.recent_findings.is_empty() {
        lines.push(Line::from(Span::styled(
            "[INFO] initializing scan engine...",
            muted_style(),
        )));
        lines.push(Line::from(Span::styled(
            "[INFO] waiting for first vector result...",
            muted_style(),
        )));
    } else {
        let visible = area.height.saturating_sub(2) as usize;
        for entry in state.timeline_entries(visible) {
            lines.push(Line::from(vec![
                Span::styled(format!("{:>02} ", entry.sequence), muted_style()),
                Span::styled(
                    format!("{:<4} ", log_status_label(entry.status)),
                    status_style(entry.status),
                ),
                Span::styled(
                    format!("{:<4} ", entry.severity.to_string().to_uppercase()),
                    severity_style(&entry.severity),
                ),
                Span::styled(format!("{:>5} ", entry.duration_label), muted_style()),
                Span::styled(
                    truncate_text(
                        &format!("{}  {}", entry.area_label, entry.vector_label),
                        area.width.saturating_sub(22) as usize,
                    ),
                    body_style(),
                ),
            ]));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(titled_panel("SCAN TIMELINE", state.tone()))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_featured_panel(frame: &mut Frame, state: &TuiState, area: Rect, wide_layout: bool) {
    let outer = Block::default().style(Style::default().bg(Color::Black));
    frame.render_widget(outer, area);

    let inner = if wide_layout {
        area.inner(Margin {
            vertical: 2,
            horizontal: 4,
        })
    } else {
        area.inner(Margin {
            vertical: 1,
            horizontal: 2,
        })
    };

    let Some(featured) = FeaturedPanelData::from_state(state) else {
        frame.render_widget(
            Paragraph::new(vec![Line::from(Span::styled(
                "No findings yet. The panel will lock onto the strongest signal once vectors begin returning.",
                muted_style(),
            ))])
            .block(finding_block("PRIMARY SIGNAL", PanelTone::Neutral))
            .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    };

    let mut lines = vec![
        Line::from(Span::styled(
            truncate_text(
                &featured.vector_name.to_uppercase(),
                inner.width.saturating_sub(4) as usize,
            ),
            emphasis_style(status_tone(featured.status)),
        )),
        render_finding_meta_line(
            "SEVERITY",
            featured.severity.to_string().to_uppercase(),
            severity_style(&featured.severity),
        ),
        render_finding_meta_line("VECTOR", featured.vector_id.clone(), body_style()),
        render_finding_meta_line(
            "STATUS",
            finding_status_label(featured.status).to_string(),
            status_style(featured.status),
        ),
        render_finding_meta_line(
            "AREA",
            format!("{}/{}", featured.category, featured.subcategory),
            body_style(),
        ),
        render_finding_meta_line("SEEN", format!("{}ms", featured.duration_ms), body_style()),
        Line::default(),
    ];

    if state.finished {
        lines.push(Line::from(Span::styled("SUMMARY:", label_style())));
        lines.push(Line::from(Span::styled(
            compact_excerpt(
                &featured.evidence_summary,
                inner.width.saturating_sub(4) as usize,
            ),
            body_style(),
        )));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("ACTION:", label_style())));
        lines.push(Line::from(Span::styled(
            compact_excerpt(
                &featured.recommendation,
                inner.width.saturating_sub(4) as usize,
            ),
            muted_style(),
        )));
    } else if featured.indicator_hits.is_empty() {
        lines.push(Line::from(Span::styled("RESPONSE:", label_style())));
        lines.push(Line::from(Span::styled(
            compact_excerpt(&featured.response, inner.width.saturating_sub(4) as usize),
            muted_style(),
        )));
    } else {
        lines.push(Line::from(Span::styled("SIGNAL:", label_style())));
        for hit in featured.indicator_hits.into_iter().take(3) {
            lines.push(Line::from(vec![
                Span::styled("│ ", muted_style()),
                Span::styled(truncate_text(&hit, 72), muted_style()),
            ]));
        }
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(finding_block(
                "PRIMARY SIGNAL",
                status_tone(featured.status),
            ))
            .wrap(Wrap { trim: true }),
        inner,
    );
}

fn render_completion_dashboard(frame: &mut Frame, state: &TuiState, area: Rect) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Min(0),
            Constraint::Length(6),
        ])
        .split(area);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(sections[2]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(10)])
        .split(body[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(12)])
        .split(body[1]);

    render_dashboard_header(frame, state, sections[0]);
    render_completion_banner_panel(
        frame,
        &state.completion_banner(),
        sections[1],
        state.preview_exit_code(),
    );
    render_dashboard_summary(frame, state, left[0]);
    render_progress_panel(frame, state, left[1]);
    render_execution_log(frame, state, right[0]);
    render_featured_panel(frame, state, right[1], true);
    render_dashboard_footer(frame, state, sections[3]);
}

fn render_completion_banner_panel(
    frame: &mut Frame,
    banner: &CompletionBanner,
    area: Rect,
    exit_code: u8,
) {
    let lines = vec![
        Line::from(Span::styled(banner.title, emphasis_style(banner.tone))),
        Line::from(Span::styled(
            compact_excerpt(&banner.detail, area.width.saturating_sub(4) as usize),
            body_style(),
        )),
        Line::from(vec![
            Span::styled("GUIDANCE: ", label_style()),
            Span::styled(
                compact_excerpt(&banner.guidance, area.width.saturating_sub(15) as usize),
                muted_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("EXIT CODE: ", label_style()),
            Span::styled(
                exit_code.to_string(),
                if exit_code == 0 {
                    output_style(true)
                } else {
                    emphasis_style(PanelTone::Warning)
                },
            ),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(titled_panel("RUN COMPLETION", banner.tone)),
        area,
    );
}

fn titled_panel(title: &str, tone: PanelTone) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {title} "), panel_title_style(tone)))
        .border_style(panel_border_style(tone))
        .style(Style::default().bg(Color::Black).fg(TEXT_COLOR))
}

fn finding_block(title: &str, tone: PanelTone) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {title} "), panel_title_style(tone)))
        .border_style(panel_border_style(tone))
        .style(Style::default().bg(Color::Black).fg(TEXT_COLOR))
}

fn render_segment_line(segment: &SegmentSummary) -> Line<'static> {
    let pct = segment.pct();
    let color = if pct >= 80 {
        SUCCESS_COLOR
    } else if pct >= 50 {
        WARNING_COLOR
    } else {
        ACCENT_COLOR
    };

    Line::from(vec![
        Span::styled(
            format!("{:<16}", segment.label.to_uppercase()),
            label_style(),
        ),
        segment_bar_line(pct, color),
        Span::raw(" "),
        Span::styled(format!("{:>3}%", pct), Style::default().fg(color)),
    ])
}

fn progress_bar_line(ratio: f64, finished: bool) -> Span<'static> {
    progress_meter_line(ratio, finished, 14)
}

fn progress_meter_line(ratio: f64, finished: bool, width: usize) -> Span<'static> {
    let pct = (ratio * 100.0).round() as usize;
    let color = if finished { SUCCESS_COLOR } else { INFO_COLOR };
    let bar = bar_cells(pct, width);
    Span::styled(format!("{bar} {:>3}%", pct), Style::default().fg(color))
}

fn segment_bar_line(pct: usize, color: Color) -> Span<'static> {
    let bar = bar_cells(pct, 10);
    Span::styled(bar, Style::default().fg(color))
}

fn bar_cells(pct: usize, width: usize) -> String {
    let filled = (pct.min(100) * width).div_ceil(100);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn render_finding_meta_line(label: &str, value: String, value_style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<9}"), label_style()),
        Span::styled(value, value_style),
    ])
}

fn severity_count_span(label: &str, count: usize, color: Color) -> Span<'static> {
    Span::styled(
        format!("{label} {count}"),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

fn status_marker(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Vulnerable => "[x]",
        FindingStatus::Resistant => "[+]",
        FindingStatus::Error => "[!]",
    }
}

fn target_type_label(target_type: TargetType) -> &'static str {
    match target_type {
        TargetType::Http => "HTTP",
        TargetType::Openclaw => "OPENCLAW",
        TargetType::Mcp => "MCP",
    }
}

fn severity_rank(severity: &Severity) -> usize {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

fn segment_priority(label: &str) -> usize {
    if label.eq_ignore_ascii_case("direct") {
        0
    } else if label.eq_ignore_ascii_case("indirect") {
        1
    } else if label.eq_ignore_ascii_case("multi-turn") {
        2
    } else {
        3
    }
}

fn finding_status_label(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Vulnerable => "VULNERABLE",
        FindingStatus::Resistant => "RESISTANT",
        FindingStatus::Error => "ERROR",
    }
}

fn log_status_label(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Vulnerable => "FAIL",
        FindingStatus::Resistant => "PASS",
        FindingStatus::Error => "ERR",
    }
}

fn compact_duration(duration_ms: u128) -> String {
    if duration_ms >= 1000 {
        format!("{:.1}s", duration_ms as f64 / 1000.0)
    } else {
        format!("{duration_ms}ms")
    }
}

fn compact_excerpt(value: &str, max_chars: usize) -> String {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_text(&normalized, max_chars)
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let total = value.chars().count();
    if total <= max_chars {
        return value.to_string();
    }

    let clipped: String = value.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{clipped}…")
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

fn muted_style() -> Style {
    Style::default().fg(MUTED_COLOR)
}

fn body_style() -> Style {
    Style::default().fg(TEXT_COLOR)
}

fn label_style() -> Style {
    Style::default()
        .fg(MUTED_COLOR)
        .add_modifier(Modifier::BOLD)
}

fn primary_metric_style() -> Style {
    Style::default().fg(TEXT_COLOR).add_modifier(Modifier::BOLD)
}

fn emphasis_style(tone: PanelTone) -> Style {
    match tone {
        PanelTone::Neutral => Style::default().fg(TEXT_COLOR).add_modifier(Modifier::BOLD),
        PanelTone::Info => Style::default().fg(INFO_COLOR).add_modifier(Modifier::BOLD),
        PanelTone::Warning => Style::default()
            .fg(WARNING_COLOR)
            .add_modifier(Modifier::BOLD),
        PanelTone::Critical => Style::default()
            .fg(ACCENT_COLOR)
            .add_modifier(Modifier::BOLD),
        PanelTone::Success => Style::default()
            .fg(SUCCESS_COLOR)
            .add_modifier(Modifier::BOLD),
    }
}

fn output_style(enabled: bool) -> Style {
    if enabled {
        emphasis_style(PanelTone::Success)
    } else {
        muted_style()
    }
}

fn grade_style(grade: Grade) -> Style {
    match grade {
        Grade::A | Grade::B => Style::default()
            .fg(SUCCESS_COLOR)
            .add_modifier(Modifier::BOLD),
        Grade::C => Style::default()
            .fg(WARNING_COLOR)
            .add_modifier(Modifier::BOLD),
        Grade::D | Grade::F => Style::default()
            .fg(ACCENT_COLOR)
            .add_modifier(Modifier::BOLD),
    }
}

fn status_style(status: FindingStatus) -> Style {
    match status {
        FindingStatus::Vulnerable => Style::default()
            .fg(ACCENT_COLOR)
            .add_modifier(Modifier::BOLD),
        FindingStatus::Resistant => Style::default()
            .fg(SUCCESS_COLOR)
            .add_modifier(Modifier::BOLD),
        FindingStatus::Error => Style::default()
            .fg(WARNING_COLOR)
            .add_modifier(Modifier::BOLD),
    }
}

fn severity_style(severity: &Severity) -> Style {
    match severity {
        Severity::Critical | Severity::High => Style::default()
            .fg(ACCENT_COLOR)
            .add_modifier(Modifier::BOLD),
        Severity::Medium => Style::default()
            .fg(WARNING_COLOR)
            .add_modifier(Modifier::BOLD),
        Severity::Low | Severity::Info => {
            Style::default().fg(TEXT_COLOR).add_modifier(Modifier::BOLD)
        }
    }
}

fn dashboard_status_style(state: &TuiState) -> Style {
    if state.finished {
        emphasis_style(state.tone())
    } else if state.total_vectors == 0 {
        emphasis_style(PanelTone::Info)
    } else {
        emphasis_style(PanelTone::Critical)
    }
}

fn panel_title_style(tone: PanelTone) -> Style {
    let (fg, bg) = match tone {
        PanelTone::Neutral => (TEXT_COLOR, BORDER_COLOR),
        PanelTone::Info => (Color::Black, INFO_COLOR),
        PanelTone::Warning => (Color::Black, WARNING_COLOR),
        PanelTone::Critical => (Color::Black, ACCENT_COLOR),
        PanelTone::Success => (Color::Black, SUCCESS_COLOR),
    };

    Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD)
}

fn panel_border_style(tone: PanelTone) -> Style {
    let color = match tone {
        PanelTone::Neutral => BORDER_COLOR,
        PanelTone::Info => INFO_COLOR,
        PanelTone::Warning => WARNING_COLOR,
        PanelTone::Critical => ACCENT_COLOR,
        PanelTone::Success => SUCCESS_COLOR,
    };

    Style::default().fg(color)
}

fn status_tone(status: FindingStatus) -> PanelTone {
    match status {
        FindingStatus::Vulnerable => PanelTone::Critical,
        FindingStatus::Resistant => PanelTone::Success,
        FindingStatus::Error => PanelTone::Warning,
    }
}

struct FeaturedPanelData {
    vector_id: String,
    vector_name: String,
    category: String,
    subcategory: String,
    severity: Severity,
    status: FindingStatus,
    duration_ms: u128,
    response: String,
    indicator_hits: Vec<String>,
    evidence_summary: String,
    recommendation: String,
}

impl FeaturedPanelData {
    fn from_state(state: &TuiState) -> Option<Self> {
        if !state.finished {
            return state.recent_findings.back().map(Self::from_recent);
        }

        state
            .featured_finding()
            .map(Self::from_finding)
            .or_else(|| state.recent_findings.back().map(Self::from_recent))
    }

    fn from_finding(finding: &FindingOutcome) -> Self {
        Self {
            vector_id: finding.vector_id.clone(),
            vector_name: finding.vector_name.clone(),
            category: finding.category.clone(),
            subcategory: finding.subcategory.clone(),
            severity: finding.severity.clone(),
            status: finding.status,
            duration_ms: finding.duration_ms,
            response: finding.response.clone(),
            indicator_hits: finding
                .analysis
                .as_ref()
                .map(|analysis| analysis.indicator_hits.clone())
                .unwrap_or_default(),
            evidence_summary: finding.evidence_summary.clone(),
            recommendation: finding.recommendation.clone(),
        }
    }

    fn from_recent(finding: &RecentFinding) -> Self {
        Self {
            vector_id: finding.vector_id.clone(),
            vector_name: finding.vector_name.clone(),
            category: finding.category.clone(),
            subcategory: finding.subcategory.clone(),
            severity: finding.severity.clone(),
            status: finding.status,
            duration_ms: finding.duration_ms,
            response: finding.response.clone(),
            indicator_hits: finding.indicator_hits.clone(),
            evidence_summary: finding.evidence_summary.clone(),
            recommendation: finding.recommendation.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        completion_exit_code, finalize_center_run, render, CenterCompletedState, CenterField,
        CenterForm, PanelTone, TuiEvent, TuiState, MAX_RECENT_FINDINGS,
    };
    use crate::{
        cli::TargetType,
        scan::{
            FindingOutcome, FindingOutcomeInput, FindingStatus, ResolvedScanSettings, ScanOutcome,
            ScanSettingsInput,
        },
        scorer::{Grade, ScoreSummary, SeverityCounts},
        vectors::model::Severity,
    };
    use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::tempdir;

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
        FindingOutcome::new(FindingOutcomeInput {
            rule_id: format!("pi-{id:03}"),
            vector_id: format!("pi-{id:03}"),
            vector_name: format!("Vector {id}"),
            category: "prompt-injection".to_string(),
            subcategory: if id.is_multiple_of(3) {
                "multi-turn".to_string()
            } else if id.is_multiple_of(2) {
                "indirect".to_string()
            } else {
                "direct".to_string()
            },
            severity: Severity::High,
            payload_name: "payload".to_string(),
            payload_prompt: "prompt".to_string(),
            status,
            status_code: Some(200),
            response: "ok".to_string(),
            analysis: None,
            duration_ms: id as u128,
            rationale: "test rationale".to_string(),
            evidence_summary: "test evidence".to_string(),
            recommendation: "test recommendation".to_string(),
        })
    }

    fn sample_outcome(findings: Vec<FindingOutcome>) -> ScanOutcome {
        let vulnerable_count = findings
            .iter()
            .filter(|finding| finding.status == FindingStatus::Vulnerable)
            .count();
        let resistant_count = findings
            .iter()
            .filter(|finding| finding.status == FindingStatus::Resistant)
            .count();
        let error_count = findings
            .iter()
            .filter(|finding| finding.status == FindingStatus::Error)
            .count();
        let score = crate::scorer::score_findings(&findings);

        ScanOutcome {
            target_type: TargetType::Http,
            target: "http://127.0.0.1:8787/chat".to_string(),
            mcp: None,
            total_vectors: findings.len(),
            vulnerable_count,
            resistant_count,
            error_count,
            score,
            findings,
            duration_ms: 42,
        }
    }

    fn render_text(state: &TuiState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal should initialize");
        terminal
            .draw(|frame| render(frame, state))
            .expect("render should succeed");
        buffer_to_string(terminal.backend().buffer())
    }

    fn buffer_to_string(buffer: &Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| {
                let mut line = String::new();
                for x in 0..buffer.area.width {
                    line.push_str(buffer[(x, y)].symbol());
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn state_accumulates_counts_from_findings() {
        let mut state = TuiState::new(&settings(), false);
        state.apply_event(TuiEvent::Started { total: 3 });
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            1,
            FindingStatus::Vulnerable,
        ))));
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            2,
            FindingStatus::Resistant,
        ))));
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            3,
            FindingStatus::Error,
        ))));

        assert_eq!(state.total_vectors, 3);
        assert_eq!(state.completed_vectors, 3);
        assert_eq!(state.vulnerable_count, 1);
        assert_eq!(state.resistant_count, 1);
        assert_eq!(state.error_count, 1);
    }

    #[test]
    fn recent_findings_keep_most_recent_entries_in_order() {
        let mut state = TuiState::new(&settings(), false);

        for id in 0..(MAX_RECENT_FINDINGS + 3) {
            state.apply_event(TuiEvent::Finding(Box::new(finding(
                id,
                FindingStatus::Resistant,
            ))));
        }

        assert_eq!(state.recent_findings.len(), MAX_RECENT_FINDINGS);
        assert_eq!(
            state
                .recent_findings
                .front()
                .map(|finding| finding.vector_id.as_str()),
            Some("pi-003")
        );
        assert_eq!(
            state
                .recent_findings
                .back()
                .map(|finding| finding.vector_id.as_str()),
            Some("pi-014")
        );
    }

    #[test]
    fn progress_ratio_uses_completed_and_total_vectors() {
        let mut state = TuiState::new(&settings(), false);
        state.apply_event(TuiEvent::Started { total: 4 });
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            1,
            FindingStatus::Resistant,
        ))));

        assert!((state.progress_ratio() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn completion_banner_escalates_errors_and_exposures() {
        let mut state = TuiState::new(&settings(), false);
        state.finish(
            &sample_outcome(vec![
                finding(1, FindingStatus::Vulnerable),
                finding(2, FindingStatus::Error),
            ]),
            Duration::from_secs(3),
        );

        let banner = state.completion_banner();

        assert_eq!(banner.title, "EXPOSURES AND ERRORS DETECTED");
        assert_eq!(banner.tone, PanelTone::Critical);
        assert_eq!(state.preview_exit_code(), 2);
    }

    #[test]
    fn provisional_score_updates_from_completed_findings() {
        let mut state = TuiState::new(&settings(), false);
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            1,
            FindingStatus::Vulnerable,
        ))));
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            2,
            FindingStatus::Resistant,
        ))));

        assert_eq!(state.score.score, 90);
        assert_eq!(state.score.grade, Grade::B);
    }

    #[test]
    fn finish_reconciles_final_counts_and_marks_state_complete() {
        let mut state = TuiState::new(&settings(), false);
        let outcome = ScanOutcome {
            target_type: TargetType::Http,
            target: "http://127.0.0.1:8787/chat".to_string(),
            mcp: None,
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

    #[test]
    fn segment_summaries_prioritize_direct_indirect_and_multi_turn() {
        let mut state = TuiState::new(&settings(), false);
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            1,
            FindingStatus::Resistant,
        ))));
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            2,
            FindingStatus::Resistant,
        ))));
        state.apply_event(TuiEvent::Finding(Box::new(finding(
            3,
            FindingStatus::Resistant,
        ))));

        let labels = state
            .segment_summaries()
            .into_iter()
            .map(|segment| segment.label)
            .collect::<Vec<_>>();

        assert_eq!(labels, vec!["direct", "indirect", "multi-turn"]);
    }

    #[test]
    fn timeline_entries_track_recent_sequence_numbers() {
        let mut state = TuiState::new(&settings(), false);
        state.apply_event(TuiEvent::Started { total: 6 });

        for id in 1..=4 {
            state.apply_event(TuiEvent::Finding(Box::new(finding(
                id,
                FindingStatus::Resistant,
            ))));
        }

        let entries = state.timeline_entries(2);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 3);
        assert_eq!(entries[1].sequence, 4);
        assert!(entries[1].vector_label.contains("pi-004"));
    }

    #[test]
    fn center_form_hides_http_fields_for_openclaw() {
        let mut form = CenterForm::from_seed(
            &ScanSettingsInput {
                target_type: Some(TargetType::Http),
                request_template: Some(
                    "{\"messages\":[{\"role\":\"user\",\"content\":{{payload}}}]}".to_string(),
                ),
                ..ScanSettingsInput::default()
            },
            false,
        );
        form.toggle(CenterField::TargetType);

        let fields = form.visible_fields();
        assert!(fields.contains(&CenterField::Target));
        assert!(!fields.contains(&CenterField::Method));
        assert!(!fields.contains(&CenterField::RequestTemplate));
        assert_eq!(form.target_type, TargetType::Openclaw);
        assert_eq!(form.category, "openclaw");
    }

    #[test]
    fn center_form_builds_scan_input_from_visible_values() {
        let mut form = CenterForm::from_seed(&ScanSettingsInput::default(), true);
        form.target_type = TargetType::Http;
        form.target = "http://127.0.0.1:8787/chat".to_string();
        form.category = "prompt-injection".to_string();
        form.vectors_dir = "./vectors".to_string();
        form.json_out = "./scan.json".to_string();
        form.html_out = "./scan.html".to_string();
        form.timeout_seconds = "45".to_string();
        form.retries = "3".to_string();
        form.retry_backoff_ms = "500".to_string();
        form.max_concurrent = "4".to_string();
        form.rate_limit_rps = "8".to_string();
        form.redact_responses = false;
        form.method = "PATCH".to_string();
        form.headers = "Authorization: Bearer test; X-Env: dev".to_string();
        form.request_template = "{\"input\":{{payload}}}".to_string();
        form.response_path = "/choices/0/message/content".to_string();

        let input = form
            .to_scan_input()
            .expect("form should convert into scan input");

        assert_eq!(input.target.as_deref(), Some("http://127.0.0.1:8787/chat"));
        assert_eq!(input.target_type, Some(TargetType::Http));
        assert_eq!(input.timeout_seconds, Some(45));
        assert_eq!(input.retries, Some(3));
        assert_eq!(input.retry_backoff_ms, Some(500));
        assert_eq!(input.max_concurrent, Some(4));
        assert_eq!(input.rate_limit_rps, Some(8));
        assert_eq!(input.redact_override, Some(false));
        assert_eq!(input.method.as_deref(), Some("PATCH"));
        assert_eq!(
            input.request_template.as_deref(),
            Some("{\"input\":{{payload}}}")
        );
        assert_eq!(
            input.response_path.as_deref(),
            Some("/choices/0/message/content")
        );
        assert_eq!(
            input.headers,
            vec![
                "Authorization: Bearer test".to_string(),
                "X-Env: dev".to_string()
            ]
        );
    }

    #[test]
    fn completion_exit_code_prefers_runtime_errors() {
        let outcome = ScanOutcome {
            target_type: TargetType::Http,
            target: "http://127.0.0.1:8787/chat".to_string(),
            mcp: None,
            total_vectors: 1,
            vulnerable_count: 1,
            resistant_count: 0,
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
            findings: vec![finding(1, FindingStatus::Vulnerable)],
            duration_ms: 15,
        };

        assert_eq!(completion_exit_code(&outcome, false), 1);
        assert_eq!(completion_exit_code(&outcome, true), 2);
    }

    #[tokio::test]
    async fn finalize_center_run_only_reports_artifacts_after_successful_writes() {
        let temp = tempdir().expect("tempdir should initialize");
        let mut resolved = settings();
        resolved.json_out = Some(temp.path().to_path_buf());
        resolved.html_out = Some(temp.path().join("scan.html"));

        let mut dashboard = TuiState::new(&resolved, true);
        let outcome = sample_outcome(vec![finding(1, FindingStatus::Resistant)]);
        dashboard.finish(&outcome, Duration::from_secs(2));

        let completed = finalize_center_run(&resolved, &dashboard, &outcome, false).await;

        assert!(completed.json_written.is_none());
        assert!(completed.html_written.is_none());
        assert_eq!(completed.exit_code, 2);
        assert!(completed
            .finalization_error
            .as_deref()
            .expect("expected finalization error")
            .contains("failed to write JSON output"));
    }

    #[tokio::test]
    async fn finalize_center_run_records_successful_artifact_writes() {
        let temp = tempdir().expect("tempdir should initialize");
        let json_path = temp.path().join("scan.json");
        let html_path = temp.path().join("scan.html");
        let mut resolved = settings();
        resolved.json_out = Some(json_path.clone());
        resolved.html_out = Some(html_path.clone());

        let mut dashboard = TuiState::new(&resolved, true);
        let outcome = sample_outcome(vec![finding(1, FindingStatus::Resistant)]);
        dashboard.finish(&outcome, Duration::from_secs(2));

        let completed = finalize_center_run(&resolved, &dashboard, &outcome, false).await;

        assert_eq!(
            completed.json_written.as_deref(),
            Some(json_path.to_string_lossy().as_ref())
        );
        assert_eq!(
            completed.html_written.as_deref(),
            Some(html_path.to_string_lossy().as_ref())
        );
        assert!(completed.finalization_error.is_none());
        assert_eq!(completed.exit_code, 0);
    }

    #[test]
    fn center_completion_banner_prefers_finalization_warning() {
        let mut dashboard = TuiState::new(&settings(), true);
        dashboard.finish(
            &sample_outcome(vec![finding(1, FindingStatus::Resistant)]),
            Duration::from_secs(2),
        );

        let completed = CenterCompletedState {
            dashboard,
            json_written: Some("scan.json".to_string()),
            html_written: Some("scan.html".to_string()),
            upload_requested: true,
            scan_run_id: None,
            share_id: None,
            share_url: None,
            finalization_error: Some("failed to upload scan artifact: timeout".to_string()),
            exit_code: 2,
        };

        let banner = completed.banner();

        assert_eq!(banner.title, "FINALIZATION WARNING");
        assert_eq!(banner.tone, PanelTone::Warning);
    }

    #[test]
    fn finished_dashboard_renders_completion_banner() {
        let mut state = TuiState::new(&settings(), false);
        state.finish(
            &sample_outcome(vec![
                finding(1, FindingStatus::Vulnerable),
                finding(2, FindingStatus::Resistant),
            ]),
            Duration::from_secs(4),
        );

        let rendered = render_text(&state, 120, 32);

        assert!(rendered.contains("RUN COMPLETION"));
        assert!(rendered.contains("EXPOSURES DETECTED"));
        assert!(rendered.contains("PRIMARY SIGNAL"));
        assert!(rendered.contains("SCAN TIMELINE"));
    }
}

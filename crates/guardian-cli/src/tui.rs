//! `guardian ui` — a lightweight terminal cockpit for approving agent actions.
//!
//! ASCII-styled, keyboard + mouse, no business logic: it polls the daemon's
//! pending queue and relays the user's allow/deny over the control socket. Built
//! with ratatui; meant to sit in a terminal pane next to the agent.

use std::io::stdout;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEventKind,
    MouseButton, MouseEventKind,
};
use crossterm::execute;
use futures::StreamExt;
use guardian_daemon::{DaemonClient, HistoryView, PendingView};
use ratatui::prelude::*;
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::DefaultTerminal;

const SPINNER: [char; 4] = ['|', '/', '-', '\\'];
const CARD_H: u16 = 5;

// Theme: bright green = positive/confirm, bright red = error/negative,
// dark green = accents that give the interface its color.
const BRIGHT_GREEN: Color = Color::Rgb(46, 230, 107);
const BRIGHT_RED: Color = Color::Rgb(255, 70, 70);
const DARK_GREEN: Color = Color::Rgb(32, 96, 64);
const MID_YELLOW: Color = Color::Rgb(240, 200, 60);

/// A clickable button region recorded during draw, for mouse hit-testing.
struct Hit {
    row: u16,
    allow: (u16, u16),
    deny: (u16, u16),
    id: u64,
}

/// Which screen the cockpit is showing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    /// Pending approvals to allow/deny (the yellow path).
    Approvals,
    /// The activity archive: what the agent did, where it went (host), the rule.
    History,
    /// A form to create a token for a site (stored in the OS keychain).
    NewToken,
    /// A form to add a sensitive value to protect (the data vault / tokenization).
    Protect,
}

/// Which field of the new-token form is being edited.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Target,
    Secret,
}

/// State of the "create a token" form. The secret is never echoed (shown masked)
/// and, on submit, is stored in the OS keychain — the agent never sees it.
struct TokenForm {
    target: String,
    secret: String,
    field: Field,
    message: String,
}

impl TokenForm {
    fn new() -> Self {
        Self {
            target: String::new(),
            secret: String::new(),
            field: Field::Target,
            message: String::new(),
        }
    }
    fn active(&mut self) -> &mut String {
        match self.field {
            Field::Target => &mut self.target,
            Field::Secret => &mut self.secret,
        }
    }
}

struct App {
    pending: Vec<PendingView>,
    selected: usize,
    spinner: usize,
    status: String,
    hits: Vec<Hit>,
    quit: bool,
    /// Self-contained preview with sample data; no daemon is contacted.
    demo: bool,
    /// Current screen (Tab switches).
    view: View,
    /// Recent decisions for the History view (most-recent-last from the daemon).
    history: Vec<HistoryView>,
    /// Scroll offset into the History view (0 = top, i.e. most recent).
    history_offset: usize,
    /// The new-token form state (used on the NewToken screen).
    form: TokenForm,
    /// The value being typed on the Protect screen (data vault / tokenization).
    protect_input: String,
    /// Status message after a protect submit.
    protect_message: String,
    /// Data-vault status: (values protected, tokens issued), refreshed from the daemon.
    vault: (usize, usize),
}

/// Entry point for `guardian ui`. With `demo`, shows sample actions and never
/// contacts a daemon (a preview of the cockpit).
pub async fn run(socket: PathBuf, demo: bool) -> Result<()> {
    let client = DaemonClient::new(socket);
    let mut terminal = ratatui::init();
    let _ = execute!(stdout(), EnableMouseCapture);

    let result = run_loop(&mut terminal, &client, demo).await;

    let _ = execute!(stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

async fn run_loop(terminal: &mut DefaultTerminal, client: &DaemonClient, demo: bool) -> Result<()> {
    let mut app = App {
        pending: if demo { demo_pending() } else { Vec::new() },
        selected: 0,
        spinner: 0,
        status: "connecting...".to_string(),
        hits: Vec::new(),
        quit: false,
        demo,
        view: View::Approvals,
        history: if demo { demo_history() } else { Vec::new() },
        history_offset: 0,
        form: TokenForm::new(),
        protect_input: String::new(),
        protect_message: String::new(),
        vault: (0, 0),
    };
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(400));

    refresh(&mut app, client).await;
    loop {
        terminal.draw(|frame| draw(frame, &mut app))?;
        if app.quit {
            break;
        }
        tokio::select! {
            _ = tick.tick() => {
                app.spinner = (app.spinner + 1) % SPINNER.len();
                refresh(&mut app, client).await;
            }
            maybe_event = events.next() => {
                if let Some(Ok(event)) = maybe_event {
                    handle_event(event, &mut app, client).await;
                }
            }
        }
    }
    Ok(())
}

async fn refresh(app: &mut App, client: &DaemonClient) {
    if app.demo {
        if app.selected >= app.pending.len() {
            app.selected = app.pending.len().saturating_sub(1);
        }
        app.status = format!("demo - {} pending", app.pending.len());
        return;
    }
    match client.pending().await {
        Ok(pending) => {
            app.pending = pending;
            if app.selected >= app.pending.len() {
                app.selected = app.pending.len().saturating_sub(1);
            }
            app.status = format!("{} pending", app.pending.len());
        }
        Err(e) => app.status = format!("daemon unreachable ({e})"),
    }
    // Refresh the activity archive when it's on screen.
    if app.view == View::History {
        if let Ok(history) = client.history(50).await {
            app.history = history;
        }
    }
    // Keep the data-vault status fresh for the Protect view.
    if let Ok(vault) = client.vault_status().await {
        app.vault = vault;
    }
}

async fn handle_event(event: Event, app: &mut App, client: &DaemonClient) {
    match event {
        // The new-token form captures all keys as text input.
        Event::Key(key) if key.kind == KeyEventKind::Press && app.view == View::NewToken => {
            handle_form_key(app, key.code);
        }
        // The protect form: type a sensitive value, Enter sends it to the data vault.
        Event::Key(key) if key.kind == KeyEventKind::Press && app.view == View::Protect => {
            match key.code {
                KeyCode::Esc => app.view = View::Approvals,
                KeyCode::Backspace => {
                    app.protect_input.pop();
                }
                KeyCode::Enter => {
                    let val = app.protect_input.trim().to_string();
                    if !val.is_empty() {
                        if app.demo {
                            app.vault.0 += 1;
                            app.protect_message = format!("(demo) would protect \"{val}\"");
                        } else {
                            match client.protect(&val).await {
                                Ok((p, t)) => {
                                    app.vault = (p, t);
                                    app.protect_message = format!(
                                        "now protecting {p} value(s) — the agent will see tokens"
                                    );
                                }
                                Err(e) => app.protect_message = format!("error: {e}"),
                            }
                        }
                        app.protect_input.clear();
                    }
                }
                KeyCode::Char(c) => app.protect_input.push(c),
                _ => {}
            }
        }
        Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
            // j/k move the approval selection, or scroll the archive on History.
            KeyCode::Char('j') | KeyCode::Down => {
                if app.view == View::History {
                    scroll_history(app, 1);
                } else {
                    move_selection(app, 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if app.view == View::History {
                    scroll_history(app, -1);
                } else {
                    move_selection(app, -1);
                }
            }
            KeyCode::Char('a') => resolve_selected(app, client, true).await,
            KeyCode::Char('d') => resolve_selected(app, client, false).await,
            KeyCode::Char('p') => panic_all(app, client).await,
            KeyCode::Char('r') => refresh(app, client).await,
            KeyCode::Char('n') => {
                app.view = View::NewToken;
                app.form = TokenForm::new();
            }
            KeyCode::Char('v') => {
                app.view = View::Protect;
                app.protect_input.clear();
                app.protect_message.clear();
                refresh(app, client).await;
            }
            KeyCode::Tab => {
                app.view = match app.view {
                    View::History => View::Approvals,
                    _ => View::History,
                };
                refresh(app, client).await;
            }
            _ => {}
        },
        Event::Mouse(m) if matches!(m.kind, MouseEventKind::Down(MouseButton::Left)) => {
            let mut action = None;
            for hit in &app.hits {
                if m.row == hit.row {
                    if (hit.allow.0..hit.allow.1).contains(&m.column) {
                        action = Some((hit.id, true));
                        break;
                    }
                    if (hit.deny.0..hit.deny.1).contains(&m.column) {
                        action = Some((hit.id, false));
                        break;
                    }
                }
            }
            if let Some((id, allow)) = action {
                act_on(app, client, id, allow).await;
            }
        }
        // Mouse wheel scrolls the activity archive.
        Event::Mouse(m) if app.view == View::History => match m.kind {
            MouseEventKind::ScrollDown => scroll_history(app, 1),
            MouseEventKind::ScrollUp => scroll_history(app, -1),
            _ => {}
        },
        _ => {}
    }
}

/// Scroll the History view, clamped to the available rows.
fn scroll_history(app: &mut App, delta: isize) {
    let max = app.history.len().saturating_sub(1);
    let next = (app.history_offset as isize + delta).clamp(0, max as isize);
    app.history_offset = next as usize;
}

/// Handle a keystroke on the new-token form. Pure + local (storing a secret is a
/// local keychain op, no daemon needed).
fn handle_form_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => app.view = View::Approvals,
        KeyCode::Tab => {
            app.form.field = match app.form.field {
                Field::Target => Field::Secret,
                Field::Secret => Field::Target,
            };
        }
        KeyCode::Backspace => {
            app.form.message.clear();
            app.form.active().pop();
        }
        KeyCode::Enter => submit_token(app),
        KeyCode::Char(c) => {
            app.form.message.clear();
            app.form.active().push(c);
        }
        _ => {}
    }
}

/// Store the form's secret for its target in the OS keychain (the agent never sees
/// it). Validates both fields are present; reports the result in the form message.
fn submit_token(app: &mut App) {
    let target = app.form.target.trim().to_string();
    if target.is_empty() || app.form.secret.is_empty() {
        app.form.message = "enter both a site (host) and a secret".to_string();
        return;
    }
    if app.demo {
        app.form = TokenForm::new();
        app.form.message = format!("(demo) would store a token for {target}");
        return;
    }
    match guardian_broker::keychain::store(&target, &app.form.secret) {
        Ok(()) => {
            app.form = TokenForm::new();
            app.form.message = format!("stored a token for {target} in the keychain");
        }
        Err(e) => app.form.message = format!("error: {e}"),
    }
}

fn move_selection(app: &mut App, delta: isize) {
    if app.pending.is_empty() {
        return;
    }
    let len = app.pending.len() as isize;
    app.selected = (((app.selected as isize + delta) % len + len) % len) as usize;
}

async fn resolve_selected(app: &mut App, client: &DaemonClient, allow: bool) {
    if let Some(item) = app.pending.get(app.selected) {
        let id = item.id;
        act_on(app, client, id, allow).await;
    }
}

async fn panic_all(app: &mut App, client: &DaemonClient) {
    let ids: Vec<u64> = app.pending.iter().map(|p| p.id).collect();
    let n = ids.len();
    for id in ids {
        act_on(app, client, id, false).await;
    }
    // Confirm the bulk deny fired (act_on/refresh otherwise only updates counts).
    app.status = format!("panic: denied {n}");
}

/// Resolve one action: locally (demo) or via the daemon (live).
async fn act_on(app: &mut App, client: &DaemonClient, id: u64, allow: bool) {
    if app.demo {
        app.pending.retain(|p| p.id != id);
        if app.selected >= app.pending.len() {
            app.selected = app.pending.len().saturating_sub(1);
        }
        app.status = format!("demo - {} pending", app.pending.len());
    } else {
        let _ = client.respond(id, allow).await;
        refresh(app, client).await;
    }
}

/// Sample pending actions for `--demo` (varied risk to show the colors).
fn demo_pending() -> Vec<PendingView> {
    let mk = |id: u64, tool: &str, text: &str, risk: u8| PendingView {
        id,
        action_id: format!("act-{id}"),
        tool: tool.to_string(),
        plain_text: text.to_string(),
        risk,
    };
    vec![
        mk(
            1,
            "bank.transfer",
            "The agent wants to move money (EUR 4,000 to an unknown account).",
            92,
        ),
        mk(
            2,
            "shell.run",
            "The agent wants to run a command: rm -rf ./build",
            74,
        ),
        mk(
            3,
            "http.post",
            "The agent wants to send a file to a site that is not on your trusted list.",
            88,
        ),
        mk(
            4,
            "fs.read",
            "The agent wants to read a note in your home folder.",
            12,
        ),
    ]
}

fn demo_history() -> Vec<HistoryView> {
    let mk =
        |decision: &str, kind: &str, host: Option<&str>, rule: &str, critical: bool| HistoryView {
            decision: decision.to_string(),
            kind: kind.to_string(),
            host: host.map(str::to_string),
            rule: Some(rule.to_string()),
            reason: None,
            critical,
        };
    vec![
        mk(
            "allow",
            "HttpRequest",
            Some("bank.example"),
            "allow-reads",
            false,
        ),
        mk(
            "deny",
            "HttpRequest",
            Some("bank.example"),
            "deny-writes",
            true,
        ),
        mk("allow", "FileRead", None, "allow-home-reads", false),
        mk("ask", "Exec", None, "-", false),
    ]
}

fn draw(frame: &mut Frame, app: &mut App) {
    app.hits.clear();
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(frame.area());

    // Header.
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " GUARDIAN ",
            Style::new().fg(BRIGHT_GREEN).bg(DARK_GREEN).bold(),
        ),
        Span::styled(
            "  AI action firewall    ",
            Style::new().fg(DARK_GREEN).bold(),
        ),
        Span::styled(
            format!("{} ", SPINNER[app.spinner]),
            Style::new().fg(DARK_GREEN),
        ),
        Span::styled(
            app.status.clone(),
            Style::new().fg(status_color(&app.status)),
        ),
    ]))
    .block(
        Block::bordered()
            .border_type(BorderType::Double)
            .border_style(Style::new().fg(DARK_GREEN)),
    );
    frame.render_widget(header, chunks[0]);

    draw_body(frame, chunks[1], app);

    // Footer key bar — the form captures keystrokes, so it shows its own hints.
    let footer_line = if app.view == View::NewToken {
        Line::from(vec![
            key(" Tab ", DARK_GREEN),
            Span::raw(" field  "),
            key(" Enter ", BRIGHT_GREEN),
            Span::raw(" save  "),
            key(" Esc ", DARK_GREEN),
            Span::raw(" cancel"),
        ])
    } else if app.view == View::Protect {
        Line::from(vec![
            key(" Enter ", BRIGHT_GREEN),
            Span::raw(" protect value  "),
            key(" Esc ", DARK_GREEN),
            Span::raw(" cancel"),
        ])
    } else {
        Line::from(vec![
            key(" j/k ", DARK_GREEN),
            Span::raw(" move  "),
            key(" a ", BRIGHT_GREEN),
            Span::raw(" allow  "),
            key(" d ", BRIGHT_RED),
            Span::raw(" deny  "),
            key(" p ", BRIGHT_RED),
            Span::raw(" panic  "),
            key(" n ", BRIGHT_GREEN),
            Span::raw(" new token  "),
            key(" v ", BRIGHT_GREEN),
            Span::raw(" protect  "),
            key(" Tab ", DARK_GREEN),
            Span::raw(" archive  "),
            key(" r ", DARK_GREEN),
            Span::raw(" refresh  "),
            key(" q ", DARK_GREEN),
            Span::raw(" quit"),
        ])
    };
    let footer = Paragraph::new(footer_line).style(Style::new().bg(Color::Black));
    frame.render_widget(footer, chunks[2]);
}

fn key(label: &str, bg: Color) -> Span<'_> {
    Span::styled(
        label.to_string(),
        Style::new().fg(Color::Black).bg(bg).bold(),
    )
}

fn status_color(status: &str) -> Color {
    if status.contains("unreachable") {
        BRIGHT_RED
    } else if status.starts_with("0 ") {
        BRIGHT_GREEN
    } else {
        MID_YELLOW
    }
}

fn draw_body(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.view {
        View::Approvals => draw_approvals(frame, area, app),
        View::History => draw_history(frame, area, app),
        View::NewToken => draw_new_token(frame, area, app),
        View::Protect => draw_protect(frame, area, app),
    }
}

/// The "create a token" form: a site (host) field and a masked secret field. On
/// submit the secret is stored in the OS keychain; the agent never sees it.
fn draw_new_token(frame: &mut Frame, area: Rect, app: &App) {
    // Granting a credential is a "yellow" (medium-stakes) action — the active field
    // is tinted yellow; a visible `[____]` track shows an empty field's input area.
    let field_line = |label: &str, value: &str, active: bool| {
        let label_style = if active {
            Style::new().fg(MID_YELLOW).bold()
        } else {
            Style::new().fg(DARK_GREEN)
        };
        let shown = if value.is_empty() {
            "____________".to_string()
        } else {
            value.to_string()
        };
        let caret = if active { "_" } else { "" };
        let value_style = if value.is_empty() {
            Style::new().fg(DARK_GREEN) // placeholder track
        } else {
            Style::new().fg(Color::White)
        };
        Line::from(vec![
            Span::styled(format!("  {label:<10} ["), label_style),
            Span::styled(format!("{shown}{caret}"), value_style),
            Span::styled("]", label_style),
        ])
    };
    let masked: String = "*".repeat(app.form.secret.chars().count());
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Create a token — Guardian holds it; the agent never sees the value.",
            Style::new().fg(DARK_GREEN),
        )),
        Line::from(""),
        field_line(
            "site/host",
            &app.form.target,
            app.form.field == Field::Target,
        ),
        field_line("secret", &masked, app.form.field == Field::Secret),
        Line::from(""),
        Line::from(Span::styled(
            "  Tab switch field   Enter save   Esc cancel",
            Style::new().fg(DARK_GREEN),
        )),
    ];
    if !app.form.message.is_empty() {
        let color = if app.form.message.starts_with("error") {
            BRIGHT_RED
        } else {
            BRIGHT_GREEN
        };
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", app.form.message),
            Style::new().fg(color).bold(),
        )));
    }
    let block = Block::bordered()
        .border_style(Style::new().fg(DARK_GREEN))
        .title(Span::styled(
            " new token ",
            Style::new().fg(MID_YELLOW).bold(),
        ));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// The "protect data" form: type a sensitive value (name, IBAN, account…). Guardian
/// replaces it with an opaque token in tool results so the agent never holds it, and
/// restores it only into an authorized outbound action (ADR-0005).
fn draw_protect(frame: &mut Frame, area: Rect, app: &App) {
    let (protected, tokens) = app.vault;
    let shown = if app.protect_input.is_empty() {
        "____________________".to_string()
    } else {
        app.protect_input.clone()
    };
    let value_style = if app.protect_input.is_empty() {
        Style::new().fg(DARK_GREEN)
    } else {
        Style::new().fg(Color::White)
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Protect a value — Guardian tokenizes it so the agent never sees it,",
            Style::new().fg(DARK_GREEN),
        )),
        Line::from(Span::styled(
            "  and restores it only into an authorized action (e.g. name, IBAN, account).",
            Style::new().fg(DARK_GREEN),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  value      [", Style::new().fg(MID_YELLOW).bold()),
            Span::styled(format!("{shown}_"), value_style),
            Span::styled("]", Style::new().fg(MID_YELLOW).bold()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!("  vault: {protected} value(s) protected · {tokens} token(s) issued"),
            Style::new().fg(BRIGHT_GREEN),
        )),
    ];
    if !app.protect_message.is_empty() {
        let color = if app.protect_message.starts_with("error") {
            BRIGHT_RED
        } else {
            BRIGHT_GREEN
        };
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", app.protect_message),
            Style::new().fg(color).bold(),
        )));
    }
    let block = Block::bordered()
        .border_style(Style::new().fg(DARK_GREEN))
        .title(Span::styled(
            " protect data ",
            Style::new().fg(MID_YELLOW).bold(),
        ));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Plain-language name for an action kind (the rest of the cockpit speaks plainly).
fn humanize_kind(kind: &str) -> &str {
    match kind {
        "HttpRequest" => "web request",
        "FileRead" => "read file",
        "FileWrite" => "write file",
        "Exec" => "run command",
        "Email" => "send email",
        "Delete" => "delete",
        other => other,
    }
}

/// The activity archive: a scrollable table, most-recent-first, colored by decision,
/// showing what the agent did, where it went (host), and the rule/reason.
fn draw_history(frame: &mut Frame, area: Rect, app: &App) {
    let total = app.history.len();
    let title = format!(" activity archive — {total} recent (j/k or wheel to scroll) ");
    let block = Block::bordered()
        .border_style(Style::new().fg(DARK_GREEN))
        .title(title);
    if total == 0 {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "   no decisions recorded yet",
                Style::new().fg(DARK_GREEN),
            )),
        ])
        .block(block);
        frame.render_widget(empty, area);
        return;
    }

    let inner_h = area.height.saturating_sub(2) as usize; // minus borders
    let header_rows = 1;
    let visible = inner_h.saturating_sub(header_rows).max(1);
    let offset = app.history_offset.min(total.saturating_sub(1));
    let drawn = visible.min(total - offset); // rows actually shown this frame
    let width = area.width.saturating_sub(2) as usize; // loop-invariant

    // Column header doubles as the legend (DARK_GREEN), then the rows.
    let mut lines = vec![Line::from(Span::styled(
        format!(
            " {:<7} {:<13} {:<20} rule / reason",
            "OUTCOME", "ACTION", "HOST"
        ),
        Style::new().fg(DARK_GREEN).bold(),
    ))];

    // Most-recent-first, windowed by the scroll offset.
    let rows: Vec<&HistoryView> = app.history.iter().rev().collect();
    for h in rows.iter().skip(offset).take(drawn) {
        let (label, color) = match h.decision.as_str() {
            "allow" => ("ALLOW", BRIGHT_GREEN),
            "deny" => ("DENY ", BRIGHT_RED),
            "ask" => ("ASK  ", MID_YELLOW),
            _ => ("?????", MID_YELLOW), // an unrecognized row should stand out
        };
        let where_to = h.host.as_deref().unwrap_or("-");
        let rule = h.rule.as_deref().unwrap_or("-");
        let mut rest = format!("{:<13} {:<20} {}", humanize_kind(&h.kind), where_to, rule);
        if let Some(reason) = &h.reason {
            rest.push_str(&format!(" — {reason}"));
        }
        if h.critical {
            rest.push_str("  [critical]");
        }
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {label} "),
                Style::new().fg(Color::Black).bg(color).bold(),
            ),
            Span::raw(" "),
            Span::styled(
                truncate(&rest, width.saturating_sub(9)),
                Style::new().fg(Color::White),
            ),
        ]));
    }

    // "more below" hint when the window doesn't reach the end.
    let shown = offset + drawn;
    if shown < total {
        lines.push(Line::from(Span::styled(
            format!("   … {} older below", total - shown),
            Style::new().fg(DARK_GREEN),
        )));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_approvals(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.pending.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "   [ all clear ]",
                Style::new().fg(BRIGHT_GREEN).bold(),
            )),
            Line::from(Span::styled(
                "   no actions are waiting for your review",
                Style::new().fg(DARK_GREEN),
            )),
        ])
        .block(Block::bordered().border_style(Style::new().fg(DARK_GREEN)));
        frame.render_widget(empty, area);
        return;
    }

    let selected = app.selected;
    let mut hits = Vec::new();
    for i in 0..app.pending.len() {
        let y = area.y + (i as u16) * CARD_H;
        if y + CARD_H > area.y + area.height {
            break; // no scrolling in v1: only render what fits
        }
        let item = &app.pending[i];
        let rect = Rect {
            x: area.x,
            y,
            width: area.width,
            height: CARD_H,
        };
        let is_selected = i == selected;
        let border_style = if is_selected {
            Style::new().fg(BRIGHT_GREEN).bold()
        } else {
            Style::new().fg(DARK_GREEN)
        };
        let marker = if is_selected { ">" } else { " " };
        let block = Block::bordered().border_style(border_style).title(format!(
            " {marker} #{} {} ",
            i + 1,
            item.tool
        ));
        let inner = block.inner(rect);
        frame.render_widget(block, rect);

        let color = risk_color(item.risk);
        let line_risk = Line::from(vec![
            Span::raw("risk "),
            Span::styled(risk_bar(item.risk), Style::new().fg(color)),
            Span::styled(format!(" {:>3}", item.risk), Style::new().fg(color).bold()),
        ]);
        let line_text = Line::from(Span::styled(
            truncate(&item.plain_text, inner.width.saturating_sub(1) as usize),
            Style::new().fg(Color::White),
        ));

        let allow_label = "[ A Allow ]";
        let deny_label = "[ D Deny ]";
        let allow_x = inner.x + 1;
        let deny_x = allow_x + allow_label.len() as u16 + 3;
        let line_buttons = Line::from(vec![
            Span::raw(" "),
            Span::styled(allow_label, button_style(BRIGHT_GREEN, is_selected)),
            Span::raw("   "),
            Span::styled(deny_label, button_style(BRIGHT_RED, is_selected)),
        ]);

        frame.render_widget(
            Paragraph::new(vec![line_risk, line_text, line_buttons]),
            inner,
        );

        hits.push(Hit {
            row: inner.y + 2,
            allow: (allow_x, allow_x + allow_label.len() as u16),
            deny: (deny_x, deny_x + deny_label.len() as u16),
            id: item.id,
        });
    }
    app.hits = hits;
}

fn button_style(color: Color, selected: bool) -> Style {
    if selected {
        Style::new().fg(Color::Black).bg(color).bold()
    } else {
        Style::new().fg(color)
    }
}

fn risk_color(risk: u8) -> Color {
    if risk >= 80 {
        BRIGHT_RED
    } else if risk >= 40 {
        MID_YELLOW
    } else {
        BRIGHT_GREEN
    }
}

fn risk_bar(risk: u8) -> String {
    let filled = ((risk as usize + 5) / 10).min(10);
    format!(
        "[{}{}]",
        "\u{2593}".repeat(filled),
        "\u{2591}".repeat(10 - filled)
    )
}

fn truncate(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let cut: String = s.chars().take(width.saturating_sub(3)).collect();
        format!("{cut}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn app(pending: Vec<PendingView>, status: &str) -> App {
        App {
            pending,
            selected: 0,
            spinner: 0,
            status: status.to_string(),
            hits: Vec::new(),
            quit: false,
            demo: false,
            view: View::Approvals,
            history: Vec::new(),
            history_offset: 0,
            form: TokenForm::new(),
            protect_input: String::new(),
            protect_message: String::new(),
            vault: (0, 0),
        }
    }

    #[test]
    fn demo_pending_has_varied_risk() {
        let items = demo_pending();
        assert_eq!(items.len(), 4);
        assert!(
            items.iter().any(|i| i.risk >= 80),
            "expected a high-risk sample"
        );
        assert!(
            items.iter().any(|i| i.risk < 40),
            "expected a low-risk sample"
        );
    }

    fn rendered(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn renders_empty_state_without_panicking() {
        let mut state = app(Vec::new(), "0 pending");
        let text = rendered(&mut state);
        assert!(text.contains("GUARDIAN"));
        assert!(text.contains("all clear"));
    }

    #[test]
    fn new_token_form_renders_and_masks_the_secret() {
        let mut state = app(Vec::new(), "0 pending");
        state.view = View::NewToken;
        state.form.target = "bank.example".to_string();
        state.form.secret = "topsecret".to_string();
        let text = rendered(&mut state);
        assert!(text.contains("new token"));
        assert!(text.contains("site/host"));
        assert!(text.contains("bank.example"));
        assert!(text.contains("*********")); // secret shown masked
        assert!(!text.contains("topsecret")); // never echoed
    }

    #[test]
    fn protect_view_renders_input_and_vault_status() {
        let mut state = app(Vec::new(), "0 pending");
        state.view = View::Protect;
        state.protect_input = "Mario Rossi".to_string();
        state.vault = (3, 7);
        let text = rendered(&mut state);
        assert!(text.contains("protect data"));
        assert!(text.contains("Mario Rossi")); // the value being typed is shown
        assert!(text.contains("3 value(s) protected"));
        assert!(text.contains("7 token(s) issued"));
    }

    #[test]
    fn form_keys_edit_fields_and_switch_with_tab() {
        let mut state = app(Vec::new(), "0 pending");
        state.view = View::NewToken;
        for c in "host".chars() {
            handle_form_key(&mut state, KeyCode::Char(c));
        }
        handle_form_key(&mut state, KeyCode::Backspace); // "hos"
        handle_form_key(&mut state, KeyCode::Tab); // → secret field
        for c in "abc".chars() {
            handle_form_key(&mut state, KeyCode::Char(c));
        }
        assert_eq!(state.form.target, "hos");
        assert_eq!(state.form.secret, "abc");
    }

    #[test]
    fn submit_requires_both_fields_then_reports() {
        let mut state = app(Vec::new(), "0 pending");
        state.demo = true; // don't touch the real keychain
        state.view = View::NewToken;
        submit_token(&mut state);
        assert!(state.form.message.contains("enter both"));
        state.form.target = "bank.example".to_string();
        state.form.secret = "s".to_string();
        submit_token(&mut state);
        assert!(state.form.message.contains("bank.example"));
        assert!(state.form.target.is_empty()); // form reset after submit
    }

    #[test]
    fn history_view_renders_the_activity_archive() {
        let mut state = app(Vec::new(), "0 pending");
        state.view = View::History;
        state.history = demo_history();
        let text = rendered(&mut state);
        assert!(text.contains("activity archive"));
        assert!(text.contains("OUTCOME")); // column header / legend
        assert!(text.contains("ALLOW"));
        assert!(text.contains("DENY"));
        assert!(text.contains("web request")); // kind humanized (HttpRequest)
        assert!(text.contains("bank.example")); // where the agent went
        assert!(text.contains("critical")); // the money-movement deny is flagged
    }

    #[test]
    fn history_scroll_offset_is_clamped() {
        let mut state = app(Vec::new(), "0 pending");
        state.history = demo_history(); // 4 rows
        scroll_history(&mut state, -1); // can't go above the top
        assert_eq!(state.history_offset, 0);
        for _ in 0..10 {
            scroll_history(&mut state, 1);
        }
        assert_eq!(state.history_offset, state.history.len() - 1); // clamped to last
    }

    #[test]
    fn renders_a_pending_card_and_records_button_hits() {
        let item = PendingView {
            id: 7,
            action_id: "act-1".to_string(),
            tool: "bank.transfer".to_string(),
            plain_text: "The agent wants to move money.".to_string(),
            risk: 90,
        };
        let mut state = app(vec![item], "1 pending");
        let text = rendered(&mut state);
        assert!(text.contains("bank.transfer"));
        assert!(text.contains("Allow"));
        assert!(text.contains("Deny"));
        // The clickable button regions were recorded for mouse hit-testing.
        assert_eq!(state.hits.len(), 1);
        assert_eq!(state.hits[0].id, 7);
    }

    #[test]
    fn status_colors_signal_state() {
        assert_eq!(status_color("daemon unreachable (x)"), BRIGHT_RED);
        assert_eq!(status_color("0 pending"), BRIGHT_GREEN);
        assert_eq!(status_color("2 pending"), MID_YELLOW);
    }

    #[test]
    fn theme_colors_are_present_in_the_rendered_buffer() {
        // Proves the colors are actually emitted (the chat can't show ANSI, but
        // the rendered cells carry the theme colors — visible in a real terminal).
        let item = PendingView {
            id: 1,
            action_id: "a".to_string(),
            tool: "shell.run".to_string(),
            plain_text: "high-risk action".to_string(),
            risk: 90, // high risk -> bright red bar
        };
        let mut state = app(vec![item], "1 pending");
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal.draw(|frame| draw(frame, &mut state)).unwrap();

        let (mut green, mut red, mut dark) = (false, false, false);
        for cell in terminal.backend().buffer().content() {
            green |= cell.fg == BRIGHT_GREEN || cell.bg == BRIGHT_GREEN;
            red |= cell.fg == BRIGHT_RED || cell.bg == BRIGHT_RED;
            dark |= cell.fg == DARK_GREEN || cell.bg == DARK_GREEN;
        }
        assert!(green, "bright green missing from the rendered buffer");
        assert!(red, "bright red missing from the rendered buffer");
        assert!(dark, "dark-green accents missing from the rendered buffer");
    }
}

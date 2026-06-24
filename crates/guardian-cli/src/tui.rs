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
use guardian_daemon::{DaemonClient, PendingView};
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

struct App {
    pending: Vec<PendingView>,
    selected: usize,
    spinner: usize,
    status: String,
    hits: Vec<Hit>,
    quit: bool,
    /// Self-contained preview with sample data; no daemon is contacted.
    demo: bool,
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
}

async fn handle_event(event: Event, app: &mut App, client: &DaemonClient) {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
            KeyCode::Char('j') | KeyCode::Down => move_selection(app, 1),
            KeyCode::Char('k') | KeyCode::Up => move_selection(app, -1),
            KeyCode::Char('a') => resolve_selected(app, client, true).await,
            KeyCode::Char('d') => resolve_selected(app, client, false).await,
            KeyCode::Char('p') => panic_all(app, client).await,
            KeyCode::Char('r') => refresh(app, client).await,
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
        _ => {}
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
    for id in ids {
        act_on(app, client, id, false).await;
    }
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

    // Footer key bar.
    let footer = Paragraph::new(Line::from(vec![
        key(" j/k ", DARK_GREEN),
        Span::raw(" move  "),
        key(" a ", BRIGHT_GREEN),
        Span::raw(" allow  "),
        key(" d ", BRIGHT_RED),
        Span::raw(" deny  "),
        key(" p ", BRIGHT_RED),
        Span::raw(" panic  "),
        key(" r ", DARK_GREEN),
        Span::raw(" refresh  "),
        key(" q ", DARK_GREEN),
        Span::raw(" quit"),
    ]))
    .style(Style::new().bg(Color::Black));
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

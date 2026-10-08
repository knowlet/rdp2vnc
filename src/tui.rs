//! Minimal terminal setup form. Secrets are masked and never saved.
use crate::{config::Args, rfb::Auth};
use anyhow::{Context, Result, ensure};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::{
    io::{self, IsTerminal},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stderr(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}
struct Fields(Vec<String>);
impl Drop for Fields {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(Zeroize::zeroize);
    }
}
pub struct Setup {
    pub args: Args,
    pub vnc_password: Option<Zeroizing<String>>,
    pub rdp_password: Option<Zeroizing<String>>,
}

const LABELS: [&str; 7] = [
    "VNC target",
    "SSH user@host (optional)",
    "VNC / Mac username (optional)",
    "VNC password (hidden)",
    "RDP listen address",
    "RDP username",
    "RDP password (hidden; blank generates)",
];

const COMPACT_LABELS: [&str; 7] = [
    "VNC target",
    "SSH host",
    "VNC username",
    "VNC password",
    "RDP listen",
    "RDP username",
    "RDP password",
];

fn render_form(
    frame: &mut ratatui::Frame<'_>,
    fields: &Fields,
    selected: usize,
    error: &str,
    flags: [bool; 3],
) {
    let area = frame.area();
    let bordered = area.height >= 30 && area.width >= 60;
    let focused_only = area.height < 16;
    let field_count = if focused_only { 1 } else { LABELS.len() };
    let field_height = if bordered { 3 } else { 1 };
    let mut constraints = vec![Constraint::Length(3)];
    constraints.extend(std::iter::repeat_n(
        Constraint::Length(field_height),
        field_count,
    ));
    constraints.push(Constraint::Min(3));
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .margin(u16::from(area.height >= 16))
        .constraints(constraints)
        .split(area);
    frame.render_widget(
        Paragraph::new("rdp2vnc · RDP/TLS/NLA → VNC\nTab/↑↓ field · F5 connect · Esc cancel\nF2 remote bind · F3 insecure VNC · F4 read-only"),
        rows[0],
    );
    for offset in 0..field_count {
        let i = if focused_only { selected } else { offset };
        let text = if i == 3 || i == 6 {
            "•".repeat(fields.0[i].chars().count())
        } else {
            fields.0[i].clone()
        };
        let style = if i == selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let widget = if bordered {
            Paragraph::new(text).block(Block::default().title(LABELS[i]).borders(Borders::ALL))
        } else {
            Paragraph::new(format!(
                "{} {}: {text}",
                if i == selected { ">" } else { " " },
                COMPACT_LABELS[i]
            ))
        };
        frame.render_widget(widget.style(style), rows[offset + 1]);
    }
    let [remote, insecure, read_only] = flags;
    // Put validation first so even very short terminals show the failure.
    let status = if error.is_empty() {
        "SSH requires a known host key and key/agent authentication. Passwords are never saved."
    } else {
        error
    };
    frame.render_widget(
        Paragraph::new(format!(
            "{status}\nRemote RDP: {remote}  Unencrypted VNC: {insecure}  Read-only: {read_only}"
        ))
        .wrap(Wrap { trim: false }),
        rows[field_count + 1],
    );
}

pub fn run() -> Result<Option<Setup>> {
    ensure!(
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        "TUI requires a terminal; pass a VNC target and password environment variables for non-interactive use"
    );
    enable_raw_mode()?;
    let _restore = Restore;
    execute!(io::stderr(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stderr()))?;
    let mut fields = Fields(vec![
        "127.0.0.1:5900".into(),
        String::new(),
        String::new(),
        String::new(),
        "127.0.0.1:3390".into(),
        "rdp2vnc".into(),
        String::new(),
    ]);
    let (mut selected, mut error) = (0, String::new());
    let (mut remote, mut insecure, mut read_only) = (false, false, false);
    loop {
        terminal.draw(|frame| {
            render_form(
                frame,
                &fields,
                selected,
                &error,
                [remote, insecure, read_only],
            );
        })?;
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.code == KeyCode::Esc
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            return Ok(None);
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down => selected = (selected + 1) % fields.0.len(),
            KeyCode::BackTab | KeyCode::Up => {
                selected = (selected + fields.0.len() - 1) % fields.0.len()
            }
            KeyCode::F(2) => remote = !remote,
            KeyCode::F(3) => insecure = !insecure,
            KeyCode::F(4) => read_only = !read_only,
            KeyCode::Backspace => {
                fields.0[selected].pop();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if fields.0[selected].len() < 1024 && !c.is_control() {
                    fields.0[selected].push(c);
                }
            }
            KeyCode::F(5) | KeyCode::Enter => {
                let parse = || -> Result<Setup> {
                    let mut args = Args::try_parse_from(["rdp2vnc"])?;
                    args.target = Some(fields.0[0].parse().context("invalid VNC target")?);
                    args.ssh = (!fields.0[1].is_empty()).then(|| fields.0[1].clone());
                    args.username = (!fields.0[2].is_empty()).then(|| fields.0[2].clone());
                    args.auth = if args.username.is_some() {
                        Auth::Ard
                    } else {
                        Auth::Auto
                    };
                    args.listen = fields.0[4].parse().context("invalid RDP listen address")?;
                    args.rdp_username = fields.0[5].clone();
                    args.allow_remote = remote;
                    args.allow_insecure_vnc = insecure;
                    args.read_only = read_only;
                    args.validate()?;
                    ensure!(
                        fields.0[6].is_empty() || fields.0[6].len() >= 12,
                        "RDP password must contain at least 12 bytes"
                    );
                    Ok(Setup {
                        args,
                        vnc_password: (!fields.0[3].is_empty())
                            .then(|| Zeroizing::new(fields.0[3].clone())),
                        rdp_password: (!fields.0[6].is_empty())
                            .then(|| Zeroizing::new(fields.0[6].clone())),
                    })
                };
                match parse() {
                    Ok(setup) => return Ok(Some(setup)),
                    Err(e) => error = format!("{e:#}"),
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn validation_is_visible_and_passwords_masked_at_common_terminal_sizes() {
        for (width, height, selected) in [
            (80, 24, 3),
            (80, 30, 3),
            (80, 16, 3),
            (40, 10, 3),
            (40, 10, 6),
        ] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let fields = Fields(vec![
                "localhost:5900".into(),
                String::new(),
                String::new(),
                "private-password".into(),
                "127.0.0.1:3390".into(),
                "rdp2vnc".into(),
                "another-secret".into(),
            ]);
            terminal
                .draw(|frame| {
                    render_form(frame, &fields, selected, "invalid VNC target", [false; 3]);
                })
                .unwrap();
            let rendered: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(rendered.contains("invalid VNC target"), "{width}x{height}");
            assert!(rendered.contains(if selected == 3 {
                "VNC password"
            } else {
                "RDP password"
            }));
            assert!(rendered.contains('•'));
            assert!(!rendered.contains("private-password"));
            assert!(!rendered.contains("another-secret"));
        }
    }
}

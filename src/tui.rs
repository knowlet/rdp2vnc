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
    widgets::{Block, Borders, Paragraph},
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

pub fn run() -> Result<Option<Setup>> {
    ensure!(
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        "TUI requires a terminal; pass a VNC target and password environment variables for non-interactive use"
    );
    enable_raw_mode()?;
    let _restore = Restore;
    execute!(io::stderr(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stderr()))?;
    let labels = [
        "VNC target",
        "SSH user@host (optional)",
        "VNC / Mac username (optional)",
        "VNC password (hidden)",
        "RDP listen address",
        "RDP username",
        "RDP password (hidden; blank generates)",
    ];
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
        terminal.draw(|f|{
            let rows=Layout::default().direction(Direction::Vertical).margin(1)
                .constraints([Constraint::Length(3),Constraint::Length(3),Constraint::Length(3),Constraint::Length(3),Constraint::Length(3),Constraint::Length(3),Constraint::Length(3),Constraint::Length(3),Constraint::Min(1)]).split(f.area());
            f.render_widget(Paragraph::new("rdp2vnc · RDP/TLS/NLA → VNC\nTab/↑↓ field · F5 connect · F2 remote bind · F3 insecure VNC · F4 read-only · Esc cancel"),rows[0]);
            for (i,label) in labels.iter().enumerate(){
                let text=if i==3||i==6{"•".repeat(fields.0[i].chars().count())}else{fields.0[i].clone()};
                let style=if i==selected{Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)}else{Style::default()};
                f.render_widget(Paragraph::new(text).block(Block::default().title(*label).borders(Borders::ALL)).style(style),rows[i+1]);
            }
            f.render_widget(Paragraph::new(format!("Remote RDP: {remote}  Unencrypted VNC: {insecure}  Read-only: {read_only}\n{error}\nSSH requires a known host key and existing key/agent authentication. No passwords are persisted.")),rows[8]);
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

pub mod cli;
pub mod filter;
pub mod format;
pub mod group;
pub mod kill;
pub mod model;
pub mod sanitize;
pub mod services;
pub mod sort;
pub mod sys;
pub mod tui;

use cli::{Config, VERSION, parse_args, usage};
use filter::{filter_port, filter_proto, filter_query, unique_idents};
use format::{format_json, format_table};
use kill::kill_all;
use model::Entry;
use std::io::{self, BufRead, IsTerminal, Read, Write};

pub struct ExitError {
    pub code: i32,
    pub msg: String,
}

impl ExitError {
    #[must_use]
    pub fn new(code: i32, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
        }
    }
}

pub fn run<R: Read + BufRead, W: Write, E: Write>(
    args: &[String],
    in_stream: R,
    mut out_stream: W,
    err_stream: E,
) -> Result<(), ExitError> {
    let cfg = parse_args(args).map_err(|e| ExitError::new(2, e))?;

    if cfg.help {
        if let Err(e) = write!(out_stream, "{}", usage())
            && e.kind() != io::ErrorKind::BrokenPipe
        {
            return Err(ExitError::new(2, e.to_string()));
        }
        return Ok(());
    }

    if cfg.version {
        if let Err(e) = writeln!(out_stream, "lsoff-rs {VERSION}")
            && e.kind() != io::ErrorKind::BrokenPipe
        {
            return Err(ExitError::new(2, e.to_string()));
        }
        return Ok(());
    }

    let is_stdout_tty = io::stdout().is_terminal();
    let use_tui = cfg.port.is_none() && !cfg.json && !cfg.kill && is_stdout_tty;
    if use_tui {
        tui::run(cfg.tcp, cfg.udp, &cfg.query).map_err(|e| ExitError::new(2, e.to_string()))?;
        return Ok(());
    }

    let entries = sys::list_listeners().map_err(|e| ExitError::new(2, e.to_string()))?;
    let mut entries = filter_proto(&entries, cfg.tcp, cfg.udp);
    if let Some(port) = cfg.port {
        entries = filter_port(&entries, port);
    }
    if !cfg.query.is_empty() {
        entries = filter_query(&entries, &cfg.query);
    }

    if cfg.kill {
        return run_kill(&cfg, &entries, in_stream, out_stream, err_stream);
    }

    if entries.is_empty() && (cfg.port.is_some() || !cfg.query.is_empty()) {
        return Err(ExitError::new(1, none_found(&cfg)));
    }

    if cfg.json {
        if let Err(e) = format_json(out_stream, &entries)
            && e.kind() != io::ErrorKind::BrokenPipe
        {
            return Err(ExitError::new(2, e.to_string()));
        }
    } else if let Err(e) = format_table(out_stream, &entries)
        && e.kind() != io::ErrorKind::BrokenPipe
    {
        return Err(ExitError::new(2, e.to_string()));
    }

    Ok(())
}

fn run_kill<R: Read + BufRead, W: Write, E: Write>(
    cfg: &Config,
    entries: &[Entry],
    mut in_stream: R,
    mut out_stream: W,
    mut err_stream: E,
) -> Result<(), ExitError> {
    if entries.is_empty() {
        return Err(ExitError::new(1, none_found(cfg)));
    }

    format_table(&mut out_stream, entries).map_err(|e| ExitError::new(2, e.to_string()))?;

    let ids = unique_idents(entries);
    if ids.is_empty() {
        return Err(ExitError::new(1, "no process ids to kill (try as root)"));
    }

    let pids: Vec<i32> = ids.iter().map(|id| id.pid).collect();
    if !cfg.yes {
        let confirmed = confirm_kill(&mut in_stream, &mut err_stream, &pids)?;
        if !confirmed {
            writeln!(err_stream, "cancelled").map_err(|e| ExitError::new(2, e.to_string()))?;
            return Err(ExitError::new(1, ""));
        }
    }

    kill_all(&ids).map_err(|e| ExitError::new(2, e))?;

    for id in &ids {
        writeln!(err_stream, "killed pid {}", id.pid)
            .map_err(|e| ExitError::new(2, e.to_string()))?;
    }

    Ok(())
}

fn confirm_kill<R: Read + BufRead, E: Write>(
    in_stream: &mut R,
    err_stream: &mut E,
    pids: &[i32],
) -> Result<bool, ExitError> {
    if !io::stdin().is_terminal() {
        return Err(ExitError::new(
            2,
            "refusing to kill without -y (stdin is not a TTY)",
        ));
    }

    let label = if pids.len() == 1 {
        "process"
    } else {
        "processes"
    };

    write!(
        err_stream,
        "Kill {} {} {:?}? [y/N] ",
        pids.len(),
        label,
        pids
    )
    .map_err(|e| ExitError::new(2, e.to_string()))?;
    err_stream
        .flush()
        .map_err(|e| ExitError::new(2, e.to_string()))?;

    let mut line = String::new();
    in_stream
        .read_line(&mut line)
        .map_err(|e| ExitError::new(2, e.to_string()))?;

    let trimmed = line.trim().to_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

fn none_found(cfg: &Config) -> String {
    match (cfg.port, !cfg.query.is_empty()) {
        (Some(port), true) => {
            format!("no listeners on port {} matching {:?}", port, cfg.query)
        }
        (Some(port), false) => format!("no listeners on port {port}"),
        (None, true) => format!("no listeners matching {:?}", cfg.query),
        (None, false) => "no listeners".to_string(),
    }
}

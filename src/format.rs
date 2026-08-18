use crate::model::{Entry, Proto, short_cwd};
use crate::sanitize::display_cell;
use crate::services::service_name;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
struct JsonRow<'a> {
    proto: Proto,
    port: u16,
    addr: &'a str,
    pid: i32,
    name: &'a str,
    path: &'a str,
    cmdline: &'a str,
    cwd: &'a str,
    project: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<&'a str>,
}

/// Formats listeners as a clean, script-friendly aligned table.
///
/// # Errors
/// Returns `io::Error` if writing to the output stream fails.
pub fn format_table<W: Write>(mut w: W, entries: &[Entry]) -> io::Result<()> {
    let headers = [
        "PROTO", "PORT", "ADDRESS", "PID", "PROJECT", "PROCESS", "PATH", "CMD", "CWD",
    ];

    let mut rows: Vec<[String; 9]> = Vec::with_capacity(entries.len());
    for e in entries {
        let pid_str = if e.pid <= 0 {
            "-".to_string()
        } else {
            e.pid.to_string()
        };
        rows.push([
            e.proto.as_str().to_string(),
            e.port.to_string(),
            display_cell(&e.addr),
            pid_str,
            display_cell(&e.project),
            display_cell(&e.name),
            display_cell(&e.path),
            display_cell(&e.cmdline),
            display_cell(&short_cwd(&e.cwd)),
        ]);
    }

    let mut col_widths = [0usize; 9];
    for (i, h) in headers.iter().enumerate() {
        col_widths[i] = h.len();
    }
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > col_widths[i] {
                col_widths[i] = cell.len();
            }
        }
    }

    // Print header
    for (i, h) in headers.iter().enumerate() {
        if i == headers.len() - 1 {
            writeln!(w, "{h}")?;
        } else {
            write!(w, "{h:width$}  ", width = col_widths[i])?;
        }
    }

    // Print rows
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i == row.len() - 1 {
                writeln!(w, "{cell}")?;
            } else {
                write!(w, "{cell:width$}  ", width = col_widths[i])?;
            }
        }
    }

    w.flush()
}

/// Formats entries as pretty JSON array (2-space indent).
///
/// # Errors
/// Returns `io::Error` if writing to the output stream fails.
pub fn format_json<W: Write>(mut w: W, entries: &[Entry]) -> io::Result<()> {
    let json_rows: Vec<JsonRow<'_>> = entries
        .iter()
        .map(|e| {
            let svc = service_name(e.proto, e.port);
            let service = if svc.is_empty() { None } else { Some(svc) };
            JsonRow {
                proto: e.proto,
                port: e.port,
                addr: &e.addr,
                pid: e.pid,
                name: &e.name,
                path: &e.path,
                cmdline: &e.cmdline,
                cwd: &e.cwd,
                project: &e.project,
                service,
            }
        })
        .collect();

    serde_json::to_writer_pretty(&mut w, &json_rows).map_err(io::Error::other)?;
    writeln!(w)?;
    Ok(())
}

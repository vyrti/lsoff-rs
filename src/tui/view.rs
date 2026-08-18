use crate::group::ViewRow;
use crate::model::{Entry, Proto, short_cwd};
use crate::sanitize::{dash, sanitize_display};
use crate::services::{search_terms, service_name};
use crate::tui::app::App;
use crate::tui::style::{
    CONFIRM_BORDER_STYLE, ERR_STYLE, HEADER_STYLE, HELP_STYLE, OK_STYLE, PATH_STYLE, SEL_STYLE,
    SHORTCUT_DANGER_STYLE, SHORTCUT_KEY_STYLE, SHORTCUT_LABEL_STYLE, SHORTCUT_SEP_STYLE, TCP_STYLE,
    TITLE_STYLE, UDP_STYLE,
};
use ratatui::Frame;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Renders the complete TUI frame.
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width < 10 || area.height < 5 {
        return;
    }

    let mut lines = Vec::with_capacity(area.height as usize);

    // Line 0: Title and meta info
    lines.push(render_title_line(app));

    // Line 1: Search bar
    lines.push(render_search_line(app, area.width as usize));

    // Line 2: Header row
    lines.push(Line::from(vec![Span::styled(
        "   PROTO  PORT  ADDRESS                PID  PROJECT         PROCESS",
        HEADER_STYLE,
    )]));

    // Table rows
    let page_size = app.page_size(area.height);
    let end = (app.offset + page_size).min(app.rows.len());

    if app.rows.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "  no matching listeners",
            HELP_STYLE,
        )]));
    } else {
        for i in app.offset..end {
            let is_selected = i == app.cursor;
            lines.push(render_row(&app.rows[i], is_selected, area.width as usize));
        }
    }

    // Blank row separator before details
    lines.push(Line::raw(""));

    // Details panel (4 lines: SVC, PATH, CMD, CWD)
    if let Some(entry) = app.selected() {
        lines.extend(render_details(&entry, area.width as usize));
    } else {
        lines.push(Line::raw(""));
        lines.push(Line::raw(""));
        lines.push(Line::raw(""));
        lines.push(Line::raw(""));
    }

    // Confirmation box / Error / Status line
    if app.confirm {
        if let Some(e) = app.selected() {
            let name = sanitize_display(&e.name);
            let display_name = dash(&name);
            let msg = format!("Kill {display_name} (pid {})?  y / n", e.pid);
            lines.push(Line::from(vec![Span::styled(
                format!("╭─ {msg} ─╮"),
                CONFIRM_BORDER_STYLE,
            )]));
        } else {
            lines.push(Line::raw(""));
        }
    } else if let Some(ref err) = app.err {
        lines.push(Line::from(vec![Span::styled(err.clone(), ERR_STYLE)]));
    } else if !app.status.is_empty() {
        lines.push(Line::from(vec![Span::styled(app.status.clone(), OK_STYLE)]));
    } else {
        lines.push(Line::raw(""));
    }

    // Footer rule line
    let rule = "─".repeat(area.width as usize);
    lines.push(Line::from(vec![Span::styled(rule, SHORTCUT_SEP_STYLE)]));

    // Shortcut bar line
    lines.push(render_shortcut_bar(area.width as usize));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);
}

fn render_title_line(app: &App) -> Line<'static> {
    let arrow = if app.sort_desc { "↓" } else { "↑" };
    let proto_label = match (app.want_tcp, app.want_udp) {
        (true, false) => "  tcp",
        (false, true) => "  udp",
        _ => "",
    };

    let mut spans = vec![
        Span::styled("lsoff", TITLE_STYLE),
        Span::styled(
            format!(
                "  {}/{}{}  {}{}",
                app.rows.len(),
                app.all.len(),
                proto_label,
                app.sort_key.as_str(),
                arrow
            ),
            HELP_STYLE,
        ),
    ];

    if app.auto {
        spans.push(Span::styled("  auto", HELP_STYLE));
    }
    if app.loading {
        spans.push(Span::styled("  loading", HELP_STYLE));
    }

    Line::from(spans)
}

fn render_search_line(app: &App, _width: usize) -> Line<'static> {
    if app.query.is_empty() && !app.filtering {
        Line::from(vec![
            Span::raw("Search: "),
            Span::styled("/ to search", HELP_STYLE),
        ])
    } else {
        Line::from(vec![Span::raw("Search: "), Span::raw(app.query.clone())])
    }
}

fn render_row(row: &ViewRow, selected: bool, width: usize) -> Line<'static> {
    let e = &row.entry;
    let mut name = sanitize_display(&e.name);
    if name.is_empty() {
        name = "-".to_string();
    }
    if row.hidden > 0 {
        name = format!("{}  +{}", name, row.hidden);
    }
    let mut proj = sanitize_display(&e.project);
    if proj.is_empty() {
        proj = "-".to_string();
    }

    let max_name = if width > 64 { width - 64 } else { 8 };
    let name_truncated = truncate_width(&name, max_name);
    let addr_truncated = truncate_width(&sanitize_display(&e.addr), 21);
    let proj_truncated = truncate_width(&proj, 14);

    let pid_str = if e.pid <= 0 {
        "-".to_string()
    } else {
        e.pid.to_string()
    };

    let rest = format!(
        "  {:>5}  {:<21}  {:>7}  {:<14}  {}",
        e.port, addr_truncated, pid_str, proj_truncated, name_truncated
    );

    let mark = row.mark();
    let proto_str = format!("{:<4}", e.proto.as_str());

    if selected {
        let full_text = format!(" {mark} {proto_str}{rest}");
        let padded = pad_right(&full_text, width);
        Line::from(vec![Span::styled(padded, SEL_STYLE)])
    } else {
        let proto_style = match e.proto {
            Proto::Tcp => TCP_STYLE,
            Proto::Udp => UDP_STYLE,
        };
        Line::from(vec![
            Span::raw(format!(" {mark} ")),
            Span::styled(proto_str, proto_style),
            Span::raw(rest),
        ])
    }
}

fn render_details(e: &Entry, width: usize) -> Vec<Line<'static>> {
    let mut svc = service_name(e.proto, e.port).to_string();
    if svc.is_empty() {
        let aliases = search_terms(e.proto, e.port);
        svc = aliases.join(", ");
    }
    let svc_display = dash(&svc);

    let path_san = sanitize_display(&e.path);
    let path_display = dash(&path_san);

    let cmd_max = if width > 6 { width - 6 } else { 8 };
    let cmd_san = sanitize_display(&e.cmdline);
    let cmd_trunc = truncate_width(&cmd_san, cmd_max);
    let cmd_display = dash(&cmd_trunc);

    let cwd_san = sanitize_display(&short_cwd(&e.cwd));
    let cwd_trunc = truncate_width(&cwd_san, cmd_max);
    let cwd_display = dash(&cwd_trunc);

    vec![
        Line::from(vec![Span::styled(
            format!("SVC   {svc_display}"),
            PATH_STYLE,
        )]),
        Line::from(vec![Span::styled(
            format!("PATH  {path_display}"),
            PATH_STYLE,
        )]),
        Line::from(vec![Span::styled(
            format!("CMD   {cmd_display}"),
            PATH_STYLE,
        )]),
        Line::from(vec![Span::styled(
            format!("CWD   {cwd_display}"),
            PATH_STYLE,
        )]),
    ]
}

struct ShortcutItem {
    key: &'static str,
    label: &'static str,
    danger: bool,
}

fn render_shortcut_bar(width: usize) -> Line<'static> {
    let enter_key = if width < 100 { "↵" } else { "enter" };

    let all = [
        ShortcutItem {
            key: "/",
            label: "search",
            danger: false,
        },
        ShortcutItem {
            key: "j/k",
            label: "move",
            danger: false,
        },
        ShortcutItem {
            key: enter_key,
            label: "expand",
            danger: false,
        },
        ShortcutItem {
            key: "y",
            label: "copy",
            danger: false,
        },
        ShortcutItem {
            key: "a",
            label: "auto",
            danger: false,
        },
        ShortcutItem {
            key: "s",
            label: "sort",
            danger: false,
        },
        ShortcutItem {
            key: "x",
            label: "kill",
            danger: true,
        },
        ShortcutItem {
            key: "q",
            label: "quit",
            danger: false,
        },
    ];

    let variants: [&[usize]; 6] = [
        &[0, 1, 2, 3, 4, 5, 6, 7],
        &[0, 1, 2, 3, 4, 6, 7],
        &[0, 1, 2, 3, 6, 7],
        &[0, 1, 2, 6, 7],
        &[0, 1, 6, 7],
        &[0, 6, 7],
    ];

    let mut chosen_indices: &[usize] = variants[variants.len() - 1];
    for indices in variants {
        let total_w = calculate_shortcuts_width(&all, indices);
        if total_w + 2 <= width {
            chosen_indices = indices;
            break;
        }
    }

    let mut spans = Vec::new();
    spans.push(Span::raw(" "));
    for (i, &idx) in chosen_indices.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", SHORTCUT_SEP_STYLE));
        }
        let item = &all[idx];
        let key_style = if item.danger {
            SHORTCUT_DANGER_STYLE
        } else {
            SHORTCUT_KEY_STYLE
        };
        spans.push(Span::styled(item.key, key_style));
        spans.push(Span::styled(
            format!(" {}", item.label),
            SHORTCUT_LABEL_STYLE,
        ));
    }

    Line::from(spans)
}

fn calculate_shortcuts_width(all: &[ShortcutItem], indices: &[usize]) -> usize {
    let mut w = 1;
    for (i, &idx) in indices.iter().enumerate() {
        if i > 0 {
            w += 3; // " · "
        }
        let item = &all[idx];
        w += item.key.width() + 1 + item.label.width();
    }
    w
}

/// Truncates string to fit within `max_width` display columns, adding `…` if truncated.
#[must_use]
pub fn truncate_width(s: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if s.width() <= max_width {
        return s.to_string();
    }
    if max_width <= 1 {
        let first_char = s.chars().next().unwrap_or(' ');
        return first_char.to_string();
    }

    let target_width = max_width - 1;
    let mut current_width = 0;
    let mut out = String::new();

    for c in s.chars() {
        let cw = c.width().unwrap_or(0);
        if current_width + cw > target_width {
            break;
        }
        out.push(c);
        current_width += cw;
    }

    out.push('…');
    out
}

/// Pads a string with spaces on the right until its display width reaches `target_width`.
#[must_use]
pub fn pad_right(s: &str, target_width: usize) -> String {
    let w = s.width();
    if w >= target_width {
        return s.to_string();
    }
    let pad = target_width - w;
    format!("{}{}", s, " ".repeat(pad))
}

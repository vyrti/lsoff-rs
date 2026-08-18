use ratatui::style::{Color, Modifier, Style};

pub const TITLE_STYLE: Style = Style::new()
    .fg(Color::Indexed(81))
    .add_modifier(Modifier::BOLD);

pub const HELP_STYLE: Style = Style::new().fg(Color::Indexed(241));

pub const HEADER_STYLE: Style = Style::new()
    .fg(Color::Indexed(249))
    .add_modifier(Modifier::BOLD);

pub const TCP_STYLE: Style = Style::new().fg(Color::Indexed(42));

pub const UDP_STYLE: Style = Style::new().fg(Color::Indexed(214));

pub const SEL_STYLE: Style = Style::new().fg(Color::Indexed(230)).bg(Color::Indexed(63));

pub const CONFIRM_BORDER_STYLE: Style = Style::new().fg(Color::Indexed(203));

pub const ERR_STYLE: Style = Style::new().fg(Color::Indexed(203));

pub const OK_STYLE: Style = Style::new().fg(Color::Indexed(114));

pub const PATH_STYLE: Style = Style::new().fg(Color::Indexed(245));

pub const SHORTCUT_KEY_STYLE: Style = Style::new();

pub const SHORTCUT_DANGER_STYLE: Style = Style::new().fg(Color::Indexed(168));

pub const SHORTCUT_LABEL_STYLE: Style = Style::new().fg(Color::Indexed(244));

pub const SHORTCUT_SEP_STYLE: Style = Style::new().fg(Color::Indexed(239));

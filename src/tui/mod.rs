pub mod app;
pub mod event;
pub mod style;
pub mod view;

use app::App;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, poll as ct_poll, read as ct_read,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{self, stdout};
use std::time::Duration;

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture);
    }
}

/// Runs the interactive terminal UI.
///
/// # Errors
/// Returns `io::Error` if terminal initialization or rendering fails.
pub fn run(want_tcp: bool, want_udp: bool, query: &str) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new(want_tcp, want_udp, query);

    while !app.should_quit {
        terminal.draw(|f| view::render(f, &app))?;

        if ct_poll(Duration::from_millis(50))? {
            let height = terminal.size()?.height;
            match ct_read()? {
                Event::Key(key) => app.handle_key(key, height),
                Event::Mouse(mouse) => app.handle_mouse(mouse, height),
                Event::Resize(_, _) => {
                    terminal.autoresize()?;
                }
                _ => {}
            }
        }

        app.tick();
    }

    Ok(())
}

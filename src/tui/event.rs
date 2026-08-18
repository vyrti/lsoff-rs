use super::app::App;
use crate::group::FoldState;
use crate::kill::kill;
use crate::model::{SortKey, endpoint};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

const VIEW_FILTER_Y: u16 = 1;
const VIEW_HEADER_Y: u16 = 2;
const VIEW_ROWS_Y: u16 = 3;

impl App {
    pub fn handle_key(&mut self, key: KeyEvent, height: u16) {
        if self.confirm {
            self.handle_key_confirm(key);
        } else if self.filtering {
            self.handle_key_filter(key, height);
        } else {
            self.handle_key_table(key, height);
        }
    }

    fn handle_key_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y' | 'Y') => {
                self.confirm = false;
                if let Some(e) = self.selected() {
                    if e.pid <= 0 {
                        self.status = "no process to kill".to_string();
                        return;
                    }
                    if e.start == 0 {
                        self.status = "process identity unknown (refusing to kill)".to_string();
                        return;
                    }
                    match kill(e.ident()) {
                        Ok(()) => {
                            self.err = None;
                            self.status = format!("killed pid {}", e.pid);
                            self.reload();
                        }
                        Err(e) => {
                            self.status.clear();
                            self.err = Some(e.to_string());
                        }
                    }
                }
            }
            KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc => {
                self.confirm = false;
                self.status = "cancelled".to_string();
            }
            _ => {}
        }
    }

    fn handle_key_filter(&mut self, key: KeyEvent, height: u16) {
        let is_ctrl_c =
            key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        let is_ctrl_p =
            key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL);
        let is_ctrl_n =
            key.code == KeyCode::Char('n') && key.modifiers.contains(KeyModifiers::CONTROL);

        if is_ctrl_c || key.code == KeyCode::Esc {
            self.filtering = false;
            self.query.clear();
            self.apply_filter();
            return;
        }

        if key.code == KeyCode::Enter {
            self.filtering = false;
            return;
        }

        if key.code == KeyCode::Up || is_ctrl_p {
            if self.cursor > 0 {
                self.cursor -= 1;
                self.clamp(height);
            }
            return;
        }

        if key.code == KeyCode::Down || is_ctrl_n {
            if !self.rows.is_empty() && self.cursor < self.rows.len() - 1 {
                self.cursor += 1;
                self.clamp(height);
            }
            return;
        }

        if key.code == KeyCode::Backspace {
            self.query.pop();
            self.apply_filter();
            return;
        }

        if let KeyCode::Char(c) = key.code {
            self.query.push(c);
            self.apply_filter();
        }
    }

    fn handle_key_table(&mut self, key: KeyEvent, height: u16) {
        let is_ctrl_c =
            key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        let is_ctrl_f =
            key.code == KeyCode::Char('f') && key.modifiers.contains(KeyModifiers::CONTROL);
        let is_ctrl_r =
            key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL);
        let is_ctrl_p =
            key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL);
        let is_ctrl_n =
            key.code == KeyCode::Char('n') && key.modifiers.contains(KeyModifiers::CONTROL);

        if is_ctrl_c || key.code == KeyCode::Char('q') {
            self.should_quit = true;
            return;
        }

        if key.code == KeyCode::Char('/') || is_ctrl_f {
            self.filtering = true;
            return;
        }

        if key.code == KeyCode::Esc {
            if !self.query.is_empty() {
                self.query.clear();
                self.apply_filter();
            }
            return;
        }

        if key.code == KeyCode::Char('k') || key.code == KeyCode::Up || is_ctrl_p {
            if self.cursor > 0 {
                self.cursor -= 1;
                self.clamp(height);
            }
            return;
        }

        if key.code == KeyCode::Char('j') || key.code == KeyCode::Down || is_ctrl_n {
            if !self.rows.is_empty() && self.cursor < self.rows.len() - 1 {
                self.cursor += 1;
                self.clamp(height);
            }
            return;
        }

        let ps = self.page_size(height);
        if key.code == KeyCode::PageUp {
            if self.cursor > ps {
                self.cursor -= ps;
            } else {
                self.cursor = 0;
            }
            self.clamp(height);
            return;
        }

        if key.code == KeyCode::PageDown {
            if !self.rows.is_empty() {
                self.cursor = (self.cursor + ps).min(self.rows.len() - 1);
                self.clamp(height);
            }
            return;
        }

        if key.code == KeyCode::Home || key.code == KeyCode::Char('g') {
            self.cursor = 0;
            self.clamp(height);
            return;
        }

        if (key.code == KeyCode::End || key.code == KeyCode::Char('G')) && !self.rows.is_empty() {
            self.cursor = self.rows.len() - 1;
            self.clamp(height);
            return;
        }

        if key.code == KeyCode::Char('r') || is_ctrl_r {
            self.reload();
            return;
        }

        if key.code == KeyCode::Char('a') {
            self.auto = !self.auto;
            self.status = if self.auto {
                "auto-refresh on (2s)".to_string()
            } else {
                "auto-refresh off".to_string()
            };
            return;
        }

        if key.code == KeyCode::Char('s') {
            self.sort_key = self.sort_key.next();
            self.apply_filter();
            return;
        }

        if key.code == KeyCode::Char('S') {
            self.sort_desc = !self.sort_desc;
            self.apply_filter();
            return;
        }

        if key.code == KeyCode::Enter || key.code == KeyCode::Char(' ') {
            self.toggle_expand();
            return;
        }

        if key.code == KeyCode::Char('l') {
            self.expand_current();
            return;
        }

        if key.code == KeyCode::Char('h') {
            self.collapse_current();
            return;
        }

        if key.code == KeyCode::Char('y') {
            self.copy_endpoint();
            return;
        }

        if key.code == KeyCode::Char('x')
            && let Some(e) = self.selected()
        {
            if e.pid > 0 {
                self.confirm = true;
            } else {
                self.status = "no process to kill (pid unknown)".to_string();
            }
        }
    }

    fn toggle_expand(&mut self) {
        if let Some(row) = self.selected_row() {
            let pid = row.entry.pid;
            if pid <= 0 {
                return;
            }
            match row.fold {
                FoldState::Collapsed => {
                    self.expanded.insert(pid, true);
                    self.apply_filter();
                }
                FoldState::Expanded => {
                    self.expanded.remove(&pid);
                    self.apply_filter();
                }
                FoldState::Child => {
                    self.expanded.remove(&pid);
                    self.apply_filter();
                }
                FoldState::None => {}
            }
        }
    }

    fn expand_current(&mut self) {
        if let Some(row) = self.selected_row() {
            let pid = row.entry.pid;
            if pid > 0 && row.fold == FoldState::Collapsed {
                self.expanded.insert(pid, true);
                self.apply_filter();
            }
        }
    }

    fn collapse_current(&mut self) {
        if let Some(row) = self.selected_row() {
            let pid = row.entry.pid;
            if pid > 0 && (row.fold == FoldState::Expanded || row.fold == FoldState::Child) {
                self.expanded.remove(&pid);
                self.apply_filter();
            }
        }
    }

    fn copy_endpoint(&mut self) {
        if let Some(e) = self.selected() {
            let ep = endpoint(&e.addr, e.port);
            if let Some(ref mut cb) = self.clipboard {
                if cb.set_text(&ep).is_ok() {
                    self.status = format!("copied {ep}");
                } else {
                    self.status = format!("failed to copy {ep}");
                }
            } else {
                self.status = format!("clipboard not available: {ep}");
            }
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent, height: u16) {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                self.handle_click(mouse.column, mouse.row, height);
            }
            MouseEventKind::ScrollUp => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.clamp(height);
                }
            }
            MouseEventKind::ScrollDown
                if !self.rows.is_empty() && self.cursor < self.rows.len() - 1 =>
            {
                self.cursor += 1;
                self.clamp(height);
            }
            _ => {}
        }
    }

    fn handle_click(&mut self, col: u16, row: u16, height: u16) {
        if self.confirm {
            return;
        }

        if row == VIEW_FILTER_Y {
            self.filtering = true;
            return;
        }

        if row == VIEW_HEADER_Y {
            self.handle_header_click(col);
            return;
        }

        let ps = self.page_size(height);
        let first_row = VIEW_ROWS_Y;
        let last_row = first_row + (ps as u16) - 1;

        if row >= first_row && row <= last_row {
            let idx = self.offset + (row - first_row) as usize;
            if idx < self.rows.len() {
                if self.cursor == idx {
                    self.toggle_expand();
                } else {
                    self.cursor = idx;
                    self.clamp(height);
                }
            }
        }
    }

    fn handle_header_click(&mut self, col: u16) {
        let key = if col < 9 {
            SortKey::Proto
        } else if col < 15 {
            SortKey::Port
        } else if col < 38 {
            SortKey::Addr
        } else if col < 43 {
            SortKey::Pid
        } else if col < 59 {
            SortKey::Project
        } else {
            SortKey::Name
        };

        if self.sort_key == key {
            self.sort_desc = !self.sort_desc;
        } else {
            self.sort_key = key;
            self.sort_desc = false;
        }
        self.apply_filter();
    }
}

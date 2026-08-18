use crate::filter::{filter_proto, filter_query};
use crate::group::{ViewRow, flatten_groups};
use crate::model::{Entry, SortKey};
use crate::sys::list_listeners;
use arboard::Clipboard;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const AUTO_INTERVAL: Duration = Duration::from_secs(2);

pub struct App {
    pub all: Vec<Entry>,
    pub rows: Vec<ViewRow>,
    pub cursor: usize,
    pub offset: usize,
    pub query: String,
    pub filtering: bool,
    pub confirm: bool,
    pub status: String,
    pub err: Option<String>,
    pub loading: bool,
    pub load_gen: usize,
    pub want_tcp: bool,
    pub want_udp: bool,
    pub auto: bool,
    pub sort_key: SortKey,
    pub sort_desc: bool,
    pub expanded: HashMap<i32, bool>,
    pub should_quit: bool,
    pub last_tick: Instant,
    pub(crate) clipboard: Option<Clipboard>,
}

impl App {
    #[must_use]
    pub fn new(want_tcp: bool, want_udp: bool, initial_query: &str) -> Self {
        let mut app = Self {
            all: Vec::new(),
            rows: Vec::new(),
            cursor: 0,
            offset: 0,
            query: initial_query.to_string(),
            filtering: !initial_query.is_empty(),
            confirm: false,
            status: String::new(),
            err: None,
            loading: true,
            load_gen: 1,
            want_tcp,
            want_udp,
            auto: false,
            sort_key: SortKey::Port,
            sort_desc: false,
            expanded: HashMap::new(),
            should_quit: false,
            last_tick: Instant::now(),
            clipboard: Clipboard::new().ok(),
        };

        app.reload();
        app
    }

    pub fn reload(&mut self) {
        self.loading = true;
        self.load_gen += 1;
        let expected_gen = self.load_gen;

        match list_listeners() {
            Ok(entries) => {
                if self.load_gen == expected_gen {
                    self.loading = false;
                    self.err = None;
                    self.all = filter_proto(&entries, self.want_tcp, self.want_udp);
                    self.apply_filter();
                    self.status = format!("{} listening sockets", self.all.len());
                }
            }
            Err(e) => {
                if self.load_gen == expected_gen {
                    self.loading = false;
                    self.err = Some(e.to_string());
                }
            }
        }
    }

    pub fn tick(&mut self) {
        if self.auto && !self.confirm && !self.loading && self.last_tick.elapsed() >= AUTO_INTERVAL
        {
            self.last_tick = Instant::now();
            self.reload();
        }
    }

    pub fn page_size(&self, height: u16) -> usize {
        let h = height as usize;
        if h > 12 { h - 12 } else { 1 }
    }

    pub fn selected(&self) -> Option<Entry> {
        self.rows.get(self.cursor).map(|r| r.entry.clone())
    }

    pub fn selected_row(&self) -> Option<&ViewRow> {
        self.rows.get(self.cursor)
    }

    pub fn apply_filter(&mut self) {
        let mut keep = Vec::new();
        if let Some(r) = self.selected_row() {
            keep.push(r.id());
            keep.push(r.entry.key());
            if r.entry.pid > 0 {
                keep.push(format!("p/{}", r.entry.pid));
            }
        }

        let filtered = filter_query(&self.all, &self.query);
        self.rows = flatten_groups(&filtered, self.sort_key, self.sort_desc, &self.expanded);

        for id in keep {
            if let Some(idx) = self
                .rows
                .iter()
                .position(|r| r.id() == id || r.entry.key() == id)
            {
                self.cursor = idx;
                self.clamp(24);
                return;
            }
        }

        if self.rows.is_empty() {
            self.cursor = 0;
        } else if self.cursor >= self.rows.len() {
            self.cursor = self.rows.len() - 1;
        }
        self.clamp(24);
    }

    pub fn clamp(&mut self, height: u16) {
        let n = self.rows.len();
        if n == 0 {
            self.cursor = 0;
            self.offset = 0;
            return;
        }
        if self.cursor >= n {
            self.cursor = n - 1;
        }

        let ps = self.page_size(height);
        if self.cursor < self.offset {
            self.offset = self.cursor;
        }
        if self.cursor >= self.offset + ps {
            self.offset = self.cursor + 1 - ps;
        }
    }
}

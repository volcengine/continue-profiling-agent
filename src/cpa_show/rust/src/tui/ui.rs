// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use crate::cpa::{parse_cpu_set, Filter, FilterSet, FilterTarget, FilterValue};
use crate::profile::{ProfileData, UiProfile};
use anyhow::Context;
use crossterm::{
    cursor::MoveTo,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget},
    Terminal,
};
use std::{
    collections::{HashMap, VecDeque},
    hash::{Hash, Hasher},
    io,
    time::{Duration, Instant},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ChartMode {
    Small,
    Half,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AggregationMode {
    BottomUp, // Root -> Leaf (Standard)
    TopDown,  // Leaf -> Root (Icicle/Sandwich)
}

#[derive(Debug, Default, Clone)]
struct ViewToggles {
    show_env: bool,
    show_pid: bool,
    show_comm: bool,
    show_cgroup_id: bool,
    show_cpu: bool,
    show_thread_name: bool,
    only_kernel: bool,

    // stack frame display aggregation
    agg_hex_addr_mod: bool,
    agg_irqoff_cpu: bool,
}

#[derive(Debug, Clone)]
struct CmdInput {
    buf: String,
    cursor: usize,
}

impl CmdInput {
    fn new() -> Self {
        Self {
            buf: String::new(),
            cursor: 0,
        }
    }

    fn insert(&mut self, ch: char) {
        self.buf.insert(self.cursor, ch);
        self.cursor += 1;
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        self.buf.remove(self.cursor);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptKind {
    Command,
    GotoTime,
    SetRange,
}

#[derive(Debug, Clone)]
struct Prompt {
    kind: PromptKind,
    input: CmdInput,
}

#[derive(Debug, Clone)]
struct Node {
    name: String,
    parent: Option<usize>,
    children: Vec<usize>,
    value: u64,
}

#[derive(Debug, Default, Clone)]
struct Arena {
    nodes: Vec<Node>,
}

impl Arena {
    fn new_root() -> Self {
        Self {
            nodes: vec![Node {
                name: "(root)".to_string(),
                parent: None,
                children: Vec::new(),
                value: 0,
            }],
        }
    }

    fn add_child(&mut self, parent: usize, name: &str) -> usize {
        let id = self.nodes.len();
        self.nodes.push(Node {
            name: name.to_string(),
            parent: Some(parent),
            children: Vec::new(),
            value: 0,
        });
        self.nodes[parent].children.push(id);
        id
    }

    fn find_or_add_child(&mut self, parent: usize, name: &str) -> usize {
        for &c in &self.nodes[parent].children {
            if self.nodes[c].name == name {
                return c;
            }
        }
        self.add_child(parent, name)
    }
}

#[derive(Debug, Clone)]
struct LayoutRect {
    node_id: usize,
    x: u16,
    w: u16,
    y: u16,
}

struct App {
    profile: UiProfile,

    start: usize,
    span: usize,
    chart_mode: ChartMode,
    agg_mode: AggregationMode,
    chart_full: bool,
    chart_window_sec_default: u64,
    chart_window_sec: u64,
    toggles: ViewToggles,

    flame: Arena,
    focused_root: usize,
    selected: usize,
    focused_child_cursor: usize,

    // flamegraph vertical scroll (row offset from focused_root, 0 means show root row)
    flame_scroll_y: u16,

    // caches
    last_build_key: u64,

    // curves
    cpu_c: Vec<f64>,
    sys_c: Vec<Option<f64>>,
    sys_next: usize,
    sys_next_redraw: usize,

    // filters
    filters: FilterSet,

    // ui
    prompt: Option<Prompt>,
    show_conf: bool,
    show_help: bool,
    show_filters: bool,
    status: VecDeque<String>,
    last_render_us: u128,

    // render
    dirty: bool,
}

impl App {
    fn new(profile: UiProfile, start: usize, span: usize) -> Self {
        let mut toggles = ViewToggles::default();
        toggles.show_env = true;
        toggles.show_pid = true;
        toggles.show_comm = true;
        toggles.show_cgroup_id = false;
        toggles.show_cpu = false;
        toggles.show_thread_name = false;
        toggles.only_kernel = false;
        toggles.agg_hex_addr_mod = false;
        toggles.agg_irqoff_cpu = false;

        // Do not scan stack.bin fully at startup; curves are computed incrementally.
        let cpu_c = vec![0.0; profile.data.record_count()];
        let sys_c = vec![None; profile.data.record_count()];

        Self {
            profile,
            start,
            span: span.max(1),
            chart_mode: ChartMode::Small,
            agg_mode: AggregationMode::BottomUp,
            chart_full: false,
            chart_window_sec_default: 600,
            chart_window_sec: 600,
            toggles,
            flame: Arena::new_root(),
            focused_root: 0,
            selected: 0,
            focused_child_cursor: 0,
            flame_scroll_y: 0,
            last_build_key: 0,
            cpu_c,
            sys_c,
            sys_next: 0,
            sys_next_redraw: 0,
            filters: FilterSet::default(),
            prompt: None,
            show_conf: false,
            show_help: false,
            show_filters: false,
            status: VecDeque::new(),
            last_render_us: 0,
            dirty: true,
        }
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn clamp_window(&mut self) {
        let len = self.profile.data.record_count();
        if len == 0 {
            self.start = 0;
            self.span = 1;
            return;
        }
        self.start = self.start.min(len - 1);
        self.span = self.span.max(1).min(len);
        if self.start + self.span > len {
            self.span = len - self.start;
        }
    }

    fn push_status(&mut self, s: impl Into<String>) {
        self.status.push_front(s.into());
        while self.status.len() > 3 {
            self.status.pop_back();
        }
        self.mark_dirty();
    }

    fn build_key(&self) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.start.hash(&mut h);
        self.span.hash(&mut h);
        self.agg_mode.hash(&mut h);
        self.toggles.show_env.hash(&mut h);
        self.toggles.show_pid.hash(&mut h);
        self.toggles.show_comm.hash(&mut h);
        self.toggles.show_cgroup_id.hash(&mut h);
        self.toggles.show_cpu.hash(&mut h);
        self.toggles.show_thread_name.hash(&mut h);
        self.toggles.only_kernel.hash(&mut h);
        self.toggles.agg_hex_addr_mod.hash(&mut h);
        self.toggles.agg_irqoff_cpu.hash(&mut h);
        // filters
        self.filters.items.len().hash(&mut h);
        // Simplification: hash Debug text to avoid custom serialization.
        format!("{:?}", self.filters.items).hash(&mut h);
        h.finish()
    }

    fn reset_curves(&mut self) {
        self.sys_next = 0;
        self.sys_next_redraw = 0;
        self.cpu_c.fill(0.0);
        self.sys_c.fill(None);
        self.mark_dirty();
    }

    fn rebuild_if_needed(&mut self) {
        let k = self.build_key();
        if k == self.last_build_key {
            return;
        }

        let t0 = Instant::now();
        let flame = build_flamegraph(
            &self.profile,
            self.start,
            self.span,
            self.agg_mode,
            &self.toggles,
            &self.filters,
        );
        let cost = t0.elapsed();
        self.flame = flame;
        self.focused_root = 0;
        self.selected = 0;
        self.focused_child_cursor = 0;
        self.flame_scroll_y = 0;
        self.last_build_key = k;
        self.push_status(format!(
            "Rebuild flamegraph: {:.2}ms",
            cost.as_secs_f64() * 1000.0
        ));
        self.mark_dirty();
    }

    fn is_curve_pending_for_current_view(&self) -> bool {
        let (idx_lo, idx_hi, _t_lo, _t_hi) = chart_view_bounds(self);
        if idx_hi <= idx_lo {
            return false;
        }
        self.sys_c[idx_lo..idx_hi].iter().any(|v| v.is_none())
    }

    fn tick_sys_curve(&mut self) {
        if self.profile.data.record_count() == 0 {
            return;
        }

        // 1) Prioritize filling the current visible chart range (avoid initial blank chart).
        let (idx_lo, idx_hi, _t_lo, _t_hi) = chart_view_bounds(self);
        let mut progressed = false;
        let mut pending_visible = false;
        if idx_hi > idx_lo {
            if let Some(next_missing) = (idx_lo..idx_hi).find(|&i| self.sys_c[i].is_none()) {
                pending_visible = true;
                let chunk = 128usize;
                let end = (next_missing + chunk).min(idx_hi);
                fill_cpu_sys_curves(
                    &*self.profile.data,
                    &self.filters,
                    next_missing,
                    end,
                    &mut self.cpu_c,
                    &mut self.sys_c,
                );
                progressed = true;
            }
        }

        // 2) Continue background full-fill (for full-history view/future windows) sequentially.
        if !progressed && self.sys_next < self.profile.data.record_count() {
            let before = self.sys_next;
            let chunk = 32usize;
            let end = (self.sys_next + chunk).min(self.profile.data.record_count());
            fill_cpu_sys_curves(
                &*self.profile.data,
                &self.filters,
                self.sys_next,
                end,
                &mut self.cpu_c,
                &mut self.sys_c,
            );
            self.sys_next = end;
            progressed = before != self.sys_next;
        }

        // 3) Refresh policy: busy-refresh only while the current visible range is incomplete.
        //    Once visible range is complete, background fill won't trigger redraw.
        if pending_visible && progressed {
            self.mark_dirty();
        }
    }

    fn handle_key(&mut self, k: KeyEvent) {
        if let Some(p) = &mut self.prompt {
            let cmd = &mut p.input;
            match k.code {
                KeyCode::Esc => {
                    self.prompt = None;
                    self.mark_dirty();
                }
                KeyCode::Enter => {
                    let line = cmd.buf.trim().to_string();
                    let kind = p.kind;
                    self.prompt = None;
                    self.mark_dirty();
                    if !line.is_empty() {
                        let r = match kind {
                            PromptKind::Command => self.apply_command(&line),
                            PromptKind::GotoTime => self.apply_goto_time(&line),
                            PromptKind::SetRange => self.apply_set_range(&line),
                        };
                        if let Err(e) = r {
                            self.push_status(format!("Input error: {e}"));
                        }
                    }
                }
                KeyCode::Backspace => cmd.backspace(),
                KeyCode::Left => cmd.cursor = cmd.cursor.saturating_sub(1),
                KeyCode::Right => cmd.cursor = (cmd.cursor + 1).min(cmd.buf.len()),
                KeyCode::Char(c) => {
                    if k.modifiers.contains(KeyModifiers::CONTROL) {
                        return;
                    }
                    cmd.insert(c);
                }
                _ => {}
            }
            self.mark_dirty();
            return;
        }

        match k.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                // handled by caller via return flag
            }
            KeyCode::Char(':') => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::Command,
                    input: CmdInput::new(),
                });
                self.mark_dirty();
            }
            KeyCode::Char('J') => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::GotoTime,
                    input: CmdInput::new(),
                });
                self.mark_dirty();
            }
            KeyCode::Char('R') => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::SetRange,
                    input: CmdInput::new(),
                });
                self.mark_dirty();
            }
            KeyCode::Char('?') | KeyCode::Char('h') => {
                self.show_help = !self.show_help;
                self.mark_dirty();
            }
            KeyCode::Char('c') if k.modifiers.is_empty() => {
                self.show_conf = !self.show_conf;
                self.mark_dirty();
            }
            KeyCode::Char('o') => {
                self.show_filters = !self.show_filters;
                self.mark_dirty();
            }

            // Time window
            KeyCode::Char('t') => {
                self.start = (self.start + self.span)
                    .min(self.profile.data.record_count().saturating_sub(1));
                self.clamp_window();
                self.rebuild_if_needed();
            }
            KeyCode::Char('T') => {
                self.start = self.start.saturating_sub(self.span);
                self.clamp_window();
                self.rebuild_if_needed();
            }
            KeyCode::Char('s') => {
                self.span = (self.span + 1).min(self.profile.data.record_count().max(1));
                self.clamp_window();
                self.rebuild_if_needed();
            }
            KeyCode::Char('S') => {
                self.span = self.span.saturating_sub(1).max(1);
                self.clamp_window();
                self.rebuild_if_needed();
            }

            // Chart window is fixed to default seconds (except full/reset).
            // Keep +/- reserved.
            KeyCode::Char('-') | KeyCode::Char('=') | KeyCode::Char('+') => {
                self.mark_dirty();
            }
            KeyCode::Char('0') => {
                self.chart_full = true;
                self.mark_dirty();
            }
            KeyCode::Char('9') => {
                self.chart_full = false;
                self.chart_window_sec = self.chart_window_sec_default;
                self.mark_dirty();
            }

            // Toggles (aligned with CUI)
            KeyCode::Char('N') => {
                self.toggles.show_env = !self.toggles.show_env;
                self.rebuild_if_needed();
            }
            KeyCode::Char('P') => {
                self.toggles.show_pid = !self.toggles.show_pid;
                self.rebuild_if_needed();
            }
            KeyCode::Char('M') => {
                self.toggles.show_comm = !self.toggles.show_comm;
                self.rebuild_if_needed();
            }
            KeyCode::Char('D') => {
                self.toggles.show_cgroup_id = !self.toggles.show_cgroup_id;
                self.rebuild_if_needed();
            }
            KeyCode::Char('C') => {
                self.toggles.show_cpu = !self.toggles.show_cpu;
                self.rebuild_if_needed();
            }
            KeyCode::Char('H') => {
                self.toggles.show_thread_name = !self.toggles.show_thread_name;
                self.rebuild_if_needed();
            }
            KeyCode::Char('O') => {
                self.toggles.only_kernel = !self.toggles.only_kernel;
                self.rebuild_if_needed();
            }

            // stack frame aggregation
            KeyCode::Char('X') => {
                self.toggles.agg_hex_addr_mod = !self.toggles.agg_hex_addr_mod;
                self.rebuild_if_needed();
            }
            KeyCode::Char('U') => {
                self.toggles.agg_irqoff_cpu = !self.toggles.agg_irqoff_cpu;
                self.rebuild_if_needed();
            }

            // View
            KeyCode::Char('I') => {
                self.agg_mode = match self.agg_mode {
                    AggregationMode::BottomUp => AggregationMode::TopDown,
                    AggregationMode::TopDown => AggregationMode::BottomUp,
                };
                self.rebuild_if_needed();
            }
            KeyCode::Char('g') | KeyCode::Char('G') => {
                self.chart_mode = match self.chart_mode {
                    ChartMode::Small => ChartMode::Half,
                    ChartMode::Half => ChartMode::Full,
                    ChartMode::Full => ChartMode::Small,
                };
                self.mark_dirty();
            }

            // flamegraph navigation
            KeyCode::Up | KeyCode::Char('k') => self.move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_down(),
            KeyCode::Left | KeyCode::Char('a') => self.move_left(),
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('d') => self.move_right(),
            KeyCode::Enter => self.zoom_in(),
            KeyCode::Esc => self.zoom_out(),
            _ => {}
        }
    }

    fn apply_goto_time(&mut self, input: &str) -> anyhow::Result<()> {
        let t = parse_time_ms(input)?;
        let idx = find_record_by_time(self.profile.data.records(), t);
        self.start = idx;
        self.clamp_window();
        self.rebuild_if_needed();
        self.push_status(format!("Jump to {} (idx={})", fmt_ms(t), idx));
        Ok(())
    }

    fn apply_set_range(&mut self, input: &str) -> anyhow::Result<()> {
        let (a, b) = parse_range_ms(input)?;
        let (s, e) = if a <= b { (a, b) } else { (b, a) };
        let start_idx = find_record_by_time(self.profile.data.records(), s);
        let end_excl = find_record_end_exclusive(self.profile.data.records(), e);
        let end_excl = end_excl.max(start_idx + 1);
        self.start = start_idx;
        self.span = end_excl - start_idx;
        self.clamp_window();
        self.rebuild_if_needed();
        self.push_status(format!("Set range time=[{}..{}]", fmt_ms(s), fmt_ms(e)));
        Ok(())
    }

    fn apply_command(&mut self, line: &str) -> anyhow::Result<()> {
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let arg = parts.collect::<Vec<_>>().join(" ");

        if cmd == "unset" {
            let name = arg.trim();
            let removed = self.filters.remove_by_command(name);
            if removed {
                self.push_status(format!("unset {name}: ok"));
                self.reset_curves();
            } else {
                self.push_status(format!("unset {name}: not found"));
            }
            self.rebuild_if_needed();
            return Ok(());
        }

        let f = parse_filter_cmd(cmd, arg.trim())?;
        self.filters.items.push(f);
        self.push_status(format!("Add filter: {line}"));
        self.reset_curves();
        self.rebuild_if_needed();
        Ok(())
    }

    fn move_up(&mut self) {
        let n = &self.flame.nodes[self.selected];
        if let Some(p) = n.parent {
            self.selected = p;
            self.mark_dirty();
        }
    }

    fn move_down(&mut self) {
        let children = self.flame.nodes[self.selected].children.clone();
        if children.is_empty() {
            return;
        }
        let mut best = children[0];
        let mut best_v = self.flame.nodes[best].value;
        for c in children {
            let v = self.flame.nodes[c].value;
            if v > best_v {
                best = c;
                best_v = v;
            }
        }
        self.selected = best;

        // update cursor when navigating within focused root
        let parent = self.flame.nodes[self.selected].parent;
        if parent == Some(self.focused_root) {
            if let Some(pos) = self.flame.nodes[self.focused_root]
                .children
                .iter()
                .position(|&x| x == self.selected)
            {
                self.focused_child_cursor = pos;
            }
        }

        self.mark_dirty();
    }

    fn move_left(&mut self) {
        self.cycle_sibling(-1);
    }

    fn move_right(&mut self) {
        self.cycle_sibling(1);
    }

    fn cycle_sibling(&mut self, delta: i32) {
        if self.flame.nodes.is_empty() {
            return;
        }

        // when focus root selected, cycle among its children
        if self.selected == self.focused_root {
            let siblings = self.flame.nodes[self.focused_root].children.clone();
            if siblings.is_empty() {
                return;
            }
            let len = siblings.len();
            let cur = self.focused_child_cursor.min(len - 1);
            let next = (cur as i32 + delta).rem_euclid(len as i32) as usize;
            self.focused_child_cursor = next;
            self.selected = siblings[next];
            self.mark_dirty();
            return;
        }

        let Some(p) = self.flame.nodes[self.selected].parent else {
            return;
        };
        let siblings = self.flame.nodes[p].children.clone();
        if siblings.is_empty() {
            return;
        }
        let len = siblings.len();
        let pos = siblings
            .iter()
            .position(|&x| x == self.selected)
            .unwrap_or(0);
        let next = (pos as i32 + delta).rem_euclid(len as i32) as usize;
        self.selected = siblings[next];
        if p == self.focused_root {
            self.focused_child_cursor = next;
        }
        self.mark_dirty();
    }

    fn zoom_in(&mut self) {
        self.focused_root = self.selected;
        self.focused_child_cursor = 0;
        self.flame_scroll_y = 0;
        self.mark_dirty();
    }

    fn zoom_out(&mut self) {
        self.focused_root = 0;
        self.selected = 0;
        self.focused_child_cursor = 0;
        self.flame_scroll_y = 0;
        self.mark_dirty();
    }
}

pub fn run(profile: UiProfile, start: usize, span: usize, timing: bool) -> anyhow::Result<()> {
    let t0 = Instant::now();

    let t_app = Instant::now();
    let mut app = App::new(profile, start, span);
    app.clamp_window();
    let dt_app = t_app.elapsed();
    let t_build = Instant::now();
    app.rebuild_if_needed();
    let dt_build = t_build.elapsed();

    if timing {
        eprintln!(
            "[cpa_show][timing] tui init (App::new): {:.2}ms",
            dt_app.as_secs_f64() * 1000.0
        );
        eprintln!(
            "[cpa_show][timing] tui init (initial flame build): {:.2}ms",
            dt_build.as_secs_f64() * 1000.0
        );
    }

    // NOTE: Do NOT print to stderr after entering AlternateScreen, it will corrupt the top line.
    if timing {
        eprintln!(
            "[cpa_show][timing] tui startup total(before AlternateScreen): {:.2}ms",
            t0.elapsed().as_secs_f64() * 1000.0
        );
    }

    enable_raw_mode().context("enable_raw_mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("EnterAlternateScreen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Terminal::new")?;

    // hard clear once on entering alternate screen to avoid stale top-line artifacts
    execute!(
        terminal.backend_mut(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        MoveTo(0, 0)
    )
    .ok();
    terminal.clear().ok();

    let tick_rate = Duration::from_millis(50);

    let res = (|| -> anyhow::Result<()> {
        loop {
            // Incremental curve computation; prioritize visible range.
            app.tick_sys_curve();

            if app.dirty {
                let t0 = Instant::now();
                terminal.draw(|f| {
                    let area = f.area();
                    render_app(f.buffer_mut(), area, &mut app);
                })?;
                app.last_render_us = t0.elapsed().as_micros();
                app.dirty = false;
            }

            // Busy-refresh strategy: when visible curve is incomplete, do not sleep (poll 0ms).
            let poll_timeout = if app.is_curve_pending_for_current_view() {
                Duration::from_millis(0)
            } else {
                tick_rate
            };

            if event::poll(poll_timeout)? {
                match event::read()? {
                    Event::Key(k) => {
                        if matches!(k.code, KeyCode::Char('q') | KeyCode::Char('Q')) {
                            break;
                        }
                        app.handle_key(k);
                    }
                    Event::Resize(_, _) => {
                        app.mark_dirty();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    res
}

fn render_app(buf: &mut Buffer, area: Rect, app: &mut App) {
    // clear full screen buffer to avoid leaving stale characters (especially on borders)
    Clear.render(area, buf);

    let chunks = match app.chart_mode {
        ChartMode::Small => Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),
                Constraint::Min(5),
                Constraint::Length(6),
            ])
            .split(area),
        ChartMode::Half => {
            let half = area.height / 2;
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(half.max(8)),
                    Constraint::Min(5),
                    Constraint::Length(6),
                ])
                .split(area)
        }
        ChartMode::Full => Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),
                Constraint::Length(0),
                Constraint::Length(6),
            ])
            .split(area),
    };

    let chart_area = chunks[0];
    let flame_area = chunks[1];
    let status_area = chunks[2];

    render_chart(buf, chart_area, app);

    if flame_area.height > 0 {
        render_flame(buf, flame_area, app);
    }

    render_status(buf, status_area, app);

    if app.show_conf {
        render_popup(buf, area, "conf", &render_conf_lines(app));
    }
    if app.show_help {
        render_popup(buf, area, "help", &render_help_lines());
    }
    if app.show_filters {
        render_popup(buf, area, "filters", &render_filter_lines(app));
    }
    if let Some(p) = &app.prompt {
        render_cmdline(buf, area, p);
    }
}

fn render_chart(buf: &mut Buffer, area: Rect, app: &App) {
    let cm = match app.chart_mode {
        ChartMode::Small => "Small",
        ChartMode::Half => "Half",
        ChartMode::Full => "Full",
    };

    let (idx_lo, idx_hi, t_lo, t_hi) = chart_view_bounds(app);
    let (win_s, win_e) = window_bounds_ms(app);
    let win_dur = fmt_dur(win_e.saturating_sub(win_s));

    // Keep title short to avoid truncation on common terminal widths.
    // Toggle states are shown in Status line.
    let title = format!(
        " CPU Trend [{cm}] Sel:{} ({}) | [t]/[T] shift  [s]/[S] span  [J] jump  [R] range  [g] height  [0] all  [9] reset ",
        fmt_ms(win_s),
        win_dur
    );

    // Render borders first; render title manually to avoid overflow corrupting corners.
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(area);
    block.render(area, buf);
    if area.width >= 2 {
        let title_w = area.width.saturating_sub(2);
        render_text_fixed_width(
            buf,
            area.x + 1,
            area.y,
            title_w,
            Style::default().fg(Color::White),
            &title,
        );
    }
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    // Reserve last line inside for x-axis labels
    let plot_h = inner.height.saturating_sub(1);
    if plot_h == 0 {
        return;
    }
    // Reserve a small left area for y-axis labels (C cores)
    let y_axis_w = if inner.width >= 16 { 6u16 } else { 0u16 };
    let plot_x = inner.x.saturating_add(y_axis_w);
    let plot_w = inner.width.saturating_sub(y_axis_w);
    if plot_w == 0 {
        return;
    }
    let plot = Rect {
        x: plot_x,
        y: inner.y,
        width: plot_w,
        height: plot_h,
    };

    // bucket points to columns to avoid NaN-based line breaks
    let (cpu_cols, sys_cols, data_max_y) = bucketize_trend_columns(app, idx_lo, idx_hi, plot.width);
    // y-axis max should be based on *current visible range only* (ceil), do NOT clamp to cpu_num.
    let axis_max_y = data_max_y.ceil().max(1.0);

    // y-axis labels (cores)
    if y_axis_w > 0 {
        draw_y_axis_cores(
            buf,
            Rect {
                x: inner.x,
                y: plot.y,
                width: y_axis_w,
                height: plot.height,
            },
            axis_max_y,
            app.profile.data.config().cpu_num,
        );
    }

    // selection markers first (lowest priority), then cpu, then sys.
    draw_selection_markers(buf, plot, t_lo, t_hi, win_s, win_e, axis_max_y);

    // draw stems (priority: sys > cpu > selection)
    for col in 0..plot.width {
        let x = plot.x + col;
        if axis_max_y <= 0.0 {
            continue;
        }

        if let Some(cpu_y) = cpu_cols.get(col as usize).copied().flatten() {
            draw_vertical_stem(
                buf,
                plot,
                x,
                cpu_y,
                axis_max_y,
                Style::default().fg(Color::Cyan),
            );
        }
        if let Some(sys_y) = sys_cols.get(col as usize).copied().flatten() {
            draw_vertical_stem(
                buf,
                plot,
                x,
                sys_y,
                axis_max_y,
                Style::default().fg(Color::Yellow),
            );
        }
    }

    // axis labels on bottom inside line
    let axis_y = inner.y + inner.height - 1;
    let left = format!("{}", fmt_ms(t_lo));
    let right = format!("{}", fmt_ms(t_hi));
    render_text_fixed_width(
        buf,
        inner.x,
        axis_y,
        inner.width,
        Style::default().fg(Color::DarkGray),
        &format!("{left} .. {right}"),
    );
}

fn draw_y_axis_cores(buf: &mut Buffer, area: Rect, max_y: f64, cpu_num: Option<u32>) {
    if area.width == 0 || area.height == 0 || max_y <= 0.0 {
        return;
    }
    let w = area.width as usize;
    let h = area.height.saturating_sub(1) as f64;
    let style = Style::default().fg(Color::DarkGray);

    let max_tick = max_y.ceil().max(1.0) as u64;

    let mut ticks: Vec<u64> = Vec::new();
    ticks.push(0);
    ticks.push(max_tick);
    if let Some(n) = cpu_num {
        if n > 0 {
            let n = n as u64;
            // Only show core-count markers if within current screen y-range.
            if n <= max_tick {
                ticks.push(n);
            }
            let half = n / 2;
            if half > 0 && half <= max_tick {
                ticks.push(half);
            }
        }
    }
    ticks.sort_unstable();
    ticks.dedup();

    let bottom = (area.y + area.height - 1) as i32;
    for t in ticks {
        let yv = (t as f64).min(max_y).max(0.0);
        let ratio = (yv / max_y).clamp(0.0, 1.0);
        let yy = (bottom as f64 - (ratio * h).round()) as i32;
        let yy = yy.clamp(area.y as i32, bottom) as u16;
        let label = format!("{t}C");
        let padded = if label.len() >= w {
            label
        } else {
            format!("{:>width$}", label, width = w)
        };
        render_text_fixed_width(buf, area.x, yy, area.width, style, &padded);
    }
}

fn bucketize_trend_columns(
    app: &App,
    idx_lo: usize,
    idx_hi: usize,
    width: u16,
) -> (Vec<Option<f64>>, Vec<Option<f64>>, f64) {
    let w = width as usize;
    let mut cpu_cols = vec![None; w];
    let mut sys_cols = vec![None; w];
    let mut max_y = 1.0f64;

    if idx_hi <= idx_lo || w == 0 {
        return (cpu_cols, sys_cols, max_y);
    }

    let n = (idx_hi - idx_lo) as f64;
    for i in idx_lo..idx_hi {
        let rel = (i - idx_lo) as f64;
        let col = ((rel / n) * (w as f64)).floor() as usize;
        let col = col.min(w - 1);

        let cpu_y = app.cpu_c[i];
        if cpu_y.is_finite() {
            max_y = max_y.max(cpu_y);
            cpu_cols[col] = Some(cpu_cols[col].unwrap_or(0.0).max(cpu_y));
        }

        if let Some(sys_y) = app.sys_c[i] {
            if sys_y.is_finite() {
                max_y = max_y.max(sys_y);
                sys_cols[col] = Some(sys_cols[col].unwrap_or(0.0).max(sys_y));
            }
        }
    }

    (cpu_cols, sys_cols, max_y.max(1e-9))
}

fn draw_vertical_stem(buf: &mut Buffer, plot: Rect, x: u16, y: f64, max_y: f64, style: Style) {
    let ratio = (y / max_y).clamp(0.0, 1.0);
    let h = plot.height as f64;
    let stem_h = (ratio * h).round() as i32;
    if stem_h <= 0 {
        return;
    }
    let bottom = (plot.y + plot.height - 1) as i32;
    let top = (bottom - stem_h + 1).max(plot.y as i32);
    for yy in top..=bottom {
        if let Some(cell) = buf.cell_mut((x, yy as u16)) {
            cell.set_char('│').set_style(style);
        }
    }
}

fn draw_selection_markers(
    buf: &mut Buffer,
    plot: Rect,
    t_lo: u64,
    t_hi: u64,
    win_s: u64,
    win_e: u64,
    max_y: f64,
) {
    if t_hi <= t_lo {
        return;
    }
    let map_x = |t: u64| -> u16 {
        let frac = ((t.saturating_sub(t_lo)) as f64) / ((t_hi - t_lo) as f64);
        let col = (frac * (plot.width.saturating_sub(1) as f64)).round() as i32;
        let col = col.clamp(0, plot.width.saturating_sub(1) as i32);
        plot.x + col as u16
    };

    let x1 = map_x(win_s);
    let style = Style::default().fg(Color::Green);
    // if selection is <= 1s, draw only one marker
    if win_e.saturating_sub(win_s) <= 1_000 {
        draw_vertical_stem(buf, plot, x1, max_y, max_y, style);
        return;
    }
    let x2 = map_x(win_e);
    draw_vertical_stem(buf, plot, x1, max_y, max_y, style);
    draw_vertical_stem(buf, plot, x2, max_y, max_y, style);
}

fn fmt_dur(ms: u64) -> String {
    if ms < 1_000 {
        return format!("{ms}ms");
    }
    if ms < 60_000 {
        return format!("{:.2}s", (ms as f64) / 1000.0);
    }
    // Keep it simple for long ranges.
    format!("{:.1}s", (ms as f64) / 1000.0)
}

fn cpu_samples_per_cpu_per_record(data: &dyn ProfileData) -> Option<f64> {
    let freq = data.config().freq? as f64;
    let interval = data.config().record_interval? as f64;
    if freq > 0.0 && interval > 0.0 {
        Some(freq * interval)
    } else {
        None
    }
}

fn fill_cpu_sys_curves(
    data: &dyn ProfileData,
    filters: &FilterSet,
    start: usize,
    end: usize,
    out_cpu: &mut [f64],
    out_sys: &mut [Option<f64>],
) {
    let Some(den) = cpu_samples_per_cpu_per_record(data) else {
        return;
    };
    if den <= 0.0 {
        return;
    }
    if data.record_count() == 0 {
        return;
    }

    let end = end.min(data.record_count());
    let start = start.min(end);

    for i in start..end {
        let mut total: u64 = 0;
        let mut sys: u64 = 0;
        let _ = data.for_each_entry_in_record(i, &mut |ids_id, count| {
            // Apply filters
            if !filters.items.is_empty() {
                if let Some(ids) = data.ids_for(ids_id) {
                    if let Some(meta) = data.metadata_for_ids(ids.as_slice()) {
                        if filters.filtered_out(&meta) {
                            return Ok(());
                        }
                    }
                }
            }

            total += count;
            if data.ids_id_has_kernel(ids_id) {
                sys += count;
            }
            Ok(())
        });
        out_cpu[i] = total as f64 / den;
        out_sys[i] = Some(sys as f64 / den);
    }
}

fn render_flame(buf: &mut Buffer, area: Rect, app: &mut App) {
    let mode_str = match app.agg_mode {
        AggregationMode::BottomUp => "BottomUp",
        AggregationMode::TopDown => "TopDown",
    };
    let title = format!(
        " Flamegraph [{}] (Enter:Zoom Esc:Back Arrows:Move) ",
        mode_str
    );
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(area);
    block.render(area, buf);
    if area.width >= 2 {
        let title_w = area.width.saturating_sub(2);
        render_text_fixed_width(
            buf,
            area.x + 1,
            area.y,
            title_w,
            Style::default().fg(Color::White),
            &title,
        );
    }
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    // Reserve the last line (inside border) for detail.
    let widget_h = inner.height.saturating_sub(1).max(1);
    let widget_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: widget_h,
    };

    // Auto-scroll to keep selected row visible.
    let max_depth = flame_max_depth(&app.flame, app.focused_root);
    let total_rows = max_depth.saturating_add(1);
    let max_scroll = total_rows.saturating_sub(widget_h);

    let mut scroll = app.flame_scroll_y.min(max_scroll);
    if let Some(sel_depth) = depth_from_root(&app.flame, app.focused_root, app.selected) {
        if sel_depth < scroll {
            scroll = sel_depth;
        } else {
            let bottom = scroll.saturating_add(widget_h.saturating_sub(1));
            if sel_depth > bottom {
                scroll = sel_depth.saturating_sub(widget_h.saturating_sub(1));
            }
        }
    }
    app.flame_scroll_y = scroll.min(max_scroll);

    // layout full depth, then render windowed by scroll
    let rects = layout_flame(
        &app.flame,
        app.focused_root,
        widget_area.width,
        total_rows.max(1),
    );
    FlameWidget {
        app,
        rects,
        scroll_y: app.flame_scroll_y,
    }
    .render(widget_area, buf);

    // detail panel: bottom line inside block (if we have space)
    if inner.height >= 2 {
        let detail_y = inner.y + widget_h;
        let detail = render_selected_detail(app);
        Paragraph::new(detail).render(
            Rect {
                x: inner.x,
                y: detail_y,
                width: inner.width,
                height: 1,
            },
            buf,
        );
    }
}

struct FlameWidget<'a> {
    app: &'a App,
    rects: Vec<LayoutRect>,
    scroll_y: u16,
}

impl<'a> Widget for FlameWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        for r in self.rects {
            if r.w == 0 {
                continue;
            }
            if r.y < self.scroll_y {
                continue;
            }
            let ry = r.y.saturating_sub(self.scroll_y);
            if ry >= area.height {
                continue;
            }
            let x0 = area.x.saturating_add(r.x);
            let y0 = area.y.saturating_add(ry);
            if y0 >= area.y + area.height {
                continue;
            }
            let w = r.w.min(area.width.saturating_sub(r.x));
            if w == 0 {
                continue;
            }
            let node = &self.app.flame.nodes[r.node_id];

            let mut style = Style::default()
                .bg(color_for_name(&node.name))
                .fg(Color::Black);

            if r.node_id == self.app.selected {
                style = style.add_modifier(Modifier::REVERSED | Modifier::BOLD);
            }

            let label = format!("▏{}", node.name);
            render_text_fixed_width(buf, x0, y0, w, style, &label);
        }
    }
}

fn depth_from_root(arena: &Arena, root: usize, node: usize) -> Option<u16> {
    if root == node {
        return Some(0);
    }
    let mut cur = node;
    let mut d: u16 = 0;
    // walk parents; stop at root
    while let Some(p) = arena.nodes.get(cur).and_then(|n| n.parent) {
        d = d.saturating_add(1);
        if p == root {
            return Some(d);
        }
        cur = p;
    }
    None
}

fn flame_max_depth(arena: &Arena, root: usize) -> u16 {
    let mut max_d: u16 = 0;
    let mut stack: Vec<(usize, u16)> = vec![(root, 0)];
    while let Some((nid, d)) = stack.pop() {
        max_d = max_d.max(d);
        let Some(node) = arena.nodes.get(nid) else {
            continue;
        };
        let nd = d.saturating_add(1);
        for &c in &node.children {
            stack.push((c, nd));
        }
    }
    max_d
}

fn render_text_fixed_width(
    buf: &mut Buffer,
    x0: u16,
    y0: u16,
    width: u16,
    style: Style,
    text: &str,
) {
    let mut x = 0u16;
    let mut remain = width;

    for ch in text.chars() {
        if remain == 0 {
            break;
        }
        let cw = UnicodeWidthChar::width(ch).unwrap_or(1) as u16;
        if cw == 0 {
            continue;
        }
        if cw > remain {
            break;
        }

        if let Some(cell) = buf.cell_mut((x0 + x, y0)) {
            cell.set_char(ch).set_style(style);
        }
        x += 1;
        remain -= 1;

        // Wide characters occupy 2 columns: write a padding space to avoid misalignment.
        if cw == 2 {
            if remain == 0 {
                break;
            }
            if let Some(cell) = buf.cell_mut((x0 + x, y0)) {
                cell.set_char(' ').set_style(style);
            }
            x += 1;
            remain -= 1;
        }
    }

    // pad
    while remain > 0 {
        if let Some(cell) = buf.cell_mut((x0 + x, y0)) {
            cell.set_char(' ').set_style(style);
        }
        x += 1;
        remain -= 1;
    }
}

fn render_selected_detail(app: &App) -> Line<'static> {
    let node = &app.flame.nodes[app.selected];
    let samples = node.value;

    // Selection duration (seconds)
    let (win_s, win_e) = window_bounds_ms(app);
    let dur_s = (win_e.saturating_sub(win_s) as f64) / 1000.0;

    // CPU usage derived from sampling: total core-seconds = samples / freq.
    // Average cores per second within the selection = total / duration.
    let freq = app.profile.data.config().freq.unwrap_or(0) as f64;
    let (avg_cps, total_c) = if freq > 0.0 && dur_s > 0.0 {
        let total_c = samples as f64 / freq;
        let avg_cps = total_c / dur_s;
        (Some(avg_cps), Some(total_c))
    } else {
        (None, None)
    };

    // Overall machine CPU usage percentage (All)
    let all_pct = app.profile.data.config().cpu_num.and_then(|n| {
        let n = n as f64;
        if n > 0.0 {
            avg_cps.map(|v| (v / n) * 100.0)
        } else {
            None
        }
    });

    // Percentage of current view (Root)
    let root_val = app.flame.nodes[0].value.max(1);
    let view_pct = (samples as f64 / root_val as f64) * 100.0;

    // Depth / scroll hint (helps orientation when flamegraph is vertically scrolled)
    let depth = depth_from_root(&app.flame, app.focused_root, app.selected).unwrap_or(0);
    let max_depth = flame_max_depth(&app.flame, app.focused_root);
    let depth_txt = format!("  D:{}/{} Y:{}", depth, max_depth, app.flame_scroll_y);

    let all_txt = all_pct
        .map(|v| format!("  All:{:.2}%", v))
        .unwrap_or_default();

    let cpu_txt = match (avg_cps, total_c) {
        (Some(avg), Some(total)) => format!("{avg:.2}C/s ({total:.2}C)"),
        _ => format!("samples={samples}"),
    };

    Line::from(vec![
        Span::styled("Selected: ", Style::default().fg(Color::Gray)),
        Span::styled(
            node.name.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  samples={}  {}{}  View:{:.1}%{}",
            samples, cpu_txt, depth_txt, view_pct, all_txt
        )),
    ])
}

fn render_status(buf: &mut Buffer, area: Rect, app: &App) {
    let (win_s, win_e) = window_bounds_ms(app);

    let total_s = app
        .profile
        .data
        .records()
        .first()
        .map(|r| r.start_ms)
        .unwrap_or(0);
    let total_e = app
        .profile
        .data
        .records()
        .last()
        .map(|r| r.end_ms)
        .unwrap_or(0);
    let total_dur = total_e.saturating_sub(total_s);
    let total_dur_s = total_dur / 1000;

    let win_dur = fmt_dur(win_e.saturating_sub(win_s));
    let status = format!(
        "Render: {:.1}ms | Window: {} (Total: {}s) | Nodes: {} | Filters: {} | Toggles: {}{}{}{}{}{}{}{}{}{}",
        app.last_render_us as f64 / 1000.0,
        win_dur,
        total_dur_s,
        app.flame.nodes.len(),
        app.filters.items.len(),
        if app.toggles.show_env { "N" } else { "-" },
        if app.toggles.show_pid { "P" } else { "-" },
        if app.toggles.show_comm { "M" } else { "-" },
        if app.toggles.show_cgroup_id { "D" } else { "-" },
        if app.toggles.show_cpu { "C" } else { "-" },
        if app.toggles.show_thread_name { "H" } else { "-" },
        if app.toggles.only_kernel { "O" } else { "-" },
        if app.toggles.agg_hex_addr_mod { "X" } else { "-" },
        if app.toggles.agg_irqoff_cpu { "U" } else { "-" },
        if app.agg_mode == AggregationMode::TopDown { "I" } else { "-" },
    );
    let total_range = format!("Total range: {} .. {}", fmt_ms(total_s), fmt_ms(total_e));
    let hint = "Keys: [q] quit  [h] help  [c] conf  [o] filters  [:] cmd  [J] jump  [R] range  [t]/[T] shift  [s]/[S] span  [g] height  [0] all  [9] reset";
    let lines = vec![
        Line::from(Span::raw(status)),
        Line::from(Span::styled(
            app.status.front().cloned().unwrap_or_default(),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(total_range, Style::default().fg(Color::Gray))),
        Line::from(Span::styled(hint, Style::default().fg(Color::Gray))),
    ];

    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(area);
    block.render(area, buf);
    if area.width >= 2 {
        render_text_fixed_width(
            buf,
            area.x + 1,
            area.y,
            area.width.saturating_sub(2),
            Style::default().fg(Color::White),
            "Status",
        );
    }
    if inner.width > 0 && inner.height > 0 {
        Paragraph::new(lines).render(inner, buf);
    }
}

fn window_bounds_ms(app: &App) -> (u64, u64) {
    let records = app.profile.data.records();
    if records.is_empty() {
        return (0, 0);
    }
    let len = records.len();
    let start = app.start.min(len - 1);
    let end = (start + app.span).min(len);
    let s = records[start].start_ms;
    let e = records[end.saturating_sub(1)].end_ms;
    (s, e)
}

fn chart_view_bounds(app: &App) -> (usize, usize, u64, u64) {
    let records = app.profile.data.records();
    let len = records.len();
    if len == 0 {
        return (0, 0, 0, 0);
    }

    if app.chart_full {
        return (0, len, records[0].start_ms, records[len - 1].end_ms);
    }

    // Fixed chart window: configurable seconds (default 600s).
    let window_ms: u64 = (app.chart_window_sec.max(1)) * 1000;

    // Keep selection start at the left; window slides as the selection moves.
    let (win_s, _win_e) = window_bounds_ms(app);

    let data_s = records[0].start_ms;
    let data_e = records[len - 1].end_ms;

    // initial bounds
    let mut t_lo = win_s;
    let mut t_hi = t_lo.saturating_add(window_ms);

    // clamp to data range by shifting (avoid stretching axis)
    if t_lo < data_s {
        t_lo = data_s;
        t_hi = t_lo.saturating_add(window_ms);
    }
    if t_hi > data_e {
        t_hi = data_e;
        t_lo = t_hi.saturating_sub(window_ms);
        if t_lo < data_s {
            t_lo = data_s;
        }
    }

    let idx_lo = find_record_by_time(records, t_lo);
    let mut idx_hi = find_record_end_exclusive(records, t_hi);
    if idx_hi <= idx_lo {
        idx_hi = (idx_lo + 1).min(len);
    }

    let t_lo_real = records[idx_lo].start_ms;
    let t_hi_real = records[idx_hi - 1].end_ms;
    (idx_lo, idx_hi, t_lo_real, t_hi_real)
}

fn fmt_ms(ms: u64) -> String {
    // ms since 00:00 of the day; may exceed 86400*1000 when spanning days.
    let day_ms = 86_400_000u64;
    let days = ms / day_ms;
    let mut rem = ms % day_ms;
    let hh = rem / 3_600_000;
    rem %= 3_600_000;
    let mm = rem / 60_000;
    rem %= 60_000;
    let ss = rem / 1000;
    let mmm = rem % 1000;
    if days > 0 {
        format!("+{days}d {:02}:{:02}:{:02}.{:03}", hh, mm, ss, mmm)
    } else {
        format!("{:02}:{:02}:{:02}.{:03}", hh, mm, ss, mmm)
    }
}

fn parse_time_ms(input: &str) -> anyhow::Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        anyhow::bail!("empty time");
    }

    let (hms, frac) = if let Some((a, b)) = s.split_once('.') {
        (a, Some(b))
    } else {
        (s, None)
    };

    let parts: Vec<&str> = hms.split(':').collect();
    let (hh, mm, ss) = match parts.as_slice() {
        [h, m, sec] => (*h, *m, *sec),
        [m, sec] => ("0", *m, *sec),
        _ => anyhow::bail!("invalid time format, expect HH:MM:SS or HH:MM:SS.mmm"),
    };

    let hh: u64 = hh.parse()?;
    let mm: u64 = mm.parse()?;
    let ss: u64 = ss.parse()?;

    let mut ms = (hh * 3600 + mm * 60 + ss) * 1000;
    if let Some(frac) = frac {
        let frac = frac.trim();
        if !frac.is_empty() {
            let mut f = frac.to_string();
            if f.len() > 3 {
                f.truncate(3);
            }
            while f.len() < 3 {
                f.push('0');
            }
            ms += f.parse::<u64>()?;
        }
    }
    Ok(ms)
}

fn parse_range_ms(input: &str) -> anyhow::Result<(u64, u64)> {
    let s = input.trim();
    if let Some((a, b)) = s.split_once("..") {
        return Ok((parse_time_ms(a)?, parse_time_ms(b)?));
    }
    // Allow '-' as a separator (avoid confusion with ':' inside time).
    if let Some((a, b)) = s.split_once('-') {
        // Accept inputs like "12:00:00-12:10:00".
        if a.contains(':') && b.contains(':') {
            return Ok((parse_time_ms(a)?, parse_time_ms(b)?));
        }
    }
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 2 {
        return Ok((parse_time_ms(parts[0])?, parse_time_ms(parts[1])?));
    }
    anyhow::bail!("invalid range format, expect A..B or 'A B' (A/B as HH:MM:SS[.mmm])")
}

fn find_record_by_time(records: &[crate::cpa::RecordMeta], t_ms: u64) -> usize {
    if records.is_empty() {
        return 0;
    }
    // Find the first record whose end_ms >= t.
    let idx = records.partition_point(|r| r.end_ms < t_ms);
    idx.min(records.len().saturating_sub(1))
}

fn find_record_end_exclusive(records: &[crate::cpa::RecordMeta], t_ms: u64) -> usize {
    if records.is_empty() {
        return 0;
    }
    // end_excl: first index whose start_ms >= t.
    let idx = records.partition_point(|r| r.start_ms < t_ms);
    idx.min(records.len())
}

#[cfg(test)]
mod ui_tests {
    use super::*;

    #[test]
    fn parse_time_ms_ok() {
        assert_eq!(parse_time_ms("00:00:01").unwrap(), 1000);
        assert_eq!(parse_time_ms("1:02:03.4").unwrap(), 3_723_400);
        assert_eq!(parse_time_ms("02:03").unwrap(), 123_000);
    }

    #[test]
    fn parse_range_ms_ok() {
        assert_eq!(parse_range_ms("00:00:01..00:00:02").unwrap(), (1000, 2000));
        assert_eq!(parse_range_ms("00:00:01 00:00:02").unwrap(), (1000, 2000));
        assert_eq!(parse_range_ms("00:00:01-00:00:02").unwrap(), (1000, 2000));
    }
}

fn render_cmdline(buf: &mut Buffer, area: Rect, p: &Prompt) {
    let h = 3u16;
    let w = area.width.min(100);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + area.height.saturating_sub(h);
    let popup = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    Clear.render(popup, buf);

    let (title, prefix) = match p.kind {
        PromptKind::Command => ("command", ":"),
        PromptKind::GotoTime => ("goto time (HH:MM:SS[.mmm])", ""),
        PromptKind::SetRange => ("set range (A..B or A B)", ""),
    };

    let text = format!("{prefix}{}", p.input.buf);
    Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .render(popup, buf);
    // cursor hint: use reversed cell
    if popup.width >= 3 {
        let prefix_w = UnicodeWidthStr::width(prefix) as u16;
        let cx = prefix_w.saturating_add(p.input.cursor as u16);
        let left = popup.x + 1;
        let right = popup.x + popup.width - 2;
        let pos = (left + cx).min(right);
        if let Some(cell) = buf.cell_mut((pos, popup.y + 1)) {
            cell.set_style(Style::default().add_modifier(Modifier::REVERSED));
        }
    }
}

fn render_popup(buf: &mut Buffer, area: Rect, title: &str, lines: &[Line<'static>]) {
    let w = area.width.saturating_mul(4) / 5;
    let h = area.height.saturating_mul(4) / 5;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup = Rect {
        x,
        y,
        width: w.max(20),
        height: h.max(10),
    };
    Clear.render(popup, buf);
    Paragraph::new(lines.to_vec())
        .block(Block::default().borders(Borders::ALL).title(title))
        .render(popup, buf);
}

fn render_conf_lines(app: &App) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    out.push(Line::from(Span::styled(
        format!("dir: {}", app.profile.source_path.display()),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(Span::raw("")));
    for (k, v) in &app.profile.data.config().raw {
        out.push(Line::from(Span::raw(format!("{k}: {v}"))));
    }
    out
}

fn render_help_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled("Navigation:", Style::default().add_modifier(Modifier::BOLD))),
        Line::from("  Arrow Keys / hjkl / ad : Move selection (wraps around)"),
        Line::from("  Enter                  : Zoom into selected node"),
        Line::from("  Esc                    : Reset zoom / Clear selection"),
        Line::from(""),
        Line::from(Span::styled("Time Window Control:", Style::default().add_modifier(Modifier::BOLD))),
        Line::from("  t / T                  : Shift window forward / backward"),
        Line::from("  s / S                  : Expand / Shrink window span"),
        Line::from("  J                      : Jump to specific time (HH:MM:SS)"),
        Line::from("  R                      : Set specific time range (A..B)"),
        Line::from(""),
        Line::from(Span::styled("Chart Control:", Style::default().add_modifier(Modifier::BOLD))),
        Line::from("  g                      : Toggle chart height (Small/Half/Full)"),
        Line::from("  Chart window is fixed to 600s"),
        Line::from("  0                      : Show full chart history"),
        Line::from("  9                      : Back to 600s window"),
        Line::from(""),
        Line::from(Span::styled("Filters & Toggles:", Style::default().add_modifier(Modifier::BOLD))),
        Line::from("  :                      : Command input (pid/comm/cpu/pod/cgid/unset...)"),
        Line::from("  Filter syntax          : :<name> <value>   (multiple filters are AND-ed)"),
        Line::from("  *v suffix              : Exclude / invert match (pidv cpuv podv commv cgidv)"),
        Line::from("  Examples               : :pid 123   :cpu 0-3,7   :pod pod-x   :comm nginx"),
        Line::from("                          : :cgid 42  :cgidv 42"),
        Line::from("  unset <name>           : Remove filters by command name"),
        Line::from("                          : e.g. unset pid / unset pidv / unset cpu / unset cpuv / unset cgid"),
        Line::from("  N / P / M / D / C / H / O  : Toggle columns (Env/Pid/Comm/Cgid/Cpu/Thread/Kernel)"),
        Line::from("  X                      : Aggregate frames like '0x... [bin]' -> '<...> [bin]'"),
        Line::from("  U                      : Aggregate IRQOFF sample CPU number (e.g. '<# IRQOFF ... CPU 47 #>')"),
        Line::from("  I                      : Toggle aggregation (Caller/Callee)"),
        Line::from("  o                      : Show active filters list"),
        Line::from("  c                      : Show loaded configuration"),
        Line::from(""),
        Line::from(Span::styled("General:", Style::default().add_modifier(Modifier::BOLD))),
        Line::from("  h / ?                  : Toggle this help overlay"),
        Line::from("  q                      : Quit application"),
    ]
}

fn render_filter_lines(app: &App) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    out.push(Line::from(Span::styled(
        format!("filters: {}", app.filters.items.len()),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(""));
    out.push(Line::from(Span::styled(
        "Format: <cmd> <arg>   (use ':unset <cmd>' to remove)",
        Style::default().fg(Color::Gray),
    )));
    out.push(Line::from(""));
    for (i, f) in app.filters.items.iter().enumerate() {
        out.push(Line::from(Span::raw(format!(
            "{}. {}",
            i + 1,
            format_filter_cmd(f)
        ))));
    }
    out
}

fn format_filter_cmd(f: &Filter) -> String {
    let (cmd, val) = match f {
        Filter::IncludeOnly { target, value } => (filter_target_cmd(target, false), value),
        Filter::Exclude { target, value } => (filter_target_cmd(target, true), value),
    };
    match val {
        FilterValue::Str(s) => format!("{cmd} {s}"),
        FilterValue::U32(v) => format!("{cmd} {v}"),
        FilterValue::U64(v) => format!("{cmd} {v}"),
        FilterValue::CpuSet(set) => format!("{cmd} {}", format_cpu_set_compact(set)),
    }
}

fn filter_target_cmd(t: &FilterTarget, inverted: bool) -> &'static str {
    match (t, inverted) {
        (FilterTarget::Pid, false) => "pid",
        (FilterTarget::Pid, true) => "pidv",
        (FilterTarget::Cpu, false) => "cpu",
        (FilterTarget::Cpu, true) => "cpuv",
        (FilterTarget::Pod, false) => "pod",
        (FilterTarget::Pod, true) => "podv",
        (FilterTarget::Comm, false) => "comm",
        (FilterTarget::Comm, true) => "commv",
        (FilterTarget::CgroupId, false) => "cgid",
        (FilterTarget::CgroupId, true) => "cgidv",
    }
}

fn format_cpu_set_compact(set: &std::collections::BTreeSet<u32>) -> String {
    if set.is_empty() {
        return "".to_string();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut it = set.iter().copied();
    let mut start = it.next().unwrap();
    let mut prev = start;
    for v in it {
        if v == prev + 1 {
            prev = v;
            continue;
        }
        parts.push(if start == prev {
            format!("{start}")
        } else {
            format!("{start}-{prev}")
        });
        start = v;
        prev = v;
    }
    parts.push(if start == prev {
        format!("{start}")
    } else {
        format!("{start}-{prev}")
    });
    parts.join(",")
}

fn parse_filter_cmd(cmd: &str, arg: &str) -> anyhow::Result<Filter> {
    if arg.is_empty() {
        anyhow::bail!("Missing argument");
    }
    match cmd {
        "pid" => Ok(Filter::IncludeOnly {
            target: FilterTarget::Pid,
            value: FilterValue::U32(arg.parse::<u32>()?),
        }),
        "pidv" => Ok(Filter::Exclude {
            target: FilterTarget::Pid,
            value: FilterValue::U32(arg.parse::<u32>()?),
        }),
        "cpu" => Ok(Filter::IncludeOnly {
            target: FilterTarget::Cpu,
            value: FilterValue::CpuSet(parse_cpu_set(arg)),
        }),
        "cpuv" => Ok(Filter::Exclude {
            target: FilterTarget::Cpu,
            value: FilterValue::CpuSet(parse_cpu_set(arg)),
        }),
        "pod" => Ok(Filter::IncludeOnly {
            target: FilterTarget::Pod,
            value: FilterValue::Str(arg.to_string()),
        }),
        "podv" => Ok(Filter::Exclude {
            target: FilterTarget::Pod,
            value: FilterValue::Str(arg.to_string()),
        }),
        "comm" => Ok(Filter::IncludeOnly {
            target: FilterTarget::Comm,
            value: FilterValue::Str(arg.to_string()),
        }),
        "commv" => Ok(Filter::Exclude {
            target: FilterTarget::Comm,
            value: FilterValue::Str(arg.to_string()),
        }),
        "cgid" => Ok(Filter::IncludeOnly {
            target: FilterTarget::CgroupId,
            value: FilterValue::U64(arg.parse::<u64>()?),
        }),
        "cgidv" => Ok(Filter::Exclude {
            target: FilterTarget::CgroupId,
            value: FilterValue::U64(arg.parse::<u64>()?),
        }),
        _ => anyhow::bail!("Unknown command: {cmd}"),
    }
}

fn build_flamegraph(
    profile: &UiProfile,
    start: usize,
    span: usize,
    agg_mode: AggregationMode,
    toggles: &ViewToggles,
    filters: &FilterSet,
) -> Arena {
    let mut arena = Arena::new_root();

    let len = profile.data.record_count();
    let end = (start + span).min(len);
    let start = start.min(end);

    let mut agg: HashMap<u32, u64> = HashMap::new();
    let _ = profile
        .data
        .for_each_entry_in_records(start, end, &mut |ids_id, count| {
            *agg.entry(ids_id).or_insert(0) += count;
            Ok(())
        });

    for (ids_id, count) in agg {
        let Some(ids) = profile.data.ids_for(ids_id) else {
            continue;
        };

        if !filters.items.is_empty() {
            let Some(meta) = profile.data.metadata_for_ids(ids.as_slice()) else {
                continue;
            };
            if filters.filtered_out(&meta) {
                continue;
            }
        }

        if toggles.only_kernel && !profile.data.ids_id_has_kernel(ids_id) {
            continue;
        }

        let Some(meta_str) = profile.data.str_for(ids[0]) else {
            continue;
        };
        if meta_str.starts_with('#') {
            continue;
        }

        let Some(meta) = profile.data.metadata_for_ids(ids.as_slice()) else {
            continue;
        };

        let mut stack = Vec::new();
        if toggles.show_env {
            stack.push(meta.env.clone());
        }
        if toggles.show_cgroup_id {
            stack.push(format!("CGID {}", meta.cgroup_id));
        }
        if toggles.show_cpu {
            stack.push(format!("CPU {:4}", meta.cpu));
        }
        if toggles.show_pid && toggles.show_comm {
            stack.push(format!("{}:{}", meta.group_comm, meta.pid));
        } else {
            if toggles.show_pid {
                stack.push(format!("{}", meta.pid));
            }
            if toggles.show_comm {
                stack.push(meta.comm.clone());
            }
        }
        if toggles.show_thread_name {
            stack.push(meta.comm.clone());
        }

        // Function stack frames
        for &sid in &ids[1..] {
            let Some(s) = profile.data.str_for(sid) else {
                continue;
            };
            if s.starts_with('#') {
                continue;
            }
            stack.push(normalize_stack_frame(s, toggles));
        }

        if agg_mode == AggregationMode::TopDown {
            stack.reverse();
        }

        // insert to tree
        arena.nodes[0].value += count;
        let mut cur = 0usize;
        for name in stack {
            let nid = arena.find_or_add_child(cur, &name);
            arena.nodes[nid].value += count;
            cur = nid;
        }
    }

    sort_arena_children(&mut arena, 0);
    arena
}

fn normalize_stack_frame(s: &str, toggles: &ViewToggles) -> String {
    let s = s.trim();

    if toggles.agg_hex_addr_mod {
        if let Some(v) = collapse_hex_addr_with_module(s) {
            return v;
        }
    }
    if toggles.agg_irqoff_cpu {
        if let Some(v) = collapse_irqoff_sample_cpu(s) {
            return v;
        }
    }

    s.to_string()
}

fn is_hex_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

fn collapse_hex_addr_with_module(s: &str) -> Option<String> {
    // Example: "0x56d20 [libc.so.6]" -> "<...> [libc.so.6]"
    let s = s.trim();
    if !s.starts_with("0x") {
        return None;
    }

    let bytes = s.as_bytes();
    if bytes.len() < 3 {
        return None;
    }
    let mut i = 2usize;
    while i < bytes.len() && is_hex_byte(bytes[i]) {
        i += 1;
    }
    if i <= 2 {
        return None;
    }

    let rest = s.get(i..)?.trim_start();
    let lb = rest.find('[')?;
    let rb = rest.get(lb..)?.find(']')? + lb;
    if rb <= lb {
        return None;
    }
    let module = &rest[lb..=rb];
    Some(format!("<...> {module}"))
}

fn collapse_irqoff_sample_cpu(s: &str) -> Option<String> {
    // Example: "<# IRQOFF SAMPLE ON CPU 47 #>" -> "<# IRQOFF SAMPLE ON CPU <...> #>"
    let s = s.trim();
    const PREFIX: &str = "<# IRQOFF SAMPLE ON CPU ";
    if !s.starts_with(PREFIX) {
        return None;
    }
    let tail = s.get(PREFIX.len()..)?;
    let mut n = 0usize;
    for ch in tail.chars() {
        if ch.is_ascii_digit() {
            n += 1;
        } else {
            break;
        }
    }
    if n == 0 {
        return None;
    }
    let rest = tail.get(n..).unwrap_or("");
    Some(format!("{PREFIX}<...>{rest}"))
}

fn sort_arena_children(arena: &mut Arena, node: usize) {
    let mut children = arena.nodes[node].children.clone();
    children.sort_by(|&a, &b| {
        let va = arena.nodes[a].value;
        let vb = arena.nodes[b].value;
        vb.cmp(&va)
            .then_with(|| arena.nodes[a].name.cmp(&arena.nodes[b].name))
    });
    arena.nodes[node].children = children;

    let next = arena.nodes[node].children.clone();
    for c in next {
        sort_arena_children(arena, c);
    }
}

// Kernel detection is handled in backend (ProfileData::ids_id_has_kernel).

fn layout_flame(arena: &Arena, root: usize, width: u16, height: u16) -> Vec<LayoutRect> {
    let mut out = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back((root, 0u16, 0u16, width));

    while let Some((nid, x, y, w)) = queue.pop_front() {
        if y >= height {
            continue;
        }
        out.push(LayoutRect {
            node_id: nid,
            x,
            y,
            w,
        });

        let node = &arena.nodes[nid];
        if node.children.is_empty() {
            continue;
        }
        if y + 1 >= height {
            continue;
        }

        let parent_v = node.value.max(1);
        let mut child_widths: Vec<(usize, u16, u64)> = node
            .children
            .iter()
            .map(|&cid| {
                let cv = arena.nodes[cid].value;
                (cid, 0u16, cv)
            })
            .collect();

        // allocate widths
        let mut used: i32 = 0;
        let mut remainders: Vec<(usize, i64)> = Vec::new();
        for (cid, cw, cv) in &mut child_widths {
            let num = (*cv as u128) * (w as u128);
            let den = parent_v as u128;
            let q = (num / den) as u16;
            let r = (num % den) as i64;
            *cw = q;
            used += q as i32;
            remainders.push((*cid, r));
        }

        let mut remaining = (w as i32 - used).max(0);
        remainders.sort_by(|a, b| b.1.cmp(&a.1));
        for (cid, _) in remainders {
            if remaining <= 0 {
                break;
            }
            if let Some(t) = child_widths.iter_mut().find(|(x, _, _)| *x == cid) {
                t.1 = t.1.saturating_add(1);
                remaining -= 1;
            }
        }

        // push children
        let mut cur_x = x;
        for (cid, cw, cv) in child_widths {
            if cw == 0 || cv == 0 {
                continue;
            }
            queue.push_back((cid, cur_x, y + 1, cw));
            cur_x = cur_x.saturating_add(cw);
        }
    }

    out
}

fn color_for_name(name: &str) -> Color {
    // Choose a palette with sufficient contrast.
    const PALETTE: &[Color] = &[
        Color::Rgb(0xF4, 0xA2, 0x61),
        Color::Rgb(0x2A, 0x9D, 0x8F),
        Color::Rgb(0xE9, 0xC4, 0x6A),
        Color::Rgb(0xE7, 0x6F, 0x51),
        Color::Rgb(0xA8, 0xDA, 0xF0),
        Color::Rgb(0xB7, 0x97, 0xF8),
        Color::Rgb(0x95, 0xD5, 0xB2),
    ];
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    let idx = (h.finish() as usize) % PALETTE.len();
    PALETTE[idx]
}

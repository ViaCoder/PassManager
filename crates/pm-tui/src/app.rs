//! TUI 状态与操作逻辑。

use std::time::{Duration, Instant};

use pm_proto::*;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use zeroize::Zeroizing;

use crate::agents::{ADAPTERS, snippet};
use crate::input::TextInput;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const REVEAL_TIME: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Full,
    Unlock,
    Trust(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Entries,
    Hosts,
    Agents,
    Doctor,
    Settings,
}

pub const TABS: [(Tab, &str); 5] =
    [(Tab::Entries, "条目"), (Tab::Hosts, "主机"), (Tab::Agents, "Agent 接入"), (Tab::Doctor, "诊断"), (Tab::Settings, "设置")];

impl Tab {
    pub fn index(self) -> usize {
        TABS.iter().position(|(t, _)| *t == self).unwrap_or(0)
    }
}

/// 可点击区域对应的动作。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hit {
    Tab(Tab),
    Row(usize),
    Button(Btn),
    Field(usize),
    DialogButton(DBtn),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Btn {
    Add,
    Edit,
    Delete,
    Reveal,
    Lock,
    Quit,
    Trust,
    ClearDomain,
    Connect,
    Disconnect,
    Recheck,
    Fix,
    SaveSettings,
    ChangePassword,
    Refresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DBtn {
    Ok,
    Cancel,
    Save,
    Generate,
    ToggleShow,
}

pub struct EntryForm {
    pub original: Option<String>,
    pub name: TextInput,
    pub secret: TextInput,
    pub domains: TextInput,
    pub note: TextInput,
    pub self_signed: bool,
    pub auto_accept: bool,
    pub focus: usize,
    pub error: Option<String>,
}

/// 表单字段：0 密钥、1 域名、2 说明、3 自签证书、4 自动接受主机密钥。引用名自动生成，不在表单中出现。
pub const FORM_FIELDS: usize = 5;

impl EntryForm {
    pub fn new() -> Self {
        let mut secret = TextInput::new(true);
        secret.multiline = true;
        Self {
            original: None,
            name: TextInput::new(false),
            secret,
            domains: TextInput::new(false),
            note: TextInput::new(false),
            self_signed: false,
            auto_accept: false,
            focus: 0,
            error: None,
        }
    }

    pub fn input_mut(&mut self, i: usize) -> Option<&mut TextInput> {
        match i {
            0 => Some(&mut self.secret),
            1 => Some(&mut self.domains),
            2 => Some(&mut self.note),
            _ => None,
        }
    }
}

pub enum Confirm {
    DeleteEntry(String),
    Disconnect(usize),
    RevokeToken(String),
}

pub enum PromptKind {
    ClearDomain,
    OtherAgentLabel,
}

pub enum Dialog {
    Login { input: TextInput, error: Option<String>, note: Option<String> },
    Entry(Box<EntryForm>),
    Confirm { text: String, what: Confirm },
    Reveal { name: String, input: TextInput, shown: Option<(Zeroizing<String>, Instant)>, error: Option<String> },
    Info { title: String, body: String, quit_after: bool },
    Prompt { title: String, input: TextInput, kind: PromptKind },
    ChangePassword { fields: [TextInput; 3], focus: usize, error: Option<String> },
    Trust { pattern: String, lines: Vec<String>, any: bool },
}

pub struct App {
    pub mode: Mode,
    pub client: Option<Client>,
    pub tab: Tab,
    pub status: Option<StatusView>,
    pub security: Option<SecurityView>,
    pub entries: Vec<EntryView>,
    pub pins: Vec<PinView>,
    pub pending: Vec<PendingPinView>,
    pub tokens: Vec<TokenView>,
    pub settings: Option<SettingsView>,
    pub sel: [usize; 5],
    pub dialog: Option<Dialog>,
    pub msg: Option<(String, bool)>,
    pub hits: Vec<(Rect, Hit)>,
    pub last_click: Option<(Instant, Hit)>,
    pub last_input: Instant,
    pub quit: bool,
    pub bin: String,
    pub auto_lock: TextInput,
    /// 需要挂起 TUI 执行的外部命令（例如 sudo PassManager harden --fix）。
    pub run_external: Option<Vec<String>>,
}

/// Agents 页的行。
pub enum AgentRow {
    Adapter(usize),
    Token(usize),
    Other,
}

impl App {
    pub fn new(mode: Mode) -> Self {
        let bin = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "PassManager".into());
        Self {
            mode,
            client: None,
            tab: Tab::Entries,
            status: None,
            security: None,
            entries: vec![],
            pins: vec![],
            pending: vec![],
            tokens: vec![],
            settings: None,
            sel: [0; 5],
            dialog: Some(Dialog::Login { input: TextInput::new(true), error: None, note: None }),
            msg: None,
            hits: vec![],
            last_click: None,
            last_input: Instant::now(),
            quit: false,
            bin,
            auto_lock: TextInput::new(false),
            run_external: None,
        }
    }

    pub fn info(&mut self, msg: impl Into<String>) {
        self.msg = Some((msg.into(), false));
    }

    pub fn error(&mut self, msg: impl Into<String>) {
        self.msg = Some((msg.into(), true));
    }

    pub fn ready(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.ready && !s.locked)
    }

    fn call(&mut self, req: Request) -> Result<serde_json::Value, ApiError> {
        match self.client.as_mut() {
            Some(c) => c.call(&req),
            None => Err(ApiError::new("DISCONNECTED", "未连接")),
        }
    }

    fn call_as<T: for<'de> serde::Deserialize<'de>>(&mut self, req: Request) -> Result<T, ApiError> {
        let v = self.call(req)?;
        serde_json::from_value(v).map_err(|e| ApiError::new("INTERNAL", e.to_string()))
    }

    pub fn refresh(&mut self) {
        if let Ok(s) = self.call_as::<StatusView>(Request::Status) {
            self.status = Some(s);
        }
        if let Ok(s) = self.call_as::<SecurityView>(Request::Security) {
            self.security = Some(s);
        }
        if self.ready() {
            self.entries = self.call_as(Request::Entries).unwrap_or_default();
            self.pins = self.call_as(Request::Pins).unwrap_or_default();
            self.pending = self.call_as(Request::PendingPins).unwrap_or_default();
            self.tokens = self.call_as(Request::Tokens).unwrap_or_default();
            self.settings = self.call_as(Request::GetSettings).ok();
            if let Some(s) = &self.settings
                && self.auto_lock.value().is_empty()
            {
                self.auto_lock.set(&s.auto_lock_hours.to_string());
            }
        }
        for (i, n) in [self.entries.len(), self.pending.len() + self.pins.len(), self.agent_rows().len(), 0, 0].into_iter().enumerate() {
            if n == 0 {
                self.sel[i] = 0;
            } else if self.sel[i] >= n {
                self.sel[i] = n - 1;
            }
        }
    }

    pub fn agent_rows(&self) -> Vec<AgentRow> {
        let mut rows: Vec<AgentRow> = (0..ADAPTERS.len()).map(AgentRow::Adapter).collect();
        for (i, t) in self.tokens.iter().enumerate() {
            if !ADAPTERS.iter().any(|a| a.name == t.label) {
                rows.push(AgentRow::Token(i));
            }
        }
        rows.push(AgentRow::Other);
        rows
    }

    pub fn token_for(&self, label: &str) -> Option<&TokenView> {
        self.tokens.iter().filter(|t| t.label == label).max_by_key(|t| t.created)
    }

    // ---- 登录 ----

    pub fn login(&mut self, password: &str) {
        match Client::connect(&Hello::Password { v: PROTO_V, password: password.to_string() }) {
            Ok(c) => {
                self.client = Some(c);
                self.refresh();
                self.after_login();
            }
            Err(e) => {
                let msg = if e.code == "NOT_RUNNING" {
                    "PassManager 服务未运行或尚未安装（sudo PassManager install）。".to_string()
                } else {
                    e.message
                };
                self.dialog = Some(Dialog::Login { input: TextInput::new(true), error: Some(msg), note: None });
            }
        }
    }

    fn after_login(&mut self) {
        let ready = self.ready();
        let level = self.status.as_ref().map(|s| s.level).unwrap_or(1);
        match self.mode.clone() {
            Mode::Full => {
                self.dialog = None;
                if !ready {
                    self.tab = Tab::Doctor;
                    self.error("安全检查未通过，库保持锁定。请按诊断页的提示处理后点 [重新检查]。");
                } else if level == 1 {
                    self.error(pm_platform::seal::L1_WARNING);
                } else if self.entries.is_empty() {
                    self.info("已解锁。还没有条目：按 a 新增第一个凭据，然后在\"3 Agent 接入\"页一键接入你的 AI Agent。");
                } else {
                    self.info("已解锁。");
                }
            }
            Mode::Unlock => {
                let body = if ready {
                    let mut s = "库已解锁，Agent 现在可以使用凭据。".to_string();
                    if level == 1 {
                        s.push_str(&format!("\n\n⚠ {}", pm_platform::seal::L1_WARNING));
                    }
                    s
                } else {
                    "安全检查未通过，库保持锁定。\n请运行 PassManager 查看\"诊断\"页。".to_string()
                };
                self.dialog = Some(Dialog::Info { title: "解锁".into(), body, quit_after: true });
            }
            Mode::Trust(pattern) => {
                if !ready {
                    self.dialog = Some(Dialog::Info {
                        title: "信任指纹".into(),
                        body: "安全检查未通过，库保持锁定。请先运行 PassManager 处理诊断页的问题。".into(),
                        quit_after: true,
                    });
                    return;
                }
                let mut lines = Vec::new();
                for p in self.pending.iter().filter(|p| pattern_matches(&pattern, &p.host_port)) {
                    lines.push(format!("{}  [{}]  指纹已变化", p.host_port, p.kind));
                    lines.push(format!("    旧：{}", p.old_fingerprint));
                    lines.push(format!("    新：{}", p.new_fingerprint));
                }
                for p in self.pins.iter().filter(|p| pattern_matches(&pattern, &p.host_port)) {
                    if !self.pending.iter().any(|x| x.host_port == p.host_port) {
                        lines.push(format!("{}  [{}]  已记录：{}", p.host_port, p.kind, p.fingerprint));
                    }
                }
                let any = !lines.is_empty();
                if !any {
                    lines.push(format!("没有与 {pattern} 匹配的主机记录。"));
                }
                self.dialog = Some(Dialog::Trust { pattern, lines, any });
            }
        }
    }

    // ---- 事件 ----

    pub fn on_paste(&mut self, s: &str) {
        self.last_input = Instant::now();
        match &mut self.dialog {
            Some(Dialog::Entry(f)) => {
                let focus = f.focus;
                if let Some(i) = f.input_mut(focus) {
                    i.insert_str(s);
                }
            }
            Some(Dialog::Login { input, .. }) | Some(Dialog::Prompt { input, .. }) | Some(Dialog::Reveal { input, .. }) => {
                input.insert_str(s)
            }
            Some(Dialog::ChangePassword { fields, focus, .. }) => fields[*focus].insert_str(s),
            None if self.tab == Tab::Settings => self.auto_lock.insert_str(s),
            _ => {}
        }
    }

    pub fn on_key(&mut self, k: KeyEvent) {
        self.last_input = Instant::now();
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        if self.dialog.is_some() {
            self.dialog_key(k);
            return;
        }
        match k.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char(c @ '1'..='5') => self.tab = TABS[(c as u8 - b'1') as usize].0,
            KeyCode::Right => self.tab = TABS[(self.tab.index() + 1) % 5].0,
            KeyCode::Left => self.tab = TABS[(self.tab.index() + 4) % 5].0,
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            _ => {
                if let Some(b) = self.key_to_button(k) {
                    self.button(b);
                }
            }
        }
    }

    fn key_to_button(&mut self, k: KeyEvent) -> Option<Btn> {
        if self.tab == Tab::Settings {
            if let KeyCode::Char(c) = k.code
                && (c.is_ascii_digit() || k.code == KeyCode::Backspace)
            {
                self.auto_lock.handle(k);
                return None;
            }
            if k.code == KeyCode::Backspace {
                self.auto_lock.handle(k);
                return None;
            }
        }
        Some(match (self.tab, k.code) {
            (_, KeyCode::Char('l')) => Btn::Lock,
            (_, KeyCode::Char('R')) => Btn::Refresh,
            (Tab::Entries, KeyCode::Char('a')) => Btn::Add,
            (Tab::Entries, KeyCode::Char('e') | KeyCode::Enter) => Btn::Edit,
            (Tab::Entries, KeyCode::Char('d') | KeyCode::Delete) => Btn::Delete,
            (Tab::Entries, KeyCode::Char('v')) => Btn::Reveal,
            (Tab::Hosts, KeyCode::Char('t') | KeyCode::Enter | KeyCode::Char('d')) => Btn::Trust,
            (Tab::Hosts, KeyCode::Char('c')) => Btn::ClearDomain,
            (Tab::Agents, KeyCode::Enter | KeyCode::Char('a')) => Btn::Connect,
            (Tab::Agents, KeyCode::Char('r') | KeyCode::Delete) => Btn::Disconnect,
            (Tab::Doctor, KeyCode::Char('r')) => Btn::Recheck,
            (Tab::Doctor, KeyCode::Char('f')) => Btn::Fix,
            (Tab::Settings, KeyCode::Enter | KeyCode::Char('s')) => Btn::SaveSettings,
            (Tab::Settings, KeyCode::Char('p')) => Btn::ChangePassword,
            _ => return None,
        })
    }

    fn rows_in_tab(&self) -> usize {
        match self.tab {
            Tab::Entries => self.entries.len(),
            Tab::Hosts => self.pending.len() + self.pins.len(),
            Tab::Agents => self.agent_rows().len(),
            _ => 0,
        }
    }

    pub fn move_sel(&mut self, d: i32) {
        let n = self.rows_in_tab();
        if n == 0 {
            return;
        }
        let i = self.tab.index();
        self.sel[i] = (self.sel[i] as i32 + d).clamp(0, n as i32 - 1) as usize;
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        self.last_input = Instant::now();
        match m.kind {
            MouseEventKind::ScrollUp => {
                if self.dialog.is_none() {
                    self.move_sel(-1)
                }
            }
            MouseEventKind::ScrollDown => {
                if self.dialog.is_none() {
                    self.move_sel(1)
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let hit = self
                    .hits
                    .iter()
                    .rev()
                    .find(|(r, _)| m.column >= r.x && m.column < r.x + r.width && m.row >= r.y && m.row < r.y + r.height)
                    .map(|(_, h)| h.clone());
                let Some(hit) = hit else { return };
                let double = self.last_click.as_ref().is_some_and(|(t, h)| *h == hit && t.elapsed() < Duration::from_millis(450));
                self.last_click = Some((Instant::now(), hit.clone()));
                self.click(hit, double);
            }
            _ => {}
        }
    }

    fn click(&mut self, hit: Hit, double: bool) {
        match hit {
            Hit::Tab(t) if self.dialog.is_none() => self.tab = t,
            Hit::Row(i) if self.dialog.is_none() => {
                self.sel[self.tab.index()] = i;
                if double {
                    match self.tab {
                        Tab::Entries => self.button(Btn::Edit),
                        Tab::Hosts => self.button(Btn::Trust),
                        Tab::Agents => self.button(Btn::Connect),
                        _ => {}
                    }
                }
            }
            Hit::Button(b) if self.dialog.is_none() => self.button(b),
            Hit::Field(i) => match &mut self.dialog {
                Some(Dialog::Entry(f)) => {
                    f.focus = i;
                    if i == 3 {
                        f.self_signed = !f.self_signed;
                    } else if i == 4 {
                        f.auto_accept = !f.auto_accept;
                    }
                }
                Some(Dialog::ChangePassword { focus, .. }) => *focus = i,
                _ => {}
            },
            Hit::DialogButton(b) => self.dialog_button(b),
            _ => {}
        }
    }

    // ---- 主界面按钮 ----

    pub fn button(&mut self, b: Btn) {
        if !self.ready() && !matches!(b, Btn::Recheck | Btn::Fix | Btn::Quit | Btn::Refresh | Btn::Lock) {
            self.error("安全检查未通过，库保持锁定。请先处理\"诊断\"页中的问题。");
            return;
        }
        match b {
            Btn::Quit => self.quit = true,
            Btn::Refresh => {
                self.refresh();
                self.info("已刷新。");
            }
            Btn::Lock => match self.call(Request::Lock) {
                Ok(_) => {
                    self.dialog = Some(Dialog::Info {
                        title: "已锁定".into(),
                        body: "库已锁定，内存中的密钥已清除。\nAgent 再次使用前需要运行 PassManager unlock。".into(),
                        quit_after: true,
                    });
                }
                Err(e) => self.error(e.message),
            },
            Btn::Add => self.dialog = Some(Dialog::Entry(Box::new(EntryForm::new()))),
            Btn::Edit => {
                if let Some(e) = self.entries.get(self.sel[0]).cloned() {
                    let mut f = EntryForm::new();
                    f.original = Some(e.name.clone());
                    f.name.set(&e.name);
                    f.domains.set(&e.domains.join(", "));
                    f.note.set(&e.note);
                    f.self_signed = e.self_signed;
                    f.auto_accept = e.auto_accept_host_key;
                    self.dialog = Some(Dialog::Entry(Box::new(f)));
                }
            }
            Btn::Delete => {
                if let Some(e) = self.entries.get(self.sel[0]) {
                    let name = e.name.clone();
                    self.dialog = Some(Dialog::Confirm {
                        text: format!("删除条目 {name}？此操作无法撤销。"),
                        what: Confirm::DeleteEntry(name),
                    });
                }
            }
            Btn::Reveal => {
                if let Some(e) = self.entries.get(self.sel[0]) {
                    if let Err(why) = pm_platform::tty::require_human_terminal() {
                        self.error(why);
                        return;
                    }
                    self.dialog = Some(Dialog::Reveal { name: e.name.clone(), input: TextInput::new(true), shown: None, error: None });
                }
            }
            Btn::Trust => {
                let i = self.sel[1];
                let hp = if i < self.pending.len() {
                    self.pending.get(i).map(|p| p.host_port.clone())
                } else {
                    self.pins.get(i - self.pending.len()).map(|p| p.host_port.clone())
                };
                if let Some(hp) = hp {
                    match self.call(Request::TrustPins { pattern: hp.clone() }) {
                        Ok(_) => {
                            self.refresh();
                            self.info(format!("已清除 {hp} 的旧记录，下次连接时将记录新指纹。"));
                        }
                        Err(e) => self.error(e.message),
                    }
                }
            }
            Btn::ClearDomain => {
                self.dialog = Some(Dialog::Prompt {
                    title: "按域名清除主机记录（例如 *.example.com）".into(),
                    input: TextInput::new(false),
                    kind: PromptKind::ClearDomain,
                })
            }
            Btn::Connect => self.agent_connect(),
            Btn::Disconnect => {
                let rows = self.agent_rows();
                match rows.get(self.sel[2]) {
                    Some(AgentRow::Adapter(i)) => {
                        let i = *i;
                        self.dialog = Some(Dialog::Confirm {
                            text: format!("断开 {}（删除其 MCP 配置并吊销令牌）？", ADAPTERS[i].name),
                            what: Confirm::Disconnect(i),
                        })
                    }
                    Some(AgentRow::Token(i)) => {
                        let t = self.tokens[*i].clone();
                        self.dialog = Some(Dialog::Confirm {
                            text: format!("吊销令牌 {}（{}）？", t.label, t.id),
                            what: Confirm::RevokeToken(t.id),
                        })
                    }
                    _ => {}
                }
            }
            Btn::Recheck | Btn::Fix => {
                let mode = self.status.as_ref().map(|s| s.mode.clone()).unwrap_or_default();
                if mode == "system" {
                    let mut args = vec!["harden".to_string()];
                    if b == Btn::Fix {
                        args.push("--fix".into());
                        args.push("--yes".into());
                    } else {
                        args.push("--check".into());
                    }
                    self.run_external = Some(elevate(&self.bin, &args));
                } else {
                    self.refresh();
                    self.info("用户模式没有账户加固检查。");
                }
            }
            Btn::SaveSettings => {
                let h: u32 = self.auto_lock.value().trim().parse().unwrap_or(12);
                match self.call(Request::SetSettings { auto_lock_hours: h }) {
                    Ok(_) => {
                        self.refresh();
                        self.info(if h == 0 {
                            "已保存：不自动锁定。".to_string()
                        } else {
                            format!("已保存：空闲 {h} 小时后自动锁定。")
                        });
                    }
                    Err(e) => self.error(e.message),
                }
            }
            Btn::ChangePassword => {
                self.dialog = Some(Dialog::ChangePassword {
                    fields: [TextInput::new(true), TextInput::new(true), TextInput::new(true)],
                    focus: 0,
                    error: None,
                })
            }
        }
    }

    /// 外部命令（sudo harden）执行完成后调用。
    pub fn after_external(&mut self) {
        let was_locked = self.status.as_ref().is_some_and(|s| s.locked || !s.ready);
        self.refresh();
        let ready_now = self.security.as_ref().is_some_and(|s| s.report.passed() && s.runtime_issues.is_empty());
        if was_locked && ready_now {
            self.dialog = Some(Dialog::Login {
                input: TextInput::new(true),
                error: None,
                note: Some("安全检查已全部通过，请重新输入口令解锁。".into()),
            });
        }
    }

    fn agent_connect(&mut self) {
        let rows = self.agent_rows();
        match rows.get(self.sel[2]) {
            Some(AgentRow::Adapter(i)) => {
                let a = &ADAPTERS[*i];
                // 先吊销该 Agent 旧的令牌，再新建。
                let old: Vec<String> = self.tokens.iter().filter(|t| t.label == a.name).map(|t| t.id.clone()).collect();
                for id in old {
                    let _ = self.call(Request::RevokeToken { id });
                }
                match self.call_as::<NewToken>(Request::CreateToken { label: a.name.into() }) {
                    Ok(t) => {
                        let tok = Zeroizing::new(t.token);
                        match a.connect(&self.bin, &tok) {
                            Ok(m) => self.info(format!("{} 已接入：{m}。重启该 Agent 后生效。", a.name)),
                            Err(e) => {
                                let _ = self.call(Request::RevokeToken { id: t.id });
                                self.error(format!("接入 {} 失败：{e}", a.name));
                            }
                        }
                    }
                    Err(e) => self.error(e.message),
                }
                self.refresh();
            }
            Some(AgentRow::Other) => {
                self.dialog = Some(Dialog::Prompt {
                    title: "其他 Agent：输入名称（用于识别令牌）".into(),
                    input: TextInput::new(false),
                    kind: PromptKind::OtherAgentLabel,
                })
            }
            Some(AgentRow::Token(_)) => self.info("这是手动配置的令牌；按 r 吊销，或在\"其他 Agent\"行新建。"),
            None => {}
        }
    }

    // ---- 对话框 ----

    fn dialog_key(&mut self, k: KeyEvent) {
        let esc = k.code == KeyCode::Esc;
        let enter = k.code == KeyCode::Enter && !k.modifiers.contains(KeyModifiers::ALT);
        let ctrl = |c: char| k.code == KeyCode::Char(c) && k.modifiers.contains(KeyModifiers::CONTROL);
        match &mut self.dialog {
            Some(Dialog::Login { input, .. }) => {
                if esc {
                    self.quit = true;
                } else if enter {
                    self.dialog_button(DBtn::Ok);
                } else {
                    input.handle(k);
                }
            }
            Some(Dialog::Entry(f)) => {
                if esc {
                    self.dialog = None;
                } else if ctrl('s') {
                    self.dialog_button(DBtn::Save);
                } else if ctrl('g') {
                    self.dialog_button(DBtn::Generate);
                } else if ctrl('r') {
                    self.dialog_button(DBtn::ToggleShow);
                } else if k.code == KeyCode::Tab || k.code == KeyCode::Down {
                    f.focus = (f.focus + 1) % FORM_FIELDS;
                } else if k.code == KeyCode::BackTab || k.code == KeyCode::Up {
                    f.focus = (f.focus + FORM_FIELDS - 1) % FORM_FIELDS;
                } else if f.focus >= 3 && (k.code == KeyCode::Char(' ') || enter) {
                    if f.focus == 3 {
                        f.self_signed = !f.self_signed;
                    } else {
                        f.auto_accept = !f.auto_accept;
                    }
                } else if enter {
                    if f.focus == 2 {
                        self.dialog_button(DBtn::Save);
                    } else {
                        f.focus += 1;
                    }
                } else {
                    let focus = f.focus;
                    if let Some(i) = f.input_mut(focus) {
                        i.handle(k);
                    }
                }
            }
            Some(Dialog::Confirm { .. }) => match k.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => self.dialog_button(DBtn::Ok),
                KeyCode::Char('n') | KeyCode::Esc => self.dialog = None,
                _ => {}
            },
            Some(Dialog::Reveal { input, shown, .. }) => {
                if esc {
                    self.dialog = None;
                } else if shown.is_none() {
                    if enter {
                        self.dialog_button(DBtn::Ok);
                    } else {
                        input.handle(k);
                    }
                } else if enter {
                    self.dialog = None;
                }
            }
            Some(Dialog::Info { .. }) => {
                if esc || enter || k.code == KeyCode::Char(' ') {
                    self.dialog_button(DBtn::Ok);
                }
            }
            Some(Dialog::Prompt { input, .. }) => {
                if esc {
                    self.dialog = None;
                } else if enter {
                    self.dialog_button(DBtn::Ok);
                } else {
                    input.handle(k);
                }
            }
            Some(Dialog::ChangePassword { fields, focus, .. }) => {
                if esc {
                    self.dialog = None;
                } else if k.code == KeyCode::Tab || k.code == KeyCode::Down {
                    *focus = (*focus + 1) % 3;
                } else if k.code == KeyCode::BackTab || k.code == KeyCode::Up {
                    *focus = (*focus + 2) % 3;
                } else if enter {
                    if *focus < 2 {
                        *focus += 1;
                    } else {
                        self.dialog_button(DBtn::Ok);
                    }
                } else {
                    fields[*focus].handle(k);
                }
            }
            Some(Dialog::Trust { .. }) => match k.code {
                KeyCode::Char('y') | KeyCode::Char('t') | KeyCode::Enter => self.dialog_button(DBtn::Ok),
                KeyCode::Esc | KeyCode::Char('n') => self.dialog_button(DBtn::Cancel),
                _ => {}
            },
            None => {}
        }
    }

    pub fn dialog_button(&mut self, b: DBtn) {
        let Some(d) = self.dialog.take() else { return };
        match d {
            Dialog::Login { input, note, .. } => match b {
                DBtn::Ok => {
                    if input.value().is_empty() {
                        self.dialog = Some(Dialog::Login { input, error: Some("请输入口令".into()), note });
                    } else {
                        let pw = Zeroizing::new(input.value().to_string());
                        self.login(&pw);
                    }
                }
                _ => self.quit = true,
            },
            Dialog::Entry(mut f) => match b {
                DBtn::Save => {
                    let input = EntryInput {
                        name: f.name.value().trim().to_string(),
                        secret: if f.secret.value().is_empty() { None } else { Some(f.secret.value().to_string()) },
                        domains: f
                            .domains
                            .value()
                            .split([',', ' ', '，'])
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect(),
                        note: f.note.value().trim().to_string(),
                        self_signed: f.self_signed,
                        auto_accept_host_key: f.auto_accept,
                    };
                    if f.original.is_none() && input.secret.is_none() {
                        f.error = Some("密钥不能为空".into());
                        self.dialog = Some(Dialog::Entry(f));
                        return;
                    }
                    let req = match &f.original {
                        Some(o) => Request::UpdateEntry { original: o.clone(), entry: input },
                        None => Request::AddEntry { entry: input },
                    };
                    match self.call(req) {
                        Ok(_) => {
                            self.refresh();
                            // 选中刚保存的条目（最近更新的那个）。
                            if let Some((i, e)) = self.entries.iter().enumerate().max_by_key(|(_, e)| e.updated) {
                                self.sel[0] = i;
                                self.info(format!("已保存（{}）。", e.domains.join(", ")));
                            }
                        }
                        Err(e) => {
                            f.error = Some(e.message);
                            self.dialog = Some(Dialog::Entry(f));
                        }
                    }
                }
                DBtn::Generate => {
                    if let Some(s) = generate_secret(32) {
                        f.secret.set(&s);
                        f.secret.masked = false;
                        f.focus = 0;
                    }
                    self.dialog = Some(Dialog::Entry(f));
                }
                DBtn::ToggleShow => {
                    f.secret.masked = !f.secret.masked;
                    self.dialog = Some(Dialog::Entry(f));
                }
                _ => {}
            },
            Dialog::Confirm { what, text } => {
                if b != DBtn::Ok {
                    return;
                }
                let r = match &what {
                    Confirm::DeleteEntry(n) => self.call(Request::DeleteEntry { name: n.clone() }).map(|_| format!("已删除 {n}。")),
                    Confirm::Disconnect(i) => {
                        let a = &ADAPTERS[*i];
                        let ids: Vec<String> = self.tokens.iter().filter(|t| t.label == a.name).map(|t| t.id.clone()).collect();
                        for id in ids {
                            let _ = self.call(Request::RevokeToken { id });
                        }
                        a.disconnect().map(|_| format!("已断开 {}。", a.name)).map_err(|e| ApiError::new("ERROR", e))
                    }
                    Confirm::RevokeToken(id) => self.call(Request::RevokeToken { id: id.clone() }).map(|_| "已吊销令牌。".to_string()),
                };
                let _ = text;
                self.refresh();
                match r {
                    Ok(m) => self.info(m),
                    Err(e) => self.error(e.message),
                }
            }
            Dialog::Reveal { name, input, shown, .. } => {
                if shown.is_some() || b != DBtn::Ok {
                    return;
                }
                let pw = input.value().to_string();
                match self.call(Request::Reveal { name: name.clone(), password: pw }) {
                    Ok(v) => {
                        let s = Zeroizing::new(v.as_str().unwrap_or_default().to_string());
                        self.dialog =
                            Some(Dialog::Reveal { name, input: TextInput::new(true), shown: Some((s, Instant::now())), error: None });
                    }
                    Err(e) => self.dialog = Some(Dialog::Reveal { name, input: TextInput::new(true), shown: None, error: Some(e.message) }),
                }
            }
            Dialog::Info { quit_after, .. } => {
                if quit_after {
                    self.quit = true;
                }
            }
            Dialog::Prompt { input, kind, .. } => {
                if b != DBtn::Ok {
                    return;
                }
                let v = input.value().trim().to_string();
                if v.is_empty() {
                    return;
                }
                match kind {
                    PromptKind::ClearDomain => match self.call(Request::TrustPins { pattern: v.clone() }) {
                        Ok(r) => {
                            let n = r.as_array().map(|a| a.len()).unwrap_or(0);
                            self.refresh();
                            self.info(format!("已清除 {n} 条与 {v} 匹配的记录。"));
                        }
                        Err(e) => self.error(e.message),
                    },
                    PromptKind::OtherAgentLabel => match self.call_as::<NewToken>(Request::CreateToken { label: v.clone() }) {
                        Ok(t) => {
                            self.refresh();
                            self.dialog = Some(Dialog::Info {
                                title: format!("{v} 的接入方式（令牌只显示这一次）"),
                                body: snippet(&self.bin, &t.token),
                                quit_after: false,
                            });
                        }
                        Err(e) => self.error(e.message),
                    },
                }
            }
            Dialog::ChangePassword { fields, focus, .. } => {
                if b != DBtn::Ok {
                    return;
                }
                let [old, new, new2] = &fields;
                let err = if new.value().chars().count() < 8 {
                    Some("新口令至少需要 8 个字符".to_string())
                } else if new.value() != new2.value() {
                    Some("两次输入的新口令不一致".to_string())
                } else {
                    match self.call(Request::ChangePassword { old: old.value().into(), new: new.value().into() }) {
                        Ok(_) => None,
                        Err(e) => Some(e.message),
                    }
                };
                match err {
                    None => self.info("口令已修改。"),
                    Some(e) => self.dialog = Some(Dialog::ChangePassword { fields, focus, error: Some(e) }),
                }
            }
            Dialog::Trust { pattern, any, .. } => {
                if b == DBtn::Ok && any {
                    match self.call(Request::TrustPins { pattern: pattern.clone() }) {
                        Ok(_) => {
                            self.dialog = Some(Dialog::Info {
                                title: "已信任".into(),
                                body: format!("已清除 {pattern} 的旧指纹，下次连接时将自动记录新指纹。\n现在可以让 Agent 重试。"),
                                quit_after: true,
                            })
                        }
                        Err(e) => self.dialog = Some(Dialog::Info { title: "失败".into(), body: e.message, quit_after: true }),
                    }
                } else {
                    self.quit = true;
                }
            }
        }
    }

    /// 定时任务：查看明文 15 秒后自动隐藏；空闲超时退出。
    pub fn tick(&mut self) {
        if let Some(Dialog::Reveal { shown: Some((_, t)), .. }) = &self.dialog
            && t.elapsed() > REVEAL_TIME
        {
            self.dialog = None;
            self.info("明文已自动隐藏。");
        }
        if self.last_input.elapsed() > IDLE_TIMEOUT {
            self.quit = true;
        }
    }
}

/// 简单的指纹记录匹配（与服务端规则一致）。
pub fn pattern_matches(pattern: &str, host_port: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    if p == host_port {
        return true;
    }
    let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    match p.strip_prefix("*.") {
        Some(base) => host == base || host.ends_with(&format!(".{base}")),
        None => host == p,
    }
}

/// 用组合 RNG 生成随机密钥（字母、数字与常用符号）。
pub fn generate_secret(len: usize) -> Option<String> {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!@#%^*+=";
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let mut buf = [0u8; 64];
        pm_crypto::rng::fill(&mut buf).ok()?;
        for b in buf {
            // 拒绝采样，避免取模偏差。
            let limit = 256 - (256 % CHARS.len());
            if (b as usize) < limit && out.len() < len {
                out.push(CHARS[b as usize % CHARS.len()] as char);
            }
        }
    }
    Some(out)
}

/// 以管理员身份运行本程序的命令行。
fn elevate(bin: &str, args: &[String]) -> Vec<String> {
    if cfg!(windows) {
        let arglist = args.join(" ");
        vec![
            "powershell.exe".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("Start-Process -FilePath '{bin}' -ArgumentList '{arglist}' -Verb RunAs -Wait"),
        ]
    } else {
        let mut v = vec!["sudo".to_string(), bin.to_string()];
        v.extend(args.iter().cloned());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_generation() {
        let s = generate_secret(32).unwrap();
        assert_eq!(s.len(), 32);
        assert_ne!(s, generate_secret(32).unwrap());
    }

    #[test]
    fn trust_patterns() {
        assert!(pattern_matches("db1.example.com:22", "db1.example.com:22"));
        assert!(pattern_matches("db1.example.com", "db1.example.com:2222"));
        assert!(pattern_matches("*.example.com", "a.b.example.com:443"));
        assert!(!pattern_matches("*.example.com", "example.org:22"));
    }
}

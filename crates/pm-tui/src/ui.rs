//! 渲染。每次绘制时记录可点击区域（hit-test）。

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

use crate::agents::ADAPTERS;
use crate::app::*;
use crate::input::TextInput;

const ACCENT: Color = Color::Cyan;
const WARN: Color = Color::Yellow;
const BAD: Color = Color::Red;
const OK: Color = Color::Green;
const DIM: Color = Color::DarkGray;

fn sel_style() -> Style {
    Style::new().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD)
}

pub fn fmt_time(ts: u64) -> String {
    if ts == 0 {
        return "-".into();
    }
    let days = (ts / 86400) as i64;
    let secs = ts % 86400;
    // 公历换算（Howard Hinnant 算法）。
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}

fn truncate(s: &str, w: usize) -> String {
    if s.width() <= w {
        return s.to_string();
    }
    let mut out = String::new();
    for c in s.chars() {
        if out.width() + 2 > w {
            break;
        }
        out.push(c);
    }
    out.push('…');
    out
}

pub fn draw(f: &mut Frame, app: &mut App) {
    app.hits.clear();
    let area = f.area();
    if app.client.is_none() {
        // 登录前只显示对话框。
        f.render_widget(Block::new().style(Style::new()), area);
        draw_header_simple(f, area, app);
        draw_dialog(f, app);
        return;
    }
    let [header, tabs, body, buttons, msg] =
        Layout::vertical([Constraint::Length(2), Constraint::Length(1), Constraint::Min(5), Constraint::Length(1), Constraint::Length(1)])
            .areas(area);
    draw_header(f, header, app);
    draw_tabs(f, tabs, app);
    match app.tab {
        Tab::Entries => draw_entries(f, body, app),
        Tab::Hosts => draw_hosts(f, body, app),
        Tab::Agents => draw_agents(f, body, app),
        Tab::Doctor => draw_doctor(f, body, app),
        Tab::Settings => draw_settings(f, body, app),
    }
    draw_buttons(f, buttons, app);
    if let Some((m, err)) = &app.msg {
        f.render_widget(Paragraph::new(Span::styled(m.clone(), Style::new().fg(if *err { BAD } else { OK }))), msg);
    }
    draw_dialog(f, app);
}

fn draw_header_simple(f: &mut Frame, area: Rect, _app: &App) {
    let r = Rect { height: 1, ..area };
    f.render_widget(
        Paragraph::new(Span::styled(
            " PassManager · 面向 AI Agent 的抗量子密码管理器",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        r,
    );
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let [l1, l2] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let st = app.status.as_ref();
    let level = st.map(|s| s.level).unwrap_or(1);
    let level_txt = pm_platform::seal::level_label(level);
    let lock_txt = match st {
        Some(s) if !s.ready => Span::styled(" 未就绪（已锁定）", Style::new().fg(BAD).add_modifier(Modifier::BOLD)),
        Some(s) if s.locked => Span::styled(" 已锁定", Style::new().fg(WARN)),
        _ => Span::styled(" 已解锁", Style::new().fg(OK)),
    };
    let mode = st.map(|s| if s.mode == "user" { " · 用户模式" } else { "" }).unwrap_or("");
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" PassManager ", Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(level_txt, Style::new().fg(if level == 1 { BAD } else { OK })),
            Span::raw(mode),
            Span::raw(" ·"),
            lock_txt,
        ])),
        l1,
    );
    if level == 1 {
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" ⚠ {} ", pm_platform::seal::L1_WARNING),
                Style::new().fg(Color::White).bg(BAD).add_modifier(Modifier::BOLD),
            )),
            l2,
        );
    } else if st.is_some_and(|s| !s.ready) {
        f.render_widget(
            Paragraph::new(Span::styled(" ⚠ 安全检查未通过，库保持锁定。请查看\"诊断\"页。", Style::new().fg(Color::White).bg(BAD))),
            l2,
        );
    }
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &mut App) {
    let mut x = area.x + 1;
    for (i, (tab, name)) in TABS.iter().enumerate() {
        let label = format!(" {} {} ", i + 1, name);
        let w = label.width() as u16;
        let style = if *tab == app.tab {
            Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(Color::White).bg(DIM)
        };
        let r = Rect { x, y: area.y, width: w.min(area.right().saturating_sub(x)), height: 1 };
        f.render_widget(Paragraph::new(Span::styled(label, style)), r);
        app.hits.push((r, Hit::Tab(*tab)));
        x += w + 1;
    }
}

/// 绘制可滚动的表格；返回可见行数。
fn draw_table(f: &mut Frame, area: Rect, app: &mut App, title: &str, header: &[(&str, u16)], rows: Vec<(Vec<String>, Style)>) {
    let block = Block::bordered().border_type(BorderType::Rounded).title(Span::styled(format!(" {title} "), Style::new().fg(ACCENT)));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height < 2 {
        return;
    }
    let widths: Vec<u16> = {
        let fixed: u16 = header.iter().skip(1).map(|(_, w)| *w).sum();
        let first = inner.width.saturating_sub(fixed).max(10);
        std::iter::once(first).chain(header.iter().skip(1).map(|(_, w)| *w)).collect()
    };
    let line = |cells: &[String], style: Style| -> Line {
        let mut spans = Vec::new();
        for (i, c) in cells.iter().enumerate() {
            let w = widths.get(i).copied().unwrap_or(10) as usize;
            let t = truncate(c, w.saturating_sub(1));
            let pad = w.saturating_sub(t.width());
            spans.push(Span::styled(format!("{t}{}", " ".repeat(pad)), style));
        }
        Line::from(spans)
    };
    let hdr: Vec<String> = header.iter().map(|(h, _)| h.to_string()).collect();
    f.render_widget(Paragraph::new(line(&hdr, Style::new().fg(DIM).add_modifier(Modifier::BOLD))), Rect { height: 1, ..inner });
    let visible = (inner.height - 1) as usize;
    let sel = app.sel[app.tab.index()];
    let offset = if sel >= visible { sel + 1 - visible } else { 0 };
    if rows.is_empty() {
        f.render_widget(Paragraph::new(Span::styled("（空）", Style::new().fg(DIM))), Rect { y: inner.y + 1, height: 1, ..inner });
    }
    for (vi, (i, (cells, style))) in rows.iter().enumerate().skip(offset).take(visible).enumerate() {
        let r = Rect { x: inner.x, y: inner.y + 1 + vi as u16, width: inner.width, height: 1 };
        let st = if i == sel { sel_style() } else { *style };
        f.render_widget(Paragraph::new(line(cells, st)).style(st), r);
        app.hits.push((r, Hit::Row(i)));
    }
}

fn draw_entries(f: &mut Frame, area: Rect, app: &mut App) {
    let rows = app
        .entries
        .iter()
        .map(|e| {
            let mut flags = Vec::new();
            if e.private_key {
                flags.push("私钥");
            }
            if e.self_signed {
                flags.push("自签证书");
            }
            if e.auto_accept_host_key {
                flags.push("自动接受主机密钥");
            }
            (vec![e.domains.join(", "), e.note.clone(), e.name.clone(), flags.join(" ")], Style::new())
        })
        .collect();
    draw_table(f, area, app, "条目（密钥 + 域名）", &[("域名", 0), ("说明", 26), ("引用名", 18), ("选项", 18)], rows);
}

fn draw_hosts(f: &mut Frame, area: Rect, app: &mut App) {
    let mut rows = Vec::new();
    for p in &app.pending {
        rows.push((
            vec![p.host_port.clone(), p.kind.clone(), format!("已变化 → {}", p.new_fingerprint), fmt_time(p.seen_at)],
            Style::new().fg(BAD).add_modifier(Modifier::BOLD),
        ));
    }
    for p in &app.pins {
        rows.push((vec![p.host_port.clone(), p.kind.clone(), p.fingerprint.clone(), fmt_time(p.first_seen)], Style::new()));
    }
    draw_table(f, area, app, "主机指纹（SSH 主机密钥 / 自签证书）", &[("主机", 0), ("类型", 7), ("指纹", 52), ("时间 (UTC)", 17)], rows);
}

fn draw_agents(f: &mut Frame, area: Rect, app: &mut App) {
    let rows = app
        .agent_rows()
        .into_iter()
        .map(|r| match r {
            AgentRow::Adapter(i) => {
                let a = &ADAPTERS[i];
                let tok = app.token_for(a.name);
                let configured = a.configured();
                let state = match (configured, tok.is_some()) {
                    (true, true) => "已接入",
                    (true, false) => "配置存在但令牌已吊销",
                    (false, true) => "令牌存在但未写入配置",
                    _ => "",
                };
                let style = if configured && tok.is_some() { Style::new().fg(OK) } else { Style::new() };
                (
                    vec![
                        a.name.to_string(),
                        if a.detected() { "已检测到".into() } else { "未检测到".into() },
                        state.into(),
                        tok.and_then(|t| t.last_used).map(fmt_time).unwrap_or_default(),
                    ],
                    style,
                )
            }
            AgentRow::Token(i) => {
                let t = &app.tokens[i];
                (
                    vec![
                        format!("{}（手动）", t.label),
                        "-".into(),
                        format!("令牌 {}", t.id),
                        t.last_used.map(fmt_time).unwrap_or_default(),
                    ],
                    Style::new(),
                )
            }
            AgentRow::Other => {
                (vec!["＋ 其他 Agent（手动配置）".into(), String::new(), String::new(), String::new()], Style::new().fg(ACCENT))
            }
        })
        .collect();
    draw_table(
        f,
        area,
        app,
        "Agent 接入（每个 Agent 一个令牌，Agent 永远看不到明文）",
        &[("Agent", 0), ("检测", 10), ("状态", 22), ("最近使用 (UTC)", 17)],
        rows,
    );
}

fn draw_doctor(f: &mut Frame, area: Rect, app: &mut App) {
    let mut lines: Vec<Line> = Vec::new();
    if let Some(s) = &app.security {
        lines.push(Line::from(vec![
            Span::raw("设备密钥封存："),
            Span::styled(
                pm_platform::seal::level_label(s.level),
                Style::new().fg(if s.level == 1 { BAD } else { OK }).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {}", s.description)),
        ]));
        if let Some(r) = &s.l1_reason {
            lines.push(Line::from(Span::styled(format!("⚠ {}：{r}", pm_platform::seal::L1_WARNING), Style::new().fg(BAD))));
        }
        for i in &s.runtime_issues {
            lines.push(Line::from(Span::styled(format!("✘ {i}"), Style::new().fg(BAD))));
        }
        lines.push(Line::raw(""));
        if let Some(sk) = &s.report.skipped {
            lines.push(Line::from(Span::styled(sk.clone(), Style::new().fg(WARN))));
        }
        for fd in &s.report.findings {
            let (mark, color, tail) = if fd.ok {
                ("✔", OK, "")
            } else if fd.advisory {
                ("⚠", WARN, "（建议，不影响使用）")
            } else if fd.auto_fix {
                ("●", WARN, "（可一键修复）")
            } else {
                ("✘", BAD, "（需要你处理）")
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{mark} "), Style::new().fg(color)),
                Span::raw(fd.title.clone()),
                Span::styled(tail, Style::new().fg(color)),
            ]));
            if !fd.ok {
                for l in fd.detail.lines() {
                    lines.push(Line::from(Span::styled(format!("    {l}"), Style::new().fg(DIM))));
                }
                for l in fd.steps.lines() {
                    lines.push(Line::from(Span::styled(format!("    → {l}"), Style::new().fg(WARN))));
                }
            }
        }
        if s.report.generated > 0 {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(format!("检查时间：{} UTC", fmt_time(s.report.generated)), Style::new().fg(DIM))));
        }
    } else {
        lines.push(Line::raw("无法获取安全状态。"));
    }
    let p = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }).block(
        Block::bordered().border_type(BorderType::Rounded).title(Span::styled(" 诊断：安全检查与账户加固 ", Style::new().fg(ACCENT))),
    );
    f.render_widget(p, area);
}

fn draw_settings(f: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::bordered().border_type(BorderType::Rounded).title(Span::styled(" 设置 ", Style::new().fg(ACCENT)));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let lines = vec![
        Line::from(vec![
            Span::raw("空闲自动锁定（小时，0 = 不自动锁定）："),
            Span::styled(format!(" {} ", app.auto_lock.value()), Style::new().bg(DIM).fg(Color::White)),
        ]),
        Line::from(Span::styled("  直接输入数字，按 s 或点 [保存] 保存。", Style::new().fg(DIM))),
        Line::raw(""),
        Line::raw("修改口令：按 p 或点 [修改口令]。"),
        Line::raw("立即锁定：按 l 或点 [锁定]。锁定后 Agent 需要你运行 PassManager unlock 才能继续使用。"),
        Line::raw(""),
        Line::from(Span::styled("PassManager 没有任何恢复机制：换机器、重装系统、清空 TPM 后库将无法打开。", Style::new().fg(WARN))),
    ];
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn buttons_for(app: &App) -> Vec<(&'static str, Btn)> {
    let mut v: Vec<(&str, Btn)> = match app.tab {
        Tab::Entries => vec![("新增 a", Btn::Add), ("编辑 e", Btn::Edit), ("删除 d", Btn::Delete), ("查看 v", Btn::Reveal)],
        Tab::Hosts => vec![("信任新指纹 / 删除记录 t", Btn::Trust), ("按域名清除 c", Btn::ClearDomain)],
        Tab::Agents => vec![("接入 Enter", Btn::Connect), ("断开/吊销 r", Btn::Disconnect)],
        Tab::Doctor => vec![("重新检查 r", Btn::Recheck), ("一键修复 f", Btn::Fix)],
        Tab::Settings => vec![("保存 s", Btn::SaveSettings), ("修改口令 p", Btn::ChangePassword)],
    };
    v.push(("锁定 l", Btn::Lock));
    v.push(("退出 q", Btn::Quit));
    v
}

fn draw_buttons(f: &mut Frame, area: Rect, app: &mut App) {
    let mut x = area.x + 1;
    for (label, b) in buttons_for(app) {
        let text = format!("[{label}]");
        let w = text.width() as u16;
        if x + w > area.right() {
            break;
        }
        let r = Rect { x, y: area.y, width: w, height: 1 };
        f.render_widget(Paragraph::new(Span::styled(text, Style::new().fg(Color::Black).bg(Color::Gray))), r);
        app.hits.push((r, Hit::Button(b)));
        x += w + 1;
    }
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(2));
    let h = h.min(area.height.saturating_sub(2));
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

fn dialog_frame(f: &mut Frame, area: Rect, title: &str) -> Rect {
    f.render_widget(Clear, area);
    let block = Block::bordered()
        .border_type(BorderType::Double)
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(format!(" {title} "), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)));
    let inner = block.inner(area);
    f.render_widget(block, area);
    inner
}

fn dialog_buttons(f: &mut Frame, app: &mut App, y: u16, x0: u16, buttons: &[(&str, DBtn)]) {
    let mut x = x0;
    for (label, b) in buttons {
        let text = format!("[ {label} ]");
        let w = text.width() as u16;
        let r = Rect { x, y, width: w, height: 1 };
        f.render_widget(Paragraph::new(Span::styled(text, Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD))), r);
        app.hits.push((r, Hit::DialogButton(*b)));
        x += w + 2;
    }
}

/// 绘制一行"标签：输入框"，返回输入框区域。
#[allow(clippy::too_many_arguments)]
fn field(
    f: &mut Frame,
    app: &mut App,
    x: u16,
    y: u16,
    width: u16,
    label: &str,
    input: &TextInput,
    focused: bool,
    idx: Option<usize>,
) -> Rect {
    let lw = label.width() as u16;
    f.render_widget(Paragraph::new(Span::raw(label.to_string())), Rect { x, y, width: lw, height: 1 });
    let r = Rect { x: x + lw, y, width: width.saturating_sub(lw), height: 1 };
    let style = if focused { Style::new().bg(Color::Blue).fg(Color::White) } else { Style::new().bg(DIM).fg(Color::White) };
    let shown = truncate(&input.display(), r.width.saturating_sub(1) as usize);
    f.render_widget(
        Paragraph::new(Span::styled(format!("{shown}{}", " ".repeat((r.width as usize).saturating_sub(shown.width()))), style)),
        r,
    );
    if focused {
        f.set_cursor_position((r.x + input.cursor_col().min(r.width.saturating_sub(1)), y));
    }
    if let Some(i) = idx {
        app.hits.push((Rect { x, ..r }.union(r), Hit::Field(i)));
    }
    r
}

fn draw_dialog(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let Some(dialog) = app.dialog.take() else { return };
    match &dialog {
        Dialog::Login { input, error, note } => {
            let title = match &app.mode {
                Mode::Unlock => "解锁 PassManager",
                Mode::Trust(_) => "确认身份",
                Mode::Full => "PassManager",
            };
            let r = centered(area, 60, 9);
            let inner = dialog_frame(f, r, title);
            let mut y = inner.y;
            let msg = note.clone().unwrap_or_else(|| "请输入 PassManager 口令：".into());
            f.render_widget(Paragraph::new(msg).wrap(Wrap { trim: false }), Rect { y, height: 2, ..inner });
            y += 2;
            field(f, app, inner.x, y, inner.width, "口令：", input, true, None);
            y += 2;
            if let Some(e) = error {
                f.render_widget(
                    Paragraph::new(Span::styled(e.clone(), Style::new().fg(BAD))).wrap(Wrap { trim: false }),
                    Rect { y, height: 2, ..inner },
                );
            }
            dialog_buttons(f, app, inner.bottom().saturating_sub(1), inner.x, &[("解锁 Enter", DBtn::Ok), ("退出 Esc", DBtn::Cancel)]);
        }
        Dialog::Entry(form) => {
            let r = centered(area, 78, 16);
            let inner = dialog_frame(f, r, if form.original.is_some() { "编辑条目" } else { "新增条目" });
            let mut y = inner.y;
            let w = inner.width;
            field(f, app, inner.x, y, w, "密钥：", &form.secret, form.focus == 0, Some(0));
            y += 1;
            let hint = if form.original.is_some() {
                "      留空表示不修改；可粘贴多行私钥；Ctrl+G 随机生成，Ctrl+R 显示/隐藏"
            } else {
                "      API 密钥、口令或 SSH 私钥（可粘贴多行）；Ctrl+G 随机生成，Ctrl+R 显示/隐藏"
            };
            f.render_widget(Paragraph::new(Span::styled(hint, Style::new().fg(DIM))), Rect { y, height: 1, ..inner });
            y += 1;
            field(f, app, inner.x, y, w, "域名：", &form.domains, form.focus == 1, Some(1));
            y += 1;
            f.render_widget(
                Paragraph::new(Span::styled("      如 api.github.com 或 *.example.com，多个用逗号分隔", Style::new().fg(DIM))),
                Rect { y, height: 1, ..inner },
            );
            y += 1;
            field(f, app, inner.x, y, w, "说明：", &form.note, form.focus == 2, Some(2));
            y += 1;
            f.render_widget(
                Paragraph::new(Span::styled("      可选，Agent 能看到（不要写敏感信息）", Style::new().fg(DIM))),
                Rect { y, height: 1, ..inner },
            );
            y += 2;
            for (i, (label, val)) in [
                (3usize, ("自签证书（固定证书指纹，公网/内网都可用）", form.self_signed)),
                (4, ("私钥条目：主机密钥变化时自动接受", form.auto_accept)),
            ] {
                let text = format!("{} {label}", if val { "[x]" } else { "[ ]" });
                let st = if form.focus == i { Style::new().bg(Color::Blue).fg(Color::White) } else { Style::new() };
                let rr = Rect { x: inner.x, y, width: (text.width() as u16).min(w), height: 1 };
                f.render_widget(Paragraph::new(Span::styled(text, st)), rr);
                app.hits.push((rr, Hit::Field(i)));
                y += 1;
            }
            y += 1;
            if let Some(e) = &form.error {
                f.render_widget(Paragraph::new(Span::styled(e.clone(), Style::new().fg(BAD))), Rect { y, height: 1, ..inner });
            }
            dialog_buttons(
                f,
                app,
                inner.bottom().saturating_sub(1),
                inner.x,
                &[
                    ("保存 Ctrl+S", DBtn::Save),
                    ("随机生成 Ctrl+G", DBtn::Generate),
                    ("显示/隐藏 Ctrl+R", DBtn::ToggleShow),
                    ("取消 Esc", DBtn::Cancel),
                ],
            );
        }
        Dialog::Confirm { text, .. } => {
            let r = centered(area, 60, 7);
            let inner = dialog_frame(f, r, "确认");
            f.render_widget(Paragraph::new(text.clone()).wrap(Wrap { trim: false }), Rect { height: 3, ..inner });
            dialog_buttons(f, app, inner.bottom().saturating_sub(1), inner.x, &[("确定 y", DBtn::Ok), ("取消 n", DBtn::Cancel)]);
        }
        Dialog::Reveal { name, input, shown, error } => {
            let r = centered(area, 76, 12);
            let inner = dialog_frame(f, r, &format!("查看明文：{name}"));
            match shown {
                None => {
                    f.render_widget(
                        Paragraph::new("查看明文需要再次输入口令。请确认周围没有人或摄像头，也不要在 Agent 的终端里查看。")
                            .wrap(Wrap { trim: false }),
                        Rect { height: 2, ..inner },
                    );
                    field(f, app, inner.x, inner.y + 3, inner.width, "口令：", input, true, None);
                    if let Some(e) = error {
                        f.render_widget(
                            Paragraph::new(Span::styled(e.clone(), Style::new().fg(BAD))),
                            Rect { y: inner.y + 5, height: 1, ..inner },
                        );
                    }
                    dialog_buttons(
                        f,
                        app,
                        inner.bottom().saturating_sub(1),
                        inner.x,
                        &[("查看 Enter", DBtn::Ok), ("取消 Esc", DBtn::Cancel)],
                    );
                }
                Some((s, t)) => {
                    let left = REVEAL_TIME.saturating_sub(t.elapsed()).as_secs();
                    f.render_widget(
                        Paragraph::new(Text::from(s.as_str()))
                            .style(Style::new().fg(WARN).add_modifier(Modifier::BOLD))
                            .wrap(Wrap { trim: false }),
                        Rect { height: inner.height.saturating_sub(2), ..inner },
                    );
                    f.render_widget(
                        Paragraph::new(Span::styled(format!("{left} 秒后自动隐藏"), Style::new().fg(DIM))),
                        Rect { y: inner.bottom().saturating_sub(2), height: 1, ..inner },
                    );
                    dialog_buttons(f, app, inner.bottom().saturating_sub(1), inner.x, &[("隐藏 Esc", DBtn::Cancel)]);
                }
            }
        }
        Dialog::Info { title, body, .. } => {
            let lines = body.lines().count() as u16;
            let r = centered(area, 84, (lines + 5).max(7));
            let inner = dialog_frame(f, r, title);
            f.render_widget(
                Paragraph::new(body.clone()).wrap(Wrap { trim: false }),
                Rect { height: inner.height.saturating_sub(2), ..inner },
            );
            dialog_buttons(f, app, inner.bottom().saturating_sub(1), inner.x, &[("确定 Enter", DBtn::Ok)]);
        }
        Dialog::Prompt { title, input, .. } => {
            let r = centered(area, 64, 6);
            let inner = dialog_frame(f, r, title);
            field(f, app, inner.x, inner.y + 1, inner.width, "", input, true, None);
            dialog_buttons(f, app, inner.bottom().saturating_sub(1), inner.x, &[("确定 Enter", DBtn::Ok), ("取消 Esc", DBtn::Cancel)]);
        }
        Dialog::ChangePassword { fields, focus, error } => {
            let r = centered(area, 64, 10);
            let inner = dialog_frame(f, r, "修改口令");
            let labels = ["当前口令　：", "新口令　　：", "再输入一次："];
            for (i, l) in labels.iter().enumerate() {
                field(f, app, inner.x, inner.y + i as u16 * 2, inner.width, l, &fields[i], *focus == i, Some(i));
            }
            if let Some(e) = error {
                f.render_widget(Paragraph::new(Span::styled(e.clone(), Style::new().fg(BAD))), Rect { y: inner.y + 6, height: 1, ..inner });
            }
            dialog_buttons(f, app, inner.bottom().saturating_sub(1), inner.x, &[("修改 Enter", DBtn::Ok), ("取消 Esc", DBtn::Cancel)]);
        }
        Dialog::Trust { pattern, lines, any } => {
            let h = (lines.len() as u16 + 7).min(area.height.saturating_sub(2));
            let r = centered(area, 96, h);
            let inner = dialog_frame(f, r, &format!("信任新指纹：{pattern}"));
            let mut text: Vec<Line> = vec![
                Line::raw("如果你确认这些主机刚刚重装过系统或更换了证书，选择 [信任]。旧记录会被清除，下次连接时记录新指纹。"),
                Line::raw(""),
            ];
            text.extend(lines.iter().map(|l| Line::raw(l.clone())));
            f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), Rect { height: inner.height.saturating_sub(2), ..inner });
            let btns: &[(&str, DBtn)] =
                if *any { &[("信任 y", DBtn::Ok), ("取消 n", DBtn::Cancel)] } else { &[("关闭", DBtn::Cancel)] };
            dialog_buttons(f, app, inner.bottom().saturating_sub(1), inner.x, btns);
        }
    }
    app.dialog = Some(dialog);
}

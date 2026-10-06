//! PassManager 管理界面（ratatui，键盘 + 鼠标）。
//!
//! 按需运行、用完即退：解锁状态由服务保持。

pub mod agents;
mod app;
pub mod input;
mod ui;

use std::io::stdout;
use std::process::ExitCode;
use std::time::Duration;

use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture, Event, KeyEventKind,
};
use ratatui::crossterm::execute;

pub use app::Mode;
use app::{App, Dialog};

fn enter() -> ratatui::DefaultTerminal {
    let t = ratatui::init();
    let _ = execute!(stdout(), EnableMouseCapture, EnableBracketedPaste);
    t
}

fn leave() {
    let _ = execute!(stdout(), DisableMouseCapture, DisableBracketedPaste);
    ratatui::restore();
}

pub fn run(mode: Mode) -> ExitCode {
    if let Err(why) = pm_platform::tty::require_human_terminal() {
        eprintln!("PassManager：{why}");
        return ExitCode::from(1);
    }
    pm_platform::process::harden_process();
    let mut app = App::new(mode);
    let mut terminal = enter();
    loop {
        if terminal.draw(|f| ui::draw(f, &mut app)).is_err() {
            break;
        }
        if app.quit {
            break;
        }
        if let Some(cmd) = app.run_external.take() {
            leave();
            println!("\n运行：{}\n", cmd.join(" "));
            let st = std::process::Command::new(&cmd[0]).args(&cmd[1..]).env_remove("PSModulePath").status();
            if let Err(e) = st {
                eprintln!("无法运行：{e}");
            }
            println!("\n按回车返回 PassManager……");
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s);
            terminal = enter();
            let _ = terminal.clear();
            app.after_external();
            continue;
        }
        // 登录前先渲染"正在验证"再阻塞调用。
        if let Ok(true) = event::poll(Duration::from_millis(250)) {
            match event::read() {
                Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => {
                    let logging_in = matches!(app.dialog, Some(Dialog::Login { .. })) && k.code == event::KeyCode::Enter;
                    if logging_in {
                        let _ = terminal.draw(|f| {
                            ui::draw(f, &mut app);
                            let a = f.area();
                            f.render_widget(
                                ratatui::widgets::Paragraph::new(" 正在验证口令（Argon2id）…… ")
                                    .style(ratatui::style::Style::new().bg(ratatui::style::Color::Yellow).fg(ratatui::style::Color::Black)),
                                ratatui::layout::Rect { x: a.x, y: a.bottom().saturating_sub(1), width: a.width.min(40), height: 1 },
                            );
                        });
                    }
                    app.on_key(k);
                }
                Ok(Event::Mouse(m)) => app.on_mouse(m),
                Ok(Event::Paste(s)) => app.on_paste(&s),
                _ => {}
            }
        }
        app.tick();
    }
    leave();
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    use super::app::*;
    use super::*;

    fn buffer_text(t: &Terminal<TestBackend>) -> String {
        let b = t.backend().buffer();
        let mut s = String::new();
        for y in 0..b.area.height {
            let mut x = 0;
            while x < b.area.width {
                let sym = b[(x, y)].symbol();
                s.push_str(sym);
                // 宽字符占两列，跳过后一列的占位格。
                x += unicode_width::UnicodeWidthStr::width(sym).max(1) as u16;
            }
            s.push('\n');
        }
        s
    }

    fn fake_app() -> App {
        let mut app = App::new(Mode::Full);
        app.dialog = None;
        app.status = Some(pm_proto::StatusView { initialized: true, locked: false, level: 2, mode: "system".into(), ready: true });
        app.entries = vec![pm_proto::EntryView {
            name: "github".into(),
            domains: vec!["*.github.com".into()],
            note: "CI token".into(),
            self_signed: false,
            auto_accept_host_key: false,
            private_key: false,
            created: 0,
            updated: 0,
        }];
        app
    }

    #[test]
    fn renders_and_mouse_hits() {
        let mut app = fake_app();
        // 没有 client 时只显示登录框；这里模拟已连接的界面需要绕过 client 检查：直接绘制各页。
        let mut term = Terminal::new(TestBackend::new(110, 30)).unwrap();
        // 登录对话框
        let mut login = App::new(Mode::Unlock);
        term.draw(|f| ui::draw(f, &mut login)).unwrap();
        assert!(buffer_text(&term).contains("解锁 PassManager"));

        // 表单对话框：键盘输入与鼠标点击复选框
        app.dialog = Some(Dialog::Entry(Box::new(EntryForm::new())));
        term.draw(|f| ui::draw(f, &mut app)).unwrap();
        let txt = buffer_text(&term);
        assert!(txt.contains("新增条目"));
        for c in "srv1".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let field4 = app.hits.iter().find(|(_, h)| *h == Hit::Field(3)).map(|(r, _)| *r).unwrap();
        app.on_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: field4.x + 1,
            row: field4.y,
            modifiers: KeyModifiers::NONE,
        });
        match &app.dialog {
            Some(Dialog::Entry(f)) => {
                assert_eq!(f.secret.value(), "srv1");
                assert!(f.self_signed);
            }
            _ => panic!("form closed"),
        }
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.dialog.is_none());
    }
}

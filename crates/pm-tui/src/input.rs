//! 单行文本输入框（支持遮罩，用于口令与密钥）。

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use unicode_width::UnicodeWidthStr;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct TextInput {
    value: Zeroizing<String>,
    /// 光标位置（字符索引）。
    cursor: usize,
    pub masked: bool,
    /// 允许输入换行（用于粘贴多行私钥：粘贴时换行会被保留）。
    pub multiline: bool,
}

impl TextInput {
    pub fn new(masked: bool) -> Self {
        Self { masked, ..Default::default() }
    }

    pub fn with_value(v: &str, masked: bool) -> Self {
        let mut t = Self::new(masked);
        t.set(v);
        t
    }

    pub fn set(&mut self, v: &str) {
        self.value = Zeroizing::new(v.to_string());
        self.cursor = v.chars().count();
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn clear(&mut self) {
        self.set("");
    }

    fn byte_idx(&self, ch: usize) -> usize {
        self.value.char_indices().nth(ch).map(|(i, _)| i).unwrap_or(self.value.len())
    }

    pub fn insert_str(&mut self, s: &str) {
        let s: String = if self.multiline { s.replace("\r\n", "\n").replace('\r', "\n") } else { s.replace(['\r', '\n'], "") };
        let i = self.byte_idx(self.cursor);
        self.value.insert_str(i, &s);
        self.cursor += s.chars().count();
    }

    /// 处理按键；返回是否被消费。
    pub fn handle(&mut self, k: KeyEvent) -> bool {
        match k.code {
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) && !k.modifiers.contains(KeyModifiers::ALT) => {
                let i = self.byte_idx(self.cursor);
                self.value.insert(i, c);
                self.cursor += 1;
            }
            KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => self.clear(),
            KeyCode::Backspace if self.cursor > 0 => {
                let i = self.byte_idx(self.cursor - 1);
                self.value.remove(i);
                self.cursor -= 1;
            }
            KeyCode::Delete if self.cursor < self.value.chars().count() => {
                let i = self.byte_idx(self.cursor);
                self.value.remove(i);
            }
            KeyCode::Left if self.cursor > 0 => self.cursor -= 1,
            KeyCode::Right if self.cursor < self.value.chars().count() => self.cursor += 1,
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.value.chars().count(),
            KeyCode::Enter if self.multiline && k.modifiers.contains(KeyModifiers::ALT) => self.insert_str("\n"),
            _ => return false,
        }
        true
    }

    /// 显示文本（遮罩时用 • 代替；多行时显示行数）。
    pub fn display(&self) -> String {
        if self.masked {
            let n = self.value.chars().count();
            if self.value.contains('\n') {
                format!("•••••• （{} 行，{} 个字符）", self.value.lines().count(), n)
            } else {
                "•".repeat(n.min(64))
            }
        } else {
            self.value.replace('\n', "⏎")
        }
    }

    /// 光标在显示文本中的列宽。
    pub fn cursor_col(&self) -> u16 {
        if self.masked {
            if self.value.contains('\n') { self.display().width() as u16 } else { self.cursor.min(64) as u16 }
        } else {
            let before: String = self.value.chars().take(self.cursor).collect();
            before.replace('\n', "⏎").width() as u16
        }
    }
}

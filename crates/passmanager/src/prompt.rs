//! 终端交互（安装程序用）。

use std::io::{BufRead, Write};

use zeroize::Zeroizing;

pub fn confirm(question: &str, default_yes: bool) -> bool {
    print!("{question} {} ", if default_yes { "[Y/n]" } else { "[y/N]" });
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    if std::io::stdin().lock().read_line(&mut s).is_err() {
        return false;
    }
    let s = s.trim().to_lowercase();
    if s.is_empty() { default_yes } else { s == "y" || s == "yes" || s == "是" }
}

pub fn line(question: &str) -> String {
    print!("{question} ");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    s.trim().to_string()
}

pub fn press_enter(msg: &str) {
    let _ = line(&format!("{msg}（按回车继续）"));
}

/// 口令强度描述（zxcvbn 0~4）。
pub fn strength(pw: &str) -> (u8, &'static str) {
    let score = zxcvbn::zxcvbn(pw, &[]).score() as u8;
    let label = match score {
        0 => "非常弱",
        1 => "弱",
        2 => "一般",
        3 => "强",
        _ => "很强",
    };
    (score, label)
}

/// 设置新口令：输入两次，至少 8 位，强度不足时只警告。
pub fn new_password() -> Option<Zeroizing<String>> {
    loop {
        let p1 = Zeroizing::new(rpassword::prompt_password("设置 PassManager 口令（至少 8 个字符）：").ok()?);
        if p1.chars().count() < 8 {
            println!("口令至少需要 8 个字符。");
            continue;
        }
        let (score, label) = strength(&p1);
        println!("口令强度：{label}");
        if score < 3
            && !confirm("口令强度不足。只有在库文件和设备密钥同时被偷时才依赖口令，但仍建议使用更强的口令。继续使用这个口令吗？", false)
        {
            continue;
        }
        let p2 = Zeroizing::new(rpassword::prompt_password("再输入一次：").ok()?);
        if *p1 != *p2 {
            println!("两次输入不一致，请重试。");
            continue;
        }
        return Some(p1);
    }
}

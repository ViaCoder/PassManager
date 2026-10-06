//! sudoers 解析（Linux / macOS 共用）。
//!
//! 只做本工具需要的判断：
//! - 适用于某用户的规则中是否含 `NOPASSWD:`；
//! - 是否存在 `Defaults ... !authenticate`。
//!
//! 修复方式：把 `NOPASSWD:` 改为 `PASSWD:`（保留授权，只要求输入口令）；注释掉 `!authenticate` 行。
//! 写回前用 `visudo -c -f` 校验，校验失败绝不写入。

use std::path::{Path, PathBuf};
use std::process::Command;

pub const MAIN: &str = "/etc/sudoers";
pub const DROPIN_DIR: &str = "/etc/sudoers.d";
pub const HARDENING_FILE: &str = "/etc/sudoers.d/zz-passmanager-hardening";
pub const HARDENING_CONTENT: &str = "# Managed by PassManager: sudo tickets are per-terminal and expire after 5 minutes.\nDefaults timestamp_type=tty\nDefaults timestamp_timeout=5\n";
pub const HARDENING_CONTENT_LEGACY: &str = "# Managed by PassManager: sudo tickets are per-terminal and expire after 5 minutes.\nDefaults tty_tickets\nDefaults timestamp_timeout=5\n";

/// 一个 sudoers 文件中的问题行。
#[derive(Debug, Clone)]
pub struct Issue {
    pub file: PathBuf,
    pub line_no: usize,
    pub line: String,
    pub kind: IssueKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    NoPasswd,
    NotAuthenticate,
}

/// 用户的身份信息（用于判断规则是否适用）。
pub struct Who<'a> {
    pub user: &'a str,
    pub uid: u32,
    pub groups: &'a [(String, u32)],
}

/// 列出 sudoers 主文件及其包含的文件（按 sudo 规则：includedir 中跳过含 '.' 或以 '~' 结尾的文件）。
pub fn files() -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from(MAIN)];
    let mut i = 0;
    while i < out.len() {
        let Ok(text) = std::fs::read_to_string(&out[i]) else {
            i += 1;
            continue;
        };
        for line in logical_lines(&text) {
            let t = line.1.trim();
            let (dir, file) = if let Some(d) = t.strip_prefix("#includedir").or_else(|| t.strip_prefix("@includedir")) {
                (Some(d.trim().to_string()), None)
            } else if let Some(f) = t.strip_prefix("#include ").or_else(|| t.strip_prefix("@include ")) {
                (None, Some(f.trim().to_string()))
            } else {
                (None, None)
            };
            if let Some(d) = dir
                && let Ok(rd) = std::fs::read_dir(&d)
            {
                let mut names: Vec<PathBuf> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        let n = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                        !n.contains('.') && !n.ends_with('~') && p.is_file()
                    })
                    .collect();
                names.sort();
                for n in names {
                    if !out.contains(&n) {
                        out.push(n);
                    }
                }
            }
            if let Some(f) = file {
                let p = PathBuf::from(f);
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
        i += 1;
    }
    out
}

/// 合并以 `\` 结尾的续行，返回 (起始行号, 内容)。
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 0;
    for (i, l) in text.lines().enumerate() {
        if cur.is_empty() {
            start = i;
        }
        if let Some(stripped) = l.strip_suffix('\\') {
            cur.push_str(stripped);
            cur.push(' ');
        } else {
            cur.push_str(l);
            out.push((start, std::mem::take(&mut cur)));
        }
    }
    if !cur.is_empty() {
        out.push((start, cur));
    }
    out
}

fn is_directive_comment(t: &str) -> bool {
    t.starts_with("#include") || t.starts_with("#includedir")
}

/// 规则的用户列表部分是否适用于该用户。
fn applies(user_list: &str, who: &Who) -> bool {
    user_list.split(',').map(str::trim).any(|item| {
        let (neg, item) = match item.strip_prefix('!') {
            Some(x) => (true, x.trim()),
            None => (false, item),
        };
        if neg {
            return false;
        }
        if item == "ALL" || item == who.user {
            return true;
        }
        if let Some(uid) = item.strip_prefix('#') {
            return uid.parse::<u32>().ok() == Some(who.uid);
        }
        if let Some(g) = item.strip_prefix("%#") {
            return g.parse::<u32>().is_ok_and(|gid| who.groups.iter().any(|(_, x)| *x == gid));
        }
        if let Some(g) = item.strip_prefix('%') {
            let g = g.trim_matches('"');
            return who.groups.iter().any(|(n, _)| n == g);
        }
        // User_Alias（全大写）：保守地视为适用。
        item.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    })
}

pub fn scan(who: &Who) -> Vec<Issue> {
    let mut issues = Vec::new();
    for f in files() {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        for (no, line) in logical_lines(&text) {
            let t = line.trim();
            if t.is_empty() || (t.starts_with('#') && !is_directive_comment(t)) || is_directive_comment(t) {
                continue;
            }
            if t.starts_with('@') {
                continue;
            }
            if t.starts_with("Defaults") {
                if t.contains("!authenticate") {
                    issues.push(Issue { file: f.clone(), line_no: no, line: line.clone(), kind: IssueKind::NotAuthenticate });
                }
                continue;
            }
            if t.starts_with("User_Alias")
                || t.starts_with("Runas_Alias")
                || t.starts_with("Host_Alias")
                || t.starts_with("Cmnd_Alias")
                || t.starts_with("Cmd_Alias")
            {
                continue;
            }
            if !t.contains("NOPASSWD:") {
                continue;
            }
            let user_list = t.split_whitespace().next().unwrap_or("");
            if applies(user_list, who) {
                issues.push(Issue { file: f.clone(), line_no: no, line: line.clone(), kind: IssueKind::NoPasswd });
            }
        }
    }
    issues
}

/// 用 `visudo -c -f` 校验一个文件。
pub fn validate(path: &Path) -> bool {
    Command::new("visudo").arg("-c").arg("-q").arg("-f").arg(path).status().map(|s| s.success()).unwrap_or(false)
}

/// 修复问题行。返回日志。
pub fn fix(issues: &[Issue], backup: &dyn Fn(&str) -> std::io::Result<()>) -> Vec<String> {
    let mut log = Vec::new();
    let mut by_file: std::collections::BTreeMap<PathBuf, Vec<&Issue>> = Default::default();
    for i in issues {
        by_file.entry(i.file.clone()).or_default().push(i);
    }
    for (file, list) in by_file {
        let Ok(text) = std::fs::read_to_string(&file) else { continue };
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        for i in &list {
            // 续行时问题可能出现在后续物理行，逐行处理直到续行结束。
            let mut n = i.line_no;
            while let Some(l) = lines.get_mut(n) {
                let cont = l.ends_with('\\');
                match i.kind {
                    IssueKind::NoPasswd => *l = l.replace("NOPASSWD:", "PASSWD:"),
                    IssueKind::NotAuthenticate => {
                        if n == i.line_no {
                            *l = format!("# disabled by PassManager: {l}");
                        } else {
                            *l = format!("# {l}");
                        }
                    }
                }
                if !cont {
                    break;
                }
                n += 1;
            }
        }
        let mut new = lines.join("\n");
        new.push('\n');
        let tmp = file.with_file_name(format!(".{}.pm-tmp", file.file_name().unwrap().to_string_lossy()));
        if std::fs::write(&tmp, &new).is_err() {
            log.push(format!("无法写入临时文件 {}", tmp.display()));
            continue;
        }
        if !validate(&tmp) {
            let _ = std::fs::remove_file(&tmp);
            log.push(format!("{} 修改后未通过 visudo 校验，已放弃修改", file.display()));
            continue;
        }
        if let Err(e) = backup(&file.to_string_lossy()) {
            let _ = std::fs::remove_file(&tmp);
            log.push(format!("备份 {} 失败：{e}，已放弃修改", file.display()));
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o440));
        }
        match std::fs::rename(&tmp, &file) {
            Ok(_) => log.push(format!("已修改 {}（{} 处）", file.display(), list.len())),
            Err(e) => log.push(format!("替换 {} 失败：{e}", file.display())),
        }
    }
    log
}

/// 检查加固 drop-in 文件是否存在且内容正确。
pub fn hardening_dropin_ok() -> bool {
    std::fs::read_to_string(HARDENING_FILE).map(|s| s == HARDENING_CONTENT || s == HARDENING_CONTENT_LEGACY).unwrap_or(false)
}

/// 写入加固 drop-in（新版 sudo 用 timestamp_type=tty，旧版退回 tty_tickets）。
pub fn write_hardening_dropin() -> Result<(), String> {
    let _ = std::fs::create_dir_all(DROPIN_DIR);
    for content in [HARDENING_CONTENT, HARDENING_CONTENT_LEGACY] {
        let tmp = PathBuf::from(format!("{DROPIN_DIR}/.zz-passmanager-hardening.pm-tmp"));
        std::fs::write(&tmp, content).map_err(|e| e.to_string())?;
        if validate(&tmp) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o440));
            }
            return std::fs::rename(&tmp, HARDENING_FILE).map_err(|e| e.to_string());
        }
        let _ = std::fs::remove_file(&tmp);
    }
    Err("visudo 校验失败".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_matching() {
        let groups = vec![("sudo".to_string(), 27u32), ("han".to_string(), 1000)];
        let who = Who { user: "han", uid: 1000, groups: &groups };
        assert!(applies("han", &who));
        assert!(applies("%sudo", &who));
        assert!(applies("%#27", &who));
        assert!(applies("#1000", &who));
        assert!(applies("ALL", &who));
        assert!(applies("ADMINS", &who));
        assert!(!applies("bob", &who));
        assert!(!applies("%wheel", &who));
        let ll = logical_lines("a \\\nb\nc\n");
        assert_eq!(ll, vec![(0, "a  b".to_string()), (2, "c".to_string())]);
    }
}

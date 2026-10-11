//! 把 PassManager 的使用规则写入 AI Agent 的全局指令文件（`enroll` 时默认写入，`--no-instructions` 跳过；
//! `unenroll` / `uninstall` 时移除）。
//!
//! - 只写在 `<!-- passmanager:begin -->` 与 `<!-- passmanager:end -->` 之间：已有块时原地更新，不会重复；
//! - 修改前把原文件保存为 `<文件>.passmanager.bak`；
//! - 标记损坏（只有开始没有结束等）时不修改文件，报告错误。

use std::path::{Path, PathBuf};

use pm_proto::agent_text::{BEGIN, END};

/// 支持全局指令文件的 Agent：（适配器 ID，名称，相对主目录的文件）。
pub const FILES: &[(&str, &str, &str)] = &[
    ("claude", "Claude Code", ".claude/CLAUDE.md"),
    ("codex", "Codex CLI", ".codex/AGENTS.md"),
    ("gemini", "Gemini CLI", ".gemini/GEMINI.md"),
    ("windsurf", "Windsurf", ".codeium/windsurf/memories/global_rules.md"),
];

#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Added,
    Updated,
    Unchanged,
}

/// 找到块的位置：Ok(None) 表示没有；标记不成对时报错。
fn span(text: &str) -> Result<Option<(usize, usize)>, String> {
    let b = text.find(BEGIN);
    let e = text.find(END);
    match (b, e) {
        (None, None) => Ok(None),
        (Some(b), Some(e)) if e > b => {
            let rest = &text[e + END.len()..];
            if rest.contains(BEGIN) || rest.contains(END) {
                return Err("有多个 PassManager 块，请手动整理".into());
            }
            let end = e + END.len() + usize::from(rest.starts_with('\n'));
            Ok(Some((b, end)))
        }
        _ => Err("PassManager 块的标记不完整，请手动修复".into()),
    }
}

/// 计算插入或更新后的内容。
pub fn upsert_text(old: &str, block: &str) -> Result<(String, Change), String> {
    let block = if block.ends_with('\n') { block.to_string() } else { format!("{block}\n") };
    match span(old)? {
        Some((b, e)) => {
            let new = format!("{}{}{}", &old[..b], block, &old[e..]);
            let c = if new == old { Change::Unchanged } else { Change::Updated };
            Ok((new, c))
        }
        None if old.trim().is_empty() => Ok((block, Change::Added)),
        None => {
            let sep = if old.ends_with("\n\n") {
                ""
            } else if old.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            Ok((format!("{old}{sep}{block}"), Change::Added))
        }
    }
}

/// 计算移除块后的内容（None 表示没有块）。
pub fn remove_text(old: &str) -> Result<Option<String>, String> {
    let Some((b, e)) = span(old)? else { return Ok(None) };
    let mut head = old[..b].to_string();
    // 去掉插入时加的空行。
    if head.ends_with("\n\n") {
        head.pop();
    }
    Ok(Some(format!("{head}{}", &old[e..])))
}

fn write_with_backup(path: &Path, old: Option<&str>, new: &str) -> Result<(), String> {
    if let Some(old) = old {
        let bak = PathBuf::from(format!("{}.passmanager.bak", path.display()));
        std::fs::write(&bak, old).map_err(|e| format!("备份 {} 失败：{e}", path.display()))?;
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("创建 {} 失败：{e}", d.display()))?;
    }
    let tmp = PathBuf::from(format!("{}.passmanager.tmp", path.display()));
    std::fs::write(&tmp, new).map_err(|e| format!("写入 {} 失败：{e}", path.display()))?;
    #[cfg(unix)]
    if let Ok(md) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, md.permissions());
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("写入 {} 失败：{e}", path.display()))
}

/// 插入或更新一个文件中的块。
pub fn upsert(path: &Path, block: &str) -> Result<Change, String> {
    let old = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("读取 {} 失败：{e}", path.display())),
    };
    let (new, change) = upsert_text(old.as_deref().unwrap_or(""), block)?;
    if change != Change::Unchanged {
        write_with_backup(path, old.as_deref(), &new)?;
    }
    Ok(change)
}

/// 移除一个文件中的块；返回是否有改动。移除后文件为空时删除文件。
pub fn remove(path: &Path) -> Result<bool, String> {
    let Ok(old) = std::fs::read_to_string(path) else { return Ok(false) };
    let Some(new) = remove_text(&old)? else { return Ok(false) };
    if new.trim().is_empty() {
        std::fs::write(PathBuf::from(format!("{}.passmanager.bak", path.display())), &old).map_err(|e| e.to_string())?;
        std::fs::remove_file(path).map_err(|e| format!("删除 {} 失败：{e}", path.display()))?;
    } else {
        write_with_backup(path, Some(&old), &new)?;
    }
    Ok(true)
}

fn home() -> PathBuf {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

/// 为检测到的 Agent 写入规则，返回每个文件的结果（名称，路径，结果）。
pub fn install_detected(block: &str) -> Vec<(&'static str, PathBuf, Result<Change, String>)> {
    let h = home();
    FILES
        .iter()
        .filter(|(id, _, _)| pm_tui::agents::ADAPTERS.iter().any(|a| a.id == *id && a.detected()))
        .map(|(_, name, rel)| {
            let p = h.join(rel);
            let r = upsert(&p, block);
            (*name, p, r)
        })
        .collect()
}

/// 从所有支持的文件中移除规则（不管是否检测到对应的 Agent）。
pub fn remove_all() -> Vec<(&'static str, PathBuf, Result<bool, String>)> {
    let h = home();
    FILES
        .iter()
        .map(|(_, name, rel)| {
            let p = h.join(rel);
            let r = remove(&p);
            (*name, p, r)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pm_proto::agent_text::{Lang, instruction_block};

    #[test]
    fn insert_update_remove_is_idempotent() {
        let b1 = instruction_block(Lang::En);
        // 空文件、已有内容（有无结尾换行）。
        let (a, c) = upsert_text("", &b1).unwrap();
        assert_eq!((a.as_str(), c), (b1.as_str(), Change::Added));
        for user in ["# My rules\n- be nice\n", "# My rules\n- be nice", "# My rules\n\n"] {
            let (t, c) = upsert_text(user, &b1).unwrap();
            assert_eq!(c, Change::Added);
            assert!(t.starts_with(user.trim_end()) && t.contains(&b1));
            let (t2, c2) = upsert_text(&t, &b1).unwrap();
            assert_eq!((t2.as_str(), c2), (t.as_str(), Change::Unchanged), "重复写入不变");
            assert_eq!(t2.matches(BEGIN).count(), 1);
            // 新版本原地更新，块后面的用户内容保留。
            let with_after = format!("{t}\n# after\n");
            let cur = format!("instructions v{}", pm_proto::agent_text::INSTRUCTIONS_VERSION);
            let b2 = b1.replace(&cur, "instructions v999");
            let (t3, c3) = upsert_text(&with_after, &b2).unwrap();
            assert_eq!(c3, Change::Updated);
            assert!(t3.contains("v999") && !t3.contains(&cur) && t3.ends_with("# after\n") && t3.matches(BEGIN).count() == 1);
            // 移除后回到用户原来的内容。
            let removed = remove_text(&t).unwrap().unwrap();
            assert_eq!(removed.trim_end(), user.trim_end());
        }
        assert_eq!(remove_text("no block here").unwrap(), None);
        // 标记损坏：不修改。
        assert!(upsert_text(&format!("x\n{BEGIN}\nhalf"), &b1).is_err());
        assert!(upsert_text(&format!("{END}\n{BEGIN}"), &b1).is_err());
        assert!(upsert_text(&format!("{b1}{b1}"), &b1).is_err());
        assert!(remove_text(&format!("{BEGIN} only")).is_err());
    }

    #[test]
    fn files_backup_and_removal() {
        let d = std::env::temp_dir().join(format!("pm-instr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let b = instruction_block(Lang::En);
        // 新文件（含上级目录）。
        let f = d.join(".claude/CLAUDE.md");
        assert_eq!(upsert(&f, &b).unwrap(), Change::Added);
        assert_eq!(upsert(&f, &b).unwrap(), Change::Unchanged);
        assert!(!PathBuf::from(format!("{}.passmanager.bak", f.display())).exists(), "新文件没有原内容可备份");
        assert!(remove(&f).unwrap());
        assert!(!f.exists(), "只有块的文件移除后删除");
        // 已有文件：备份原内容。
        let g = d.join(".codex/AGENTS.md");
        std::fs::create_dir_all(g.parent().unwrap()).unwrap();
        std::fs::write(&g, "# team rules\n").unwrap();
        assert_eq!(upsert(&g, &b).unwrap(), Change::Added);
        let bak = PathBuf::from(format!("{}.passmanager.bak", g.display()));
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "# team rules\n");
        assert!(remove(&g).unwrap());
        assert_eq!(std::fs::read_to_string(&g).unwrap(), "# team rules\n");
        assert!(!remove(&g).unwrap(), "没有块时不改动");
        assert!(!remove(&d.join("missing.md")).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }
}

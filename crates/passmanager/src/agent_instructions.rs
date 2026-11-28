//! 删除旧版本（≤ 0.3.11-rc.28）写进 AI Agent 全局指令文件的 PassManager 规则块。
//!
//! 0.3.11-rc.29 起 Agent 只从 MCP 了解 PassManager（服务器说明、工具描述、lookup 的 how、错误的 Next:），
//! 不再往 CLAUDE.md、AGENTS.md 等文件里写规则：常驻的规则会过度影响 Agent 的判断。
//!
//! - 已注册的客户端第一次运行会检查自动更新的命令时（自动更新换上新程序后的第一条命令就是），
//!   调用 [`migrate_once`] 删除旧块，然后在配置目录里留下标记，以后不再检查；`enroll`、`unenroll`、`uninstall` 也会删除；
//! - 只删除 `<!-- passmanager:begin -->` 与 `<!-- passmanager:end -->` 之间的内容，文件里用户自己写的部分保持不变；
//! - 不留备份（用户 2026-11-28："no need backup of passmanager memory"）：删掉的只是 PassManager 自己写的块；
//! - 标记损坏（只有开始没有结束等）时不修改文件，报告错误。

use std::path::{Path, PathBuf};

use pm_proto::agent_text::{BEGIN, END};

/// 旧版本写过规则块的文件：（名称，相对主目录的文件）。
pub const FILES: &[(&str, &str)] = &[
    ("Claude Code", ".claude/CLAUDE.md"),
    ("Codex CLI", ".codex/AGENTS.md"),
    ("Gemini CLI", ".gemini/GEMINI.md"),
    ("Windsurf", ".codeium/windsurf/memories/global_rules.md"),
];

/// 迁移完成的标记文件（放在客户端配置目录里）。
pub const DONE_FILE: &str = "instructions-removed";

/// 找到块的位置：Ok(None) 表示没有；标记不成对时报错。
fn span(text: &str) -> Result<Option<(usize, usize)>, String> {
    // 开始与结束标记第一次出现的位置
    let b = text.find(BEGIN);
    let e = text.find(END);
    match (b, e) {
        // 两个都没有：没有块
        (None, None) => Ok(None),
        // 成对且顺序正确
        (Some(b), Some(e)) if e > b => {
            // 结束标记之后不能再有标记（多个块时不猜，交给用户）
            let rest = &text[e + END.len()..];
            if rest.contains(BEGIN) || rest.contains(END) {
                return Err("有多个 PassManager 块，请手动整理".into());
            }
            // 块的结尾包含结束标记后面的一个换行
            let end = e + END.len() + usize::from(rest.starts_with('\n'));
            Ok(Some((b, end)))
        }
        // 只有一个标记，或者顺序反了
        _ => Err("PassManager 块的标记不完整，请手动修复".into()),
    }
}

/// 计算移除块后的内容（None 表示没有块）。
pub fn remove_text(old: &str) -> Result<Option<String>, String> {
    // 没有块：不改
    let Some((b, e)) = span(old)? else { return Ok(None) };
    // 块前面的部分
    let mut head = old[..b].to_string();
    // 去掉插入时加的空行
    if head.ends_with("\n\n") {
        head.pop();
    }
    // 块前面 + 块后面
    Ok(Some(format!("{head}{}", &old[e..])))
}

/// 移除一个文件中的块；返回是否有改动。移除后文件为空时删除文件。不留备份。
pub fn remove(path: &Path) -> Result<bool, String> {
    // 文件不存在或读不了：没有可删的
    let Ok(old) = std::fs::read_to_string(path) else { return Ok(false) };
    // 没有块：不改
    let Some(new) = remove_text(&old)? else { return Ok(false) };
    if new.trim().is_empty() {
        // 文件里只有这个块：删除文件
        std::fs::remove_file(path).map_err(|e| format!("删除 {} 失败：{e}", path.display()))?;
    } else {
        // 先写临时文件，保留原来的权限，再原子地换过去
        let tmp = PathBuf::from(format!("{}.passmanager.tmp", path.display()));
        std::fs::write(&tmp, &new).map_err(|e| format!("写入 {} 失败：{e}", path.display()))?;
        #[cfg(unix)]
        if let Ok(md) = std::fs::metadata(path) {
            let _ = std::fs::set_permissions(&tmp, md.permissions());
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("写入 {} 失败：{e}", path.display()))?;
    }
    Ok(true)
}

/// 主目录（HOME，Windows 上是 USERPROFILE）。
pub fn home() -> PathBuf {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

/// 从 `home` 下所有支持的文件中移除旧块，返回每个文件的结果（名称，路径，是否有改动）。
pub fn remove_all_in(home: &Path) -> Vec<(&'static str, PathBuf, Result<bool, String>)> {
    FILES
        .iter()
        .map(|(name, rel)| {
            // 每个文件单独处理，一个失败不影响其他文件
            let p = home.join(rel);
            let r = remove(&p);
            (*name, p, r)
        })
        .collect()
}

/// 从当前用户主目录下所有支持的文件中移除旧块（`enroll`、`unenroll`、`uninstall` 用）。
pub fn remove_all() -> Vec<(&'static str, PathBuf, Result<bool, String>)> {
    remove_all_in(&home())
}

/// 只做一次的迁移：配置目录 `config` 里还没有标记时删除 `home` 下的旧块并写下标记。
/// 返回每个有改动或出错的文件（没有改动的不列出）；已经迁移过时返回空列表。
pub fn migrate_once_in(config: &Path, home: &Path) -> Vec<(&'static str, PathBuf, Result<bool, String>)> {
    // 已经迁移过：什么都不做
    let done = config.join(DONE_FILE);
    if done.exists() {
        return Vec::new();
    }
    // 删除旧块，只留下有改动或出错的结果
    let out: Vec<_> = remove_all_in(home).into_iter().filter(|(_, _, r)| !matches!(r, Ok(false))).collect();
    // 写下标记（标记损坏的文件也不再重试：错误只报告这一次，用户可以手动整理）
    let _ = pm_platform::paths::write_atomic(&done, b"1\n", 0o600);
    out
}

/// 运行时调用：已注册的客户端（有配置目录）迁移一次，结果写到标准错误输出（MCP 的标准输出不受影响）。
pub fn migrate_once() {
    // 只处理已经注册的客户端：规则块只在注册时写过
    let d = crate::remote::dir();
    if crate::remote::load_in(&d).is_none() {
        return;
    }
    for (name, path, r) in migrate_once_in(&d, &home()) {
        match r {
            Ok(_) => {
                eprintln!("PassManager：已从 {name} 的全局指令文件删除旧的使用规则（{}）；Agent 改为只用 MCP 的说明。", path.display())
            }
            Err(e) => eprintln!("PassManager：没能从 {name} 的全局指令文件删除旧的使用规则（{e}）。"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 旧版本写入的块（形状与 ≤ rc.28 的 instruction_block 相同）。
    fn old_block() -> String {
        format!("{BEGIN}\n## PassManager (agent instructions v7)\n\n- Use the PassManager MCP tools.\n{END}\n")
    }

    /// 测试用的临时目录（每个测试一个，避免并行冲突）。
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pm-instr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn remove_text_restores_user_content() {
        let b = old_block();
        // 块在前（旧版本写在空文件里或用户内容前）、块在后（追加在用户内容后面，中间有空行）
        assert_eq!(remove_text(&b).unwrap().unwrap(), "");
        assert_eq!(remove_text(&format!("{b}# after\n")).unwrap().unwrap(), "# after\n");
        for user in ["# My rules\n- be nice\n", "# My rules\n\n"] {
            let sep = if user.ends_with("\n\n") { "" } else { "\n" };
            let t = format!("{user}{sep}{b}");
            assert_eq!(remove_text(&t).unwrap().unwrap().trim_end(), user.trim_end());
        }
        assert_eq!(remove_text("no block here").unwrap(), None);
        // 标记损坏：不修改
        assert!(remove_text(&format!("{BEGIN} only")).is_err());
        assert!(remove_text(&format!("{END}\n{BEGIN}")).is_err());
        assert!(remove_text(&format!("{b}{b}")).is_err());
    }

    #[test]
    fn remove_deletes_empty_files_without_backup() {
        let d = tmp("rm");
        let b = old_block();
        // 只有块的文件：删除，不留备份
        let f = d.join(".claude/CLAUDE.md");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, &b).unwrap();
        assert!(remove(&f).unwrap());
        assert!(!f.exists());
        assert!(!PathBuf::from(format!("{}.passmanager.bak", f.display())).exists(), "不留备份");
        // 有用户内容的文件：只删块
        let g = d.join(".codex/AGENTS.md");
        std::fs::create_dir_all(g.parent().unwrap()).unwrap();
        std::fs::write(&g, format!("{b}# team rules\n")).unwrap();
        assert!(remove(&g).unwrap());
        assert_eq!(std::fs::read_to_string(&g).unwrap(), "# team rules\n");
        // 再删一次、不存在的文件：没有改动
        assert!(!remove(&g).unwrap());
        assert!(!remove(&d.join("missing.md")).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remove_all_in_covers_every_file() {
        let d = tmp("all");
        // 4 个文件都有旧块，其中一个有用户内容
        for (_, rel) in FILES {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, old_block()).unwrap();
        }
        std::fs::write(d.join(".claude/CLAUDE.md"), format!("# mine\n\n{}", old_block())).unwrap();
        let r = remove_all_in(&d);
        assert_eq!(r.len(), FILES.len());
        assert!(r.iter().all(|(_, _, x)| matches!(x, Ok(true))), "{r:?}");
        assert_eq!(std::fs::read_to_string(d.join(".claude/CLAUDE.md")).unwrap(), "# mine\n");
        assert!(!d.join(".codex/AGENTS.md").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn migrate_once_runs_only_once() {
        let d = tmp("mig");
        let (cfg, home) = (d.join("cfg"), d.join("home"));
        std::fs::create_dir_all(&cfg).unwrap();
        let f = home.join(".claude/CLAUDE.md");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, format!("# mine\n\n{}", old_block())).unwrap();
        // 第一次：删除旧块，只列出有改动的文件，写下标记
        let r = migrate_once_in(&cfg, &home);
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(matches!(r[0].2, Ok(true)) && r[0].0 == "Claude Code");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "# mine\n");
        assert!(cfg.join(DONE_FILE).exists());
        // 之后即使又出现旧块也不再动（只迁移一次，不跟用户手动加的内容作对）
        std::fs::write(&f, format!("# mine\n\n{}", old_block())).unwrap();
        assert!(migrate_once_in(&cfg, &home).is_empty());
        assert!(std::fs::read_to_string(&f).unwrap().contains(BEGIN));
        // 标记损坏的文件：报告一次错误，也写下标记
        let cfg2 = d.join("cfg2");
        std::fs::create_dir_all(&cfg2).unwrap();
        std::fs::write(&f, format!("{BEGIN} only")).unwrap();
        let r = migrate_once_in(&cfg2, &home);
        assert!(r.len() == 1 && r[0].2.is_err() && cfg2.join(DONE_FILE).exists(), "{r:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}

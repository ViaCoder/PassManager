//! 安全检查与账户加固（`PassManager harden`）。
//!
//! 直接对照推荐架构逐项检查：
//! - 禁用内置管理员（root / Administrator）；
//! - 日常使用"有管理员权限的普通账户"，每次提权都必须输入口令；
//! - Agent 永远不以提权状态运行；
//! - PassManager 自身的文件、目录、服务配置权限正确。
//!
//! 能安全自动修改的项直接修改（修改前备份），其余给出具体处理步骤。
//! **只有全部项都通过才能解锁。**

use serde::{Deserialize, Serialize};

use crate::paths::{InstallInfo, Layout, Mode};

#[cfg(unix)]
pub mod sudoers;
#[cfg(unix)]
pub(crate) mod unix_perm;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub ok: bool,
    /// 未通过时能否自动修改。
    pub auto_fix: bool,
    /// 问题说明。
    #[serde(default)]
    pub detail: String,
    /// 需要用户处理时的具体步骤。
    #[serde(default)]
    pub steps: String,
    /// 仅为建议：未通过时显示提示，但不阻止解锁。
    #[serde(default)]
    pub advisory: bool,
}

impl Finding {
    pub fn pass(id: &str, title: &str) -> Self {
        Self { id: id.into(), title: title.into(), ok: true, auto_fix: false, detail: String::new(), steps: String::new(), advisory: false }
    }

    pub fn fixable(id: &str, title: &str, detail: impl Into<String>) -> Self {
        Self { id: id.into(), title: title.into(), ok: false, auto_fix: true, detail: detail.into(), steps: String::new(), advisory: false }
    }

    pub fn manual(id: &str, title: &str, detail: impl Into<String>, steps: impl Into<String>) -> Self {
        Self { id: id.into(), title: title.into(), ok: false, auto_fix: false, detail: detail.into(), steps: steps.into(), advisory: false }
    }

    /// 建议项：未通过时只提示，不阻止解锁。
    pub fn advice(id: &str, title: &str, detail: impl Into<String>, steps: impl Into<String>) -> Self {
        Self { advisory: true, ..Self::manual(id, title, detail, steps) }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub generated: u64,
    pub platform: String,
    pub client_user: String,
    pub findings: Vec<Finding>,
    /// 用户模式等不执行检查的说明。
    #[serde(default)]
    pub skipped: Option<String>,
}

impl Report {
    /// 除建议项外全部通过。
    pub fn passed(&self) -> bool {
        self.findings.iter().all(|f| f.ok || f.advisory)
    }

    /// 未通过的必需项（不含建议项）。
    pub fn failing(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.ok && !f.advisory)
    }

    pub fn load(layout: &Layout) -> std::io::Result<Self> {
        let path = layout.harden_report_path();
        #[cfg(unix)]
        if layout.mode == Mode::System {
            // 报告必须由 root 写入且不可被他人修改。
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(&path)?;
            if m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "harden report not owned by root"));
            }
        }
        let s = std::fs::read_to_string(path)?;
        serde_json::from_str(&s).map_err(std::io::Error::other)
    }

    pub fn store(&self, layout: &Layout) -> std::io::Result<()> {
        std::fs::create_dir_all(&layout.run_dir)?;
        let path = layout.harden_report_path();
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        }
        std::fs::rename(tmp, path)
    }
}

/// 检查上下文。
pub struct Ctx<'a> {
    pub layout: &'a Layout,
    pub info: &'a InstallInfo,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 执行全部检查（系统模式需要 root/管理员权限才能完整检查）。
pub fn check(ctx: &Ctx) -> Report {
    let mut r = Report {
        generated: now(),
        platform: std::env::consts::OS.into(),
        client_user: ctx.info.client_user.clone(),
        findings: Vec::new(),
        skipped: None,
    };
    if ctx.layout.mode == Mode::User {
        r.skipped = Some("用户模式：服务与 Agent 运行在同一个系统用户下，不存在账户隔离，因此不执行账户加固检查。".into());
        return r;
    }
    #[cfg(target_os = "linux")]
    {
        r.findings = linux::check(ctx);
    }
    #[cfg(target_os = "macos")]
    {
        r.findings = macos::check(ctx);
    }
    #[cfg(windows)]
    {
        r.findings = windows::check(ctx);
    }
    r
}

/// 自动修改所有可以安全修改的项，返回操作日志；之后应重新检查。
pub fn fix(ctx: &Ctx, report: &Report) -> Vec<String> {
    let ids: Vec<&str> = report.failing().filter(|f| f.auto_fix).map(|f| f.id.as_str()).collect();
    if ids.is_empty() {
        return vec![];
    }
    let _ = std::fs::create_dir_all(ctx.layout.backup_dir());
    #[cfg(target_os = "linux")]
    {
        linux::fix(ctx, &ids)
    }
    #[cfg(target_os = "macos")]
    {
        macos::fix(ctx, &ids)
    }
    #[cfg(windows)]
    {
        windows::fix(ctx, &ids)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = ids;
        vec![]
    }
}

/// 还原 `fix` 修改前备份的文件（卸载时可选）。
pub fn restore_backups(layout: &Layout) -> Vec<String> {
    let mut log = Vec::new();
    let Ok(rd) = std::fs::read_dir(layout.backup_dir()) else { return log };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        // 备份文件名：原路径中的 '/' 替换为 '%'。
        let original = name.replace('%', "/");
        if original.starts_with('/') {
            match std::fs::copy(e.path(), &original) {
                Ok(_) => log.push(format!("已还原 {original}")),
                Err(err) => log.push(format!("还原 {original} 失败：{err}")),
            }
        }
    }
    log
}

/// 备份一个即将修改的文件。
#[cfg(unix)]
pub(crate) fn backup_file(layout: &Layout, path: &str) -> std::io::Result<()> {
    let dst = layout.backup_dir().join(path.replace('/', "%"));
    if !dst.exists() {
        std::fs::create_dir_all(layout.backup_dir())?;
        std::fs::copy(path, dst)?;
    }
    Ok(())
}

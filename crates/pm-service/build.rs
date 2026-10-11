//! 构建信息：只有从与版本号一致的发布标签构建时才记录（标签，提交），用于 `agent-setup` 的源码构建固定值。
//!
//! 来源（按顺序）：
//! 1. `PASSMANAGER_RELEASE_TAG` + `PASSMANAGER_RELEASE_COMMIT`（显式指定，例如从发布源码包构建时）；
//! 2. GitHub Actions 的标签构建（`GITHUB_REF_TYPE=tag`、`GITHUB_REF_NAME`、`GITHUB_SHA`）；
//! 3. 本地 git：HEAD 恰好是标签 `v<版本>` 且工作区没有已跟踪文件的改动。
//!
//! 标签必须等于 `v<版本>`、提交必须是 40 位十六进制，否则不记录（`agent-setup` 会说明这是开发构建）。

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let o = Command::new("git").args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn valid(tag: &str, commit: &str, version: &str) -> bool {
    tag == format!("v{version}") && commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit())
}

fn main() {
    for v in ["PASSMANAGER_RELEASE_TAG", "PASSMANAGER_RELEASE_COMMIT", "GITHUB_REF_TYPE", "GITHUB_REF_NAME", "GITHUB_SHA"] {
        println!("cargo:rerun-if-env-changed={v}");
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let root = Path::new(&manifest).join("../..");
    for f in [".git/HEAD", ".git/packed-refs", ".git/refs/tags", ".git/index"] {
        let p = root.join(f);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    let mut pin: Option<(String, String)> = None;
    if let (Some(t), Some(c)) = (env("PASSMANAGER_RELEASE_TAG"), env("PASSMANAGER_RELEASE_COMMIT")) {
        pin = valid(&t, &c, &version).then_some((t, c.to_ascii_lowercase()));
    } else if env("GITHUB_REF_TYPE").as_deref() == Some("tag")
        && let (Some(t), Some(c)) = (env("GITHUB_REF_NAME"), env("GITHUB_SHA"))
    {
        pin = valid(&t, &c, &version).then_some((t, c.to_ascii_lowercase()));
    } else if root.join(".git").exists() {
        let want = format!("v{version}");
        let tags = git(&["-C", root.to_str().unwrap_or("."), "tag", "--points-at", "HEAD"]).unwrap_or_default();
        let clean =
            git(&["-C", root.to_str().unwrap_or("."), "status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| s.is_empty());
        if clean
            && tags.lines().any(|t| t.trim() == want)
            && let Some(c) = git(&["-C", root.to_str().unwrap_or("."), "rev-parse", "HEAD"])
            && valid(&want, &c, &version)
        {
            pin = Some((want, c));
        }
    }
    let (tag, commit) = pin.unwrap_or_default();
    println!("cargo:rustc-env=PM_BUILD_TAG={tag}");
    println!("cargo:rustc-env=PM_BUILD_COMMIT={commit}");
}

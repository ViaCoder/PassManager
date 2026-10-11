//! 发布前扫描（scripts/release_scan.py）：受跟踪的文件只能是白名单里的类型；高熵字符串、PEM 块与
//! 私有 IPv4 字面量（文档地址段 RFC 5737 与回环地址除外）都必须在允许清单里。没有 python3 或 git 时跳过。
//!
//! 扫描也包括未跟踪但未被忽略的文件，所以 CI 的检出目录必须保持干净：构建工具、安装包等下载到 `RUNNER_TEMP`
//! 之类的临时目录（`.github/actions/setup` 的最后一步会检查）。不要为这类文件添加允许清单条目。

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn have(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").output().is_ok_and(|o| o.status.success())
}

#[test]
fn release_scan_passes_on_tracked_files() {
    let root = root();
    if !have("python3") || !have("git") || !root.join(".git").exists() {
        eprintln!("跳过：没有 python3 / git 或不在 git 仓库里");
        return;
    }
    let script = root.join("scripts/release_scan.py");
    let o = Command::new("python3").arg("-I").arg(&script).arg("--self-test").current_dir(&root).output().unwrap();
    assert!(o.status.success(), "self-test: {}", String::from_utf8_lossy(&o.stderr));
    let o = Command::new("python3").arg("-I").arg(&script).current_dir(&root).output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "release scan findings:\n{out}");
    assert!(out.contains("findings: 0"), "{out}");
}

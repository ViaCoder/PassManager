//! 运行安装脚本的 DRY_RUN 测试（tests/install_scripts_test.sh）：生成的单元、nftables 规则、sysctl 配置、
//! 替身记录的系统命令、token 不落盘明文、权限受限容器里的降级处理，以及 shellcheck（已安装时）。

#[test]
#[cfg(target_os = "linux")]
fn install_scripts_dry_run() {
    let has =
        |c: &str| std::process::Command::new("sh").args(["-c", &format!("command -v {c}")]).output().is_ok_and(|o| o.status.success());
    if !has("bash") || !has("python3") {
        eprintln!("跳过：需要 bash 与 python3");
        return;
    }
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/install_scripts_test.sh");
    let out = std::process::Command::new("bash").arg(&script).arg(env!("CARGO_BIN_EXE_PassManager")).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("全部通过"), "{text}");
}

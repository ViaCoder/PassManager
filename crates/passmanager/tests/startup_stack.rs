#![cfg(target_os = "linux")]
//! 程序在很小的主线程栈上也能启动：Windows 主线程只有 1 MiB，clap 派生的解析代码在 debug 构建里会把它用完。
//! 这里用 ulimit 模拟，不必等 Windows CI 才发现。

use std::process::Command;

#[test]
fn starts_on_a_small_main_stack() {
    let bin = env!("CARGO_BIN_EXE_PassManager");
    let o = Command::new("sh").arg("-c").arg("ulimit -s 256 && exec \"$0\" --version").arg(bin).output().unwrap();
    assert!(o.status.success(), "{:?} {}", o.status, String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("PassManager"));
}

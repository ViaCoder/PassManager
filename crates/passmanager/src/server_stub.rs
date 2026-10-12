//! 非 Linux 平台：服务器（局域网在线版）的 root 命令只支持 Linux。Agent 端（`enroll`、远程 MCP / CLI）在所有平台可用。

use std::path::Path;
use std::process::ExitCode;

pub use crate::server_opts::InitOpts;

fn linux_only() -> ExitCode {
    crate::install::fail("服务器模式（局域网在线版）只支持 Linux；本机可以用 passmanager enroll 作为 Agent 接入服务器。")
}

pub fn init(_: InitOpts) -> ExitCode {
    linux_only()
}
pub fn login() -> ExitCode {
    linux_only()
}
pub fn is_admin() -> bool {
    false
}
pub fn show_code(_: &str, _: &str) -> ExitCode {
    linux_only()
}
pub fn show_url(_: &str) -> ExitCode {
    linux_only()
}
pub fn layout() -> pm_platform::paths::Layout {
    pm_platform::paths::Layout::system()
}
pub fn import(_: crate::import::ImportOpts) -> ExitCode {
    linux_only()
}
pub fn token_list() -> ExitCode {
    linux_only()
}
pub fn token_revoke(_: &str) -> ExitCode {
    linux_only()
}
pub fn lock(_: bool) -> ExitCode {
    linux_only()
}
pub fn reseal() -> ExitCode {
    linux_only()
}
pub fn import_cert(_: &Path, _: &Path) -> ExitCode {
    linux_only()
}
pub fn print_unit(_: Option<&str>, _: bool) -> ExitCode {
    linux_only()
}
/// Agent 机器上的 `passmanager status`：显示远程配置并测试连接。
pub fn status() -> ExitCode {
    crate::remote::status()
}

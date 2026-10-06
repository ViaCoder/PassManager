//! PassManager —— 面向 AI Agent 的抗量子密码管理器。
//!
//! - `PassManager`：打开管理界面（TUI）。
//! - `PassManager unlock` / `PassManager trust <主机>`：只弹出对应对话框。
//! - `PassManager mcp`：MCP 服务器（供 AI Agent 使用）。
//! - `PassManager list|http|ssh|scp`：CLI（输出 JSON，供 AI Agent 使用）。
//! - `sudo PassManager install`：一键安装。

mod cli;
mod install;
mod mcp;
mod prompt;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "PassManager", version, about = "面向 AI Agent 的抗量子密码管理器。不带参数运行即打开管理界面。")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// 解锁库（弹出解锁对话框，完成后退出）
    Unlock,
    /// 信任主机的新指纹（SSH 主机重装或自签证书更换后使用）
    Trust {
        /// 主机名（如 db1.example.com，清除该主机所有端口的记录）、*.domain 批量，或 host:port 只清除一个端口
        pattern: String,
    },
    /// 一键安装（需要管理员权限；无管理员权限时用 --user）
    Install {
        /// 用户模式（L1，无账户隔离，仅在没有管理员权限时使用）
        #[arg(long)]
        user: bool,
        /// 指定日常使用的账户（默认取 SUDO_USER）
        #[arg(long)]
        client_user: Option<String>,
        /// 不询问，直接执行自动修改
        #[arg(long, short)]
        yes: bool,
        /// 非交互：从标准输入读取口令（视为已确认"没有恢复机制"），用于自动化部署与 CI
        #[arg(long)]
        password_stdin: bool,
        /// 只做安全检查，不执行任何自动修改
        #[arg(long)]
        no_fix: bool,
    },
    /// 卸载（删除服务、服务账户与全部数据）
    Uninstall {
        #[arg(long)]
        user: bool,
        /// 同时还原账户加固前备份的配置文件
        #[arg(long)]
        restore_hardening: bool,
        #[arg(long, short)]
        yes: bool,
    },
    /// 安全检查与账户加固（需要管理员权限）
    Harden {
        /// 只检查，不修改
        #[arg(long)]
        check: bool,
        /// 自动修改可以修改的项
        #[arg(long)]
        fix: bool,
        #[arg(long, short)]
        yes: bool,
    },
    /// 运行服务（由 systemd / launchd / Windows 服务管理器启动）
    Service {
        #[arg(long)]
        user: bool,
    },
    #[command(hide = true)]
    ServicePrepare,
    #[command(hide = true)]
    SealDeviceKey {
        #[arg(long)]
        stdin: bool,
    },
    #[command(hide = true)]
    ExportDeviceKey,
    /// 输出当前使用的本地 socket / 命名管道地址（测试脚本用）
    #[command(hide = true)]
    SocketPath,
    /// MCP 服务器（stdio），供 AI Agent 使用
    Mcp,
    /// 列出已保存密钥的主机
    List,
    /// HTTPS 请求（curl 风格）：在需要密钥的位置写 {{secret}}
    #[command(override_usage = "PassManager http [METHOD] <URL> [-X METHOD] [-H 'K: V']... [-d BODY | -d @file | --json BODY]")]
    Http {
        /// [METHOD] URL
        #[arg(required = true, num_args = 1..=2)]
        args: Vec<String>,
        /// 请求方法（同 curl -X）
        #[arg(short = 'X', long = "request")]
        request: Option<String>,
        /// 请求头，如 -H 'Authorization: Bearer {{secret}}'
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// 请求体；@文件名 从文件读取，@- 从标准输入读取；多个 -d 用 & 连接（同 curl）
        #[arg(short = 'd', long = "data", visible_aliases = ["data-raw", "data-binary", "data-urlencode"])]
        data: Vec<String>,
        /// JSON 请求体（同 curl --json：自动加 Content-Type 与 Accept）
        #[arg(long)]
        json: Option<String>,
        /// 兼容 curl 的常见选项（忽略）
        #[arg(short = 's', long = "silent", hide = true)]
        _silent: bool,
        #[arg(short = 'S', long = "show-error", hide = true)]
        _show_error: bool,
        #[arg(short = 'L', long = "location", hide = true)]
        _location: bool,
        #[arg(short = 'f', long = "fail", hide = true)]
        _fail: bool,
        #[arg(long = "compressed", hide = true)]
        _compressed: bool,
    },
    /// 通过 SSH 执行命令（OpenSSH 风格）：PassManager ssh [-p 端口] [-l 用户] user@host <命令>
    Ssh {
        /// 端口（同 ssh -p）
        #[arg(short = 'p', long)]
        port: Option<u16>,
        /// 用户（同 ssh -l）
        #[arg(short = 'l', long = "login")]
        login: Option<String>,
        /// 兼容 ssh 的常见选项（忽略）
        #[arg(short = 'o', hide = true)]
        _options: Vec<String>,
        #[arg(short = 't', hide = true)]
        _tty: bool,
        #[arg(short = 'T', hide = true)]
        _no_tty: bool,
        #[arg(short = 'q', hide = true)]
        _quiet: bool,
        /// user@host、user@host:port 或 ssh://user@host:port
        target: String,
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// 复制文件（scp 风格）：远程一侧写成 user@host:/path
    Scp {
        /// 端口（同 scp -P）
        #[arg(short = 'P', long)]
        port: Option<u16>,
        /// 兼容 scp 的常见选项（忽略）
        #[arg(short = 'q', hide = true)]
        _quiet: bool,
        #[arg(short = 'p', hide = true)]
        _preserve: bool,
        #[arg(short = 'o', hide = true)]
        _options: Vec<String>,
        source: String,
        destination: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        None => pm_tui::run(pm_tui::Mode::Full),
        Some(Cmd::Unlock) => pm_tui::run(pm_tui::Mode::Unlock),
        Some(Cmd::Trust { pattern }) => pm_tui::run(pm_tui::Mode::Trust(pattern)),
        Some(Cmd::Install { user, client_user, yes, password_stdin, no_fix }) => {
            install::install(install::InstallOpts { user, client_user, yes, password_stdin, no_fix })
        }
        Some(Cmd::Uninstall { user, restore_hardening, yes }) => install::uninstall(user, restore_hardening, yes),
        Some(Cmd::Harden { check, fix, yes }) => install::harden_cmd(check, fix, yes),
        Some(Cmd::Service { user }) => install::service(user),
        Some(Cmd::ServicePrepare) => install::service_prepare(),
        Some(Cmd::SealDeviceKey { stdin }) => install::seal_device_key_cmd(stdin),
        Some(Cmd::ExportDeviceKey) => install::export_device_key_cmd(),
        Some(Cmd::SocketPath) => {
            println!("{}", pm_platform::Layout::detect_client().socket.display());
            ExitCode::SUCCESS
        }
        Some(Cmd::Mcp) => {
            mcp::run();
            ExitCode::SUCCESS
        }
        Some(Cmd::List) => cli::tool("list", serde_json::json!({})),
        Some(Cmd::Http { args, request, headers, data, json, .. }) => cli::http(args, request, headers, data, json),
        Some(Cmd::Ssh { port, login, target, command, .. }) => cli::ssh(port, login, target, command),
        Some(Cmd::Scp { port, source, destination, .. }) => cli::scp(port, source, destination),
    }
}

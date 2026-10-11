//! PassManager —— 面向 AI Agent 的抗量子密码管理器。
//!
//! - `PassManager`：打开管理界面（TUI）。
//! - `PassManager unlock` / `PassManager trust <主机>`：只弹出对应对话框。
//! - `PassManager mcp`：MCP 服务器（供 AI Agent 使用）。
//! - `PassManager list|http|ssh|scp`：CLI（输出 JSON，供 AI Agent 使用）。
//! - `sudo PassManager install`：一键安装。
//! - 局域网在线版（服务器，root）：`passmanager init|login|token|status|lock|unlock|reseal`；
//!   Agent 端：`passmanager enroll <注册码>`，之后 MCP / CLI 用法不变。

mod agent_instructions;
mod cli;
mod git_proxy;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod import;
mod install;
mod mcp;
mod prompt;
mod remote;
#[cfg(target_os = "linux")]
mod server;
#[cfg(not(target_os = "linux"))]
#[path = "server_stub.rs"]
mod server;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod server_opts;
#[cfg(unix)]
mod ssh_agent;

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
    /// 解锁库（单机：弹出解锁对话框，完成后退出；服务器：root 用设备密钥解锁）
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
    /// [服务器，root] 初始化局域网在线版：设备密钥、内层通道密钥、无口令密码库、证书、systemd 服务
    #[command(after_help = "\
示例：
  # 在服务器上（root）：域名与允许的网段必须指定；Cloudflare token 从标准输入读入，用设备密钥封存
  passmanager init --domain pm.example.com --lan-cidr 198.51.100.0/24 --cf-token-stdin < /root/cf-token
  # 不使用 ACME：跳过证书申请，之后用 import-cert 导入
  passmanager init --domain pm.example.com --lan-cidr 198.51.100.0/24 --skip-acme
  # 重复运行是安全的：已有的密钥、库与证书保持不变，只更新指定的配置项
  passmanager init --lan-cidr 198.51.100.0/24 --lan-cidr 203.0.113.0/24")]
    Init {
        /// 域名（证书与 Host 校验）；首次初始化时必须指定
        #[arg(long)]
        domain: Option<String>,
        /// 允许访问的 IPv4 网段（可重复）；首次初始化时必须指定，没有默认值
        #[arg(long = "lan-cidr", visible_alias = "lan")]
        lan: Vec<String>,
        /// 监听地址（IPv4），默认 0.0.0.0
        #[arg(long)]
        bind: Option<String>,
        /// 网页端口，默认 443
        #[arg(long)]
        web_port: Option<u16>,
        /// Agent 端口，默认 8443
        #[arg(long)]
        agent_port: Option<u16>,
        /// 从标准输入读取 Cloudflare API token（第一行），用设备密钥封存
        #[arg(long)]
        cf_token_stdin: bool,
        /// 不申请证书
        #[arg(long)]
        skip_acme: bool,
        /// ACME 目录 URL（默认 Let's Encrypt 正式环境；空字符串表示不使用 ACME）
        #[arg(long)]
        acme_directory: Option<String>,
        /// 测试：ACME 服务器的根证书（Pebble）
        #[arg(long, hide = true)]
        acme_root_pem: Option<std::path::PathBuf>,
        /// 测试：DNS-01 方式（cloudflare 或 challtest:<url>）
        #[arg(long, hide = true)]
        dns: Option<String>,
        /// 可选：swtpm 数据套接字（Unix 套接字，存在时优先于自动检测的 /dev/tpmrm0；空字符串取消配置）
        #[arg(long)]
        tpm_socket: Option<String>,
        /// 只写配置，不启动服务
        #[arg(long)]
        no_start: bool,
    },
    /// [服务器，root] 输出网页管理的一次性登录链接（2 分钟有效，只能使用一次）
    #[command(after_help = "示例：\n  ssh root@server passmanager login\n  # 在浏览器打开输出的 https://pm.example.com/l/… 并点击\"登录\"")]
    Login,
    /// [服务器，root] 从标准输入导入密钥（不回显、不记录；只打印名称、字节数与域名数）
    #[command(after_help = "\
内容原样保存（可以多行，例如 PEM 私钥），只去掉末尾的一个换行；上限 64 KiB。
--fields 时第 1..n 行依次是各字段的值（行数必须正好等于字段数）。没有 --domain 时条目为\"未绑定域名\"，
在网页里添加域名之前 Agent 无法使用。

示例：
  passmanager import --name github --domain api.github.com < token.txt
  passmanager import --name mail --fields username,password --domain mail.example.com < creds.txt
  passmanager import --name admin-key --kind ssh-key --domain db1.example.com:22 \\
      --host-key \"$(ssh-keyscan -t ecdsa db1.example.com 2>/dev/null)\" < id_ecdsa
  passmanager import --name init-pw --domain '*.example.com' --domain 198.51.100.0/24 --ops ssh < initial-password.txt
  passmanager import --name github --replace --domain api.github.com < new-token.txt
  passmanager import --name pin --interactive              # 在终端里不回显地输入")]
    Import {
        /// 引用名
        #[arg(long)]
        name: String,
        /// 绑定的目标（可重复）：主机名、*.example.com（不含 example.com 本身）、IP、网段（198.51.100.0/24，只匹配直接用 IP 访问的目标），都可加 :端口
        #[arg(long = "domain")]
        domains: Vec<String>,
        /// 只允许这些用途（逗号分隔：http、ssh、git；默认不限），例如只用于 SSH 登录的初始口令写 --ops ssh
        #[arg(long, value_delimiter = ',')]
        ops: Vec<String>,
        /// 说明
        #[arg(long, default_value = "")]
        note: String,
        /// 自签证书（首次连接时记录证书指纹）
        #[arg(long)]
        self_signed: bool,
        /// 同名条目已存在时替换
        #[arg(long)]
        replace: bool,
        /// 类型：password（默认）或 ssh-key（校验私钥并打印公钥指纹）
        #[arg(long)]
        kind: Option<String>,
        /// 多字段：字段名（逗号分隔），标准输入每行一个值
        #[arg(long, value_delimiter = ',')]
        fields: Option<Vec<String>>,
        /// 在终端里以不回显方式输入（标准输入是终端时必须）
        #[arg(long)]
        interactive: bool,
        /// SSH 私钥：允许 ssh-agent 桥签名的主机密钥（SHA256:… 指纹或公钥行，可重复）
        #[arg(long = "host-key")]
        host_keys: Vec<String>,
    },
    /// [服务器，root] 为一台 Agent 机器生成接入说明（含一次性注册码），整段交给那台机器上的 AI Agent
    #[command(after_help = "\
打印一段给 AI Agent 的文字：一行安装命令（curl … | sh：安装客户端、注册、配置 MCP 与使用规则）、
TLS 握手失败时从固定的发布源码构建客户端的步骤，以及使用规则。注册码 10 分钟内有效、只能使用一次。

示例：
  ssh root@server passmanager agent-setup --label laptop
  ssh root@server passmanager agent-setup --label build-box --lang zh")]
    AgentSetup {
        /// 标签（例如机器名或 Agent 名），默认 agent
        #[arg(long, default_value = "agent")]
        label: String,
        /// 说明语言：en（默认）或 zh
        #[arg(long, default_value = "en")]
        lang: String,
    },
    /// 打印给 AI Agent 的 PassManager 使用规则（enroll 时会写入 Agent 的全局指令文件）
    AgentInstructions {
        /// en（默认）或 zh
        #[arg(long, default_value = "en")]
        lang: String,
    },
    /// [Agent 机器] 取消注册：删除远程配置与令牌、移除 MCP 配置与写入的使用规则
    Unenroll,
    /// 内部：一键接入用的 Agent 程序目录（安装脚本使用）
    #[command(hide = true)]
    AgentBinDir,
    /// 构建信息：版本、发布标签与提交（只有从发布标签构建时才有后两项）
    #[command(hide = true)]
    BuildInfo,
    /// [服务器，root] 管理 Agent 令牌
    #[command(
        subcommand,
        after_help = "示例：\n  passmanager token add laptop-claude\n  passmanager token list\n  passmanager token revoke 1a2b3c4d"
    )]
    Token(TokenCmd),
    /// 显示状态（服务器上：封存等级、证书、令牌；Agent 机器上：远程配置与连接测试）
    #[command(after_help = "示例：\n  passmanager status")]
    Status,
    /// [服务器，root] 立即锁定密码库（丢弃内存中的密钥）
    Lock,
    /// [服务器，root] 把设备密钥从 L2（主机密钥）升级到 L3（TPM + 主机密钥）
    #[command(after_help = "\
有可用的 TPM 之后运行（/dev/tpmrm0，或用 passmanager init --tpm-socket 配置的 swtpm 套接字）。
不绑定 PCR。升级后只有这块 TPM 能解开设备密钥：TPM 状态丢失或迁移到别的节点后库将永久无法打开（没有恢复途径）。

示例：
  passmanager reseal")]
    Reseal,
    /// [Agent 机器] 用一次性注册码接入服务器：核对指纹、保存令牌（0600）、写入 Claude Code / Codex 等的 MCP 配置
    #[command(
        after_help = "示例：\n  passmanager enroll 'pm-enroll://pm.example.com:8443/<注册码>#<指纹>'\n  passmanager enroll --no-mcp 'pm-enroll://…'   # 只保存令牌，不改 Agent 配置"
    )]
    Enroll {
        /// 注册码（pm-enroll://主机:端口/注册码#指纹）
        code: String,
        /// 不写入 Agent 的 MCP 配置（也不写使用规则）
        #[arg(long)]
        no_mcp: bool,
        /// 不把使用规则写入 Agent 的全局指令文件（CLAUDE.md、AGENTS.md 等）
        #[arg(long)]
        no_instructions: bool,
        /// 测试：直接连接的 IPv4:端口
        #[arg(long, hide = true)]
        connect_addr: Option<std::net::SocketAddr>,
        /// 测试：额外信任的 CA 证书文件
        #[arg(long, hide = true)]
        ca_file: Option<std::path::PathBuf>,
    },
    /// [Agent 机器] OpenSSH agent 桥：让普通的 ssh / scp / git 使用服务器上保存的私钥（私钥不离开服务器）
    #[command(after_help = "\
在已注册（passmanager enroll）的机器上运行，按输出设置 SSH_AUTH_SOCK：
  eval \"$(passmanager ssh-agent &)\"        # 或：passmanager ssh-agent --socket ~/.ssh/pm-agent.sock &
  ssh-add -L                                # 列出可用的公钥（服务器上的 SSH 私钥条目）
  ssh deploy@db1.example.com               # 由服务器签名（只签与已绑定主机的会话，拒绝转发会话）

需要 OpenSSH ≥ 8.9（session-bind@openssh.com）。主机密钥必须在条目上绑定（import --host-key 或网页），
或已在 PassManager 的指纹库中、且与条目的域名匹配。")]
    SshAgent {
        /// 套接字路径（默认 $XDG_RUNTIME_DIR/passmanager-agent/agent.sock）
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },
    /// [Agent 机器] git 凭据注入代理：git 经本机代理访问 HTTPS 仓库，由服务器带上访问令牌（本机不接触令牌）
    #[command(after_help = "\
在已注册（passmanager enroll）的机器上运行，然后按输出配置 git：
  passmanager git-proxy --host github.com --host git.example.com:8121 &
  git config --global url.\"http://127.0.0.1:7878/<路径令牌>/https/github.com/\".insteadOf \"https://github.com/\"
  git clone https://github.com/owner/repo.git

服务器上要有绑定该主机的条目（单值 PAT，或带 username 与 token/password 字段的多字段条目）。
只代理 git smart-HTTP 请求；路径令牌保存在配置目录（0600），只监听回环地址。")]
    GitProxy {
        /// 监听地址（只能是回环地址），默认 127.0.0.1:7878
        #[arg(long)]
        listen: Option<String>,
        /// 打印这些主机的 git 配置命令（可重复）
        #[arg(long = "host")]
        hosts: Vec<String>,
    },
    /// [服务器，root] 导入 TLS 证书（不使用 ACME 时）
    #[command(hide = true)]
    ImportCert { chain: std::path::PathBuf, key: std::path::PathBuf },
    /// 输出服务器模式的 systemd 单元（安装脚本使用）
    #[command(hide = true)]
    ServerUnit {
        /// 附加组（可访问 TPM，例如 tss）
        #[arg(long)]
        tpm_group: Option<String>,
        /// 输出 tmpfiles.d 配置而不是单元
        #[arg(long)]
        tmpfiles: bool,
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

#[derive(Subcommand)]
enum TokenCmd {
    /// 生成一次性注册码 pm-enroll://…（10 分钟有效，只能使用一次）
    Add {
        /// 标签（例如机器名或 Agent 名）
        label: String,
    },
    /// 列出令牌与未使用的注册码
    List,
    /// 吊销令牌（立即失效），或作废未使用的注册码
    Revoke { id: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        None => pm_tui::run(pm_tui::Mode::Full),
        Some(Cmd::Unlock) if server_mode() => server::lock(true),
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
        Some(Cmd::Init {
            domain,
            lan,
            bind,
            web_port,
            agent_port,
            cf_token_stdin,
            skip_acme,
            acme_directory,
            acme_root_pem,
            dns,
            tpm_socket,
            no_start,
        }) => server::init(server::InitOpts {
            domain,
            lan,
            bind,
            web_port,
            agent_port,
            acme_directory,
            acme_root_pem,
            dns,
            tpm_socket,
            cf_token_stdin,
            skip_acme,
            no_start,
        }),
        Some(Cmd::Login) => server::login(),
        Some(Cmd::Import { name, domains, ops, note, self_signed, replace, kind, fields, interactive, host_keys }) => {
            server::import(import::ImportOpts { name, domains, ops, note, self_signed, replace, kind, fields, interactive, host_keys })
        }
        Some(Cmd::Token(TokenCmd::Add { label })) => server::token_add(&label),
        Some(Cmd::Token(TokenCmd::List)) => server::token_list(),
        Some(Cmd::Token(TokenCmd::Revoke { id })) => server::token_revoke(&id),
        Some(Cmd::Status) => server::status(),
        Some(Cmd::Lock) => server::lock(false),
        Some(Cmd::Reseal) => server::reseal(),
        Some(Cmd::Enroll { code, no_mcp, no_instructions, connect_addr, ca_file }) => {
            remote::enroll_cmd(&code, remote::EnrollOpts { no_mcp, no_instructions, connect_addr, ca_file })
        }
        Some(Cmd::AgentSetup { label, lang }) => server::agent_setup(&label, &lang),
        Some(Cmd::AgentInstructions { lang }) => match pm_proto::agent_text::Lang::parse(&lang) {
            Ok(l) => {
                print!("{}", pm_proto::agent_text::instruction_block(l));
                ExitCode::SUCCESS
            }
            Err(e) => install::fail(e),
        },
        Some(Cmd::Unenroll) => remote::unenroll(),
        Some(Cmd::BuildInfo) => {
            let b = pm_service::build_info();
            match b.pinned() {
                Some((tag, commit)) => println!("version {}\ntag {tag}\ncommit {commit}", b.version),
                None => println!("version {}\ntag none (development build)\ncommit none", b.version),
            }
            ExitCode::SUCCESS
        }
        Some(Cmd::AgentBinDir) => {
            println!("{}", server::layout().data_dir.join("agent-bin").display());
            ExitCode::SUCCESS
        }
        Some(Cmd::ImportCert { chain, key }) => server::import_cert(&chain, &key),
        Some(Cmd::GitProxy { listen, hosts }) => git_proxy::run(listen, hosts),
        Some(Cmd::SshAgent { socket }) => {
            #[cfg(unix)]
            {
                ssh_agent::run(socket)
            }
            #[cfg(not(unix))]
            {
                let _ = socket;
                install::fail("ssh-agent 桥目前只支持 Linux / macOS（Unix 套接字）。")
            }
        }
        Some(Cmd::ServerUnit { tpm_group, tmpfiles }) => server::print_unit(tpm_group.as_deref(), tmpfiles),
    }
}

/// 本机是否为服务器模式（install.json 有 server 配置）。
fn server_mode() -> bool {
    cfg!(target_os = "linux")
        && pm_platform::InstallInfo::load(&{
            if std::env::var_os("PASSMANAGER_HOME").is_some() { pm_platform::Layout::user() } else { pm_platform::Layout::system() }
        })
        .ok()
        .is_some_and(|i| i.server.is_some())
}

//! PassManager —— 面向 AI Agent 的抗量子密码管理器。
//!
//! - `PassManager`：打开管理界面（TUI）。
//! - `PassManager unlock` / `PassManager trust <主机>`：只弹出对应对话框。
//! - `PassManager mcp`：MCP 服务器（供 AI Agent 使用）。
//! - `PassManager list|http|ssh|scp`：CLI（输出 JSON，供 AI Agent 使用）。
//! - `sudo PassManager install`：一键安装。
//! - 局域网在线版（服务器，root）：`passmanager init|login|show|token|status|lock|unlock|reseal`；
//!   接入 Agent：`passmanager show --label <名称>`（一次性注册码 + 给 AI Agent 的完整说明）；
//!   Agent 端：一行安装命令或 `passmanager enroll <注册码>`，之后 MCP / CLI 用法不变。

mod agent_instructions;
mod cli;
mod git_proxy;
mod git_service;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod import;
mod install;
mod mcp;
mod prompt;
mod remote;
#[cfg(unix)]
mod run;
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
    /// 查询某个目标（URL、user@host 或主机）可用的凭据，返回照抄即可的写法（只显示这一个目标的信息）
    Lookup {
        /// URL、user@host[:port]、主机，或 {{名称}}
        target: String,
        /// 用途：http、ssh、scp、git（省略时按目标推断）
        #[arg(long = "use")]
        use_: Option<String>,
    },
    /// 已废弃：不再列出条目，请用 lookup
    #[command(hide = true)]
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
  passmanager init --lan-cidr 198.51.100.0/24 --lan-cidr 203.0.113.0/24
  # 单端口模式（网页与 Agent 共用 8121），并允许两个额外的地址访问该端口（不含 SSH）
  passmanager init --port 8121 --allow \"203.0.113.7 2001:db8::/32\"
  # 清空允许列表
  passmanager init --allow \"\"")]
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
        /// 单端口模式：网页与 Agent 通道共用这个端口（按 TLS ALPN 分流），例如 --port 8121
        #[arg(long, conflicts_with_all = ["web_port", "agent_port"])]
        port: Option<u16>,
        /// 额外允许访问服务端口的 IPv4 / IPv6 地址或网段（可重复；一个值可含多个以空格分隔的条目；
        /// 给空字符串表示清空）。与 --lan-cidr 不同，防火墙不为它们开放 SSH
        #[arg(long = "allow")]
        allow: Option<Vec<String>>,
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
        /// 备注：一句用途说明（不要写路径、URL、账号或秘密）
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
    /// [服务器 root] 修改条目的绑定、用途或备注（不涉及密钥）
    #[command(after_help = "\
示例：
  ssh root@server passmanager update --name forge --domain git.example.com
  ssh root@server passmanager update --name init --add-op ssh --remove-domain 203.0.113.0/24
  ssh root@server passmanager update --name ai --note 'AI gateway key'

备注只写一句用途：不要写路径、URL、账号或秘密。")]
    Update {
        /// 引用名
        #[arg(long)]
        name: String,
        /// 增加绑定的目标（可重复，格式同 import --domain）
        #[arg(long = "domain")]
        add_domains: Vec<String>,
        /// 移除绑定的目标（可重复）
        #[arg(long = "remove-domain")]
        remove_domains: Vec<String>,
        /// 增加允许的用途（http、ssh、git；可重复或逗号分隔）
        #[arg(long = "add-op", value_delimiter = ',')]
        add_ops: Vec<String>,
        /// 移除允许的用途
        #[arg(long = "remove-op", value_delimiter = ',')]
        remove_ops: Vec<String>,
        /// 新的备注（一句用途说明）
        #[arg(long)]
        note: Option<String>,
    },
    /// 显示 Agent 接入说明；服务器上的 root 加 --label 时附带一次性注册码（10 分钟有效，只能使用一次）
    #[command(after_help = "\
服务器上的 root 加 --label：生成一次性注册码，打印给 AI Agent 的完整接入说明——一行安装命令（安装客户端、注册、
配置 MCP、使用规则与 git 凭据代理服务）、curl 不支持后量子 TLS（退出码 35）时从固定的发布源码构建再 enroll 的步骤，
以及使用规则。把整段交给那台机器上的 AI Agent。
不带 --label，或不是服务器上的 root：只打印公开的接入说明（不含注册码）；已注册的机器还会显示连接的服务器。

示例：
  ssh root@server passmanager show --label laptop              # 完整的接入说明（含一行安装命令）
  ssh root@server passmanager show --label laptop --lang en    # 英文
  ssh root@server passmanager show --label laptop --url        # 只打印 pm-enroll://… 注册码
  passmanager show --rules                                     # 只打印使用规则
  passmanager show                                             # 公开的接入说明")]
    Show {
        /// 标签（例如机器名或 Agent 名）：为这台 Agent 机器生成一次性注册码（需要服务器上的 root）
        #[arg(long)]
        label: Option<String>,
        /// 只打印 pm-enroll://… 注册码（需要 --label；在 Agent 机器上用 passmanager enroll '<注册码>' 注册）
        #[arg(long, requires = "label")]
        url: bool,
        /// 只打印给 AI Agent 的使用规则（enroll 时会写入 Agent 的全局指令文件）
        #[arg(long, conflicts_with_all = ["label", "url"])]
        rules: bool,
        /// 与 --rules 一起：把规则写入本机已检测到的 Agent 的全局指令文件（原地更新，与 enroll 时相同，英文）
        #[arg(long, requires = "rules")]
        write: bool,
        /// 说明语言：zh（默认）或 en
        #[arg(long, default_value = "zh")]
        lang: String,
    },
    /// [Agent 机器] 取消注册：删除远程配置与令牌、移除 MCP 配置与写入的使用规则
    Unenroll,
    /// 内部：一键接入用的 Agent 程序目录（安装脚本使用）
    #[command(hide = true)]
    AgentBinDir,
    /// 内部：校验 IP 地址 / 网段列表（安装脚本与服务使用同一个解析器）；每个有效条目输出"4 条目"或"6 条目"
    #[command(hide = true)]
    CheckNet {
        /// 只接受 IPv4（局域网网段）
        #[arg(long)]
        v4_only: bool,
        /// 条目（每个参数可含多个以空格分隔的条目）
        entries: Vec<String>,
    },
    /// 构建信息：版本、发布标签与提交（只有从发布标签构建时才有后两项）
    #[command(hide = true)]
    BuildInfo,
    /// [服务器，root] 管理 Agent 令牌
    #[command(
        subcommand,
        after_help = "新的 Agent 用 passmanager show --label <名称> 接入。\n\n示例：\n  passmanager token list\n  passmanager token revoke 1a2b3c4d"
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
    /// [Agent 机器] 用一次性注册码接入服务器：核对指纹、保存令牌（0600）、写入 Claude Code / Codex 等的 MCP 配置、
    /// 使用规则与 git 凭据代理服务
    #[command(
        after_help = "注册码由服务器上的 root 生成：passmanager show --label <名称> --url（或完整说明：show --label <名称>）。\n\n示例：\n  passmanager enroll 'pm-enroll://pm.example.com:8443/<注册码>#<指纹>'\n  passmanager enroll --no-git-proxy 'pm-enroll://…'   # 不安装 git 代理服务\n  passmanager enroll --no-mcp 'pm-enroll://…'         # 只保存令牌，不改 Agent 与 git 的配置"
    )]
    Enroll {
        /// 注册码（pm-enroll://主机:端口/注册码#指纹）
        code: String,
        /// 不写入 Agent 的 MCP 配置（也不写使用规则、不安装 git 代理服务）
        #[arg(long)]
        no_mcp: bool,
        /// 不把使用规则写入 Agent 的全局指令文件（CLAUDE.md、AGENTS.md 等）
        #[arg(long)]
        no_instructions: bool,
        /// 不安装 git 凭据代理服务，也不写 git 的 insteadOf 配置
        #[arg(long)]
        no_git_proxy: bool,
        /// git 代理服务的监听地址（只能是回环地址），默认 127.0.0.1:7878
        #[arg(long, value_name = "ADDR")]
        git_proxy_listen: Option<String>,
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
enroll 已把它装成开机 / 登录时自动启动的用户服务（Linux：systemd 用户单元；macOS：LaunchAgent；Windows：打印手动步骤），
并为服务器上每个有 git 用途条目的主机写入全局的 git insteadOf，之后直接使用 https:// 地址即可。
新增 git 条目之后重新运行 --install（可重复运行：服务文件与 insteadOf 整体替换，不会重复）。

  passmanager git-proxy --install            # 安装 / 更新服务与 git 配置
  passmanager git-proxy --uninstall          # 停止并移除服务与 git 配置
  passmanager git-proxy &                    # 前台运行，打印每个 git 主机的配置命令
  git config --global url.\"http://127.0.0.1:7878/<路径令牌>/https/github.com/\".insteadOf \"https://github.com/\"

服务器上要有绑定该主机、用途包含 git 的条目（单值 PAT，或带 username 与 token/password 字段的多字段条目）。
只代理 git smart-HTTP 请求；路径令牌持久保存在配置目录（0600），只监听回环地址。")]
    GitProxy {
        /// 监听地址（只能是回环地址），默认 127.0.0.1:7878
        #[arg(long)]
        listen: Option<String>,
        /// git 主机（可重复）；默认是服务器上有 git 用途的所有条目的主机
        #[arg(long = "host")]
        hosts: Vec<String>,
        /// 安装为开机 / 登录时自动启动的用户服务，并写入 git 的 insteadOf
        #[arg(long, conflicts_with = "uninstall")]
        install: bool,
        /// 停止并移除用户服务与 PassManager 写入的 git insteadOf
        #[arg(long, conflicts_with_all = ["listen", "hosts"])]
        uninstall: bool,
    },
    /// [Agent 机器] 只为一条命令准备经服务器转发的认证（git 经服务器带上访问令牌，ssh 由服务器签名），命令结束就全部清除
    #[command(after_help = "\
  passmanager run git push                         # 基于 HTTPS 的 git：由服务器带上访问令牌
  passmanager run git clone https://github.com/<所有者>/<仓库>.git
  passmanager run ssh deploy@db1.example.com       # ssh / scp / rsync / 基于 SSH 的 git：由服务器签名
  passmanager run rsync -a ./site/ deploy@db1.example.com:/srv/site/

不写任何 git 或 ssh 配置，也不需要常驻服务：转发口（随机端口、一次性令牌）和 agent 套接字只在这条命令运行期间存在。
令牌和私钥从不离开服务器。退出码与命令相同。")]
    Run {
        /// 经 PassManager 的 git 主机（可重复）；默认是服务器上有 git 用途的所有条目的主机
        #[arg(long = "host")]
        hosts: Vec<String>,
        /// 要运行的命令和参数
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
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
        Some(Cmd::Lookup { target, use_ }) => cli::tool("lookup", serde_json::json!({"target": target, "use": use_})),
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
            port,
            allow,
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
            port,
            allow,
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
        Some(Cmd::Update { name, add_domains, remove_domains, add_ops, remove_ops, note }) => {
            server::update(import::UpdateOpts { name, add_domains, remove_domains, add_ops, remove_ops, note })
        }
        Some(Cmd::Token(TokenCmd::List)) => server::token_list(),
        Some(Cmd::Token(TokenCmd::Revoke { id })) => server::token_revoke(&id),
        Some(Cmd::Status) => server::status(),
        Some(Cmd::Lock) => server::lock(false),
        Some(Cmd::Reseal) => server::reseal(),
        Some(Cmd::Enroll { code, no_mcp, no_instructions, no_git_proxy, git_proxy_listen, connect_addr, ca_file }) => {
            remote::enroll_cmd(&code, remote::EnrollOpts { no_mcp, no_instructions, no_git_proxy, git_proxy_listen, connect_addr, ca_file })
        }
        Some(Cmd::Show { label, url, rules, write, lang }) => show(label, url, rules, write, &lang),
        Some(Cmd::Unenroll) => remote::unenroll(),
        Some(Cmd::BuildInfo) => {
            let b = pm_service::build_info();
            match b.pinned() {
                Some((tag, commit)) => println!("version {}\ntag {tag}\ncommit {commit}", b.version),
                None => println!("version {}\ntag none (development build)\ncommit none", b.version),
            }
            ExitCode::SUCCESS
        }
        Some(Cmd::CheckNet { v4_only, entries }) => {
            for e in server_opts::split_allow(&entries) {
                match pm_platform::paths::parse_net(&e) {
                    Ok((ip, _)) if v4_only && !ip.is_ipv4() => return install::fail(format!("局域网网段只支持 IPv4：{e}")),
                    Ok((ip, _)) => println!("{} {e}", if ip.is_ipv4() { 4 } else { 6 }),
                    Err(m) => return install::fail(m),
                }
            }
            ExitCode::SUCCESS
        }
        Some(Cmd::AgentBinDir) => {
            println!("{}", server::layout().data_dir.join("agent-bin").display());
            ExitCode::SUCCESS
        }
        Some(Cmd::ImportCert { chain, key }) => server::import_cert(&chain, &key),
        Some(Cmd::GitProxy { listen, hosts, install: true, .. }) => git_service::install_cmd(listen, hosts),
        Some(Cmd::GitProxy { uninstall: true, .. }) => git_service::uninstall_cmd(),
        Some(Cmd::GitProxy { listen, hosts, .. }) => git_proxy::run(listen, hosts),
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
        Some(Cmd::Run { hosts, command }) => {
            #[cfg(unix)]
            {
                run::run(hosts, command)
            }
            #[cfg(not(unix))]
            {
                let _ = (hosts, command);
                install::fail("passmanager run 目前只支持 Linux / macOS（Unix 套接字）。")
            }
        }
        Some(Cmd::ServerUnit { tpm_group, tmpfiles }) => server::print_unit(tpm_group.as_deref(), tmpfiles),
    }
}

/// `passmanager show`：服务器上的 root 加 `--label` 时生成一次性注册码（完整说明或只有 URL）；
/// 否则打印不含注册码的公开说明（已注册的机器说明连接的服务器）。说明文字只来自 `pm_proto::agent_text`。
fn show(label: Option<String>, url: bool, rules: bool, write: bool, lang: &str) -> ExitCode {
    use pm_proto::agent_text::{Lang, instruction_block, public_text};
    let l = match Lang::parse(lang) {
        Ok(l) => l,
        Err(e) => return install::fail(e),
    };
    if write {
        // 与 enroll 写入的一致（英文），升级客户端后运行一次即可更新各 Agent 的规则块。
        let block = instruction_block(Lang::En);
        let mut ok = true;
        let mut any = false;
        for (name, path, r) in agent_instructions::install_detected(&block) {
            any = true;
            match r {
                Ok(agent_instructions::Change::Unchanged) => println!("{name}：使用规则已是最新（{}）", path.display()),
                Ok(_) => println!("{name}：已更新使用规则（{}）", path.display()),
                Err(e) => {
                    ok = false;
                    println!("{name}：未写入使用规则（{e}）")
                }
            }
        }
        if !any {
            println!("没有检测到支持全局指令文件的 Agent。");
        }
        return if ok { ExitCode::SUCCESS } else { ExitCode::from(1) };
    }
    if rules {
        print!("{}", instruction_block(l));
        return ExitCode::SUCCESS;
    }
    let admin = server_mode() && server::is_admin();
    match label {
        Some(label) if admin && url => server::show_url(&label),
        Some(label) if admin => server::show_code(&label, lang),
        Some(_) if url => install::fail("只有服务器上的 root 能生成注册码：ssh root@<服务器> passmanager show --label <名称> --url"),
        other => {
            if other.is_some() {
                eprintln!("（不是服务器上的 root：只显示公开的接入说明，不生成注册码。）");
            } else if admin {
                eprintln!("（加 --label <名称> 生成一次性注册码与完整的接入说明。）");
            }
            print!("{}", public_text(l, remote::connected_server().as_deref()));
            ExitCode::SUCCESS
        }
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

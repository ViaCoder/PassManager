//! 目录布局。
//!
//! - 系统模式（推荐）：服务以专用用户运行，数据放在 $HOME 之外。
//! - 用户模式（无管理员权限时的降级方案，L1）：服务以当前用户运行。
//! - `PASSMANAGER_HOME`：测试/开发用覆盖，所有文件放在该目录下（视为用户模式）。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SERVICE_USER: &str = if cfg!(target_os = "macos") { "_passmanager" } else { "passmanager" };
pub const APP: &str = "PassManager";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    System,
    User,
}

#[derive(Clone, Debug)]
pub struct Layout {
    pub mode: Mode,
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
    /// Unix：socket 文件路径；Windows：命名管道名。
    pub socket: PathBuf,
}

/// 用户主目录。MCP 客户端启动子进程时环境变量可能很少，因此 Unix 上缺少 HOME 时从账户数据库读取。
fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    #[cfg(unix)]
    if let Ok(Some(u)) = nix::unistd::User::from_uid(nix::unistd::getuid()) {
        return u.dir;
    }
    PathBuf::from(".")
}

impl Layout {
    pub fn system() -> Self {
        #[cfg(target_os = "linux")]
        {
            let run = PathBuf::from("/run/passmanager");
            Self { mode: Mode::System, data_dir: "/var/lib/passmanager".into(), socket: run.join("passmanager.sock"), run_dir: run }
        }
        #[cfg(target_os = "macos")]
        {
            let run = PathBuf::from("/var/run/passmanager");
            Self {
                mode: Mode::System,
                data_dir: "/Library/Application Support/PassManager".into(),
                socket: run.join("passmanager.sock"),
                run_dir: run,
            }
        }
        #[cfg(windows)]
        {
            let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            let data = base.join(APP);
            Self { mode: Mode::System, run_dir: data.join("run"), data_dir: data, socket: PathBuf::from(r"\\.\pipe\PassManager") }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let run = PathBuf::from("/var/run/passmanager");
            Self { mode: Mode::System, data_dir: "/var/db/passmanager".into(), socket: run.join("passmanager.sock"), run_dir: run }
        }
    }

    pub fn user() -> Self {
        if let Some(h) = std::env::var_os("PASSMANAGER_HOME") {
            let h = PathBuf::from(h);
            // Windows 的本地 IPC 是命名管道，不能放在目录里：按目录路径派生一个管道名。
            #[cfg(windows)]
            let socket = PathBuf::from(format!(r"\\.\pipe\PassManager-{:016x}", fnv1a(h.to_string_lossy().as_bytes())));
            #[cfg(not(windows))]
            let socket = h.join("run").join("passmanager.sock");
            return Self { mode: Mode::User, data_dir: h.join("data"), socket, run_dir: h.join("run") };
        }
        #[cfg(windows)]
        {
            let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| home().join("AppData").join("Local"));
            let data = base.join(APP);
            // 管道名按用户 SID 生成，不依赖 USERNAME 等环境变量（MCP 客户端可能不传递它们）。
            let who = crate::process::current_user_sid().unwrap_or_else(|| std::env::var("USERNAME").unwrap_or_else(|_| "user".into()));
            Self {
                mode: Mode::User,
                run_dir: data.join("run"),
                data_dir: data,
                socket: PathBuf::from(format!(r"\\.\pipe\PassManager-{who}")),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let data = home().join("Library/Application Support/PassManager");
            Self { mode: Mode::User, run_dir: data.join("run"), socket: data.join("run").join("passmanager.sock"), data_dir: data }
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let data =
                std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".local/share")).join("passmanager");
            // socket 位置只由 uid 决定（/run/user/<uid>），不依赖 XDG_RUNTIME_DIR：
            // 服务（systemd --user）与 MCP 子进程看到的环境变量可能不同。
            let uid_run = PathBuf::from(format!("/run/user/{}", nix::unistd::getuid()));
            let run = if uid_run.is_dir() {
                uid_run.join("passmanager")
            } else {
                match std::env::var_os("XDG_RUNTIME_DIR") {
                    Some(r) => PathBuf::from(r).join("passmanager"),
                    None => data.join("run"),
                }
            };
            Self { mode: Mode::User, socket: run.join("passmanager.sock"), run_dir: run, data_dir: data }
        }
    }

    /// 客户端用：按优先级找到正在使用的布局（覆盖变量 > 系统模式 > 用户模式）。
    pub fn detect_client() -> Self {
        if std::env::var_os("PASSMANAGER_HOME").is_some() {
            return Self::user();
        }
        let sys = Self::system();
        #[cfg(windows)]
        {
            // 普通用户无权读取系统数据目录；通过列出 \\.\pipe\ 判断系统服务的管道是否存在
            // （打开管道会占用一个实例，因此不直接打开）。
            let running = std::fs::read_dir(r"\\.\pipe\")
                .map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case("PassManager")))
                .unwrap_or(false);
            if running || sys.data_dir.join("install.json").exists() {
                return sys;
            }
            Self::user()
        }
        #[cfg(not(windows))]
        {
            if sys.socket.exists() || sys.run_dir.exists() {
                return sys;
            }
            Self::user()
        }
    }

    pub fn vault_path(&self) -> PathBuf {
        self.data_dir.join("vault.pmv")
    }

    pub fn install_info_path(&self) -> PathBuf {
        self.data_dir.join("install.json")
    }

    pub fn harden_report_path(&self) -> PathBuf {
        self.run_dir.join("harden.json")
    }

    pub fn backup_dir(&self) -> PathBuf {
        self.data_dir.join("hardening-backup")
    }

    /// 服务器模式：启动前由 root（`ExecStartPre=+… service-prepare`）解封出的设备密钥，
    /// 服务读取后立即删除。非特权 LXC 不支持 `LoadCredentialEncrypted=`，所以用这个等价方式。
    pub fn key_handoff_dir(&self) -> PathBuf {
        match self.mode {
            Mode::System if cfg!(target_os = "linux") => PathBuf::from("/run/passmanager-key"),
            _ => self.run_dir.join("key"),
        }
    }

    pub fn key_handoff_path(&self) -> PathBuf {
        self.key_handoff_dir().join("device.key")
    }

    /// 服务器模式的 TLS 证书目录。
    pub fn tls_dir(&self) -> PathBuf {
        self.data_dir.join("tls")
    }
}

/// Agent 端（远程模式）的配置目录：`remote.toml`、令牌文件、缓存的服务端公钥。
///
/// 注册（写入）与之后的使用（读取）必须找到同一个目录，而 `XDG_CONFIG_HOME` 等环境变量在不同的启动方式之间常常不同
/// （例如 `curl | sh` 的终端、Agent 启动 MCP 子进程、CI 运行器）。因此：
/// - 写入固定在 `~/.config/passmanager`（Unix）/ `%APPDATA%\PassManager`（Windows），不受 `XDG_CONFIG_HOME` 影响；
/// - 读取先找该目录，再兼容 0.3.0 及更早版本按 `XDG_CONFIG_HOME` 写入的位置；
/// - `PASSMANAGER_CONFIG_DIR` 覆盖以上全部（测试与特殊部署用）。
pub fn client_config_dir() -> PathBuf {
    client_config_dirs_with(|k| std::env::var_os(k), &home()).0
}

/// 读取时使用的目录：第一个含有 `probe` 文件的候选目录；都没有时为写入目录。
pub fn client_config_read_dir(probe: &str) -> PathBuf {
    let (write, candidates) = client_config_dirs_with(|k| std::env::var_os(k), &home());
    candidates.into_iter().find(|d| d.join(probe).is_file()).unwrap_or(write)
}

/// 所有可能的客户端配置目录（写入目录在前），用于取消注册时全部清理。
pub fn client_config_dirs() -> Vec<PathBuf> {
    client_config_dirs_with(|k| std::env::var_os(k), &home()).1
}

/// 纯函数：由环境变量与主目录得到（写入目录，读取候选目录）。
pub fn client_config_dirs_with(get: impl Fn(&str) -> Option<std::ffi::OsString>, home: &Path) -> (PathBuf, Vec<PathBuf>) {
    let nonempty = |k: &str| get(k).filter(|d| !d.is_empty()).map(PathBuf::from);
    if let Some(d) = nonempty("PASSMANAGER_CONFIG_DIR") {
        return (d.clone(), vec![d]);
    }
    if cfg!(windows) {
        let d = nonempty("APPDATA").unwrap_or_else(|| home.join("AppData").join("Roaming")).join(APP);
        return (d.clone(), vec![d]);
    }
    let canonical = home.join(".config").join("passmanager");
    let mut candidates = vec![canonical.clone()];
    if let Some(x) = nonempty("XDG_CONFIG_HOME").map(|x| x.join("passmanager"))
        && x != canonical
    {
        candidates.push(x);
    }
    (canonical, candidates)
}

/// 局域网在线版（服务器模式）的配置。写在 root 所有的 install.json 里，服务只读。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 证书与 Host 校验使用的域名（安装时必须指定，例如 `pm.example.com`）。没有默认值。
    pub domain: String,
    /// 网页管理端口（默认 443）。与 `agent_port` 相同时为单端口模式：一个 TLS 监听按 ALPN 分流网页与 Agent 通道。
    #[serde(default = "default_web_port")]
    pub web_port: u16,
    /// Agent 通道端口（默认 8443）。
    #[serde(default = "default_agent_port")]
    pub agent_port: u16,
    /// 监听地址（只支持 IPv4）。
    #[serde(default = "default_bind")]
    pub bind: String,
    /// 允许连接的来源网段（IPv4 CIDR，安装时必须指定）。没有默认值：为空时服务拒绝启动网络监听。
    #[serde(default)]
    pub lan: Vec<String>,
    /// 额外允许访问服务端口的地址或网段（IPv4 / IPv6，例如 `203.0.113.7`、`2001:db8::/32`）。与 `lan` 不同，
    /// 防火墙不为它们开放 SSH（22）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// ACME 目录 URL；为空表示不自动申请证书（只用 `import-cert` 导入的证书）。
    #[serde(default)]
    pub acme_directory: String,
    /// 测试用：ACME 服务器的自签根证书（Pebble）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_root_pem: Option<PathBuf>,
    /// DNS-01 写 TXT 记录的方式：`cloudflare`（默认）或 `challtest:<url>`（Pebble 测试）。
    #[serde(default = "default_dns")]
    pub dns: String,
    /// 剩余有效期少于多少天时续期。
    #[serde(default = "default_renew_days")]
    pub renew_days: u32,
    /// 可选：swtpm 的 Unix 数据套接字（例如宿主机为容器提供的软件 TPM）。配置且存在时优先于 /dev/tpmrm0；
    /// 不配置时只自动检测 /dev/tpmrm0。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm_socket: Option<String>,
    /// 可选：本机 tangd 的回环地址（例如 `127.0.0.1:7500`）。配置后网页端口提供 `/tang/`（Clevis 网络绑定加密），
    /// 访问限制与网页相同（局域网网段与允许列表）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tang: Option<String>,
}

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

fn default_web_port() -> u16 {
    443
}
fn default_agent_port() -> u16 {
    8443
}
fn default_bind() -> String {
    "0.0.0.0".into()
}
fn default_dns() -> String {
    "cloudflare".into()
}
fn default_renew_days() -> u32 {
    30
}

/// 默认值只包含与站点无关的项；域名与允许的网段为空，必须在安装时指定（否则 `validate` 失败）。
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            web_port: default_web_port(),
            agent_port: default_agent_port(),
            bind: default_bind(),
            lan: Vec::new(),
            allow: Vec::new(),
            acme_directory: LETS_ENCRYPT.into(),
            acme_root_pem: None,
            dns: default_dns(),
            renew_days: default_renew_days(),
            tpm_socket: None,
            tang: None,
        }
    }
}

impl ServerConfig {
    /// 校验配置（服务启动时失败即视为配置错误，退出码 78）。
    pub fn validate(&self) -> Result<(), String> {
        let d = &self.domain;
        if d.is_empty() {
            return Err("没有配置域名（passmanager init --domain <域名>）".into());
        }
        if d.len() > 253
            || d.len() > 253
            || !d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            || !d.contains('.')
        {
            return Err(format!("域名无效：{d}"));
        }
        // 两个端口相同表示单端口模式（按 ALPN 分流），不是错误。
        if self.web_port == 0 || self.agent_port == 0 {
            return Err("端口无效（不能为 0）".into());
        }
        if self.bind.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(format!("监听地址必须是 IPv4：{}", self.bind));
        }
        if self.lan.is_empty() {
            return Err("没有配置允许访问的网段，拒绝启动网络监听（passmanager init --lan-cidr <CIDR>，可重复）".into());
        }
        for c in &self.lan {
            parse_cidr(c)?;
        }
        for a in &self.allow {
            parse_net(a).map_err(|e| format!("允许列表中的条目无效：{e}"))?;
        }
        if let Some(t) = &self.tpm_socket
            && (!t.starts_with('/') || t.contains(['\n', ' ']))
        {
            return Err(format!("TPM 套接字路径必须是绝对路径：{t}"));
        }
        if let Some(t) = &self.tang {
            parse_tang(t)?;
        }
        if !(self.dns == "cloudflare" || self.dns.starts_with("challtest:")) {
            return Err(format!("未知的 DNS 方式：{}", self.dns));
        }
        Ok(())
    }
}

/// 解析 tangd 地址：只接受本机回环（`127.0.0.1:端口` 或 `[::1]:端口`），转发的明文请求不离开本机。
pub fn parse_tang(s: &str) -> Result<std::net::SocketAddr, String> {
    let a: std::net::SocketAddr = s.trim().parse().map_err(|_| format!("tangd 地址无效（应为 127.0.0.1:端口）：{s}"))?;
    if !a.ip().is_loopback() || a.port() == 0 {
        return Err(format!("tangd 地址必须是本机回环地址与非零端口：{s}"));
    }
    Ok(a)
}

/// 解析 IPv4 CIDR（`a.b.c.d/n`，或单个地址视为 /32）。
pub fn parse_cidr(s: &str) -> Result<(std::net::Ipv4Addr, u8), String> {
    let (ip, len) = match s.split_once('/') {
        Some((ip, len)) => (ip, len.parse::<u8>().map_err(|_| format!("网段无效：{s}"))?),
        None => (s, 32),
    };
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| format!("网段无效（只支持 IPv4）：{s}"))?;
    if len > 32 {
        return Err(format!("网段无效：{s}"));
    }
    Ok((ip, len))
}

impl ServerConfig {
    /// 单端口模式：网页与 Agent 通道共用一个端口（按 ALPN 分流）。
    pub fn single_port(&self) -> bool {
        self.web_port == self.agent_port
    }

    /// 服务端口（单端口模式下只有一个）。
    pub fn service_ports(&self) -> Vec<u16> {
        if self.single_port() { vec![self.web_port] } else { vec![self.web_port, self.agent_port] }
    }

    /// 应用层的来源检查（网页与 Agent 通道都使用；与防火墙规则使用同一份列表）：
    /// 本机回环（127.0.0.1、::1）总是允许；其次是局域网网段 `lan` 与允许列表 `allow`。
    pub fn source_allowed(&self, ip: std::net::IpAddr) -> bool {
        let ip = normalize_ip(ip);
        ip == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || ip == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            || ip_allowed(ip, &self.lan)
            || net_allowed(ip, &self.allow)
    }
}

/// IPv4 映射的 IPv6 地址按 IPv4 处理。
fn normalize_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// 解析 IPv4 / IPv6 地址或网段（`addr` 视为 /32 或 /128）。主机位必须为 0（防止写错的网段被悄悄放宽或收窄）。
pub fn parse_net(s: &str) -> Result<(std::net::IpAddr, u8), String> {
    let s = s.trim();
    let (ip, len) = match s.split_once('/') {
        Some((ip, len)) => {
            let ip: std::net::IpAddr = ip.parse().map_err(|_| format!("不是 IP 地址或网段：{s}"))?;
            let len: u8 = len.parse().map_err(|_| format!("前缀长度无效：{s}"))?;
            (ip, len)
        }
        None => {
            let ip: std::net::IpAddr = s.parse().map_err(|_| format!("不是 IP 地址或网段：{s}"))?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if len > max {
        return Err(format!("前缀长度无效：{s}"));
    }
    let (bits, mask) = net_bits(ip, len);
    if bits & !mask != 0 {
        return Err(format!("网段的主机位不为 0：{s}（是否想写 {}/{len}？）", net_addr(ip, len)));
    }
    Ok((ip, len))
}

fn net_bits(ip: std::net::IpAddr, len: u8) -> (u128, u128) {
    match ip {
        std::net::IpAddr::V4(v) => (u32::from(v) as u128, if len == 0 { 0 } else { (u32::MAX << (32 - len as u32)) as u128 }),
        std::net::IpAddr::V6(v) => (u128::from(v), if len == 0 { 0 } else { u128::MAX << (128 - len as u32) }),
    }
}

fn net_addr(ip: std::net::IpAddr, len: u8) -> std::net::IpAddr {
    let (b, m) = net_bits(ip, len);
    match ip {
        std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::from((b & m) as u32)),
        std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(b & m)),
    }
}

/// 地址是否落在任一条目（IPv4 / IPv6 地址或网段）内；地址族不同不匹配，无效条目不匹配任何地址。
pub fn net_allowed(ip: std::net::IpAddr, entries: &[String]) -> bool {
    let ip = normalize_ip(ip);
    entries.iter().filter_map(|e| parse_net(e).ok()).any(|(net, len)| {
        if net.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let (a, m) = net_bits(ip, len);
        let (n, _) = net_bits(net, len);
        a & m == n & m
    })
}

/// 来源地址是否在允许的网段内。IPv6 一律拒绝（IPv4 映射地址按 IPv4 处理）。
pub fn ip_allowed(ip: std::net::IpAddr, lan: &[String]) -> bool {
    let v4 = match ip {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
    };
    lan.iter().filter_map(|c| parse_cidr(c).ok()).any(|(net, len)| {
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        u32::from(v4) & mask == u32::from(net) & mask
    })
}

/// FNV-1a 64 位哈希（只用于派生管道名，不涉及安全）。
#[cfg_attr(not(windows), allow(dead_code))]
fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x0000_0100_0000_01b3))
}

/// 安装信息（系统模式下由安装程序以 root 写入，服务只读）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallInfo {
    pub mode: Mode,
    /// 安装用户（Agent 与 TUI 所在的桌面用户）。
    pub client_user: String,
    #[serde(default)]
    pub client_uid: Option<u32>,
    #[serde(default)]
    pub client_gid: Option<u32>,
    #[serde(default)]
    pub client_sid: Option<String>,
    pub service_user: String,
    pub seal_method: String,
    pub seal_level: u8,
    pub binary: String,
    /// 局域网在线版（服务器模式）。None 表示原来的单机模式。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerConfig>,
}

impl InstallInfo {
    pub fn load(layout: &Layout) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(layout.install_info_path())?;
        serde_json::from_str(&s).map_err(std::io::Error::other)
    }

    pub fn store(&self, layout: &Layout) -> std::io::Result<()> {
        std::fs::create_dir_all(&layout.data_dir)?;
        let s = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        write_atomic(&layout.install_info_path(), s.as_bytes(), 0o644)
    }
}

/// 原子写入：临时文件 → fsync → rename → fsync 目录（断电后要么是旧内容，要么是新内容）。
pub fn write_atomic(path: &std::path::Path, data: &[u8], #[allow(unused_variables)] mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent()
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    /// 注册与使用必须找到同一个目录：写入不受 XDG_CONFIG_HOME 影响；读取兼容旧位置；PASSMANAGER_CONFIG_DIR 优先。
    #[cfg(not(windows))]
    #[test]
    fn client_config_dir_ignores_xdg_for_writing() {
        let home = Path::new("/home/u");
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(a, _)| *a == k).map(|(_, v)| std::ffi::OsString::from(v))
        };
        let canonical = PathBuf::from("/home/u/.config/passmanager");
        let (w, c) = client_config_dirs_with(env(&[]), home);
        assert_eq!((w.clone(), c), (canonical.clone(), vec![canonical.clone()]));
        for xdg in [
            &[("XDG_CONFIG_HOME", "/ci/.config")][..],
            &[("XDG_CONFIG_HOME", "/ci/.config"), ("XDG_DATA_HOME", "/ci/data"), ("XDG_STATE_HOME", "/ci/state")],
        ] {
            let (w2, c2) = client_config_dirs_with(env(xdg), home);
            assert_eq!(w2, canonical, "写入目录与 XDG_CONFIG_HOME 无关");
            assert_eq!(c2, vec![canonical.clone(), PathBuf::from("/ci/.config/passmanager")], "读取兼容旧位置");
        }
        let (w3, c3) = client_config_dirs_with(env(&[("XDG_CONFIG_HOME", "/home/u/.config")]), home);
        assert_eq!((w3, c3.len()), (canonical.clone(), 1), "XDG 与默认相同时只有一个候选");
        let (w4, c4) = client_config_dirs_with(env(&[("XDG_CONFIG_HOME", "")]), home);
        assert_eq!((w4, c4.len()), (canonical, 1));
        let (w5, c5) = client_config_dirs_with(env(&[("PASSMANAGER_CONFIG_DIR", "/opt/pm"), ("XDG_CONFIG_HOME", "/x")]), home);
        assert_eq!((w5, c5), (PathBuf::from("/opt/pm"), vec![PathBuf::from("/opt/pm")]));
    }

    use super::*;

    #[test]
    fn tang_address_is_loopback_only() {
        // 回环地址与端口可用；其他地址、0 端口、没有端口、垃圾都是配置错误。
        assert_eq!(parse_tang("127.0.0.1:7500").unwrap().port(), 7500);
        assert!(parse_tang(" [::1]:7500 ").is_ok());
        for bad in ["192.0.2.1:7500", "0.0.0.0:7500", "127.0.0.1:0", "127.0.0.1", "localhost:7500", ""] {
            assert!(parse_tang(bad).is_err(), "{bad}");
        }
        let c = ServerConfig { domain: "pm.example.com".into(), lan: vec!["198.51.100.0/24".into()], ..Default::default() };
        assert!(ServerConfig { tang: Some("127.0.0.1:7500".into()), ..c.clone() }.validate().is_ok());
        assert!(ServerConfig { tang: Some("198.51.100.5:7500".into()), ..c }.validate().is_err());
    }

    #[test]
    fn allowlist_parsing_and_source_check() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        // 解析：v4、v6、网段；主机位不为 0、垃圾、越界前缀都拒绝。
        assert_eq!(parse_net("203.0.113.7").unwrap(), (ip("203.0.113.7"), 32));
        assert_eq!(parse_net("198.51.100.0/24").unwrap(), (ip("198.51.100.0"), 24));
        assert_eq!(parse_net("2001:db8::/32").unwrap(), (ip("2001:db8::"), 32));
        assert_eq!(parse_net("2001:db8::5").unwrap(), (ip("2001:db8::5"), 128));
        for bad in [
            "198.51.100.1/24",
            "2001:db8::1/32",
            "198.51.100.0/33",
            "2001:db8::/129",
            "pm.example.com",
            "198.51.100",
            "",
            "1.2.3.4/x",
            "1.2.3.4 5.6.7.8",
        ] {
            assert!(parse_net(bad).is_err(), "{bad:?}");
        }
        assert!(parse_net("198.51.100.1/24").unwrap_err().contains("198.51.100.0/24"), "提示正确的写法");
        // 来源检查：LAN、允许列表（v4 与 v6）、其他；回环总是允许；映射地址按 v4。
        let mut c = ServerConfig { domain: "pm.example.com".into(), lan: vec!["198.51.100.0/24".into()], ..Default::default() };
        c.allow = vec!["203.0.113.7".into(), "203.0.113.64/26".into(), "2001:db8::/32".into()];
        for ok in ["198.51.100.9", "203.0.113.7", "203.0.113.100", "2001:db8::42", "::ffff:203.0.113.7", "127.0.0.1", "::1"] {
            assert!(c.source_allowed(ip(ok)), "{ok}");
        }
        for bad in ["203.0.113.8", "203.0.113.63", "192.0.2.1", "2001:db9::1", "127.0.0.2", "fe80::1", "::ffff:192.0.2.1"] {
            assert!(!c.source_allowed(ip(bad)), "{bad}");
        }
        assert!(c.validate().is_ok());
        c.allow.push("203.0.113.1/24".into());
        assert!(c.validate().unwrap_err().contains("允许列表"), "无效条目是配置错误");
        // 单端口模式：两个端口相同。
        let mut s = ServerConfig { domain: "pm.example.com".into(), lan: vec!["198.51.100.0/24".into()], ..Default::default() };
        assert!(!s.single_port() && s.service_ports() == vec![443, 8443]);
        s.web_port = 8121;
        s.agent_port = 8121;
        assert!(s.validate().is_ok() && s.single_port() && s.service_ports() == vec![8121]);
        s.agent_port = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn server_config_defaults_and_validation() {
        // 默认值不含任何站点信息：域名与网段为空，校验失败（服务拒绝启动网络监听）。
        let d = ServerConfig::default();
        assert_eq!((d.domain.as_str(), d.web_port, d.agent_port, d.lan.len(), d.tpm_socket.as_deref()), ("", 443, 8443, 0, None));
        assert!(d.validate().unwrap_err().contains("域名"));
        assert!(ServerConfig { domain: "pm.example.com".into(), ..d.clone() }.validate().unwrap_err().contains("网段"));
        let c = ServerConfig { domain: "pm.example.com".into(), lan: vec!["198.51.100.0/24".into()], ..Default::default() };
        c.validate().unwrap();
        // 旧的 install.json（没有 server 字段）仍能读取。
        let old = r#"{"mode":"system","client_user":"a","service_user":"passmanager","seal_method":"file","seal_level":1,"binary":"/x"}"#;
        let i: InstallInfo = serde_json::from_str(old).unwrap();
        assert!(i.server.is_none());
        assert!(!serde_json::to_string(&i).unwrap().contains("server"));
        // 只写了域名的配置：其余用默认值补全，但没有网段时校验失败。
        let i: InstallInfo = serde_json::from_str(&old.replace("}", r#","server":{"domain":"pm.example.com"}}"#)).unwrap();
        let s = i.server.unwrap();
        assert!(s.lan.is_empty() && s.tpm_socket.is_none());
        assert_eq!(s.dns, "cloudflare");
        assert!(s.validate().is_err());
        for bad in [
            ServerConfig { domain: "".into(), ..c.clone() },
            ServerConfig { domain: "nodot".into(), ..c.clone() },
            ServerConfig { domain: "a..b".into(), ..c.clone() },
            ServerConfig { domain: "a b.c".into(), ..c.clone() },
            ServerConfig { web_port: 0, ..c.clone() },
            ServerConfig { agent_port: 0, ..c.clone() },
            ServerConfig { allow: vec!["203.0.113.0/16".into()], ..c.clone() },
            ServerConfig { allow: vec!["not-an-ip".into()], ..c.clone() },
            ServerConfig { bind: "::".into(), ..c.clone() },
            ServerConfig { lan: vec![], ..c.clone() },
            ServerConfig { lan: vec!["198.51.100.0/33".into()], ..c.clone() },
            ServerConfig { lan: vec!["fd00::/8".into()], ..c.clone() },
            ServerConfig { dns: "route53".into(), ..c.clone() },
            ServerConfig { tpm_socket: Some("tpm.sock".into()), ..c.clone() },
            ServerConfig { tpm_socket: Some("/a b".into()), ..c.clone() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        // 0.3.5 起两个端口相同表示单端口模式（之前是错误）。
        assert!(ServerConfig { web_port: 8443, ..c.clone() }.validate().is_ok());
        ServerConfig { tpm_socket: Some("/run/swtpm/tpm.sock".into()), ..c }.validate().unwrap();
    }

    #[test]
    fn lan_matching_is_ipv4_only_with_exact_boundaries() {
        let lan = vec!["198.51.100.0/24".to_string()];
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        for ok in ["198.51.100.0", "198.51.100.1", "198.51.100.55", "198.51.100.255", "::ffff:198.51.100.9"] {
            assert!(ip_allowed(ip(ok), &lan), "{ok}");
        }
        for bad in
            ["198.51.99.255", "203.0.113.0", "203.0.113.7", "127.0.0.1", "8.8.8.8", "::1", "fe80::1", "2001:db8::1", "::ffff:203.0.113.1"]
        {
            assert!(!ip_allowed(ip(bad), &lan), "{bad}");
        }
        assert!(ip_allowed(ip("127.0.0.1"), &["127.0.0.0/8".into()]));
        assert!(ip_allowed(ip("192.0.2.3"), &["192.0.2.3".into()]));
        assert!(!ip_allowed(ip("192.0.2.4"), &["192.0.2.3".into()]));
        assert!(ip_allowed(ip("1.2.3.4"), &["0.0.0.0/0".into()]));
        assert!(ip_allowed(ip("198.51.100.9"), &["203.0.113.0/24".into(), "198.51.100.0/24".into()]), "多个网段");
        assert!(!ip_allowed(ip("198.51.100.1"), &["garbage".into()]), "无效网段不匹配任何地址");
        assert!(!ip_allowed(ip("198.51.100.1"), &[]));
    }

    #[test]
    fn atomic_write_replaces_and_sets_mode() {
        let dir = std::env::temp_dir().join(format!("pm-aw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("install.json");
        write_atomic(&p, b"one", 0o644).unwrap();
        // 残留的半写临时文件不影响下一次写入。
        std::fs::write(dir.join("install.json.tmp"), b"half").unwrap();
        write_atomic(&p, b"two", 0o644).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert!(!dir.join("install.json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o644);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

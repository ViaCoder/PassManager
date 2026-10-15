//! Agent 端的远程模式：经双层加密（TLS 1.3 混合后量子 + 内层 ML-KEM-1024/McEliece）连接局域网里的
//! PassManager 服务器。MCP / CLI 的用法完全不变：存在远程配置时自动走远程通道。
//!
//! 配置目录（Linux `~/.config/passmanager`，0700）：
//! - `remote.toml`：服务器地址、端口、服务端公钥指纹（SHA-384，注册时固定，不是 TOFU）；
//! - `token`：访问令牌（0600）；环境变量 `PASSMANAGER_TOKEN` 优先；
//! - `server-keys.bin`：服务端公钥包（约 1 MB，注册时下载，每次连接都按固定的指纹重新核对）。

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pm_net::client::Target;
use pm_net::enroll::{EnrollUrl, fpr_text, parse_fpr};
use pm_net::inner::{FPR_LEN, ServerPublic};
use pm_proto::{ApiError, Client, ENV_TOKEN, Hello, PROTO_V};
use zeroize::Zeroizing;

pub const CONFIG_FILE: &str = "remote.toml";
pub const TOKEN_FILE: &str = "token";
pub const KEYS_FILE: &str = "server-keys.bin";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteConfig {
    pub server: String,
    pub port: u16,
    pub fingerprint: [u8; FPR_LEN],
    /// 测试 / 特殊网络：直接连接的 `IPv4:端口`（TLS 的 SNI 与证书校验仍用 `server`）。
    pub connect_addr: Option<std::net::SocketAddr>,
    /// 测试：额外信任的 CA 证书文件（生产环境只信任公共根证书）。
    pub ca_file: Option<PathBuf>,
}

/// 读取用的配置目录（已注册时是保存 `remote.toml` 的目录，见 `pm_platform::paths::client_config_dir`）。
pub fn dir() -> PathBuf {
    pm_platform::paths::client_config_read_dir(CONFIG_FILE)
}

/// 注册时写入的目录（固定，不受 XDG_CONFIG_HOME 影响）。
pub fn write_dir() -> PathBuf {
    pm_platform::paths::client_config_dir()
}

impl RemoteConfig {
    pub fn to_toml(&self) -> String {
        let mut d = toml_edit::DocumentMut::new();
        d["server"] = toml_edit::value(&self.server);
        d["port"] = toml_edit::value(self.port as i64);
        d["fingerprint"] = toml_edit::value(fpr_text(&self.fingerprint));
        if let Some(a) = self.connect_addr {
            d["connect_addr"] = toml_edit::value(a.to_string());
        }
        if let Some(c) = &self.ca_file {
            d["ca_file"] = toml_edit::value(c.display().to_string());
        }
        format!("# PassManager 远程模式（由 passmanager enroll 生成）。\n{d}")
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let d: toml_edit::DocumentMut = text.parse().map_err(|e| format!("remote.toml 格式错误：{e}"))?;
        let s = |k: &str| d.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let server = s("server").filter(|v| !v.is_empty()).ok_or("remote.toml 缺少 server")?;
        let port = d
            .get("port")
            .and_then(|v| v.as_integer())
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or("remote.toml 的 port 无效")?;
        let fingerprint = parse_fpr(&s("fingerprint").ok_or("remote.toml 缺少 fingerprint")?)?;
        let connect_addr = match s("connect_addr") {
            Some(a) => Some(a.parse().map_err(|_| "remote.toml 的 connect_addr 无效".to_string())?),
            None => None,
        };
        Ok(Self { server, port, fingerprint, connect_addr, ca_file: s("ca_file").map(PathBuf::from) })
    }

    pub fn target(&self) -> Result<Target, String> {
        let extra = match &self.ca_file {
            Some(p) => Some(std::fs::read_to_string(p).map_err(|e| format!("读取 {} 失败：{e}", p.display()))?),
            None => None,
        };
        Ok(Target { host: self.server.clone(), port: self.port, connect_addr: self.connect_addr, extra_ca_pem: extra })
    }
}

/// 读取远程配置；不存在时返回 None（走本地 socket）。
pub fn load_in(d: &Path) -> Option<Result<RemoteConfig, String>> {
    let text = std::fs::read_to_string(d.join(CONFIG_FILE)).ok()?;
    Some(RemoteConfig::parse(&text))
}

/// 缓存的公钥包按固定的指纹重新核对（文件被替换或损坏时拒绝连接）。
pub fn server_public(d: &Path, cfg: &RemoteConfig) -> Result<ServerPublic, String> {
    let b = std::fs::read(d.join(KEYS_FILE)).map_err(|e| format!("读取缓存的服务端公钥失败：{e}（请重新运行 passmanager enroll）"))?;
    ServerPublic::from_bundle(&b, &cfg.fingerprint).map_err(|e| format!("缓存的服务端公钥与固定的指纹不符：{e}"))
}

fn token_in(d: &Path) -> Option<Zeroizing<String>> {
    if let Some(t) = std::env::var(ENV_TOKEN).ok().filter(|t| !t.is_empty()) {
        return Some(Zeroizing::new(t));
    }
    std::fs::read_to_string(d.join(TOKEN_FILE)).ok().map(|t| Zeroizing::new(t.trim().to_string())).filter(|t| !t.is_empty())
}

/// 用远程配置连接（令牌会话）。
pub fn connect_in(d: &Path, cfg: &RemoteConfig) -> Result<Client, ApiError> {
    let token = token_in(d)
        .ok_or_else(|| ApiError::new("NO_TOKEN", "No PassManager token found. Ask the user to run: passmanager enroll <code>"))?;
    let public = server_public(d, cfg).map_err(|m| ApiError::new("NOT_READY", m))?;
    let target = cfg.target().map_err(|m| ApiError::new("NOT_READY", m))?;
    let stream = pm_net::client::connect(&target, &public).map_err(|e| {
        ApiError::new(
            "NOT_RUNNING",
            format!(
                "Cannot reach the PassManager server {}:{} ({e}). Ask the user to check the server and the LAN connection.",
                cfg.server, cfg.port
            ),
        )
    })?;
    Client::connect_stream(stream, &Hello::Token { v: PROTO_V, token: token.to_string() })
}

/// MCP / CLI 的连接入口：设置了 `PASSMANAGER_HOME`（测试）或没有远程配置时返回 None（走本地 socket）。
pub fn connect_if_configured() -> Option<Result<Client, ApiError>> {
    if std::env::var_os("PASSMANAGER_HOME").is_some() && std::env::var_os("PASSMANAGER_CONFIG_DIR").is_none() {
        return None;
    }
    let d = dir();
    let cfg = load_in(&d)?;
    Some(cfg.map_err(|m| ApiError::new("NOT_READY", m)).and_then(|c| connect_in(&d, &c)))
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    pm_platform::paths::write_atomic(path, data, 0o600).map_err(|e| format!("写入 {} 失败：{e}", path.display()))
}

#[derive(Clone, Debug, Default)]
pub struct EnrollOpts {
    /// 不写入 Agent 的 MCP 配置（只保存远程配置与令牌；也不写使用规则）。
    pub no_mcp: bool,
    /// 不把使用规则写入 Agent 的全局指令文件。
    pub no_instructions: bool,
    /// 不安装 git-proxy 服务、不写 git 的 insteadOf。
    pub no_git_proxy: bool,
    /// git-proxy 服务的监听地址（默认 127.0.0.1:7878）。
    pub git_proxy_listen: Option<String>,
    /// 测试：直接连接的地址。
    pub connect_addr: Option<std::net::SocketAddr>,
    /// 测试：额外信任的 CA 文件。
    pub ca_file: Option<PathBuf>,
}

/// 注册：核对指纹 → 下载并缓存公钥包 → 双层加密会话中用注册码换令牌 → 保存（0600）→ 写入 MCP 配置。
pub fn enroll(url: &str, o: &EnrollOpts) -> Result<RemoteConfig, String> {
    let u = EnrollUrl::parse(url)?;
    let cfg =
        RemoteConfig { server: u.host.clone(), port: u.port, fingerprint: u.fpr, connect_addr: o.connect_addr, ca_file: o.ca_file.clone() };
    let target = cfg.target()?;
    let public = pm_net::client::fetch_server_public(&target, &u.fpr).map_err(|e| match e {
        pm_net::inner::InnerError::Fingerprint => {
            "服务端公钥与注册码里的指纹不符：拒绝注册（可能连到了别的服务器或遭到中间人攻击）".to_string()
        }
        e => format!("连接 {}:{} 失败：{e}", u.host, u.port),
    })?;
    let stream = pm_net::client::connect(&target, &public).map_err(|e| format!("建立加密会话失败：{e}"))?;
    let token = Zeroizing::new(Client::enroll_stream(stream, &u.code, &u.host).map_err(|e| e.message)?);
    let d = write_dir();
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    write_private(&d.join(KEYS_FILE), &public.bundle)?;
    write_private(&d.join(TOKEN_FILE), token.as_bytes())?;
    write_private(&d.join(CONFIG_FILE), cfg.to_toml().as_bytes())?;
    Ok(cfg)
}

pub fn enroll_cmd(url: &str, o: EnrollOpts) -> ExitCode {
    match enroll(url, &o) {
        Ok(cfg) => {
            let d = dir();
            println!("已注册到 {}:{}（服务端公钥指纹 {}）", cfg.server, cfg.port, fpr_text(&cfg.fingerprint));
            println!("  · 配置与令牌：{}（仅本人可读）", d.display());
            if !o.no_mcp {
                let bin = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "PassManager".into());
                let mut any = false;
                for a in pm_tui::agents::ADAPTERS.iter().filter(|a| a.detected()) {
                    any = true;
                    match a.connect_with(&bin, None) {
                        Ok(m) => println!("  · {}：{m}", a.name),
                        Err(e) => println!("  · {}：失败（{e}）", a.name),
                    }
                }
                if !any {
                    println!("  · 没有检测到已安装的 Agent。MCP 配置：{{\"command\": \"{bin}\", \"args\": [\"mcp\"]}}");
                }
                if !o.no_instructions {
                    let block = pm_proto::agent_text::instruction_block(pm_proto::agent_text::Lang::En);
                    for (name, path, r) in crate::agent_instructions::install_detected(&block) {
                        match r {
                            Ok(crate::agent_instructions::Change::Unchanged) => {
                                println!("  · {name}：使用规则已是最新（{}）", path.display())
                            }
                            Ok(_) => println!("  · {name}：已写入使用规则（{}）", path.display()),
                            Err(e) => println!("  · {name}：未写入使用规则（{e}）"),
                        }
                    }
                }
                if !o.no_git_proxy {
                    for m in crate::git_service::after_enroll(o.git_proxy_listen.as_deref()) {
                        println!("  · git-proxy：{m}");
                    }
                }
            }
            println!("测试：{} list", std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "PassManager".into()));
            ExitCode::SUCCESS
        }
        Err(e) => crate::install::fail(e),
    }
}

/// `passmanager unenroll`：删除远程配置与令牌，移除 MCP 配置与写入的使用规则。服务器上的令牌请在网页里吊销。
pub fn unenroll() -> ExitCode {
    let run = crate::git_service::run_cmd;
    for m in crate::git_service::uninstall_all(&crate::git_service::Ctx::current(crate::git_proxy::DEFAULT_LISTEN, &run)) {
        println!("  · git-proxy：{m}");
    }
    for d in pm_platform::paths::client_config_dirs() {
        let mut removed = 0;
        for f in [CONFIG_FILE, TOKEN_FILE, KEYS_FILE, "git-proxy.token"] {
            if std::fs::remove_file(d.join(f)).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            println!("已删除远程配置（{} 个文件，{}）", removed, d.display());
        }
    }
    for a in pm_tui::agents::ADAPTERS.iter().filter(|a| a.configured()) {
        match a.disconnect() {
            Ok(()) => println!("  · {}：已移除 MCP 配置", a.name),
            Err(e) => println!("  · {}：移除 MCP 配置失败（{e}）", a.name),
        }
    }
    for (name, path, r) in crate::agent_instructions::remove_all() {
        match r {
            Ok(true) => println!("  · {name}：已移除使用规则（{}）", path.display()),
            Ok(false) => {}
            Err(e) => println!("  · {name}：未移除使用规则（{e}）"),
        }
    }
    println!("服务器上的令牌请在网页\"Agent 令牌\"页吊销，或在服务器上运行 passmanager token revoke <ID>。");
    ExitCode::SUCCESS
}

/// 本机已注册的服务器（`主机:端口`），用于 `passmanager show` 的公开说明。
pub fn connected_server() -> Option<String> {
    match load_in(&dir()) {
        Some(Ok(c)) => Some(format!("{}:{}", c.server, c.port)),
        _ => None,
    }
}

/// 本机注册的服务器主机名（用于错误后面的 Next: 提示里的 `ssh root@<服务器>`）。
pub fn server_host() -> Option<String> {
    match load_in(&dir()) {
        Some(Ok(c)) => Some(c.server),
        _ => None,
    }
}

/// 非服务器上的 `passmanager status`：显示远程配置并测试连接。
pub fn status() -> ExitCode {
    let d = dir();
    match load_in(&d) {
        None => {
            println!(
                "没有远程配置（{}）。本机用法：PassManager（单机模式）或 passmanager enroll <注册码>。",
                d.join(CONFIG_FILE).display()
            );
            ExitCode::from(1)
        }
        Some(Err(e)) => crate::install::fail(e),
        Some(Ok(cfg)) => {
            println!("服务器       {}:{}", cfg.server, cfg.port);
            println!("公钥指纹     {}", fpr_text(&cfg.fingerprint));
            let r = connect_in(&d, &cfg).and_then(|mut c| c.call_as::<pm_proto::StatusView>(&pm_proto::Request::Status));
            match r {
                Ok(s) => {
                    println!("连接         正常（双层加密）；库{}", if s.locked { "已锁定" } else { "已解锁" });
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("连接         失败：{}: {}", e.code, e.message);
                    ExitCode::from(1)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_toml_roundtrip_and_validation() {
        let c = RemoteConfig { server: "pm.example.com".into(), port: 8443, fingerprint: [7u8; 48], connect_addr: None, ca_file: None };
        let t = c.to_toml();
        assert!(t.contains("server = \"pm.example.com\"") && t.contains("port = 8443"));
        assert_eq!(RemoteConfig::parse(&t).unwrap(), c);
        let c2 = RemoteConfig { connect_addr: Some("127.0.0.1:9".parse().unwrap()), ca_file: Some("/tmp/ca.pem".into()), ..c.clone() };
        assert_eq!(RemoteConfig::parse(&c2.to_toml()).unwrap(), c2);
        for bad in [
            "",
            "server = \"x\"",
            "server = \"x\"\nport = 0\nfingerprint = \"AA\"",
            "server = \"x\"\nport = 70000\nfingerprint = \"AA\"",
            "port = 1\nfingerprint=\"AA\"",
            "not toml [",
        ] {
            assert!(RemoteConfig::parse(bad).is_err(), "{bad}");
        }
        let mut c3 = c.to_toml();
        c3.push_str("connect_addr = \"nope\"\n");
        assert!(RemoteConfig::parse(&c3).is_err());
    }

    #[test]
    fn cached_bundle_is_checked_against_the_pinned_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = b"PMK1\x00\x00\x00\x01a\x00\x00\x00\x01b".to_vec();
        let cfg = RemoteConfig {
            server: "pm.test".into(),
            port: 8443,
            fingerprint: pm_net::inner::fingerprint(&bundle),
            connect_addr: None,
            ca_file: None,
        };
        assert!(server_public(dir.path(), &cfg).is_err(), "没有缓存");
        std::fs::write(dir.path().join(KEYS_FILE), &bundle).unwrap();
        assert!(server_public(dir.path(), &cfg).is_ok());
        let mut tampered = bundle.clone();
        tampered[8] = b'z';
        std::fs::write(dir.path().join(KEYS_FILE), &tampered).unwrap();
        assert!(server_public(dir.path(), &cfg).err().unwrap().contains("指纹不符"));
        // 没有令牌：明确的错误码。
        std::fs::write(dir.path().join(KEYS_FILE), &bundle).unwrap();
        if std::env::var_os(ENV_TOKEN).is_none() {
            assert_eq!(connect_in(dir.path(), &cfg).err().unwrap().code, "NO_TOKEN");
        }
        assert!(load_in(dir.path()).is_none());
        std::fs::write(dir.path().join(CONFIG_FILE), "garbage [").unwrap();
        assert!(load_in(dir.path()).unwrap().is_err());
    }
}

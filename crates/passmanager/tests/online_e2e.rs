//! 局域网在线版端到端测试（本机、用户模式、真实进程）：
//! `init` → 导入证书 → 启动服务（自动解锁无口令库）→ root 的 `token add` → Agent `enroll`（双层加密）→
//! 网页一次性链接登录并新增条目（密钥只写不读）→ MCP `list` 与 `http`（打本地自签 HTTPS 回显）全程脱敏 →
//! 网络上的口令 / 首次设置 / root 握手被静默拒绝 → 非允许网段的来源被拒 → 吊销令牌立即失效 →
//! kill -9 后重启自动解锁、主库文件损坏时从 .bak 恢复 → 配置错误以 78 退出。
//!
//! 只在 Linux 上运行：服务器模式只支持 Linux，且测试用 127.0.0.2 作为"非允许来源"。
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pm_net::client::Target;
use pm_net::inner::ServerPublic;
use pm_proto::{Client, Hello, PROTO_V};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_PassManager");
const SECRET: &str = "ghp_OnlineSecret+/=987654321";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Env {
    home: PathBuf,
    agent_dir: PathBuf,
    web: u16,
    agent: u16,
    ca: PathBuf,
    ca_pem: String,
}

impl Env {
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args).env("PASSMANAGER_HOME", &self.home).env_remove("PASSMANAGER_TOKEN").env_remove("PASSMANAGER_CONFIG_DIR");
        c.env("PASSMANAGER_TPM_SOCKET", "/nonexistent/tpm.sock").env("PASSMANAGER_TPM_DEVICE", "/nonexistent/tpmrm0");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).stdin(Stdio::null()).output().unwrap()
    }

    /// Agent 端进程：没有 PASSMANAGER_HOME（不是测试布局），只用远程配置目录。
    fn agent_cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args).env_remove("PASSMANAGER_HOME").env_remove("PASSMANAGER_TOKEN").env("PASSMANAGER_CONFIG_DIR", &self.agent_dir);
        c
    }

    fn start(&self) -> Child {
        let child = self.cmd(&["service", "--user"]).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
        let t0 = Instant::now();
        while !(self.home.join("run/passmanager.sock").exists()
            && TcpStream::connect(("127.0.0.1", self.agent)).is_ok()
            && TcpStream::connect(("127.0.0.1", self.web)).is_ok())
        {
            assert!(t0.elapsed() < Duration::from_secs(60), "service did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        child
    }

    fn target(&self) -> Target {
        Target {
            host: "pm.test".into(),
            port: self.agent,
            connect_addr: Some(SocketAddr::from(([127, 0, 0, 1], self.agent))),
            extra_ca_pem: Some(self.ca_pem.clone()),
        }
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---------- 网页客户端（HTTP/1.1 over TLS，与浏览器相同的后量子策略） ----------

struct Http {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Http {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
}

fn https(env: &Env, method: &str, path: &str, cookie: Option<&str>, form: Option<&str>) -> Http {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from_pem_slice(env.ca_pem.as_bytes()).unwrap()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(pm_net::tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = rustls::ClientConnection::new(Arc::new(cfg), "pm.test".try_into().unwrap()).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", env.web)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: pm.test:{}\r\nConnection: close\r\n", env.web);
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: __Host-pm={c}\r\n"));
    }
    match form {
        Some(f) => req.push_str(&format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{f}", f.len())),
        None => req.push_str("\r\n"),
    }
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines.next().unwrap_or("").split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    // 分块编码：去掉块长度行（只用于内容检查）。
    Http { status, headers, body: body.to_string() }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

// ---------- 本地自签 HTTPS 回显（被代填的目标） ----------

fn echo_server() -> u16 {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cfg = Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let cfg = cfg.clone();
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, s);
                let mut r = BufReader::new(&mut tls);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{head}",
                    head.len()
                );
                let _ = tls.write_all(resp.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

fn mcp(env: &Env, calls: &[Value]) -> Vec<Value> {
    let mut c = env.agent_cmd(&["mcp"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    {
        let stdin = c.stdin.as_mut().unwrap();
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}})).unwrap();
        for (i, call) in calls.iter().enumerate() {
            writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":i + 1,"method":"tools/call","params":call})).unwrap();
        }
    }
    drop(c.stdin.take());
    let mut out = String::new();
    c.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    let _ = c.wait();
    out.lines().skip(1).map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn tool_text(v: &Value) -> String {
    v["result"]["content"][0]["text"].as_str().unwrap_or("").to_string()
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn lan_server_end_to_end() {
    let base = PathBuf::from("/tmp").join(format!("pm-online-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let (cert, key) = pm_net::tls::self_signed(&["pm.test"]);
    let ca = base.join("ca.pem");
    std::fs::write(&ca, &cert).unwrap();
    std::fs::write(base.join("key.pem"), &key).unwrap();
    let env = Env {
        home: base.join("server"),
        agent_dir: base.join("agent"),
        web: free_port(),
        agent: free_port(),
        ca: ca.clone(),
        ca_pem: cert.clone(),
    };
    std::fs::create_dir_all(&env.home).unwrap();

    // ---- init（无口令库、内层密钥）与证书导入 ----
    let (w, a) = (env.web.to_string(), env.agent.to_string());
    let o = env.run(&[
        "init",
        "--skip-acme",
        "--no-start",
        "--domain",
        "pm.test",
        "--lan",
        "127.0.0.1/32",
        "--bind",
        "127.0.0.1",
        "--web-port",
        &w,
        "--agent-port",
        &a,
        "--acme-directory",
        "",
    ]);
    assert!(o.status.success(), "init: {}{}", stdout(&o), stderr(&o));
    let data = env.home.join("data");
    for f in ["vault.pmv", "server-keys.pub", "server-keys.sealed", "install.json"] {
        assert!(data.join(f).exists(), "{f}");
    }
    let h = pm_vault::Vault::read_header(&data.join("vault.pmv")).unwrap();
    assert_eq!(h.mode, pm_vault::VaultMode::DeviceOnly);
    // 再次运行 init：幂等，库与密钥不变。
    let fpr_before = std::fs::read(data.join("server-keys.pub")).unwrap();
    assert!(env.run(&["init", "--skip-acme", "--no-start"]).status.success());
    assert_eq!(std::fs::read(data.join("server-keys.pub")).unwrap(), fpr_before);
    let o = env.run(&["import-cert", ca.to_str().unwrap(), base.join("key.pem").to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(!std::fs::read(data.join("tls/key.sealed")).unwrap().windows(11).any(|w| w == b"PRIVATE KEY"));

    // ---- 启动：自动解锁 ----
    let mut svc = env.start();
    let st = env.run(&["status"]);
    assert!(stdout(&st).contains("已解锁") && stdout(&st).contains("全部通过"), "{}{}", stdout(&st), stderr(&st));

    // ---- 注册 ----
    let o = env.run(&["token", "add", "laptop"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let url = stdout(&o).trim().to_string();
    assert!(url.starts_with(&format!("pm-enroll://pm.test:{a}/")), "{url}");
    // 指纹不对的注册码：拒绝（不消耗真正的注册码）。
    let parsed = pm_net::enroll::EnrollUrl::parse(&url).unwrap();
    let mut wrong = parsed.clone();
    wrong.fpr[0] ^= 1;
    let addr = format!("127.0.0.1:{a}");
    let enroll = |u: &str| {
        env.agent_cmd(&["enroll", "--no-mcp", "--connect-addr", &addr, "--ca-file", env.ca.to_str().unwrap(), u]).output().unwrap()
    };
    let o = enroll(&wrong.to_string());
    assert!(!o.status.success() && stderr(&o).contains("指纹不符"), "{}", stderr(&o));
    let o = enroll(&url);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    for (f, m) in [("token", 0o600), ("remote.toml", 0o600), ("server-keys.bin", 0o600)] {
        assert_eq!(mode_of(&env.agent_dir.join(f)), m, "{f}");
    }
    assert_eq!(mode_of(&env.agent_dir), 0o700);
    let token = std::fs::read_to_string(env.agent_dir.join("token")).unwrap();
    assert!(token.starts_with("pm_"));
    // 同一注册码不能再用。
    let reuse_dir = base.join("agent2");
    let o = env
        .agent_cmd(&["enroll", "--no-mcp", "--connect-addr", &addr, "--ca-file", env.ca.to_str().unwrap(), &url])
        .env("PASSMANAGER_CONFIG_DIR", &reuse_dir)
        .output()
        .unwrap();
    assert!(!o.status.success(), "注册码只能使用一次");
    // 服务器上只保存令牌哈希。
    assert!(!std::fs::read_to_string(data.join("tokens.json")).unwrap().contains(&token));

    // ---- 网络上的口令 / 首次设置 / root / 错误令牌：静默拒绝 ----
    let public = ServerPublic::from_bundle(&fpr_before, &parsed.fpr).unwrap();
    for hello in [
        Hello::Password { v: PROTO_V, password: "anything".into() },
        Hello::Setup { v: PROTO_V, password: "anything-long".into() },
        Hello::Root { v: PROTO_V },
        Hello::Token { v: PROTO_V, token: "pm_wrong".into() },
        Hello::Enroll { v: PROTO_V, code: parsed.code.clone(), host: String::new() },
    ] {
        let stream = pm_net::client::connect(&env.target(), &public).unwrap();
        assert!(Client::connect_stream(stream, &hello).is_err());
    }
    // 非允许网段的来源（127.0.0.2 不在 127.0.0.1/32 内）：连 TLS 握手都没有。
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        use tokio::io::AsyncReadExt;
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        let mut s = sock.connect(SocketAddr::from(([127, 0, 0, 1], env.agent))).await.unwrap();
        let mut b = [0u8; 8];
        let r = tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await.expect("must be closed immediately");
        assert!(matches!(r, Ok(0) | Err(_)));
    });

    // ---- 网页：一次性链接登录、新增条目（密钥只写） ----
    let o = env.run(&["login"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let link = stdout(&o).trim().to_string();
    let path = link.split_once(&format!("pm.test:{w}")).unwrap().1.to_string();
    let r = https(&env, "GET", &path, None, None);
    assert_eq!(r.status, 200);
    assert!(r.body.contains("X25519MLKEM768") && r.body.contains("TLS13_AES_256_GCM_SHA384"), "页面显示协商的后量子算法");
    assert!(r.header("content-security-policy").unwrap().starts_with("default-src 'none'"));
    let r = https(&env, "POST", &path, None, Some(""));
    assert_eq!(r.status, 303);
    let cookie = r.header("set-cookie").unwrap().split(';').next().unwrap().strip_prefix("__Host-pm=").unwrap().to_string();
    assert_eq!(https(&env, "POST", &path, None, Some("")).status, 404, "链接只能使用一次");
    let page = https(&env, "GET", "/entries/new", Some(&cookie), None);
    let i = page.body.find("name=\"csrf\" value=\"").unwrap() + 19;
    let csrf = page.body[i..].split('"').next().unwrap().to_string();
    let form = format!("csrf={csrf}&name=echo&domains=127.0.0.1&secret={}&self_signed=1", enc(SECRET));
    assert_eq!(https(&env, "POST", "/entries", Some(&cookie), Some(&form)).status, 303);
    for p in ["/", "/entries", "/entries/echo/edit", "/tokens", "/security", "/pins", "/settings"] {
        let r = https(&env, "GET", p, Some(&cookie), None);
        assert_eq!(r.status, 200, "{p}");
        assert!(!r.body.contains(SECRET) && !r.body.contains("OnlineSecret"), "{p} 泄露了密钥");
    }
    assert!(https(&env, "GET", "/tokens", Some(&cookie), None).body.contains("laptop"));

    // ---- Agent：MCP list 与 http（经双层通道），结果脱敏 ----
    let echo = echo_server();
    let out = mcp(
        &env,
        &[
            json!({"name": "list", "arguments": {}}),
            json!({"name": "http", "arguments": {"method": "GET", "url": format!("https://127.0.0.1:{echo}/x"), "headers": {"Authorization": "Bearer {{secret}}"}}}),
        ],
    );
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(tool_text(&out[0]).contains("\"echo\""), "{}", tool_text(&out[0]));
    let t = tool_text(&out[1]);
    assert!(t.contains("[REDACTED:echo]") && !t.contains(SECRET), "{t}");
    let o = env.agent_cmd(&["list"]).output().unwrap();
    assert!(o.status.success() && stdout(&o).contains("echo"), "{}", stdout(&o));
    let o = env.agent_cmd(&["status"]).output().unwrap();
    assert!(stdout(&o).contains("双层加密"), "{}", stdout(&o));

    // ---- kill -9 后重启：自动解锁，无需任何人工操作 ----
    svc.kill().unwrap();
    let _ = svc.wait();
    let _ = std::fs::remove_file(env.home.join("run/passmanager.sock"));
    let mut svc = env.start();
    let o = env.agent_cmd(&["list"]).output().unwrap();
    assert!(o.status.success() && stdout(&o).contains("echo"), "{}", stdout(&o));

    // ---- 吊销令牌：立即失效 ----
    let o = env.run(&["token", "list"]);
    let id = stdout(&o).lines().find(|l| l.contains("laptop")).unwrap().split_whitespace().next().unwrap().to_string();
    assert!(env.run(&["token", "revoke", &id]).status.success());
    let o = env.agent_cmd(&["list"]).output().unwrap();
    assert!(!o.status.success() && stdout(&o).contains("AUTH_FAILED"), "{}", stdout(&o));

    // ---- 断电：主库文件被截断 → 重启后从 .bak 恢复（.bak 由上次保存产生） ----
    svc.kill().unwrap();
    let _ = svc.wait();
    let _ = std::fs::remove_file(env.home.join("run/passmanager.sock"));
    let v = std::fs::read(data.join("vault.pmv")).unwrap();
    std::fs::write(data.join("vault.pmv"), &v[..v.len() / 3]).unwrap();
    let mut svc = env.start();
    let st = stdout(&env.run(&["status"]));
    assert!(st.contains("已解锁") && st.contains(".bak"), "{st}");
    svc.kill().unwrap();
    let _ = svc.wait();
    let _ = std::fs::remove_file(env.home.join("run/passmanager.sock"));

    // ---- 配置错误：以 78 退出（systemd 不再重启） ----
    let info_path = data.join("install.json");
    let orig = std::fs::read_to_string(&info_path).unwrap();
    std::fs::write(&info_path, orig.replace("127.0.0.1/32", "not-a-cidr")).unwrap();
    let o = env.run(&["service", "--user"]);
    assert_eq!(o.status.code(), Some(78), "{}", stderr(&o));
    std::fs::write(&info_path, &orig).unwrap();
    std::fs::rename(data.join("server-keys.sealed"), data.join("moved")).unwrap();
    let o = env.run(&["service", "--user"]);
    assert_eq!(o.status.code(), Some(78), "{}", stderr(&o));
    std::fs::rename(data.join("moved"), data.join("server-keys.sealed")).unwrap();
    // 端口被占用：暂时性故障（75，systemd 有限次重试）。
    let _busy = TcpListener::bind(("127.0.0.1", env.web)).unwrap();
    let o = env.run(&["service", "--user"]);
    assert_eq!(o.status.code(), Some(75), "{}", stderr(&o));
    let _ = std::fs::remove_dir_all(&base);
}

//! 局域网在线版端到端测试（本机、用户模式、真实进程）：
//! `init` → 导入证书 → 启动服务（自动解锁无口令库）→ root 的 `show --label --url` → Agent `enroll`（双层加密）→
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
use pm_proto::{Client, Hello, PROTO_V, Request};
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
    let o = env.run(&["show", "--label", "laptop", "--url"]);
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
        Hello::Token { v: PROTO_V, token: "pm_wrong".into(), dial: false },
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
    let form = format!("csrf={csrf}&name=echo&domains=127.0.0.1&op_http=1&secret={}&self_signed=1", enc(SECRET));
    assert_eq!(https(&env, "POST", "/entries", Some(&cookie), Some(&form)).status, 303);
    for p in ["/", "/entries", "/entries/echo/edit", "/tokens", "/security", "/pins", "/settings"] {
        let r = https(&env, "GET", p, Some(&cookie), None);
        assert_eq!(r.status, 200, "{p}");
        assert!(!r.body.contains(SECRET) && !r.body.contains("OnlineSecret"), "{p} 泄露了密钥");
    }
    assert!(https(&env, "GET", "/tokens", Some(&cookie), None).body.contains("laptop"));
    // 编辑页遮住已保存的值（一段都不露）；"全部显示"要 POST + CSRF，之后值在可编辑的输入框里
    let edit = https(&env, "GET", "/entries/echo/edit", Some(&cookie), None);
    assert!(edit.body.contains("••••••••") && !edit.body.contains(SECRET) && !edit.body.contains("4321"), "遮住");
    assert_eq!(https(&env, "POST", "/entries/echo/show", Some(&cookie), Some("csrf=wrong")).status, 403);
    let shown = https(&env, "POST", "/entries/echo/show", Some(&cookie), Some(&format!("csrf={csrf}")));
    assert_eq!(shown.status, 200);
    assert!(shown.body.contains(&SECRET.replace('/', "&#x2f;")) || shown.body.contains(SECRET), "显示后有完整的值");
    // 遮住时新增一行：服务端在原值后追加（不覆盖），之后编辑页显示两个遮罩；全部显示能看到原来的与新增的
    let add =
        format!("csrf={csrf}&name=echo&domains=127.0.0.1&op_http=1&self_signed=1&kind=password&line_count=1&secret=second-line-value");
    assert_eq!(https(&env, "POST", "/entries/echo", Some(&cookie), Some(&add)).status, 303);
    let edit = https(&env, "GET", "/entries/echo/edit", Some(&cookie), None);
    assert_eq!(edit.body.matches("••••••••").count(), 2, "两行两个遮罩");
    assert!(!edit.body.contains("second-line-value") && !edit.body.contains(SECRET));
    let shown = https(&env, "POST", "/entries/echo/show", Some(&cookie), Some(&format!("csrf={csrf}")));
    assert!(shown.body.contains("second-line-value"), "追加的行");
    assert!(shown.body.contains(&SECRET.replace('/', "&#x2f;")) || shown.body.contains(SECRET), "原来的行还在");
    // 删回去：勾选删除第 2 行，值恢复原样（之后的 Agent 测试仍用这个条目）
    let del = format!("csrf={csrf}&name=echo&domains=127.0.0.1&op_http=1&self_signed=1&kind=password&line_count=2&line_remove_1=1&secret=");
    assert_eq!(https(&env, "POST", "/entries/echo", Some(&cookie), Some(&del)).status, 303);
    assert_eq!(https(&env, "GET", "/entries/echo/edit", Some(&cookie), None).body.matches("••••••••").count(), 1);

    // ---- 服务器模式没有 TUI：信任新指纹只能在网页"主机指纹"页做 ----
    for args in [&[][..], &["trust", "127.0.0.1"]] {
        let o = env.run(args);
        assert!(!o.status.success() && stderr(&o).contains("服务器模式没有 TUI") && stderr(&o).contains("主机指纹"), "{}", stderr(&o));
    }
    // root 会话（本机 socket）发 TrustPins：拒绝
    let mut root = Client::connect_at(&env.home.join("run/passmanager.sock"), &Hello::Root { v: PROTO_V }).unwrap();
    let e = root.call(&Request::TrustPins { pattern: "127.0.0.1".into() }).unwrap_err();
    assert!(e.code == "FORBIDDEN" && e.message.contains("web UI"), "{}: {}", e.code, e.message);
    // 网页：要 CSRF，带上之后照常清除
    assert_eq!(https(&env, "POST", "/pins/trust", Some(&cookie), Some("csrf=wrong&pattern=127.0.0.1")).status, 403);
    let r = https(&env, "POST", "/pins/trust", Some(&cookie), Some(&format!("csrf={csrf}&pattern=127.0.0.1")));
    assert_eq!(r.status, 303, "网页信任");

    // ---- Agent：MCP lookup 与 http（经双层通道），结果脱敏 ----
    let echo = echo_server();
    let out = mcp(
        &env,
        &[
            json!({"name": "lookup", "arguments": {"target": format!("https://127.0.0.1:{echo}/x")}}),
            json!({"name": "http", "arguments": {"method": "GET", "url": format!("https://127.0.0.1:{echo}/x"), "headers": {"Authorization": "Bearer {{secret}}"}}}),
        ],
    );
    assert_eq!(out.len(), 2, "{out:?}");
    let found = tool_text(&out[0]);
    assert!(found.contains("\"echo\"") && found.contains("{{secret}}") && !found.contains(SECRET), "{found}");
    let t = tool_text(&out[1]);
    assert!(t.contains("[REDACTED:echo]") && !t.contains(SECRET), "{t}");
    let o = env.agent_cmd(&["lookup", "127.0.0.1"]).output().unwrap();
    assert!(o.status.success() && stdout(&o).contains("echo"), "{}", stdout(&o));
    let o = env.agent_cmd(&["status"]).output().unwrap();
    assert!(stdout(&o).contains("双层加密"), "{}", stdout(&o));
    // 已注册的客户端没有本机 TUI：不带参数、trust、unlock 都拒绝，并指向服务器的网页
    for args in [&[][..], &["trust", "127.0.0.1"], &["unlock"]] {
        let o = env.agent_cmd(args).stdin(Stdio::null()).output().unwrap();
        let e = stderr(&o);
        assert!(!o.status.success() && e.contains("已注册到 PassManager 服务器 pm.test") && e.contains("passmanager web"), "{args:?}: {e}");
    }

    // ---- 客户端自动更新：开发构建的客户端不检查也不被替换；开发构建的服务器不提供更新 ----
    assert!(!env.agent_dir.join("update-check").exists(), "开发构建的客户端运行前不检查更新");
    let o = env.agent_cmd(&["self-update"]).output().unwrap();
    assert!(!o.status.success() && stderr(&o).contains("开发构建"), "{}", stderr(&o));
    let ab = data.join("agent-bin");
    std::fs::create_dir_all(&ab).unwrap();
    let fake = b"#!/bin/sh\nexit 0\n";
    std::fs::write(ab.join("PassManager-x86_64-unknown-linux-gnu"), fake).unwrap();
    let ver = env!("CARGO_PKG_VERSION");
    std::fs::write(ab.join("RELEASE"), format!("{ver} x86_64-unknown-linux-gnu {}\n", hex::encode(pm_crypto::sha256(fake)))).unwrap();
    let stream = pm_net::client::connect(&env.target(), &public).unwrap();
    let mut c = Client::connect_stream(stream, &Hello::Token { v: PROTO_V, token: token.trim().to_string(), dial: false }).unwrap();
    let r = c.call(&Request::ClientUpdate { targets: vec!["x86_64-unknown-linux-gnu".into()], have: "0.0.1".into() }).unwrap();
    assert!(r.is_null(), "开发构建的服务器不提供更新：{r}");
    std::fs::remove_dir_all(&ab).unwrap();

    // ---- kill -9 后重启：自动解锁，无需任何人工操作 ----
    svc.kill().unwrap();
    let _ = svc.wait();
    let _ = std::fs::remove_file(env.home.join("run/passmanager.sock"));
    let mut svc = env.start();
    let o = env.agent_cmd(&["lookup", "127.0.0.1"]).output().unwrap();
    assert!(o.status.success() && stdout(&o).contains("echo"), "{}", stdout(&o));

    // ---- 吊销令牌：立即失效 ----
    let o = env.run(&["token", "list"]);
    let id = stdout(&o).lines().find(|l| l.contains("laptop")).unwrap().split_whitespace().next().unwrap().to_string();
    assert!(env.run(&["token", "revoke", &id]).status.success());
    let o = env.agent_cmd(&["lookup", "127.0.0.1"]).output().unwrap();
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

// ---------- 经客户端网络连接 SSH 主机（服务器连不到、客户端连得到） ----------

const BOX_PW: &str = "ViaClientPw-5d2e!";

/// 测试 SSH 服务器看到的事件（"password 用户"、"exec 命令"）与接受过的 TCP 连接数。
#[derive(Clone, Default)]
struct SshLog {
    events: Arc<std::sync::Mutex<Vec<String>>>,
    conns: Arc<std::sync::atomic::AtomicUsize>,
}

impl SshLog {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
    fn conns(&self) -> usize {
        self.conns.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// 测试 SSH 服务器：只有口令认证；exec 回显命令。
struct Box1 {
    log: SshLog,
    channels: std::collections::HashMap<russh::ChannelId, russh::Channel<russh::server::Msg>>,
}

impl russh::server::Handler for Box1 {
    type Error = russh::Error;

    async fn auth_password(&mut self, u: &str, p: &str) -> Result<russh::server::Auth, Self::Error> {
        self.log.events.lock().unwrap().push(format!("password {u}"));
        Ok(if p == BOX_PW { russh::server::Auth::Accept } else { russh::server::Auth::reject() })
    }
    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _s: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.log.events.lock().unwrap().push(format!("exec {}", String::from_utf8_lossy(data)));
        session.channel_success(channel)?;
        session.data(channel, format!("target ran: {}\n", String::from_utf8_lossy(data)).into_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

/// 在 `port`（0 为随机）上起测试 SSH 服务器，主机密钥取自 `host_key`（OpenSSH 私钥文件）。
fn ssh_box(rt: &tokio::runtime::Runtime, port: u16, host_key: &Path, log: &SshLog) -> (u16, tokio::task::JoinHandle<()>) {
    let key = russh::keys::decode_secret_key(&std::fs::read_to_string(host_key).unwrap(), None).unwrap();
    let cfg = Arc::new(russh::server::Config {
        keys: vec![key],
        methods: russh::MethodSet::from(&[russh::MethodKind::Password][..]),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    let l = rt.block_on(tokio::net::TcpListener::bind(("127.0.0.1", port))).unwrap();
    let port = l.local_addr().unwrap().port();
    let log = log.clone();
    let task = rt.spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
            log.conns.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (cfg, h) = (cfg.clone(), Box1 { log: log.clone(), channels: Default::default() });
            tokio::spawn(async move {
                if let Ok(r) = russh::server::run_stream(cfg, s, h).await {
                    let _ = r.await;
                }
            });
        }
    });
    (port, task)
}

/// OpenSSH 主机密钥（ECDSA P-384）与它的 SHA256 指纹。
fn host_key(dir: &Path, name: &str) -> (PathBuf, String) {
    let p = dir.join(name);
    let o = Command::new("ssh-keygen").args(["-q", "-t", "ecdsa", "-b", "384", "-N", "", "-C", "", "-f"]).arg(&p).output().unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    let k = russh::keys::decode_secret_key(&std::fs::read_to_string(&p).unwrap(), None).unwrap();
    let fp = k.public_key().fingerprint(russh::keys::HashAlg::Sha256).to_string();
    (p, fp)
}

#[test]
fn ssh_via_the_clients_network() {
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("跳过：没有 ssh-keygen");
        return;
    }
    let base = PathBuf::from("/tmp").join(format!("pm-via-{}", std::process::id()));
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
    let o = env.run(&["import-cert", ca.to_str().unwrap(), base.join("key.pem").to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    // 服务日志写进文件（之后检查"经客户端"的记录与有没有泄露口令）
    let svc_log = base.join("service.log");
    let mut svc = env.cmd(&["service", "--user"]).stdout(Stdio::null()).stderr(std::fs::File::create(&svc_log).unwrap()).spawn().unwrap();
    let t0 = Instant::now();
    while !(TcpStream::connect(("127.0.0.1", env.agent)).is_ok() && TcpStream::connect(("127.0.0.1", env.web)).is_ok()) {
        assert!(t0.elapsed() < Duration::from_secs(60), "service did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    // 注册客户端
    let url = stdout(&env.run(&["show", "--label", "laptop", "--url"])).trim().to_string();
    let addr = format!("127.0.0.1:{a}");
    let o = env
        .agent_cmd(&[
            "enroll",
            "--no-mcp",
            "--no-instructions",
            "--no-git-proxy",
            "--connect-addr",
            &addr,
            "--ca-file",
            ca.to_str().unwrap(),
            &url,
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    // 网页登录
    let link = stdout(&env.run(&["login"])).trim().to_string();
    let path = link.split_once(&format!("pm.test:{w}")).unwrap().1.to_string();
    let r = https(&env, "POST", &path, None, Some(""));
    let cookie = r.header("set-cookie").unwrap().split(';').next().unwrap().strip_prefix("__Host-pm=").unwrap().to_string();
    let page = https(&env, "GET", "/entries/new", Some(&cookie), None);
    let i = page.body.find("name=\"csrf\" value=\"").unwrap() + 19;
    let csrf = page.body[i..].split('"').next().unwrap().to_string();

    // 目标 SSH 服务器与它的口令条目
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let (k1, fp1) = host_key(&base, "hk1");
    let (k2, fp2) = host_key(&base, "hk2");
    let log = SshLog::default();
    let (port, task) = ssh_box(&rt, 0, &k1, &log);
    let hp = format!("127.0.0.1:{port}");
    let target = format!("deploy@{hp}");
    let form = format!("csrf={csrf}&name=box&domains={}&op_ssh=1&secret={}", enc(&hp), enc(BOX_PW));
    assert_eq!(https(&env, "POST", "/entries", Some(&cookie), Some(&form)).status, 303);
    let mut outputs = String::new();
    // 客户端命令：返回（是否成功, 标准输出 + 标准错误）；调用方把输出记进 outputs 供最后检查
    let ssh = |args: &[&str]| {
        let o = env.agent_cmd(args).stdin(Stdio::null()).output().unwrap();
        (o.status.success(), stdout(&o) + &stderr(&o))
    };

    // ---- 只能在网页上设置：root 会话被拒；网页要 CSRF ----
    let mut root = Client::connect_at(&env.home.join("run/passmanager.sock"), &Hello::Root { v: PROTO_V }).unwrap();
    let e = root.call(&Request::AddViaClientHost { host: hp.clone() }).unwrap_err();
    assert!(e.code == "FORBIDDEN" && e.message.contains("web UI"), "{}: {}", e.code, e.message);
    assert_eq!(https(&env, "POST", "/pins/via", Some(&cookie), Some(&format!("csrf=wrong&host={}", enc(&hp)))).status, 403);
    assert_eq!(https(&env, "POST", "/pins/via", Some(&cookie), Some(&format!("csrf={csrf}&host={}", enc(&hp)))).status, 303);
    assert!(https(&env, "GET", "/pins", Some(&cookie), None).body.contains(&hp));

    // ---- 第一次经客户端：主机密钥未确认，目标只看到一次 TCP 连接，收不到任何认证 ----
    let (ok, out) = ssh(&["ssh", &target, "uptime"]);
    outputs += &out;
    assert!(!ok && out.contains("HOST_KEY_UNCONFIRMED") && out.contains("Host fingerprints page") && out.contains(&fp1), "{out}");
    assert_eq!(log.conns(), 1, "客户端替服务器连了一次");
    assert!(log.take().is_empty(), "主机密钥未确认，目标收不到认证");
    // 网页：待确认（首次、经客户端），信任后记下的正是这个指纹
    // 网页转义 `/`（指纹是 base64，常带 `/`）
    let html = |s: &str| s.replace('/', "&#x2f;");
    let page = https(&env, "GET", "/pins", Some(&cookie), None).body;
    assert!(page.contains("首次") && page.contains("经客户端") && page.contains(&html(&fp1)), "{page}");
    assert_eq!(https(&env, "POST", "/pins/trust", Some(&cookie), Some(&format!("csrf={csrf}&pattern={}", enc(&hp)))).status, 303);
    let pins: Vec<pm_proto::PinView> = root.call_as(&Request::Pins).unwrap();
    let pin = pins.iter().find(|p| p.host_port == hp).expect("pin recorded");
    assert_eq!((pin.algo.as_str(), pin.fingerprint.as_str()), ("ecdsa-sha2-nistp384", fp1.as_str()));

    // ---- 信任后：CLI 与 MCP 都经客户端登录并执行 ----
    let (ok, out) = ssh(&["ssh", &target, "uptime"]);
    outputs += &out;
    assert!(ok && out.contains("target ran: uptime"), "{out}");
    let ev = log.take();
    assert!(ev.contains(&"password deploy".to_string()) && ev.contains(&"exec uptime".to_string()), "{ev:?}");
    assert_eq!(log.conns(), 2);
    let out = mcp(&env, &[json!({"name": "ssh", "arguments": {"target": target, "command": "id"}})]);
    let t = tool_text(&out[0]);
    outputs += &t;
    assert!(t.contains("target ran: id"), "{t}");
    assert_eq!(log.conns(), 3);
    log.take();

    // ---- 不能转发的连接（旧版本客户端）：RELAY_UNAVAILABLE，服务器也没有自己去连 ----
    let token = std::fs::read_to_string(env.agent_dir.join("token")).unwrap();
    let parsed = pm_net::enroll::EnrollUrl::parse(&url).unwrap();
    let public = ServerPublic::from_bundle(&std::fs::read(env.home.join("data/server-keys.pub")).unwrap(), &parsed.fpr).unwrap();
    let stream = pm_net::client::connect(&env.target(), &public).unwrap();
    let mut old = Client::connect_stream(stream, &Hello::Token { v: PROTO_V, token: token.trim().to_string(), dial: false }).unwrap();
    let e = old.call(&Request::Ssh { target: target.clone(), command: "uptime".into() }).unwrap_err();
    assert_eq!(e.code, "RELAY_UNAVAILABLE", "{}", e.message);
    assert_eq!(log.conns(), 3, "服务器没有直连");

    // ---- 客户端连不上目标：很快返回 UPSTREAM_ERROR，原因来自客户端 ----
    let closed = free_port();
    let hp2 = format!("127.0.0.1:{closed}");
    let form = format!("csrf={csrf}&name=box2&domains={}&op_ssh=1&secret={}", enc(&hp2), enc(BOX_PW));
    assert_eq!(https(&env, "POST", "/entries", Some(&cookie), Some(&form)).status, 303);
    assert_eq!(https(&env, "POST", "/pins/via", Some(&cookie), Some(&format!("csrf={csrf}&host={}", enc(&hp2)))).status, 303);
    let t0 = Instant::now();
    let (ok, out) = ssh(&["ssh", &format!("deploy@{hp2}"), "uptime"]);
    outputs += &out;
    assert!(!ok && out.contains("UPSTREAM_ERROR") && out.contains(&format!("the client could not connect to {hp2}")), "{out}");
    assert!(t0.elapsed() < Duration::from_secs(20), "不必等到超时");

    // ---- 主机密钥变化（经客户端）：HOST_KEY_CHANGED，目标收不到认证；信任后记下新指纹 ----
    task.abort();
    std::thread::sleep(Duration::from_millis(300));
    let (_, task2) = ssh_box(&rt, port, &k2, &log);
    let (ok, out) = ssh(&["ssh", &target, "uptime"]);
    outputs += &out;
    assert!(!ok && out.contains("HOST_KEY_CHANGED") && out.contains("client's network") && out.contains(&fp2), "{out}");
    assert!(log.take().is_empty(), "主机密钥变化后目标收不到认证");
    assert_eq!(https(&env, "POST", "/pins/trust", Some(&cookie), Some(&format!("csrf={csrf}&pattern={}", enc(&hp)))).status, 303);
    let (ok, out) = ssh(&["ssh", &target, "uptime"]);
    outputs += &out;
    assert!(ok && out.contains("target ran: uptime"), "{out}");

    // ---- 改回直连：服务器自己连，不再经客户端 ----
    let via_lines = |s: &str| s.matches("ssh via the client's network: ").count();
    let before = via_lines(&std::fs::read_to_string(&svc_log).unwrap());
    assert!(before >= 4, "经客户端的每次连接都有记录：{before}");
    let r = https(&env, "POST", "/pins/via/remove", Some(&cookie), Some(&format!("csrf={csrf}&host_port={}", enc(&hp))));
    assert_eq!(r.status, 303);
    let (ok, out) = ssh(&["ssh", &target, "uptime"]);
    outputs += &out;
    assert!(ok && out.contains("target ran: uptime"), "{out}");
    let logtext = std::fs::read_to_string(&svc_log).unwrap();
    assert_eq!(via_lines(&logtext), before, "直连不经客户端");
    assert!(logtext.contains(&format!("ssh via the client's network enabled for {hp}")));
    assert!(logtext.contains(&format!("host key confirmed in the web UI for {hp}")));

    // ---- 口令从不出现在输出与日志里 ----
    assert!(!outputs.contains(BOX_PW) && !logtext.contains(BOX_PW));
    drop(task2);
    svc.kill().unwrap();
    let _ = svc.wait();
    let _ = std::fs::remove_dir_all(&base);
}

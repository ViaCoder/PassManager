//! 端到端测试：以用户模式启动真实的服务进程，通过本地协议（与 MCP/CLI 相同的客户端）验证：
//! 口令设置与解锁、令牌鉴权、防探测、条目管理、HTTPS 代填与脱敏、域名限制、只允许 HTTPS、
//! 不跟随跨主机重定向、自签证书指纹固定与变更、SSH 执行与主机密钥变更、锁定。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pm_proto::*;
use serde_json::{Value, json};

const PW: &str = "correct-horse-battery";
const GH_SECRET: &str = "ghp_TestSecret+/=0123456789";
const SSH_PW: &str = "ssh-Passw0rd!";

struct Service {
    child: Child,
    home: PathBuf,
    socket: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

impl Service {
    fn start(home: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_PassManager"))
            .args(["service", "--user"])
            .env("PASSMANAGER_HOME", home)
            .env("PASSMANAGER_INSECURE_TEST_KDF", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn service");
        // 由程序自己给出地址（Unix socket 路径或 Windows 命名管道名）。
        let out = Command::new(env!("CARGO_BIN_EXE_PassManager")).arg("socket-path").env("PASSMANAGER_HOME", home).output().unwrap();
        let socket = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
        let s = Self { child, home: home.to_path_buf(), socket };
        let start = Instant::now();
        while !s.listening() {
            assert!(start.elapsed() < Duration::from_secs(30), "service did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        s
    }

    fn listening(&self) -> bool {
        if cfg!(windows) {
            let name = self.socket.file_name().unwrap().to_owned();
            std::fs::read_dir(r"\\.\pipe\").is_ok_and(|rd| rd.flatten().any(|e| e.file_name().eq_ignore_ascii_case(&name)))
        } else {
            self.socket.exists()
        }
    }

    fn socket(&self) -> PathBuf {
        self.socket.clone()
    }

    /// 原始连接（用于防探测测试）。
    fn raw(&self) -> Box<dyn ReadWrite> {
        #[cfg(unix)]
        {
            let s = std::os::unix::net::UnixStream::connect(&self.socket).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            Box::new(s)
        }
        #[cfg(windows)]
        {
            Box::new(std::fs::OpenOptions::new().read(true).write(true).open(&self.socket).unwrap())
        }
    }

    fn admin(&self) -> Client {
        Client::connect_at(&self.socket(), &Hello::Password { v: PROTO_V, password: PW.into() }).expect("admin login")
    }

    fn agent(&self, token: &str) -> Result<Client, ApiError> {
        Client::connect_at(&self.socket(), &Hello::Token { v: PROTO_V, token: token.into() })
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn code(r: Result<Value, ApiError>) -> String {
    r.err().map(|e| e.code).unwrap_or_else(|| "OK".into())
}

// ---------- 本地 HTTPS 回显服务（自签证书） ----------

struct Tls {
    port: u16,
    stop: Arc<AtomicBool>,
}

impl Drop for Tls {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn tls_server(port: u16) -> Tls {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cfg = Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            if stop2.load(Ordering::SeqCst) {
                break;
            }
            let Ok(s) = s else { continue };
            let cfg = cfg.clone();
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, s);
                let mut reader = BufReader::new(&mut tls);
                let mut head = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    head.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; len];
                let _ = reader.read_exact(&mut body);
                let req = format!("{head}{}", String::from_utf8_lossy(&body));
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let resp = if path.starts_with("/redirect") {
                    "HTTP/1.1 302 Found\r\nLocation: https://example.invalid/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                } else {
                    // 回显完整请求，并附上 base64 与 hex 编码，用来验证脱敏。
                    let echo = format!("{req}\nB64:{}\nHEX:{}\n", STANDARD.encode(req.as_bytes()), hex_of(req.as_bytes()));
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: session=abc\r\nX-Echo-Auth: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{echo}",
                        req.lines().find(|l| l.to_ascii_lowercase().starts_with("authorization:")).unwrap_or("").replace("\r", ""),
                        echo.len()
                    )
                };
                let _ = tls.write_all(resp.as_bytes());
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    Tls { port, stop }
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------- 本地 SSH 测试服务器（russh） ----------

mod sftpd {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use russh_sftp::protocol::{Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode};

    pub type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;

    pub struct S(pub Files);

    fn ok(id: u32) -> Status {
        Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
    }

    impl russh_sftp::server::Handler for S {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn open(&mut self, id: u32, filename: String, pflags: OpenFlags, _attrs: FileAttributes) -> Result<Handle, Self::Error> {
            let mut f = self.0.lock().unwrap();
            if pflags.contains(OpenFlags::CREATE) && (pflags.contains(OpenFlags::TRUNCATE) || !f.contains_key(&filename)) {
                f.insert(filename.clone(), Vec::new());
            }
            if !f.contains_key(&filename) {
                return Err(StatusCode::NoSuchFile);
            }
            Ok(Handle { id, handle: filename })
        }

        async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
            Ok(ok(id))
        }

        async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
            let f = self.0.lock().unwrap();
            let d = f.get(&handle).ok_or(StatusCode::NoSuchFile)?;
            let off = offset as usize;
            if off >= d.len() {
                return Err(StatusCode::Eof);
            }
            Ok(Data { id, data: d[off..(off + len as usize).min(d.len())].to_vec() })
        }

        async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
            let mut f = self.0.lock().unwrap();
            let d = f.get_mut(&handle).ok_or(StatusCode::NoSuchFile)?;
            let off = offset as usize;
            if d.len() < off + data.len() {
                d.resize(off + data.len(), 0);
            }
            d[off..off + data.len()].copy_from_slice(&data);
            Ok(ok(id))
        }

        async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            let f = self.0.lock().unwrap();
            let d = f.get(&path).ok_or(StatusCode::NoSuchFile)?;
            Ok(Attrs { id, attrs: FileAttributes { size: Some(d.len() as u64), ..Default::default() } })
        }

        async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            self.stat(id, path).await
        }

        async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
            self.stat(id, handle).await
        }
    }
}

mod sshd {
    use std::collections::HashMap;
    use std::sync::Arc;

    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
    use russh::server::{Auth, Handler, Msg, Session};
    use russh::{Channel, ChannelId, MethodKind, MethodSet};

    pub struct H {
        pub files: super::sftpd::Files,
        pub channels: HashMap<ChannelId, Channel<Msg>>,
    }

    impl Handler for H {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            if user == "deploy" && password == super::SSH_PW { Ok(Auth::Accept) } else { Ok(Auth::reject()) }
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.channels.insert(channel.id(), channel);
            reply.accept().await;
            Ok(())
        }

        async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
            if name == "sftp"
                && let Some(ch) = self.channels.remove(&channel)
            {
                session.channel_success(channel)?;
                let files = self.files.clone();
                tokio::spawn(russh_sftp::server::run(ch.into_stream(), super::sftpd::S(files)));
                return Ok(());
            }
            session.channel_failure(channel)?;
            Ok(())
        }

        async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let cmd = String::from_utf8_lossy(data).to_string();
            // 模拟一个把密码打印出来的命令，验证输出脱敏。
            let out = format!("ran: {cmd}\nleak: {}\n", super::SSH_PW);
            session.data(channel, out.into_bytes())?;
            session.exit_status_request(channel, 7)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    pub fn config(seed: u8) -> Arc<russh::server::Config> {
        let kp = Ed25519Keypair::from_seed(&[seed; 32]);
        let key = PrivateKey::new(KeypairData::Ed25519(kp), "test").unwrap();
        Arc::new(russh::server::Config {
            keys: vec![key],
            methods: MethodSet::from(&[MethodKind::Password][..]),
            auth_rejection_time: std::time::Duration::from_millis(10),
            auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
            ..Default::default()
        })
    }
}

fn ssh_server(rt: &tokio::runtime::Runtime, seed: u8, port: u16, files: sftpd::Files) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = rt.block_on(tokio::net::TcpListener::bind(("127.0.0.1", port))).unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = sshd::config(seed);
    let h = rt.spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else { break };
            let cfg = cfg.clone();
            let h = sshd::H { files: files.clone(), channels: Default::default() };
            tokio::spawn(async move {
                if let Ok(running) = russh::server::run_stream(cfg, s, h).await {
                    let _ = running.await;
                }
            });
        }
    });
    (port, h)
}

#[test]
fn end_to_end() {
    // macOS 的临时目录路径很长，Unix socket 路径有 104 字节上限，因此 Unix 上固定使用 /tmp。
    let base = if cfg!(windows) { std::env::temp_dir() } else { PathBuf::from("/tmp") };
    let home = base.join(format!("pm-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let svc = Service::start(&home);

    // 未初始化：口令登录失败（静默断开）。
    assert!(Client::connect_at(&svc.socket(), &Hello::Password { v: PROTO_V, password: PW.into() }).is_err());
    // 防探测：随机字节 / 错误令牌都被静默断开。
    {
        let mut s = svc.raw();
        let _ = s.write_all(b"\x00\x00\x00\x05hello");
        let mut buf = [0u8; 16];
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "server must not answer probes");
    }
    assert_eq!(svc.agent("pm_wrong").err().unwrap().code, "AUTH_FAILED");

    // 设置口令（用户模式允许同一用户）。
    Client::connect_at(&svc.socket(), &Hello::Setup { v: PROTO_V, password: PW.into() }).expect("setup");
    assert!(Client::connect_at(&svc.socket(), &Hello::Setup { v: PROTO_V, password: PW.into() }).is_err(), "second setup must fail");
    assert!(Client::connect_at(&svc.socket(), &Hello::Password { v: PROTO_V, password: "wrong-password".into() }).is_err());

    let mut admin = svc.admin();
    let st: StatusView = admin.call_as(&Request::Status).unwrap();
    assert!(st.initialized && !st.locked && st.ready);
    assert_eq!(st.level, 1);

    // 令牌与条目。
    let tok: NewToken = admin.call_as(&Request::CreateToken { label: "test-agent".into() }).unwrap();
    assert!(tok.token.starts_with(TOKEN_PREFIX));
    let add = |c: &mut Client, name: &str, secret: &str, domains: &[&str], self_signed: bool| {
        c.call(&Request::AddEntry {
            entry: EntryInput {
                name: name.into(),
                secret: Some(secret.into()),
                domains: domains.iter().map(|s| s.to_string()).collect(),
                note: format!("{name} note"),
                self_signed,
                auto_accept_host_key: false,
            },
        })
    };
    add(&mut admin, "gh", GH_SECRET, &["127.0.0.1"], true).unwrap();
    add(&mut admin, "srv", SSH_PW, &["localhost"], false).unwrap();
    add(&mut admin, "public", "pub-secret-xyz", &["*.example.com"], false).unwrap();
    assert_eq!(code(add(&mut admin, "bad", "x", &["*.com"], false)), "BAD_REQUEST");
    assert_eq!(code(add(&mut admin, "gh", "x", &["a.example.com"], false)), "BAD_REQUEST");

    let mut agent = svc.agent(&tok.token).unwrap();
    // Agent 不能执行管理操作。
    assert_eq!(code(agent.call(&Request::Entries)), "FORBIDDEN");
    assert_eq!(code(agent.call(&Request::Reveal { name: "gh".into(), password: PW.into() })), "FORBIDDEN");
    // 不填名称：按第一个域名自动生成引用名。
    add(&mut admin, "", "auto-secret-value", &["*.auto.example.com"], false).unwrap();
    let list = agent.call(&Request::List).unwrap();
    assert!(list.as_array().unwrap().iter().any(|e| e["name"] == "auto.example.com"), "{list}");
    admin.call(&Request::DeleteEntry { name: "auto.example.com".into() }).unwrap();
    let list = agent.call(&Request::List).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 3);
    assert!(!list.to_string().contains(GH_SECRET));

    // ---- HTTPS ----
    let tls = tls_server(0);
    let url = format!("https://127.0.0.1:{}/echo?key={{{{secret}}}}", tls.port);
    let r: HttpResult = agent
        .call_as(&Request::Http {
            method: "POST".into(),
            url: url.clone(),
            headers: vec![("Authorization".into(), "Bearer {{secret}}".into())],
            body: Some(json!({"token": "{{secret}}"}).to_string()),
        })
        .unwrap();
    assert_eq!(r.status, 200);
    // 服务端确实收到了密钥（回显的请求头被脱敏，说明原文出现过）。
    assert!(r.body.to_ascii_lowercase().contains("authorization: bearer [redacted:gh]"), "{}", r.body);
    assert!(r.body.contains("key=[REDACTED:gh]"), "query must be redacted: {}", r.body);
    assert!(!r.body.contains(GH_SECRET));
    assert!(!r.body.contains(&STANDARD.encode(GH_SECRET)));
    assert!(r.body.contains("[REDACTED:gh]"));
    // base64 与 hex 编码的整个请求也不能泄露密钥的任何编码形式。
    let b64_line = r.body.lines().find(|l| l.starts_with("B64:")).unwrap();
    assert!(b64_line.contains("[REDACTED:gh]"), "base64 echo not redacted");
    let hex_line = r.body.lines().find(|l| l.starts_with("HEX:")).unwrap();
    assert!(hex_line.contains("[REDACTED:gh]") && !hex_line.contains(&hex_of(GH_SECRET.as_bytes())));
    assert!(r.headers.iter().all(|(k, _)| k != "set-cookie"), "Set-Cookie must be stripped");
    assert!(r.headers.iter().any(|(k, v)| k == "x-echo-auth" && v.contains("[REDACTED:gh]")));

    // 首次连接后记录了证书指纹。
    let pins: Vec<PinView> = admin.call_as(&Request::Pins).unwrap();
    assert!(pins.iter().any(|p| p.kind == "https" && p.host_port == format!("127.0.0.1:{}", tls.port)));

    // 域名限制 / 只允许 HTTPS / 未知凭据 / 必须使用占位符 / 不跟随跨主机重定向。
    let http = |a: &mut Client, url: &str| {
        a.call(&Request::Http { method: "GET".into(), url: url.into(), headers: vec![("X-Key".into(), "{{gh}}".into())], body: None })
    };
    assert_eq!(code(http(&mut agent, "https://evil.example.org/")), "DOMAIN_MISMATCH");
    assert_eq!(code(http(&mut agent, &format!("http://127.0.0.1:{}/", tls.port))), "USE_HTTPS");
    assert_eq!(
        code(agent.call(&Request::Http {
            method: "GET".into(),
            url: format!("https://127.0.0.1:{}/{{{{nope}}}}", tls.port),
            headers: vec![],
            body: None
        })),
        "UNKNOWN_CREDENTIAL"
    );
    assert_eq!(
        code(agent.call(&Request::Http {
            method: "GET".into(),
            url: format!("https://127.0.0.1:{}/", tls.port),
            headers: vec![],
            body: None
        })),
        "BAD_REQUEST"
    );
    let red: HttpResult = serde_json::from_value(http(&mut agent, &format!("https://127.0.0.1:{}/redirect", tls.port)).unwrap()).unwrap();
    assert_eq!(red.status, 302, "cross-host redirect must not be followed");
    // 公共 CA 校验：自签证书主机在非 self_signed 条目上必须失败（这里用 public 条目指向 *.example.com 之外，先触发域名错误）。
    assert_eq!(
        code(agent.call(&Request::Http {
            method: "GET".into(),
            url: format!("https://127.0.0.1:{}/", tls.port),
            headers: vec![("X".into(), "{{public}}".into())],
            body: None
        })),
        "DOMAIN_MISMATCH"
    );

    // 证书更换：同一端口换一张自签证书 → HOST_KEY_CHANGED，并且不发送任何数据。
    let port = tls.port;
    drop(tls);
    std::thread::sleep(Duration::from_millis(300));
    let tls2 = tls_server(port);
    let e = http(&mut agent, &format!("https://127.0.0.1:{port}/echo")).err().unwrap();
    assert_eq!(e.code, "HOST_KEY_CHANGED");
    assert!(e.message.contains("PassManager trust 127.0.0.1"), "{}", e.message);
    let pending: Vec<PendingPinView> = admin.call_as(&Request::PendingPins).unwrap();
    assert_eq!(pending.len(), 1);
    admin.call(&Request::TrustPins { pattern: format!("127.0.0.1:{port}") }).unwrap();
    assert_eq!(code(http(&mut agent, &format!("https://127.0.0.1:{port}/echo"))), "OK");
    drop(tls2);

    // ---- SSH ----
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let files: sftpd::Files = Default::default();
    files.lock().unwrap().insert("/etc/app.conf".into(), format!("user=deploy\npassword={SSH_PW}\n").into_bytes());
    let (sport, sh) = ssh_server(&rt, 1, 0, files.clone());
    let ssh = |a: &mut Client, target: String, cmd: &str| a.call(&Request::Ssh { target, command: cmd.into() });
    let me = |user: &str| format!("{user}@localhost:{sport}");
    // 不指定凭据：按主机自动选择。
    let r: SshResult = serde_json::from_value(ssh(&mut agent, me("deploy"), "uptime").unwrap()).unwrap();
    assert_eq!(r.exit_code, Some(7));
    assert!(r.stdout.contains("ran: uptime"));
    assert!(r.stdout.contains("leak: [REDACTED:srv]") && !r.stdout.contains(SSH_PW), "{}", r.stdout);
    // 以 sudo 开头的命令：服务用 sudo -S 从 stdin 提供密码。
    let r: SshResult = serde_json::from_value(ssh(&mut agent, me("deploy"), "sudo systemctl restart x").unwrap()).unwrap();
    assert!(r.stdout.contains("ran: sudo -k -S -p '' -- sh -c 'systemctl restart x'"), "{}", r.stdout);
    // 显式指定凭据（同一主机有多个凭据时使用）。
    assert_eq!(code(ssh(&mut agent, format!("srv/{}", me("deploy")), "uptime")), "OK");
    assert_eq!(code(ssh(&mut agent, me("nobody"), "uptime")), "AUTH_REJECTED");
    assert_eq!(code(ssh(&mut agent, format!("gh/{}", me("deploy")), "x")), "DOMAIN_MISMATCH");
    assert_eq!(code(ssh(&mut agent, format!("deploy@10.9.9.9:{sport}"), "x")), "NO_CREDENTIAL");
    // 主机重装（换主机密钥）→ HOST_KEY_CHANGED；信任（只写主机名）后恢复。
    sh.abort();
    std::thread::sleep(Duration::from_millis(200));
    let (_p2, sh2) = ssh_server(&rt, 2, sport, files.clone());
    let e = ssh(&mut agent, me("deploy"), "uptime").err().unwrap();
    assert_eq!(e.code, "HOST_KEY_CHANGED", "{}", e.message);
    assert!(e.message.contains("PassManager trust localhost"), "{}", e.message);
    admin.call(&Request::TrustPins { pattern: "localhost".into() }).unwrap();
    assert_eq!(code(ssh(&mut agent, me("deploy"), "uptime")), "OK");

    // SFTP：上传（创建/截断）与下载（内容脱敏）。
    let up = |a: &mut Client, data: &[u8]| {
        a.call(&Request::Upload { target: me("deploy"), path: "/tmp/new.txt".into(), data_base64: STANDARD.encode(data) })
    };
    up(&mut agent, b"first version, quite long").unwrap();
    up(&mut agent, b"second").unwrap();
    assert_eq!(files.lock().unwrap().get("/tmp/new.txt").unwrap().as_slice(), b"second", "upload must truncate");
    let d: DownloadResult = agent.call_as(&Request::Download { target: me("deploy"), path: "/etc/app.conf".into() }).unwrap();
    let content = String::from_utf8(STANDARD.decode(d.data_base64).unwrap()).unwrap();
    assert_eq!(d.redactions, 1);
    assert!(content.contains("password=[REDACTED:srv]") && !content.contains(SSH_PW), "{content}");
    sh2.abort();

    // 同一主机有两个凭据：{{secret}} 报 AMBIGUOUS，并列出可选的引用名。
    add(&mut admin, "gh2", "other-token-value", &["127.0.0.1"], false).unwrap();
    let e = http(&mut agent, &format!("https://127.0.0.1:{}/echo?k={{{{secret}}}}", 1)).err().unwrap();
    assert_eq!(e.code, "AMBIGUOUS", "{}", e.message);
    assert!(e.message.contains("gh") && e.message.contains("gh2"));
    admin.call(&Request::DeleteEntry { name: "gh2".into() }).unwrap();

    // 查看明文需要口令。
    assert_eq!(code(admin.call(&Request::Reveal { name: "gh".into(), password: "nope-nope".into() })), "WRONG_PASSWORD");
    let s = admin.call(&Request::Reveal { name: "gh".into(), password: PW.into() }).unwrap();
    assert_eq!(s.as_str().unwrap(), GH_SECRET);

    // 吊销令牌后立即失效。
    let tok2: NewToken = admin.call_as(&Request::CreateToken { label: "tmp".into() }).unwrap();
    assert!(svc.agent(&tok2.token).is_ok());
    admin.call(&Request::RevokeToken { id: tok2.id }).unwrap();
    assert!(svc.agent(&tok2.token).is_err());

    // 锁定后 Agent 得到 LOCKED 及解锁命令；口令登录后重新解锁。
    agent.call(&Request::Lock).unwrap();
    let e = agent.call(&Request::List).err().unwrap();
    assert_eq!(e.code, "LOCKED");
    assert!(e.message.contains("PassManager unlock"));
    let _ = svc.admin();
    assert_eq!(code(agent.call(&Request::List)), "OK");

    // 库文件中没有明文，令牌文件中只有哈希。
    let vault = std::fs::read(home.join("data/vault.pmv")).unwrap();
    assert!(!vault.windows(GH_SECRET.len()).any(|w| w == GH_SECRET.as_bytes()));
    let tokens = std::fs::read_to_string(home.join("data/tokens.json")).unwrap();
    assert!(!tokens.contains(&tok.token));

    // MCP 进程：通过 stdio 调用 list_credentials。
    let mut mcp = Command::new(env!("CARGO_BIN_EXE_PassManager"))
        .arg("mcp")
        .env("PASSMANAGER_HOME", &home)
        .env("PASSMANAGER_TOKEN", &tok.token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = mcp.stdin.as_mut().unwrap();
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}})).unwrap();
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","method":"notifications/initialized"})).unwrap();
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list","arguments":{}}})).unwrap();
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http_request","arguments":{"method":"GET","url":"http://x.example.com/{{public}}"}}})).unwrap();
    }
    drop(mcp.stdin.take());
    let mut out = String::new();
    mcp.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    let _ = mcp.wait();
    let lines: Vec<Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[1]["result"]["isError"], false);
    assert!(lines[1]["result"]["content"][0]["text"].as_str().unwrap().contains("\"gh\""));
    assert_eq!(lines[2]["result"]["isError"], true);
    assert!(lines[2]["result"]["content"][0]["text"].as_str().unwrap().starts_with("USE_HTTPS"));

    // CLI：输出 JSON。
    let out = Command::new(env!("CARGO_BIN_EXE_PassManager"))
        .arg("list")
        .env("PASSMANAGER_HOME", &home)
        .env("PASSMANAGER_TOKEN", &tok.token)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 3);
    let out = Command::new(env!("CARGO_BIN_EXE_PassManager"))
        .arg("list")
        .env("PASSMANAGER_HOME", &home)
        .env("PASSMANAGER_TOKEN", "pm_bad")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("AUTH_FAILED"));

    // TUI 在非 TTY / Agent 会话中拒绝运行。
    let out = Command::new(env!("CARGO_BIN_EXE_PassManager"))
        .arg("unlock")
        .env("PASSMANAGER_HOME", &home)
        .env("CLAUDECODE", "1")
        .output()
        .unwrap();
    assert!(!out.status.success());
    drop(svc);
}

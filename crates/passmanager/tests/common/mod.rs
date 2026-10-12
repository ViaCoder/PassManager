//! 端到端测试的公共部分：以用户模式（PASSMANAGER_HOME）初始化并启动服务器模式的服务，Agent 注册，
//! 本地自签 HTTPS 摘要服务（返回请求体的 SHA-256，用来证明服务端发出的字节与导入的完全一致）。
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub const BIN: &str = env!("CARGO_BIN_EXE_PassManager");

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub struct Env {
    pub base: PathBuf,
    pub home: PathBuf,
    pub agent_dir: PathBuf,
    pub web: u16,
    pub agent: u16,
    pub ca: PathBuf,
    pub service_log: PathBuf,
    pub child: Option<Child>,
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

impl Env {
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args).env("PASSMANAGER_HOME", &self.home).env_remove("PASSMANAGER_TOKEN").env_remove("PASSMANAGER_CONFIG_DIR");
        c.env("PASSMANAGER_TPM_SOCKET", "/nonexistent/tpm.sock").env("PASSMANAGER_TPM_DEVICE", "/nonexistent/tpmrm0");
        c
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).stdin(Stdio::null()).output().unwrap()
    }

    /// 以 `input` 作为标准输入运行。
    pub fn run_stdin(&self, args: &[&str], input: &[u8]) -> Output {
        let mut c = self.cmd(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        c.stdin.take().unwrap().write_all(input).unwrap();
        c.wait_with_output().unwrap()
    }

    pub fn agent_cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args).env_remove("PASSMANAGER_HOME").env_remove("PASSMANAGER_TOKEN").env("PASSMANAGER_CONFIG_DIR", &self.agent_dir);
        // 服务管理器（systemctl / loginctl / launchctl）总是替身：测试从不改动本机真实的用户服务。
        let orig = std::env::var("PATH").unwrap_or_default();
        c.env("PATH", format!("{}:{orig}", self.fakes().display())).env_remove("GIT_CONFIG_GLOBAL");
        // Agent 端的 MCP 配置与使用规则写入临时主目录，不碰真实的 ~/.claude 等。
        let home = self.base.join("agent-home");
        let _ = std::fs::create_dir_all(&home);
        c.env("HOME", &home).env_remove("CODEX_HOME");
        c
    }

    pub fn agent(&self, args: &[&str]) -> Output {
        self.agent_cmd(args).stdin(Stdio::null()).output().unwrap()
    }

    pub fn start(&mut self) {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(&self.service_log).unwrap();
        let child = self.cmd(&["service", "--user"]).stdout(Stdio::null()).stderr(Stdio::from(log)).spawn().unwrap();
        let t0 = Instant::now();
        while !(self.home.join("run/passmanager.sock").exists() && TcpStream::connect(("127.0.0.1", self.agent)).is_ok()) {
            assert!(t0.elapsed() < Duration::from_secs(60), "service did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        self.child = Some(child);
    }

    /// 初始化服务器（用户模式）、导入自签证书、启动服务、注册一个 Agent。
    pub fn setup(tag: &str) -> Self {
        Self::setup_with(tag, false)
    }

    /// `single`：单端口模式（网页与 Agent 通道共用一个端口，按 ALPN 分流）。
    pub fn setup_with(tag: &str, single: bool) -> Self {
        let base = PathBuf::from("/tmp").join(format!("pm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let (cert, key) = pm_net::tls::self_signed(&["pm.test"]);
        let ca = base.join("ca.pem");
        std::fs::write(&ca, &cert).unwrap();
        std::fs::write(base.join("key.pem"), &key).unwrap();
        let mut env = Env {
            home: base.join("server"),
            agent_dir: base.join("agent"),
            web: 0,
            agent: 0,
            ca,
            service_log: base.join("service.log"),
            base,
            child: None,
        };
        std::fs::create_dir_all(&env.home).unwrap();
        env.web = free_port();
        env.agent = if single { env.web } else { free_port() };
        let (w, a) = (env.web.to_string(), env.agent.to_string());
        let mut args =
            vec!["init", "--skip-acme", "--no-start", "--domain", "pm.test", "--lan-cidr", "127.0.0.1/32", "--bind", "127.0.0.1"];
        if single {
            args.extend(["--port", w.as_str()]);
        } else {
            args.extend(["--web-port", w.as_str(), "--agent-port", a.as_str()]);
        }
        args.extend(["--acme-directory", ""]);
        let o = env.run(&args);
        assert!(o.status.success(), "init: {}{}", stdout(&o), stderr(&o));
        let o = env.run(&["import-cert", env.ca.to_str().unwrap(), env.base.join("key.pem").to_str().unwrap()]);
        assert!(o.status.success(), "{}", stderr(&o));
        env.start();
        let o = env.run(&["show", "--label", "agent", "--url"]);
        assert!(o.status.success(), "show --url: {}", stderr(&o));
        let url = stdout(&o).trim().to_string();
        let addr = format!("127.0.0.1:{a}");
        let o = env.agent(&["enroll", "--no-mcp", "--connect-addr", &addr, "--ca-file", env.ca.to_str().unwrap(), &url]);
        assert!(o.status.success(), "enroll: {}{}", stdout(&o), stderr(&o));
        env
    }

    pub fn service_log(&self) -> String {
        std::fs::read_to_string(&self.service_log).unwrap_or_default()
    }

    /// 替身 systemctl / loginctl / launchctl 的目录（只把调用记录到 [`Env::fake_calls`]）。
    pub fn fakes(&self) -> PathBuf {
        fake_service_managers(&self.base)
    }

    /// 替身记录的调用。
    pub fn fake_calls(&self) -> String {
        std::fs::read_to_string(self.base.join("fake-calls.log")).unwrap_or_default()
    }

    /// 干净环境里运行客户端用的 PATH：替身在前，然后是 git 所在目录与系统目录。
    pub fn fake_path(&self) -> String {
        let git =
            Command::new("sh").args(["-c", "command -v git"]).output().ok().map(|o| stdout(&o).trim().to_string()).unwrap_or_default();
        let git_dir = Path::new(&git).parent().map(|p| format!("{}:", p.display())).unwrap_or_default();
        format!("{}:{git_dir}/usr/local/bin:/usr/bin:/bin", self.fakes().display())
    }
}

/// 在 `base/fakes` 写入替身 systemctl / loginctl / launchctl：只把调用追加到 `base/fake-calls.log`，成功退出。
pub fn fake_service_managers(base: &Path) -> PathBuf {
    let dir = base.join("fakes");
    let log = base.join("fake-calls.log");
    std::fs::create_dir_all(&dir).unwrap();
    for c in ["systemctl", "loginctl", "launchctl"] {
        let p = dir.join(c);
        if !p.exists() {
            let tmp = dir.join(format!(".{c}.tmp"));
            std::fs::write(&tmp, format!("#!/bin/sh\necho \"{c} $*\" >> '{}'\n", log.display())).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::rename(&tmp, &p).unwrap();
        }
    }
    dir
}

/// 自签 HTTPS 服务：回复 `sha256=<请求体的 SHA-256 十六进制>`（请求体本身不回显）。
pub fn digest_server() -> u16 {
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
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
                let out = format!("sha256={}", hex(&pm_crypto::sha256(&body)));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                    out.len()
                );
                let _ = tls.write_all(resp.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 在一段输出里查找任一秘密值（以及多行值的每一行）。
pub fn leaks(haystack: &str, secrets: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for s in secrets {
        let mut needles = vec![s.to_string()];
        needles.extend(s.lines().map(str::trim).filter(|l| l.len() >= 8).map(str::to_string));
        for n in needles {
            if haystack.contains(&n) {
                out.push(format!("value of length {}", n.len()));
            }
        }
    }
    out
}

pub fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// 自签 HTTPS 回显服务：原样返回请求行、请求头与请求体（用来检查脱敏）。
pub fn echo_server() -> u16 {
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
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
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
                let _ = r.read_exact(&mut body);
                let echo = format!("{head}{}", String::from_utf8_lossy(&body));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{echo}",
                    echo.len()
                );
                let _ = tls.write_all(resp.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

/// 用 ssh-keygen 生成一次性的 ECDSA P-384 密钥，返回（私钥路径，SHA256 指纹）。
pub fn keygen(dir: &std::path::Path, name: &str, passphrase: &str) -> (PathBuf, String) {
    let p = dir.join(name);
    let o = Command::new("ssh-keygen")
        .args(["-q", "-t", "ecdsa", "-b", "384", "-N", passphrase, "-C", "pm-test", "-f"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(o.status.success(), "ssh-keygen: {}", String::from_utf8_lossy(&o.stderr));
    let fp = String::from_utf8_lossy(&Command::new("ssh-keygen").arg("-lf").arg(&p).output().unwrap().stdout)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    (p, fp)
}

pub fn have(cmd: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {cmd}")]).output().is_ok_and(|o| o.status.success())
}

/// 系统 OpenSSH sshd（当前用户、高端口），加固配置：只允许公钥认证，P-384 主机密钥与公钥，aes256-gcm，hmac-sha2-512-etm，
/// 密钥交换为本机支持的后量子混合组（mlkem768x25519 或 sntrup761x25519）+ ecdh-sha2-nistp384。
pub struct Sshd {
    pub child: Child,
    pub port: u16,
    pub host_key: PathBuf,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn start_sshd(dir: &std::path::Path, authorized_pub: &std::path::Path) -> Sshd {
    std::fs::create_dir_all(dir).unwrap();
    let (host, _) = keygen(dir, "host_ecdsa", "");
    std::fs::copy(authorized_pub, dir.join("authorized_keys")).unwrap();
    let kex = String::from_utf8_lossy(&Command::new("ssh").args(["-Q", "kex"]).output().unwrap().stdout).to_string();
    let pq = if kex.lines().any(|l| l == "mlkem768x25519-sha256") { "mlkem768x25519-sha256" } else { "sntrup761x25519-sha512@openssh.com" };
    let port = free_port();
    let cfg = dir.join("sshd_config");
    std::fs::write(
        &cfg,
        format!(
            "ListenAddress 127.0.0.1:{port}\nHostKey {}\nPidFile none\nUsePAM no\nStrictModes no\nAuthorizedKeysFile {}\n\
             KexAlgorithms {pq},ecdh-sha2-nistp384\nHostKeyAlgorithms ecdsa-sha2-nistp384\nPubkeyAcceptedAlgorithms ecdsa-sha2-nistp384\n\
             Ciphers aes256-gcm@openssh.com\nMACs hmac-sha2-512-etm@openssh.com\nAuthenticationMethods publickey\nPasswordAuthentication no\n\
             KbdInteractiveAuthentication no\nMaxAuthTries 3\nLogLevel ERROR\n",
            host.display(),
            dir.join("authorized_keys").display()
        ),
    )
    .unwrap();
    let child = Command::new("/usr/sbin/sshd").args(["-D", "-e", "-f"]).arg(&cfg).stderr(Stdio::null()).spawn().unwrap();
    let t0 = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10), "sshd did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    Sshd { child, port, host_key: host }
}

/// 运行系统 ssh（不读用户的配置与密钥：HOME 指向临时目录、-F /dev/null），只用 SSH_AUTH_SOCK 里的 agent。
pub fn real_ssh(home: &std::path::Path, sock: &std::path::Path, port: u16, user: &str, cmd: &str) -> Output {
    std::fs::create_dir_all(home).unwrap();
    Command::new("ssh")
        .args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "IdentityFile=/nonexistent-pm-test", "-o", "PreferredAuthentications=publickey", "-o", "LogLevel=ERROR", "-p"])
        .arg(port.to_string())
        .arg(format!("{user}@127.0.0.1"))
        .arg(cmd)
        .env("HOME", home)
        .env("SSH_AUTH_SOCK", sock)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

pub struct Counts {
    pub authed: AtomicUsize,
    pub rejected: AtomicUsize,
}

/// TLS 上的 git http-backend（CGI，自签证书），每个连接一个请求；只接受带 `x-access-token:<pat>` Basic 认证的请求。
pub fn git_server(root: PathBuf, pat: &'static str) -> (u16, Arc<Counts>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cfg = Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let counts = Arc::new(Counts { authed: AtomicUsize::new(0), rejected: AtomicUsize::new(0) });
    let c2 = counts.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let (cfg, root, counts) = (cfg.clone(), root.clone(), c2.clone());
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, s);
                let mut r = BufReader::new(&mut tls);
                let mut lines = Vec::new();
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let l = line.trim_end().to_string();
                    if l.is_empty() {
                        break;
                    }
                    lines.push(l);
                }
                let mut it = lines[0].split(' ');
                let (method, target) = (it.next().unwrap().to_string(), it.next().unwrap().to_string());
                let hdr = |k: &str| {
                    lines[1..].iter().find_map(|l| {
                        l.split_once(':').filter(|(a, _)| a.trim().eq_ignore_ascii_case(k)).map(|(_, v)| v.trim().to_string())
                    })
                };
                let want = format!("Basic {}", STANDARD.encode(format!("x-access-token:{pat}")));
                if hdr("authorization").as_deref() != Some(want.as_str()) {
                    counts.rejected.fetch_add(1, Ordering::SeqCst);
                    let _ = r.get_mut().write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    return;
                }
                counts.authed.fetch_add(1, Ordering::SeqCst);
                let (path, query) =
                    target.split_once('?').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((target.clone(), String::new()));
                let mut cmd = Command::new("git");
                cmd.arg("http-backend")
                    .env("GIT_PROJECT_ROOT", &root)
                    .env("GIT_HTTP_EXPORT_ALL", "1")
                    .env("PATH_INFO", &path)
                    .env("QUERY_STRING", &query)
                    .env("REQUEST_METHOD", &method)
                    .env("REMOTE_USER", "tester")
                    .env("REMOTE_ADDR", "127.0.0.1")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null());
                if let Some(ct) = hdr("content-type") {
                    cmd.env("CONTENT_TYPE", ct);
                }
                if let Some(gp) = hdr("git-protocol") {
                    cmd.env("GIT_PROTOCOL", gp);
                }
                let chunked = hdr("transfer-encoding").is_some_and(|v| v.contains("chunked"));
                let len: Option<u64> = hdr("content-length").and_then(|v| v.parse().ok());
                if let Some(n) = len {
                    cmd.env("CONTENT_LENGTH", n.to_string());
                }
                let mut child = cmd.spawn().unwrap();
                let mut stdin = child.stdin.take().unwrap();
                // 请求体：读完写入 CGI 的标准输入。
                let mut body = Vec::new();
                if chunked {
                    loop {
                        let mut size = String::new();
                        r.read_line(&mut size).unwrap();
                        let n = usize::from_str_radix(size.trim().split(';').next().unwrap(), 16).unwrap();
                        if n == 0 {
                            let mut t = String::new();
                            let _ = r.read_line(&mut t);
                            break;
                        }
                        let mut chunk = vec![0u8; n];
                        r.read_exact(&mut chunk).unwrap();
                        body.extend_from_slice(&chunk);
                        let mut crlf = [0u8; 2];
                        r.read_exact(&mut crlf).unwrap();
                    }
                } else if let Some(n) = len {
                    body.resize(n as usize, 0);
                    r.read_exact(&mut body).unwrap();
                }
                let w = std::thread::spawn(move || {
                    let _ = stdin.write_all(&body);
                });
                let mut out = BufReader::new(child.stdout.take().unwrap());
                let mut status = "200 OK".to_string();
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    if out.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let l = line.trim_end();
                    if l.is_empty() {
                        break;
                    }
                    match l.split_once(':') {
                        Some((k, v)) if k.eq_ignore_ascii_case("status") => status = v.trim().to_string(),
                        _ => headers.push_str(&format!("{l}\r\n")),
                    }
                }
                let tls = r.get_mut();
                let _ = write!(tls, "HTTP/1.1 {status}\r\n{headers}Connection: close\r\n\r\n");
                let _ = std::io::copy(&mut out, tls);
                tls.conn.send_close_notify();
                let _ = tls.flush();
                let _ = w.join();
                let _ = child.wait();
            });
        }
    });
    (port, counts)
}

//! 端到端测试的公共部分：以用户模式（PASSMANAGER_HOME）初始化并启动服务器模式的服务，Agent 注册，
//! 本地自签 HTTPS 摘要服务（返回请求体的 SHA-256，用来证明服务端发出的字节与导入的完全一致）。
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        let o = env.run(&["token", "add", "agent"]);
        let url = stdout(&o).trim().to_string();
        let addr = format!("127.0.0.1:{a}");
        let o = env.agent(&["enroll", "--no-mcp", "--connect-addr", &addr, "--ca-file", env.ca.to_str().unwrap(), &url]);
        assert!(o.status.success(), "enroll: {}{}", stdout(&o), stderr(&o));
        env
    }

    pub fn service_log(&self) -> String {
        std::fs::read_to_string(&self.service_log).unwrap_or_default()
    }
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

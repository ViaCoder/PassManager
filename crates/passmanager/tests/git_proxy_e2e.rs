//! git 凭据注入代理端到端（Linux，真实 git）：本地 TLS 的 `git http-backend`（自签证书，要求假 PAT 的 Basic 认证），
//! Agent 机器上的 `passmanager git-proxy` 经双层加密通道转发；服务器注入 PAT。
//! 覆盖：push / clone（含 70 MiB 的大包，超过 64 MiB）、内容一致、上游每个请求都带正确的 PAT、
//! 未绑定的主机被拒、非 smart-HTTP 路径被拒、错误的路径令牌被拒、PAT 不出现在客户端的任何输出、进程参数、环境与配置文件里。
#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;

const PAT: &str = "ghp_FakePatForTests_0123456789abcdefXYZ";

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Counts {
    authed: AtomicUsize,
    rejected: AtomicUsize,
}

/// TLS 上的 git http-backend（CGI），每个连接一个请求。
fn git_server(root: PathBuf) -> (u16, Arc<Counts>) {
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
                let want = format!("Basic {}", STANDARD.encode(format!("x-access-token:{PAT}")));
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

fn git(home: &Path, dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .unwrap()
}

#[test]
fn git_proxy_push_and_clone() {
    if !have("git") {
        eprintln!("跳过：没有 git");
        return;
    }
    let env = Env::setup("gitproxy");
    let root = env.base.join("repos");
    std::fs::create_dir_all(&root).unwrap();
    let home = env.base.join("home");
    std::fs::create_dir_all(&home).unwrap();
    assert!(git(&home, &root, &["init", "-q", "--bare", "-b", "main", "repo.git"]).status.success());
    let (port, counts) = git_server(root.clone());
    let upstream = format!("127.0.0.1:{port}");

    // 服务器上的条目：PAT（自签证书主机）。
    let o = env.run_stdin(&["import", "--name", "gitpat", "--domain", &upstream, "--self-signed"], format!("{PAT}\n").as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));

    // Agent 机器上的代理。
    let lport = free_port();
    let listen = format!("127.0.0.1:{lport}");
    let mut proxy = Kill(
        env.agent_cmd(&["git-proxy", "--listen", &listen, "--host", &upstream])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let t0 = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", lport)).is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(50));
    }
    let token = std::fs::read_to_string(env.agent_dir.join("git-proxy.token")).unwrap().trim().to_string();
    let prefix = format!("http://127.0.0.1:{lport}/{token}/https/{upstream}/");
    let instead = format!("url.{prefix}.insteadOf=https://{upstream}/");

    // 工作区：一个小文件 + 70 MiB 的随机数据（大于 64 MiB，验证流式传输）。
    let work = env.base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    assert!(git(&home, &work, &["init", "-q", "-b", "main"]).status.success());
    std::fs::write(work.join("README"), "hello via proxy\n").unwrap();
    let mut big = vec![0u8; 70 * 1024 * 1024];
    pm_crypto::rng::fill(&mut big).unwrap();
    std::fs::write(work.join("big.bin"), &big).unwrap();
    let big_hash = hex(&pm_crypto::sha256(&big));
    drop(big);
    for args in [&["add", "."][..], &["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init"]] {
        assert!(git(&home, &work, args).status.success());
    }
    let mut outputs = String::new();
    let o = git(&home, &work, &["-c", &instead, "push", "-q", &format!("https://{upstream}/repo.git"), "main"]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "push: {}", stderr(&o));

    // clone 回来，内容一致。
    let o = git(&home, &env.base, &["-c", &instead, "clone", "-q", &format!("https://{upstream}/repo.git"), "cloned"]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "clone: {}", stderr(&o));
    assert_eq!(std::fs::read_to_string(env.base.join("cloned/README")).unwrap(), "hello via proxy\n");
    assert_eq!(hex(&pm_crypto::sha256(&std::fs::read(env.base.join("cloned/big.bin")).unwrap())), big_hash);
    assert!(counts.authed.load(Ordering::SeqCst) >= 4, "上游每个请求都带 PAT");
    assert_eq!(counts.rejected.load(Ordering::SeqCst), 0);

    // 未绑定的主机：拒绝（不会把 PAT 发出去）。
    let other_prefix = format!("http://127.0.0.1:{lport}/{token}/https/127.0.0.2:{port}/");
    let o = git(
        &home,
        &env.base,
        &[
            "-c",
            &format!("url.{other_prefix}.insteadOf=https://127.0.0.2:{port}/"),
            "clone",
            "-q",
            &format!("https://127.0.0.2:{port}/repo.git"),
            "nope",
        ],
    );
    assert!(!o.status.success());
    outputs += &(stdout(&o) + &stderr(&o));
    // 非 smart-HTTP 路径、错误的路径令牌。
    let raw = |path: &str| {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", lport)).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    };
    let r = raw(&format!("/{token}/https/{upstream}/api/v3/user"));
    assert!(r.starts_with("HTTP/1.1 403") && r.contains("FORBIDDEN"), "{r}");
    outputs += &r;
    let r = raw(&format!("/{}/https/{upstream}/repo.git/info/refs?service=git-upload-pack", "0".repeat(32)));
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    let before = counts.authed.load(Ordering::SeqCst);
    assert_eq!(counts.authed.load(Ordering::SeqCst), before);

    // PAT 不出现在客户端的任何地方：git 输出、代理输出、代理进程的参数与环境、Agent 配置目录。
    let pid = proxy.0.id();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
    let _ = proxy.0.kill();
    let o = proxy.0.wait_with_output_compat();
    outputs += &o;
    outputs += &String::from_utf8_lossy(&cmdline);
    outputs += &String::from_utf8_lossy(&environ);
    for f in std::fs::read_dir(&env.agent_dir).unwrap().flatten() {
        if f.path().is_file() {
            outputs += &String::from_utf8_lossy(&std::fs::read(f.path()).unwrap());
        }
    }
    assert!(!outputs.contains(PAT) && !outputs.contains(&STANDARD.encode(format!("x-access-token:{PAT}"))), "PAT 出现在客户端");
    assert!(!env.service_log().contains(PAT));
    assert!(env.service_log().contains("git-proxy: entry=gitpat"), "服务端审计");
}

trait WaitCompat {
    fn wait_with_output_compat(&mut self) -> String;
}

impl WaitCompat for Child {
    fn wait_with_output_compat(&mut self) -> String {
        let _ = self.wait();
        let mut s = String::new();
        if let Some(mut o) = self.stdout.take() {
            let _ = o.read_to_string(&mut s);
        }
        if let Some(mut e) = self.stderr.take() {
            let _ = e.read_to_string(&mut s);
        }
        s
    }
}

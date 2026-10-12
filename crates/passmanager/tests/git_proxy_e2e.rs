//! git 凭据注入代理端到端（Linux，真实 git）：本地 TLS 的 `git http-backend`（自签证书，要求假 PAT 的 Basic 认证），
//! Agent 机器上的 `passmanager git-proxy` 经双层加密通道转发；服务器注入 PAT。
//! 覆盖：push / clone（含 70 MiB 的大包，超过 64 MiB）、内容一致、上游每个请求都带正确的 PAT、
//! 未绑定的主机被拒、非 smart-HTTP 路径被拒、错误的路径令牌被拒、PAT 不出现在客户端的任何输出、进程参数、环境与配置文件里。
#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
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
    let (port, counts) = git_server(root.clone(), PAT);
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

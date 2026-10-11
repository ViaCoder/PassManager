//! 一键接入端到端（Linux）：root 的 `agent-setup` → 服务器的 `/a/<注册码>` 安装脚本 → 系统 curl | sh →
//! 校验 SHA-256、安装、`enroll`（配置 MCP 与使用规则）。
//!
//! 服务器只接受后量子 TLS 组，系统 curl（OpenSSL 3.0）不支持，所以测试里用一个经典 TLS 的本地代理（测试 CA，经
//! `CURL_CA_BUNDLE` 交给 curl）把请求原样转给真实服务器（后量子 TLS）。覆盖：
//! SHA-256 不一致时中止且什么都不安装、获取脚本不消耗注册码、注册码只能用一次（脚本与直接 enroll 两条路径之间也一样）、
//! 未知注册码 404、不在允许网段的来源连握手都没有、审计记录、输出中没有令牌。
#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;

/// 用后量子 TLS 向真实服务器发请求，返回（状态码，正文）。
fn pq_get(env: &Env, method: &str, path: &str) -> (u16, Vec<u8>) {
    pq_get_at(env.web, &env.ca, method, path)
}

fn pq_get_at(web: u16, ca: &Path, method: &str, path: &str) -> (u16, Vec<u8>) {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from_pem_file(ca).unwrap()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(pm_net::tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = rustls::ClientConnection::new(Arc::new(cfg), "pm.test".try_into().unwrap()).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", web)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut s = rustls::StreamOwned::new(conn, tcp);
    write!(s, "{method} {path} HTTP/1.1\r\nHost: pm.test:{web}\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body = raw.get(split + 4..).unwrap_or_default().to_vec();
    let status = head.lines().next().unwrap_or("").split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut r = BufReader::new(&body[..]);
        loop {
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let n = usize::from_str_radix(line.trim(), 16).unwrap_or(0);
            if n == 0 {
                break;
            }
            let mut c = vec![0u8; n + 2];
            r.read_exact(&mut c).unwrap();
            out.extend_from_slice(&c[..n]);
        }
        body = out;
    }
    (status, body)
}

/// 经典 TLS 的本地代理（系统 curl 能连），把请求转给真实服务器。`tamper` 时篡改下载的程序。
fn proxy(env: &Env, tamper: Arc<AtomicBool>) -> (u16, std::path::PathBuf) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let ca = env.base.join("proxy-ca.pem");
    std::fs::write(&ca, cert.cert.pem()).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cfg = Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (web, real_ca) = (env.web, env.ca.clone());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg.clone()).unwrap(), s);
            let mut line = String::new();
            let mut r = BufReader::new(&mut tls);
            if r.read_line(&mut line).is_err() {
                continue;
            }
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                    break;
                }
            }
            let mut it = line.split_whitespace();
            let (method, path) = (it.next().unwrap_or("GET").to_string(), it.next().unwrap_or("/").to_string());
            let (status, mut body) = pq_get_at(web, &real_ca, &method, &path);
            if path.contains("/bin/") && tamper.load(Ordering::SeqCst) && !body.is_empty() {
                let n = body.len() - 1;
                body[n] ^= 0x55;
            }
            if !path.contains("/bin/") {
                let text = String::from_utf8_lossy(&body).replace(&format!("https://pm.test:{web}"), &format!("https://127.0.0.1:{port}"));
                body = text.into_bytes();
            }
            let tls = r.into_inner();
            let _ = write!(tls, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = tls.write_all(&body);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    (port, ca)
}

fn sh(home: &Path, ca: &Path, cmd: &str) -> Output {
    sh_env(home, ca, cmd, &[])
}

/// 以干净的环境运行一行命令（只有 HOME、PATH、测试 CA 与 `extra`）。
fn sh_env(home: &Path, ca: &Path, cmd: &str, extra: &[(&str, &str)]) -> Output {
    let mut c = Command::new("sh");
    c.arg("-c")
        .arg(cmd)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("CURL_CA_BUNDLE", ca)
        .env("PASSMANAGER_TPM_SOCKET", "/nonexistent");
    for (k, v) in extra {
        c.env(k, v);
    }
    c.output().unwrap()
}

/// （说明，要设置的环境变量，要移除的环境变量）。
type EnvVariant<'a> = (&'a str, Vec<(&'a str, &'a str)>, Vec<&'a str>);

/// 以给定的环境运行注册后的客户端（模拟 Agent 启动 MCP / CLI 时与安装时不同的环境）。
fn client_list(home: &Path, env: &[(&str, &str)], remove: &[&str]) -> Output {
    let mut c = Command::new(BIN);
    c.arg("list").env("HOME", home).env_remove("PASSMANAGER_CONFIG_DIR").env_remove("PASSMANAGER_HOME");
    for k in remove {
        c.env_remove(k);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

/// 从接入说明里取出一行命令与注册码。
fn one_liner(text: &str) -> (String, String) {
    let line = text.lines().map(str::trim).find(|l| l.starts_with("curl ")).expect("one-liner").to_string();
    let url = line.split_whitespace().find(|w| w.starts_with("https://")).unwrap();
    let code = url.rsplit('/').next().unwrap().to_string();
    (line, code)
}

#[test]
fn one_line_agent_setup() {
    if !have("curl") || !have("sha256sum") {
        eprintln!("跳过：没有 curl 或 sha256sum");
        return;
    }
    let env = Env::setup("agentsetup");
    // 服务器的 Agent 程序目录：放一个"客户端"包装脚本（转调测试构建的程序，并带上测试用的连接地址与 CA）。
    let o = env.run(&["agent-bin-dir"]);
    let bin_dir = std::path::PathBuf::from(stdout(&o).trim());
    std::fs::create_dir_all(&bin_dir).unwrap();
    let target = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
    let wrapper = format!("#!/bin/sh\nexec {BIN} \"$@\" --connect-addr 127.0.0.1:{} --ca-file {}\n", env.agent, env.ca.display());
    std::fs::write(bin_dir.join(format!("PassManager-{target}")), &wrapper).unwrap();
    let tamper = Arc::new(AtomicBool::new(false));
    let (pport, pca) = proxy(&env, tamper.clone());
    let mut outputs = String::new();

    // ---- agent-setup：一段文字，一个注册码（开发构建：没有固定的源码，给出说明）----
    let o = env.run(&["agent-setup", "--label", "laptop"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let text = stdout(&o);
    outputs += &(text.clone() + &stderr(&o));
    let (line, code) = one_liner(&text);
    assert_eq!(line, format!("curl --proto =https --tlsv1.3 -fsSL https://pm.test:{}/a/{code} | sh", env.web));
    assert_eq!(code.len(), 43);
    assert_eq!(text.matches(&code).count(), 1, "开发构建只在一行命令里出现注册码");
    assert!(text.contains("development build") && !text.contains("git clone"), "{text}");
    assert!(text.contains("MCP tools") && text.contains("{{entry.field}}"));
    assert!(!text.contains("install-agent.sh") && !text.contains("pm_"), "没有其他安装方式，也没有令牌");
    assert!(stdout(&env.run(&["build-info"])).contains("development build"), "测试构建不是发布标签构建");
    let zh = env.run(&["agent-setup", "--label", "laptop-zh", "--lang", "zh"]);
    assert!(stdout(&zh).contains("PassManager 接入说明") && stdout(&zh).contains("开发构建"));

    // ---- 获取脚本不消耗注册码；未知注册码 404 ----
    let (s, script) = pq_get(&env, "GET", &format!("/a/{code}"));
    assert_eq!(s, 200);
    let script = String::from_utf8(script).unwrap();
    assert!(script.contains(&format!("{target}) sum={} ;;", hex(&pm_crypto::sha256(wrapper.as_bytes())))));
    assert!(script.contains("PM_ENROLL='pm-enroll://pm.test:"));
    assert_eq!(pq_get(&env, "HEAD", &format!("/a/{code}")).0, 200);
    assert_eq!(pq_get(&env, "GET", &format!("/a/{}", "Q".repeat(43))).0, 404);

    // ---- SHA-256 不一致：中止，什么都不安装，注册码仍有效 ----
    tamper.store(true, Ordering::SeqCst);
    let h1 = env.base.join("h1");
    std::fs::create_dir_all(&h1).unwrap();
    let cmd = line.replace(&format!("https://pm.test:{}", env.web), &format!("https://127.0.0.1:{pport}"));
    let o = sh(&h1, &pca, &cmd);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(!o.status.success() && stderr(&o).contains("SHA-256 mismatch"), "{}{}", stdout(&o), stderr(&o));
    assert!(!h1.join(".local/bin/PassManager").exists());
    assert_eq!(pq_get(&env, "GET", &format!("/a/{code}")).0, 200, "失败的安装不消耗注册码");
    tamper.store(false, Ordering::SeqCst);

    // ---- 正常安装：安装、注册、MCP 与使用规则 ----
    let h2 = env.base.join("h2");
    std::fs::create_dir_all(h2.join(".codex")).unwrap();
    std::fs::write(h2.join(".claude.json"), "{}").unwrap();
    std::fs::create_dir_all(h2.join(".claude")).unwrap();
    std::fs::write(h2.join(".claude/CLAUDE.md"), "# my own rules\n").unwrap();
    let o = sh(&h2, &pca, &cmd);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(std::fs::read_to_string(h2.join(".local/bin/PassManager")).unwrap(), wrapper);
    assert!(h2.join(".local/bin/passmanager").exists());
    assert!(h2.join(".config/passmanager/remote.toml").exists(), "{}", stdout(&o));
    let claude_md = std::fs::read_to_string(h2.join(".claude/CLAUDE.md")).unwrap();
    assert!(claude_md.starts_with("# my own rules\n") && claude_md.matches("<!-- passmanager:begin -->").count() == 1, "{claude_md}");
    assert!(std::fs::read_to_string(h2.join(".codex/AGENTS.md")).unwrap().contains("<!-- passmanager:end -->"));
    assert_eq!(std::fs::read_to_string(h2.join(".claude/CLAUDE.md.passmanager.bak")).unwrap(), "# my own rules\n");
    assert!(std::fs::read_to_string(h2.join(".claude.json")).unwrap().contains("passmanager"), "MCP 配置");
    // 注册后的客户端可以使用——无论之后的环境里 XDG_* 是否设置、是否与安装时不同（CI 运行器会设置 XDG_CONFIG_HOME）。
    let xdg = env.base.join("xdg-other");
    let xdg_s = xdg.to_str().unwrap().to_string();
    let variants: Vec<EnvVariant> = vec![
        ("继承测试进程的环境", vec![], vec![]),
        ("没有任何 XDG_*", vec![], vec!["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"]),
        ("XDG_CONFIG_HOME 指向别处", vec![("XDG_CONFIG_HOME", xdg_s.as_str())], vec![]),
        (
            "全部 XDG_* 指向别处",
            vec![("XDG_CONFIG_HOME", xdg_s.as_str()), ("XDG_DATA_HOME", xdg_s.as_str()), ("XDG_STATE_HOME", xdg_s.as_str())],
            vec![],
        ),
        ("最小 PATH", vec![("PATH", "/usr/bin:/bin")], vec![]),
    ];
    for (what, set, remove) in &variants {
        let o = client_list(&h2, set, remove);
        assert!(o.status.success(), "{what}: {}{}", stdout(&o), stderr(&o));
    }
    let token = std::fs::read_to_string(h2.join(".config/passmanager/token")).unwrap();

    // ---- 安装时设置了 XDG_*（与之后的使用不同）：配置仍写到固定位置，之后在任何环境下都能找到 ----
    let o = env.run(&["agent-setup", "--label", "xdg"]);
    let (xline, _) = one_liner(&stdout(&o));
    let xcmd = xline.replace(&format!("https://pm.test:{}", env.web), &format!("https://127.0.0.1:{pport}"));
    let h6 = env.base.join("h6");
    std::fs::create_dir_all(&h6).unwrap();
    let install_xdg = env.base.join("xdg-install");
    let ix = install_xdg.to_str().unwrap();
    let o = sh_env(&h6, &pca, &xcmd, &[("XDG_CONFIG_HOME", ix), ("XDG_DATA_HOME", ix), ("XDG_STATE_HOME", ix)]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(h6.join(".config/passmanager/remote.toml").exists() && !install_xdg.join("passmanager").exists(), "写入位置与 XDG 无关");
    for (what, set, remove) in &variants {
        let o = client_list(&h6, set, remove);
        assert!(o.status.success(), "安装时有 XDG，使用时{what}: {}{}", stdout(&o), stderr(&o));
    }
    // 0.3.0 及更早版本按 XDG_CONFIG_HOME 写入的配置仍能读取；unenroll 清理所有位置。
    let legacy = env.base.join("xdg-legacy");
    std::fs::create_dir_all(legacy.join("passmanager")).unwrap();
    for f in ["remote.toml", "token", "server-keys.bin"] {
        std::fs::rename(h6.join(".config/passmanager").join(f), legacy.join("passmanager").join(f)).unwrap();
    }
    let lx = legacy.to_str().unwrap();
    let o = client_list(&h6, &[("XDG_CONFIG_HOME", lx)], &[]);
    assert!(o.status.success(), "旧位置：{}{}", stdout(&o), stderr(&o));
    let o = Command::new(BIN)
        .arg("unenroll")
        .env("HOME", &h6)
        .env("XDG_CONFIG_HOME", lx)
        .env_remove("PASSMANAGER_CONFIG_DIR")
        .output()
        .unwrap();
    assert!(o.status.success() && !legacy.join("passmanager/remote.toml").exists(), "{}", stdout(&o));

    // ---- 只能用一次：脚本已消耗 → /a/ 404，直接 enroll 失败 ----
    assert_eq!(pq_get(&env, "GET", &format!("/a/{code}")).0, 404);
    let h3 = env.base.join("h3");
    std::fs::create_dir_all(&h3).unwrap();
    let o = sh(&h3, &pca, &cmd);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(!h3.join(".local/bin/PassManager").exists(), "注册码已用过：什么都不安装");
    let enroll_url = script.lines().find_map(|l| l.strip_prefix("PM_ENROLL='")).unwrap().trim_end_matches('\'').to_string();
    let direct = |home: &Path, url: &str| {
        Command::new(BIN)
            .args(["enroll", url, "--connect-addr", &format!("127.0.0.1:{}", env.agent), "--ca-file", env.ca.to_str().unwrap()])
            .env("HOME", home)
            .env_remove("PASSMANAGER_CONFIG_DIR")
            .output()
            .unwrap()
    };
    let o = direct(&h3, &enroll_url);
    assert!(!o.status.success(), "已用过的注册码不能再直接 enroll");

    // ---- 直接 enroll（自行构建的客户端）同样配置使用规则，并消耗注册码 → /a/ 404 ----
    let o = env.run(&["agent-setup", "--label", "source-build"]);
    let (_, code2) = one_liner(&stdout(&o));
    let (_, s2) = pq_get(&env, "GET", &format!("/a/{code2}"));
    let url2 = String::from_utf8_lossy(&s2).lines().find_map(|l| l.strip_prefix("PM_ENROLL='")).unwrap().trim_end_matches('\'').to_string();
    let h4 = env.base.join("h4");
    std::fs::create_dir_all(h4.join(".gemini")).unwrap();
    let o = direct(&h4, &url2);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(std::fs::read_to_string(h4.join(".gemini/GEMINI.md")).unwrap().contains("PassManager (agent instructions v1)"));
    assert_eq!(pq_get(&env, "GET", &format!("/a/{code2}")).0, 404);
    // --no-instructions：不写规则。
    let o = env.run(&["agent-setup", "--label", "noinstr"]);
    let (_, code3) = one_liner(&stdout(&o));
    let (_, s3) = pq_get(&env, "GET", &format!("/a/{code3}"));
    let url3 = String::from_utf8_lossy(&s3).lines().find_map(|l| l.strip_prefix("PM_ENROLL='")).unwrap().trim_end_matches('\'').to_string();
    let h5 = env.base.join("h5");
    std::fs::create_dir_all(h5.join(".gemini")).unwrap();
    let o = Command::new(BIN)
        .args([
            "enroll",
            "--no-instructions",
            &url3,
            "--connect-addr",
            &format!("127.0.0.1:{}", env.agent),
            "--ca-file",
            env.ca.to_str().unwrap(),
        ])
        .env("HOME", &h5)
        .env_remove("PASSMANAGER_CONFIG_DIR")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(!h5.join(".gemini/GEMINI.md").exists());

    // ---- unenroll：移除规则（恢复用户原来的内容）、MCP 配置与远程配置 ----
    let o = Command::new(BIN).arg("unenroll").env("HOME", &h2).env_remove("PASSMANAGER_CONFIG_DIR").output().unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(std::fs::read_to_string(h2.join(".claude/CLAUDE.md")).unwrap(), "# my own rules\n");
    assert!(!h2.join(".codex/AGENTS.md").exists());
    assert!(!h2.join(".config/passmanager/remote.toml").exists());
    assert!(!std::fs::read_to_string(h2.join(".claude.json")).unwrap().contains("passmanager"));

    // ---- 不在允许网段的来源：/a/ 也连握手都没有 ----
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let refused = rt.block_on(async {
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        let Ok(mut s) = sock.connect(format!("127.0.0.1:{}", env.web).parse().unwrap()).await else { return true };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = s.write_all(b"\x16\x03\x01\x00\x05hello").await;
        let mut buf = [0u8; 16];
        matches!(tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await, Ok(Ok(0)) | Ok(Err(_)))
    });
    assert!(refused, "非允许网段");

    // ---- 审计；任何输出里都没有令牌 ----
    let log = env.service_log();
    assert!(log.contains("bootstrap: script for enrollment code") && log.contains("bootstrap: unknown or expired code"), "{log}");
    assert!(log.contains("agent-setup: enrollment code"));
    assert!(!outputs.contains(token.trim()) && !log.contains(token.trim()), "令牌不出现在输出里");
}

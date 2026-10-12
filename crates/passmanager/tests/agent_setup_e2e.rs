//! 一键接入端到端（Linux）：root 的 `show --label` → 服务器的 `/a/<注册码>` 安装脚本 → 系统 curl | sh →
//! 校验 SHA-256、安装、`enroll`（配置 MCP、使用规则与 git 凭据代理服务）。
//!
//! 服务器只接受后量子 TLS 组，系统 curl（OpenSSL 3.0）不支持，所以测试里用一个经典 TLS 的本地代理（测试 CA，经
//! `CURL_CA_BUNDLE` 交给 curl）把请求原样转给真实服务器（后量子 TLS）。覆盖：
//! SHA-256 不一致时中止且什么都不安装、获取脚本不消耗注册码、注册码只能用一次（脚本与直接 enroll 两条路径之间也一样）、
//! 未知注册码 404、不在允许网段的来源连握手都没有、审计记录、输出中没有令牌；`show` 的公开说明（不带 --label /
//! 不是服务器上的 root）不含注册码；并发兑换同一注册码只有一个成功；失败次数过多的来源被暂时拒绝。
//! 另一个测试：一键接入后 git 经常驻的 git-proxy 服务访问本地 git 服务器（insteadOf、服务文件、本机没有 PAT、吊销后失败）。
//!
//! 服务管理器（systemctl / loginctl / launchctl）在所有客户端命令里都是替身（只记录调用）。
#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Stdio;
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

fn sh(path: &str, home: &Path, ca: &Path, cmd: &str) -> Output {
    sh_env(path, home, ca, cmd, &[])
}

/// 用指定的 shell（sh / bash / zsh）以 `-c` 运行打印出来的一行命令。
fn shell(bin: &str, path: &str, home: &Path, ca: &Path, cmd: &str) -> Output {
    Command::new(bin)
        .arg("-c")
        .arg(cmd)
        .env_clear()
        .env("HOME", home)
        .env("PATH", path)
        .env("CURL_CA_BUNDLE", ca)
        .env("PASSMANAGER_TPM_SOCKET", "/nonexistent")
        .output()
        .unwrap()
}

/// 以干净的环境运行一行命令（只有 HOME、PATH（替身在前）、测试 CA 与 `extra`）。
fn sh_env(path: &str, home: &Path, ca: &Path, cmd: &str, extra: &[(&str, &str)]) -> Output {
    let mut c = Command::new("sh");
    c.arg("-c")
        .arg(cmd)
        .env_clear()
        .env("HOME", home)
        .env("PATH", path)
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
    let line = text.lines().map(str::trim).find(|l| l.starts_with("sh -c ")).expect("one-liner").to_string();
    let url = line.split_whitespace().find(|w| w.starts_with("https://")).unwrap();
    let code = url.rsplit('/').next().unwrap().to_string();
    (line, code)
}

#[test]
fn one_line_agent_setup() {
    run_agent_setup(false);
}

/// 单端口模式（网页与 Agent 通道共用一个端口，按 ALPN 分流）：同样的完整流程，所有地址都带这个端口。
#[test]
fn one_line_agent_setup_single_port() {
    run_agent_setup(true);
}

fn run_agent_setup(single: bool) {
    if !have("curl") || !have("sha256sum") {
        eprintln!("跳过：没有 curl 或 sha256sum");
        return;
    }
    let env = Env::setup_with(if single { "agentsetup1" } else { "agentsetup2" }, single);
    assert_eq!(env.web == env.agent, single);
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
    let path = env.fake_path();
    let mut codes: Vec<String> = Vec::new();

    // ---- show（不带 --label / 不是服务器上的 root）：公开说明，没有注册码 ----
    let no_code = |t: &str| {
        !t.contains("pm-enroll://pm.test")
            && t.match_indices("/a/").all(|(i, _)| t[i + 3..].starts_with('<'))
            && !t.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_').any(|w| w.len() == 43)
    };
    let pending_before = stdout(&env.run(&["token", "list"]));
    let o = env.run(&["show"]);
    assert!(o.status.success() && stdout(&o).contains("passmanager show --label <名称>"), "{}", stdout(&o));
    assert!(no_code(&stdout(&o)) && stderr(&o).contains("--label"), "{}{}", stdout(&o), stderr(&o));
    let fresh = env.base.join("not-root-home");
    std::fs::create_dir_all(&fresh).unwrap();
    let not_root = |args: &[&str], home: &Path| {
        Command::new(BIN)
            .args(args)
            .env("HOME", home)
            .env("PATH", &path)
            .env_remove("PASSMANAGER_HOME")
            .env_remove("PASSMANAGER_CONFIG_DIR")
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap()
    };
    let o = not_root(&["show", "--label", "laptop", "--lang", "en"], &fresh);
    assert!(o.status.success() && stdout(&o).contains("public guide") && stdout(&o).contains("not enrolled"), "{}", stdout(&o));
    assert!(no_code(&stdout(&o)) && stderr(&o).contains("root"), "{}{}", stdout(&o), stderr(&o));
    let o = not_root(&["show", "--label", "laptop", "--url"], &fresh);
    assert!(!o.status.success() && !stdout(&o).contains("pm-enroll://"), "{}", stdout(&o));
    assert_eq!(stdout(&env.run(&["token", "list"])), pending_before, "公开说明不生成注册码");
    let o = env.run(&["show", "--rules", "--lang", "en"]);
    assert_eq!(stdout(&o), pm_proto::agent_text::instruction_block(pm_proto::agent_text::Lang::En));
    assert!(stdout(&env.run(&["show", "--rules"])).contains("Agent 使用规则"), "默认中文");

    // ---- show --label --url：只有一行 pm-enroll:// 注册码 ----
    let o = env.run(&["show", "--label", "url-only", "--url"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let only = stdout(&o);
    assert_eq!(only.lines().count(), 1, "{only}");
    let parsed = pm_net::enroll::EnrollUrl::parse(only.trim()).unwrap();
    assert_eq!((parsed.host.as_str(), parsed.port), ("pm.test", env.agent));
    codes.push(parsed.code.clone());

    // ---- show --label：一段文字，一个注册码（开发构建：没有固定的源码，给出说明）----
    let o = env.run(&["show", "--label", "laptop", "--lang", "en"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let text = stdout(&o);
    outputs += &(text.clone() + &stderr(&o));
    let (line, code) = one_liner(&text);
    codes.push(code.clone());
    assert_eq!(
        line,
        format!("sh -c \"$(curl --proto '=https' --tlsv1.3 -fsSL https://pm.test:{}/a/{code} || echo \"exit $?\")\"", env.web)
    );
    // 与安装了什么 shell 无关的检查：zsh 会展开未加引号的 =https。
    assert!(line.contains("--proto '=https'") && !line.contains("--proto =https") && !line.contains("| sh"));
    assert_eq!(code.len(), 43);
    assert_eq!(text.matches(&code).count(), 1, "开发构建只在一行命令里出现注册码");
    assert!(text.contains("development build") && !text.contains("git clone"), "{text}");
    assert!(text.contains("MCP tools") && text.contains("{{entry.field}}") && text.contains("git-proxy"));
    assert!(!text.contains("install-agent.sh") && !text.contains("pm_"), "没有其他安装方式，也没有令牌");
    assert!(stdout(&env.run(&["build-info"])).contains("development build"), "测试构建不是发布标签构建");
    let zh = env.run(&["show", "--label", "laptop-zh"]);
    assert!(stdout(&zh).contains("PassManager 接入说明") && stdout(&zh).contains("开发构建"), "默认中文");
    codes.push(one_liner(&stdout(&zh)).1);

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
    let o = sh(&path, &h1, &pca, &cmd);
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
    let o = sh(&path, &h2, &pca, &cmd);
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
    // git 代理服务：单元已写入，经（替身）systemctl 启用；服务器上还没有 git 条目时不写 insteadOf，并说明之后怎么做。
    assert!(h2.join(".config/systemd/user/passmanager-git-proxy.service").exists(), "{}", stdout(&o));
    assert!(env.fake_calls().contains("systemctl --user enable passmanager-git-proxy.service"), "{}", env.fake_calls());
    assert!(stdout(&o).contains("git-proxy --install"), "{}", stdout(&o));
    // 已注册的机器：公开说明里写出连接的服务器（仍然没有注册码）。
    let o = not_root(&["show"], &h2);
    assert!(stdout(&o).contains(&format!("pm.test:{}", env.agent)) && no_code(&stdout(&o)), "{}", stdout(&o));
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
    // 经服务器代为发出 HTTP 请求（本地回显服务），密钥只在服务器上代入，结果脱敏。
    let echo = echo_server();
    let dom = format!("127.0.0.1:{echo}");
    let o = env.run_stdin(&["import", "--name", "echo-key", "--domain", &dom, "--self-signed"], b"EchoSecret-0123456789\n");
    assert!(o.status.success(), "{}", stderr(&o));
    let o = Command::new(BIN)
        .args(["http", &format!("https://{dom}/x"), "-H", "Authorization: Bearer {{secret}}"])
        .env("HOME", &h2)
        .env_remove("PASSMANAGER_CONFIG_DIR")
        .env_remove("PASSMANAGER_HOME")
        .output()
        .unwrap();
    let out = stdout(&o);
    assert!(o.status.success() && out.contains("[REDACTED:echo-key]") && !out.contains("EchoSecret-0123456789"), "{out}{}", stderr(&o));
    outputs += &out;
    // URL 以 {{条目.base_url}} 开头：基础地址（路径里有账号标识）只在服务器上代入；响应（回显的请求行）与错误里都不出现。
    let base = format!("https://127.0.0.1:{echo}/v1/acct-7f3e/gw-secret");
    let o = env.run_stdin(
        &["import", "--name", "ai", "--fields", "base_url,api_key", "--domain", &dom, "--self-signed"],
        format!("{base}\nsk-gw-0123456789\n").as_bytes(),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let client = |args: &[&str]| {
        Command::new(BIN).args(args).env("HOME", &h2).env_remove("PASSMANAGER_CONFIG_DIR").env_remove("PASSMANAGER_HOME").output().unwrap()
    };
    let o = client(&["http", "{{ai.base_url}}/models", "-H", "Authorization: Bearer {{ai.api_key}}"]);
    let out = stdout(&o) + &stderr(&o);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("[REDACTED:ai.base_url]") && out.contains("[REDACTED:ai.api_key]"), "{out}");
    assert!(!out.contains("acct-7f3e") && !out.contains("sk-gw-0123456789"), "{out}");
    outputs += &out;
    // 上游连不上：错误里只有占位符，没有地址。
    let closed = free_port();
    let bad_dom = format!("127.0.0.1:{closed}");
    let o = env.run_stdin(
        &["import", "--name", "ai-down", "--fields", "base_url,api_key", "--domain", &bad_dom, "--self-signed"],
        format!("https://127.0.0.1:{closed}/v1/acct-7f3e/down\nsk-down-0123456789\n").as_bytes(),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let o = client(&["http", "{{ai-down.base_url}}/models", "-H", "Authorization: Bearer {{ai-down.api_key}}"]);
    let out = stdout(&o) + &stderr(&o);
    assert!(!o.status.success() && out.contains("{{ai-down.base_url}}") && !out.contains("acct-7f3e") && !out.contains(&bad_dom), "{out}");
    // 主机不在条目的绑定内：拒绝，不发送，错误里没有值。
    let o = env.run_stdin(
        &["import", "--name", "ai-evil", "--fields", "base_url,api_key", "--domain", &dom, "--self-signed"],
        b"https://evil.example/v1/acct-7f3e/x\nsk-evil-0123456789\n",
    );
    assert!(o.status.success());
    let o = client(&["http", "{{ai-evil.base_url}}", "-H", "Authorization: Bearer {{ai-evil.api_key}}"]);
    let out = stdout(&o) + &stderr(&o);
    assert!(!o.status.success() && out.contains("DOMAIN_MISMATCH") && !out.contains("acct-7f3e") && !out.contains("evil.example"), "{out}");
    outputs += &out;
    assert!(!env.service_log().contains("acct-7f3e"), "日志里没有基础地址");
    let token = std::fs::read_to_string(h2.join(".config/passmanager/token")).unwrap();

    // ---- 安装时设置了 XDG_*（与之后的使用不同）：配置仍写到固定位置，之后在任何环境下都能找到 ----
    let o = env.run(&["show", "--label", "xdg"]);
    let (xline, xcode) = one_liner(&stdout(&o));
    codes.push(xcode);
    let xcmd = xline.replace(&format!("https://pm.test:{}", env.web), &format!("https://127.0.0.1:{pport}"));
    let h6 = env.base.join("h6");
    std::fs::create_dir_all(&h6).unwrap();
    let install_xdg = env.base.join("xdg-install");
    let ix = install_xdg.to_str().unwrap();
    let o = sh_env(&path, &h6, &pca, &xcmd, &[("XDG_CONFIG_HOME", ix), ("XDG_DATA_HOME", ix), ("XDG_STATE_HOME", ix)]);
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
        .env("PATH", &path)
        .env("XDG_CONFIG_HOME", lx)
        .env_remove("PASSMANAGER_CONFIG_DIR")
        .output()
        .unwrap();
    assert!(o.status.success() && !legacy.join("passmanager/remote.toml").exists(), "{}", stdout(&o));

    // ---- 只能用一次：脚本已消耗 → /a/ 404，直接 enroll 失败 ----
    assert_eq!(pq_get(&env, "GET", &format!("/a/{code}")).0, 404);
    let h3 = env.base.join("h3");
    std::fs::create_dir_all(&h3).unwrap();
    let o = sh(&path, &h3, &pca, &cmd);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(!h3.join(".local/bin/PassManager").exists(), "注册码已用过：什么都不安装");
    assert_eq!(o.status.code(), Some(22), "下载失败时大声失败（curl 的退出码）：{}", stderr(&o));
    assert!(stderr(&o).contains("curl: (22)"), "{}", stderr(&o));
    // 服务器只接受后量子 TLS：系统 curl 不支持 X25519MLKEM768 时握手失败，退出码 35（说明里让 AI 转到第 2 步）。
    let direct_cmd = line.replace("https://pm.test:", "https://127.0.0.1:");
    let o = sh(&path, &h3, &pca, &direct_cmd);
    let code_seen = o.status.code();
    assert!(code_seen.is_some_and(|c| c != 0), "握手失败不能被吞掉：{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("curl: ({})", code_seen.unwrap())), "{}", stderr(&o));
    assert!(matches!(code_seen, Some(35) | Some(60)), "35 = 握手失败（不支持 ML-KEM）；60 = 支持 ML-KEM 但不信任测试 CA：{code_seen:?}");
    assert!(!h3.join(".local/bin/PassManager").exists());
    let enroll_url = script.lines().find_map(|l| l.strip_prefix("PM_ENROLL='")).unwrap().trim_end_matches('\'').to_string();
    let direct = |home: &Path, url: &str| {
        Command::new(BIN)
            .args(["enroll", url, "--connect-addr", &format!("127.0.0.1:{}", env.agent), "--ca-file", env.ca.to_str().unwrap()])
            .env("HOME", home)
            .env("PATH", &path)
            .env_remove("PASSMANAGER_CONFIG_DIR")
            .output()
            .unwrap()
    };
    let o = direct(&h3, &enroll_url);
    assert!(!o.status.success(), "已用过的注册码不能再直接 enroll");

    // ---- 直接 enroll（自行构建的客户端）同样配置使用规则，并消耗注册码 → /a/ 404 ----
    let o = env.run(&["show", "--label", "source-build"]);
    let (_, code2) = one_liner(&stdout(&o));
    codes.push(code2.clone());
    let (_, s2) = pq_get(&env, "GET", &format!("/a/{code2}"));
    let url2 = String::from_utf8_lossy(&s2).lines().find_map(|l| l.strip_prefix("PM_ENROLL='")).unwrap().trim_end_matches('\'').to_string();
    let h4 = env.base.join("h4");
    std::fs::create_dir_all(h4.join(".gemini")).unwrap();
    let o = direct(&h4, &url2);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(
        std::fs::read_to_string(h4.join(".gemini/GEMINI.md"))
            .unwrap()
            .contains(&format!("PassManager (agent instructions v{})", pm_proto::agent_text::INSTRUCTIONS_VERSION))
    );
    assert_eq!(pq_get(&env, "GET", &format!("/a/{code2}")).0, 404);
    // --no-instructions：不写规则。
    let o = env.run(&["show", "--label", "noinstr"]);
    let (_, code3) = one_liner(&stdout(&o));
    codes.push(code3.clone());
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
        .env("PATH", &path)
        .env_remove("PASSMANAGER_CONFIG_DIR")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(!h5.join(".gemini/GEMINI.md").exists());

    // ---- 打印出来的一行命令在 bash 与 zsh 中也能直接运行（zsh 会展开未加引号的 =https）----
    for bin in ["bash", "zsh"] {
        if !have(bin) {
            eprintln!("跳过 {bin}：没有安装");
            continue;
        }
        let o = env.run(&["show", "--label", bin]);
        let (bline, bcode) = one_liner(&stdout(&o));
        codes.push(bcode);
        let bcmd = bline.replace(&format!("https://pm.test:{}", env.web), &format!("https://127.0.0.1:{pport}"));
        let hb = env.base.join(format!("home-{bin}"));
        std::fs::create_dir_all(&hb).unwrap();
        let o = shell(bin, &path, &hb, &pca, &bcmd);
        outputs += &(stdout(&o) + &stderr(&o));
        assert!(o.status.success(), "{bin}: {}{}", stdout(&o), stderr(&o));
        assert!(hb.join(".config/passmanager/remote.toml").exists(), "{bin}");
        // 已用过的注册码：同样大声失败。
        let o = shell(bin, &path, &hb, &pca, &bcmd);
        assert_eq!(o.status.code(), Some(22), "{bin}: {}", stderr(&o));
    }
    if have("zsh") {
        // 回归保护：未加引号的旧写法在 zsh 中根本不会运行 curl。
        let o = shell("zsh", &path, &env.base, &pca, "echo curl --proto =https");
        assert!(!o.status.success() && stderr(&o).contains("not found"), "{}", stderr(&o));
    }

    // ---- unenroll：移除规则（恢复用户原来的内容）、MCP 配置与远程配置 ----
    let o = Command::new(BIN).arg("unenroll").env("HOME", &h2).env("PATH", &path).env_remove("PASSMANAGER_CONFIG_DIR").output().unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(!h2.join(".config/systemd/user/passmanager-git-proxy.service").exists(), "git-proxy 服务已移除");
    assert!(env.fake_calls().contains("systemctl --user disable --now passmanager-git-proxy.service"));
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

    // ---- 并发兑换同一个注册码：恰好一个成功 ----
    let o = env.run(&["show", "--label", "race", "--url"]);
    let race_url = stdout(&o).trim().to_string();
    codes.push(pm_net::enroll::EnrollUrl::parse(&race_url).unwrap().code);
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let (url, dir, agent, ca) = (race_url.clone(), env.base.join(format!("race{i}")), env.agent, env.ca.clone());
            std::thread::spawn(move || {
                Command::new(BIN)
                    .args(["enroll", "--no-mcp", &url, "--connect-addr", &format!("127.0.0.1:{agent}"), "--ca-file", ca.to_str().unwrap()])
                    .env("PASSMANAGER_CONFIG_DIR", &dir)
                    .env_remove("PASSMANAGER_HOME")
                    .output()
                    .unwrap()
                    .status
                    .success()
            })
        })
        .collect();
    let wins = handles.into_iter().map(|h| h.join().unwrap()).filter(|ok| *ok).count();
    assert_eq!(wins, 1, "并发兑换同一个注册码只有一个成功");

    // ---- 审计：只有标签、来源与结果，从不记录注册码；任何输出里都没有令牌 ----
    let log = env.service_log();
    assert!(log.contains("bootstrap: script for enrollment code") && log.contains("bootstrap: unknown or expired code"), "{log}");
    assert!(log.contains("(setup text)") && log.contains("created for \"url-only\""), "{log}");
    assert!(log.contains("enroll: ok, token ") && log.contains("from 127.0.0.1"), "{log}");
    assert!(log.contains("enroll: rejected (unknown, used or expired code) from 127.0.0.1"), "{log}");
    assert!(!outputs.contains(token.trim()) && !log.contains(token.trim()), "令牌不出现在输出里");
    for c in &codes {
        assert!(!log.contains(c.as_str()), "日志里没有注册码");
    }

    // ---- 失败次数过多：这个来源暂时不受理，连有效的注册码也不受理（且不被消耗）----
    if !single {
        let garbage = format!("pm-enroll://pm.test:{}/{}#{}", env.agent, "A".repeat(43), race_url.rsplit('#').next().unwrap());
        for i in 0..10 {
            let o = direct(&env.base.join(format!("junk{i}")), &garbage);
            assert!(!o.status.success());
        }
        let o = env.run(&["show", "--label", "after-block", "--url"]);
        let good = stdout(&o).trim().to_string();
        let good_code = pm_net::enroll::EnrollUrl::parse(&good).unwrap().code;
        let o = direct(&env.base.join("blocked"), &good);
        assert!(!o.status.success(), "锁定中的来源");
        assert_eq!(pq_get(&env, "GET", &format!("/a/{good_code}")).0, 200, "锁定时不消耗注册码");
        assert!(env.service_log().contains("enroll: rejected (too many failed attempts) from 127.0.0.1"));
    }
}

const PAT: &str = "ghp_fake_bootstrap_pat_for_tests_only";

/// 递归读取目录下所有普通文件的内容（不跟随符号链接）。
fn read_tree(dir: &Path, out: &mut Vec<u8>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            read_tree(&e.path(), out);
        } else if ft.is_file() {
            out.extend(std::fs::read(e.path()).unwrap_or_default());
            out.push(b'\n');
        }
    }
}

/// 一键接入之后 git 直接可用：`show` → 安装脚本 → `enroll` 写入 git-proxy 的用户服务（替身 systemctl / loginctl）
/// 与每个 git 条目主机的 insteadOf；按单元里的 ExecStart 启动代理（与 systemd 相同的命令）后，普通的
/// `git push` / `git ls-remote https://…` 经代理与服务器访问本地 git 服务器（服务器注入 PAT）。
/// 重复运行 `git-proxy --install` 不会重复写入；临时 HOME 里找不到 PAT；吊销令牌后 git 失败。
#[test]
fn bootstrap_sets_up_git_proxy_service() {
    if !have("curl") || !have("sha256sum") || !have("git") {
        eprintln!("跳过：没有 curl、sha256sum 或 git");
        return;
    }
    let env = Env::setup_with("agentgit", false);
    let path = env.fake_path();
    // 本地 git 服务器（只接受带 PAT 的请求）与服务器上的条目：一个 git 条目、一个只用于 http 的条目。
    let root = env.base.join("repos");
    std::fs::create_dir_all(&root).unwrap();
    let git = |home: &Path, dir: &Path, args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .env_remove("GIT_CONFIG_GLOBAL")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap()
    };
    assert!(git(&env.base, &root, &["init", "-q", "--bare", "-b", "main", "repo.git"]).status.success());
    let (gport, counts) = git_server(root.clone(), PAT);
    let upstream = format!("127.0.0.1:{gport}");
    let o = env
        .run_stdin(&["import", "--name", "forge", "--ops", "git", "--domain", &upstream, "--self-signed"], format!("{PAT}\n").as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    let o = env.run_stdin(&["import", "--name", "api-only", "--ops", "http", "--domain", "api.example.org"], b"not-a-git-token-123\n");
    assert!(o.status.success(), "{}", stderr(&o));

    // 服务器的 Agent 程序：包装脚本（测试用的连接地址、CA 与一个空闲的代理端口）。
    let lport = free_port();
    let listen = format!("127.0.0.1:{lport}");
    let o = env.run(&["agent-bin-dir"]);
    let bin_dir = std::path::PathBuf::from(stdout(&o).trim());
    std::fs::create_dir_all(&bin_dir).unwrap();
    let target = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
    let wrapper = format!(
        "#!/bin/sh\nexec {BIN} \"$@\" --connect-addr 127.0.0.1:{} --ca-file {} --git-proxy-listen {listen}\n",
        env.agent,
        env.ca.display()
    );
    std::fs::write(bin_dir.join(format!("PassManager-{target}")), &wrapper).unwrap();
    let (pport, pca) = proxy(&env, Arc::new(AtomicBool::new(false)));

    // ---- show → 一行命令 → 安装脚本 ----
    let o = env.run(&["show", "--label", "gitbox"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let (line, _) = one_liner(&stdout(&o));
    let cmd = line.replace(&format!("https://pm.test:{}", env.web), &format!("https://127.0.0.1:{pport}"));
    let home = env.base.join("hg");
    std::fs::create_dir_all(&home).unwrap();
    let o = sh(&path, &home, &pca, &cmd);
    let mut outputs = stdout(&o) + &stderr(&o);
    assert!(o.status.success(), "{outputs}");

    // 服务文件、替身记录的调用、insteadOf。
    let unit_path = home.join(".config/systemd/user/passmanager-git-proxy.service");
    let unit = std::fs::read_to_string(&unit_path).unwrap_or_else(|_| panic!("没有服务文件：{outputs}"));
    assert!(
        unit.contains(&format!("ExecStart=\"{BIN}\" git-proxy --listen {listen}\n")) && unit.contains("WantedBy=default.target"),
        "{unit}"
    );
    let calls = env.fake_calls();
    for c in [
        "systemctl --user daemon-reload",
        "systemctl --user enable passmanager-git-proxy.service",
        "systemctl --user restart passmanager-git-proxy.service",
        "loginctl --no-ask-password enable-linger",
    ] {
        assert!(calls.lines().any(|l| l == c), "缺少 {c}：{calls}");
    }
    let token_file = home.join(".config/passmanager/git-proxy.token");
    let ptoken = std::fs::read_to_string(&token_file).unwrap().trim().to_string();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&token_file).unwrap().permissions().mode() & 0o777, 0o600);
    let gitconfig = || std::fs::read_to_string(home.join(".gitconfig")).unwrap_or_default();
    let section = format!("[url \"http://{listen}/{ptoken}/https/{upstream}/\"]");
    let gc = gitconfig();
    assert_eq!(gc.matches(&section).count(), 1, "{gc}");
    assert_eq!(gc.matches(&format!("insteadOf = https://{upstream}/")).count(), 1, "{gc}");
    assert!(!gc.contains("api.example.org"), "只有 git 用途的条目：{gc}");
    assert!(outputs.contains(&format!("https://{upstream}/")), "{outputs}");

    // ---- 重复运行：替换，不重复；路径令牌不变 ----
    let unit_before = unit.clone();
    let o = Command::new(BIN)
        .args(["git-proxy", "--install", "--listen", &listen])
        .env("HOME", &home)
        .env("PATH", &path)
        .env_remove("PASSMANAGER_HOME")
        .env_remove("PASSMANAGER_CONFIG_DIR")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(gitconfig(), gc, "重复运行后 git 配置不变（不重复）");
    assert_eq!(std::fs::read_to_string(&unit_path).unwrap(), unit_before);
    assert_eq!(std::fs::read_to_string(&token_file).unwrap().trim(), ptoken, "路径令牌持久");

    // ---- 按单元的 ExecStart 启动代理（systemd 会执行的同一条命令，干净的环境）----
    let exec = unit.lines().find_map(|l| l.strip_prefix("ExecStart=")).unwrap();
    let (prog, args) = exec.strip_prefix('"').and_then(|r| r.split_once("\" ")).unwrap();
    let mut svc = Command::new(prog)
        .args(args.split_whitespace())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let t0 = std::time::Instant::now();
    while TcpStream::connect(("127.0.0.1", lport)).is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10), "代理没有启动");
        std::thread::sleep(Duration::from_millis(50));
    }

    // ---- 普通的 https:// 地址：push 与 ls-remote 经代理成功 ----
    let work = env.base.join("gwork");
    std::fs::create_dir_all(&work).unwrap();
    assert!(git(&home, &work, &["init", "-q", "-b", "main"]).status.success());
    std::fs::write(work.join("README"), "via resident git-proxy\n").unwrap();
    assert!(git(&home, &work, &["add", "."]).status.success());
    assert!(git(&home, &work, &["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init"]).status.success());
    let remote = format!("https://{upstream}/repo.git");
    let o = git(&home, &work, &["push", "-q", &remote, "main"]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "push: {}", stderr(&o));
    let o = git(&home, &work, &["ls-remote", &remote]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success() && stdout(&o).contains("refs/heads/main"), "ls-remote: {}", stderr(&o));
    assert!(counts.authed.load(Ordering::SeqCst) >= 3 && counts.rejected.load(Ordering::SeqCst) == 0, "上游每个请求都带 PAT");

    // ---- 本机没有 PAT：临时 HOME 的所有文件、命令输出 ----
    let mut tree = Vec::new();
    read_tree(&home, &mut tree);
    let b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{PAT}"))
    };
    let tree = String::from_utf8_lossy(&tree);
    assert!(!tree.contains(PAT) && !tree.contains(&b64), "PAT 出现在 Agent 机器的文件里");
    assert!(!outputs.contains(PAT) && !outputs.contains(&b64));

    // ---- 吊销这台机器的令牌：git 立即失败 ----
    let o = env.run(&["token", "list"]);
    let id = stdout(&o).lines().find(|l| l.contains("gitbox")).and_then(|l| l.split_whitespace().next()).unwrap().to_string();
    assert!(env.run(&["token", "revoke", &id]).status.success());
    let o = git(&home, &work, &["ls-remote", &remote]);
    assert!(!o.status.success(), "吊销后 git 不能再使用：{}", stdout(&o));
    let _ = svc.kill();
    let mut svc_out = String::new();
    let _ = svc.stdout.take().unwrap().read_to_string(&mut svc_out);
    let _ = svc.stderr.take().unwrap().read_to_string(&mut svc_out);
    let _ = svc.wait();
    assert!(svc_out.contains(&format!("https://{upstream}/")), "没有 --host 时默认是 git 条目的主机：{svc_out}");
    assert!(!svc_out.contains(PAT) && !env.service_log().contains(PAT));
}

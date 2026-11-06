#![cfg(target_os = "linux")]
//! URL 别名：真实服务 + 真实 TLS 回显服务器 + Agent 命令行。
//! Agent 只写 `alias://名称`；原主机不能被直接访问，真实地址不出现在任何结果里。

mod common;

use std::sync::Arc;

use common::{Env, echo_server, stdout};

const SECRET: &[u8] = b"alias-e2e-secret-value";

/// 把一次 Agent 调用的全部输出拼起来（检查泄露时 stdout 与 stderr 都算）。
fn all(o: &std::process::Output) -> String {
    format!("{}{}", stdout(o), common::stderr(o))
}

#[test]
fn alias_hides_the_real_address_from_agents() {
    let mut env = Env::setup("alias");
    let port = echo_server();
    let real = format!("https://127.0.0.1:{port}/v1");
    let hostport = format!("127.0.0.1:{port}");

    // 凭据绑定到真实主机，再由 root 设别名。
    let o = env.run_stdin(&["import", "--name", "echo", "--domain", "127.0.0.1", "--ops", "http,ssh,git", "--self-signed"], SECRET);
    assert!(o.status.success(), "{}", all(&o));
    let o = env.run(&["alias", "add", "billing", &real, "--note", "internal"]);
    assert!(o.status.success(), "{}", all(&o));
    assert!(stdout(&env.run(&["alias", "list"])).contains(&real), "root 看得到真实地址");

    // lookup 只给别名的写法：没有条目名、地址、端口。
    let o = env.agent_cmd(&["lookup", "alias://billing"]).output().unwrap();
    let out = all(&o);
    assert!(o.status.success() && out.contains("alias://billing/<path>"), "{out}");
    assert!(!out.contains(&hostport) && !out.contains("\"echo\""), "{out}");

    // 经别名访问：服务器代入真实地址与凭据；回显里的 Host 头与路径都被换掉，密钥也被脱敏。
    let o = env.agent_cmd(&["http", "GET", "alias://billing/items?q=1", "-H", "Authorization: Bearer {{secret}}"]).output().unwrap();
    let out = all(&o);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("GET /v1/items?q=1") && out.contains("alias://billing"), "请求到达了真实路径，主机被换成别名：{out}");
    assert!(!out.contains(&hostport) && !out.contains(&port.to_string()), "真实地址泄露：{out}");
    assert!(!out.contains(std::str::from_utf8(SECRET).unwrap()), "{out}");

    // Agent 要求压缩也不行：服务器收到的是 identity（压缩后的字节里找不到要脱敏的文本）。
    let o = env.agent_cmd(&["http", "GET", "alias://billing/z", "-H", "Accept-Encoding: gzip"]).output().unwrap();
    let out = all(&o).to_ascii_lowercase();
    assert!(out.contains("accept-encoding: identity") && !out.contains("gzip"), "{out}");
    let o = env.agent_cmd(&["http", "GET", "alias://billing/z", "-H", "Range: bytes=0-9"]).output().unwrap();
    assert!(!o.status.success() && all(&o).contains("BAD_REQUEST"), "{}", all(&o));

    // 直接访问原地址：每条路都被拒绝，错误里没有别名。
    for args in [
        vec!["http".to_string(), "GET".into(), format!("{real}/x"), "-H".into(), "Authorization: Bearer {{secret}}".into()],
        vec![
            "http".to_string(),
            "GET".into(),
            format!("https://127.0.0.1:{}/other", common::free_port()),
            "-H".into(),
            "X: {{secret}}".into(),
        ],
        vec!["lookup".to_string(), real.clone()],
        vec!["lookup".to_string(), "127.0.0.1".into()],
        vec!["lookup".to_string(), "root@127.0.0.1".into()],
        vec!["lookup".to_string(), "{{echo}}".into()],
        vec!["ssh".to_string(), "root@127.0.0.1".into(), "uptime".into()],
        vec!["ssh".to_string(), "root@198.51.100.7".into(), "curl https://127.0.0.1/".into()],
    ] {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = env.agent_cmd(&refs).output().unwrap();
        let out = all(&o);
        assert!(!o.status.success() && out.contains("ALIAS_ONLY"), "{args:?}: {out}");
        assert!(!out.contains("billing"), "{args:?}: {out}");
    }

    // 路径穿越、未知别名。
    let o = env.agent_cmd(&["http", "GET", "alias://billing/../x"]).output().unwrap();
    assert!(!o.status.success() && all(&o).contains("BAD_URL"), "{}", all(&o));
    let o = env.agent_cmd(&["http", "GET", "alias://nope/x"]).output().unwrap();
    assert!(!o.status.success() && all(&o).contains("UNKNOWN_ALIAS"), "{}", all(&o));

    // 重启后别名还在（库写成 v3），限制继续有效。
    if let Some(mut c) = env.child.take() {
        c.kill().unwrap();
        let _ = c.wait();
    }
    let _ = std::fs::remove_file(env.home.join("run/passmanager.sock"));
    env.start();
    let o = env.agent_cmd(&["lookup", "127.0.0.1"]).output().unwrap();
    assert!(all(&o).contains("ALIAS_ONLY"), "{}", all(&o));

    // 删除别名：恢复直接访问。
    assert!(env.run(&["alias", "remove", "billing"]).status.success());
    let o = env.agent_cmd(&["lookup", "127.0.0.1"]).output().unwrap();
    assert!(o.status.success() && all(&o).contains("echo"), "{}", all(&o));
    assert!(!env.run(&["alias", "remove", "billing"]).status.success(), "再删一次是错误");
}

/// 经真实 TLS 连接取状态码（ConnInfo 由真实的前端写入）。
fn web_status(env: &Env, path: &str) -> u16 {
    use rustls::pki_types::pem::PemObject;
    use std::io::{Read, Write};
    let pem = std::fs::read(&env.ca).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from_pem_slice(&pem).unwrap()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(pm_net::tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = rustls::ClientConnection::new(Arc::new(cfg), "pm.test".try_into().unwrap()).unwrap();
    let tcp = std::net::TcpStream::connect(("127.0.0.1", env.web)).unwrap();
    let mut s = rustls::StreamOwned::new(conn, tcp);
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: pm.test:{}\r\nConnection: close\r\n\r\n", env.web).as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    String::from_utf8_lossy(&raw).split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

fn reinit(env: &mut Env, args: &[&str]) -> std::process::Output {
    if let Some(mut c) = env.child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    let _ = std::fs::remove_file(env.home.join("run/passmanager.sock"));
    let mut a = vec!["init", "--skip-acme", "--no-start", "--acme-directory", ""];
    a.extend_from_slice(args);
    env.run(&a)
}

#[test]
fn admin_allow_limits_the_web_ui_on_real_connections() {
    let mut env = Env::setup("adminallow");
    assert_eq!(web_status(&env, "/login"), 200, "默认不限制");

    // 只允许别的地址：本机（127.0.0.1）打不开管理界面。
    let o = reinit(&mut env, &["--admin-allow", "198.51.100.10 198.51.100.12"]);
    assert!(o.status.success(), "{}", all(&o));
    env.start();
    for p in ["/", "/login", "/entries"] {
        assert_eq!(web_status(&env, p), 404, "{p}");
    }
    assert!(stdout(&env.run(&["status"])).contains("198.51.100.10"), "status 显示来源限制");
    // Agent 通道不受影响。
    assert!(env.agent_cmd(&["status"]).output().unwrap().status.success());

    // 空列表不是放行：配置被拒绝。
    let o = reinit(&mut env, &["--admin-allow", ""]);
    assert!(!o.status.success(), "{}", all(&o));

    // 明确取消后恢复。
    let o = reinit(&mut env, &["--admin-allow", "any"]);
    assert!(o.status.success(), "{}", all(&o));
    env.start();
    assert_eq!(web_status(&env, "/login"), 200);
}

#[test]
fn one_click_login_link_works_once_on_a_real_connection() {
    let env = Env::setup("autologin");
    let o = env.run(&["login", "--auto"]);
    assert!(o.status.success(), "{}", all(&o));
    let url = stdout(&o).trim().to_string();
    let path = &url[url.find("/l/").unwrap()..];
    assert_eq!(web_status(&env, path), 200, "打开即登录");
    assert_eq!(web_status(&env, path), 404, "只能用一次");
    // 一键链接只由服务器上的 root 生成：Agent 没有这个入口。
    let o = env.agent_cmd(&["login", "--auto"]).output().unwrap();
    assert!(!o.status.success(), "{}", all(&o));
}

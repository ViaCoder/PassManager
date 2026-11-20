//! 两步验证端到端（服务器模式，真实的服务进程与网页）：
//! root 会话拿不到两步验证；网页一次导入二维码图片（普通链接与 Google 迁移码，经 `qr-decode` 子进程解码）、
//! 粘贴的 Steam 链接和 2FAS 备份；各账户详情页的验证码与按种子算出的一致；"显示密钥"返回的正是那个种子；改名、删除；
//! 服务日志与库文件里找不到任何种子；坏图片不影响服务。服务器模式只支持 Linux，所以只在 Linux 上编译。
#![cfg(target_os = "linux")]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use common::*;
use pm_proto::*;

/// 网页响应。
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

/// HTTP/1.1 over TLS 1.3（信任测试的自签证书）。`body` = (Content-Type, 内容)。
fn https(env: &Env, method: &str, path: &str, cookie: Option<&str>, body: Option<(&str, &[u8])>) -> Http {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&env.ca).unwrap();
    roots.add(rustls::pki_types::CertificateDer::from_pem_slice(&pem).unwrap()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(pm_net::tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = rustls::ClientConnection::new(Arc::new(cfg), "pm.test".try_into().unwrap()).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", env.web)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: pm.test:{}\r\nConnection: close\r\n", env.web).into_bytes();
    if let Some(c) = cookie {
        req.extend_from_slice(format!("Cookie: __Host-pm={c}\r\n").as_bytes());
    }
    match body {
        Some((ct, b)) => {
            req.extend_from_slice(format!("Content-Type: {ct}\r\nContent-Length: {}\r\n\r\n", b.len()).as_bytes());
            req.extend_from_slice(b);
        }
        None => req.extend_from_slice(b"\r\n"),
    }
    s.write_all(&req).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines.next().unwrap_or("").split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    Http { status, headers, body: body.to_string() }
}

/// 表单请求体。
fn form(s: &str) -> Option<(&'static str, &[u8])> {
    Some(("application/x-www-form-urlencoded", s.as_bytes()))
}

/// 一张灰度二维码 PNG。
fn qr_png(text: &str) -> Vec<u8> {
    let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
    let (n, colors) = (code.width(), code.to_colors());
    let side = (n + 8) * 4;
    let mut px = vec![255u8; side * side];
    for y in 0..side {
        for x in 0..side {
            let (mx, my) = ((x / 4).wrapping_sub(4), (y / 4).wrapping_sub(4));
            if mx < n && my < n && colors[my * n + mx] == qrcode::Color::Dark {
                px[y * side + x] = 0;
            }
        }
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, side as u32, side as u32);
        enc.set_color(png::ColorType::Grayscale);
        enc.write_header().unwrap().write_image_data(&px).unwrap();
    }
    out
}

/// multipart/form-data：每项 (字段名, 文件名, 内容)。
fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> (String, Vec<u8>) {
    let boundary = "pme2eboundary91c";
    let mut body = Vec::new();
    for (name, file, data) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match file {
            Some(f) => body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes()),
        }
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

/// 测试用的 Base32（RFC 4648，不带填充）。
fn b32(b: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0);
    for &x in b {
        acc = (acc << 8) | x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Google 迁移码：一个 TOTP（SHA1、6 位）账户。protobuf 按 migration.proto 的字段号手工拼。
fn migration_link(secret: &[u8], name: &str, issuer: &str) -> String {
    fn bytes_field(n: u8, data: &[u8], out: &mut Vec<u8>) {
        out.push(n << 3 | 2);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    let mut p = Vec::new();
    bytes_field(1, secret, &mut p);
    bytes_field(2, name.as_bytes(), &mut p);
    bytes_field(3, issuer.as_bytes(), &mut p);
    p.extend_from_slice(&[4 << 3, 1, 5 << 3, 1, 6 << 3, 2]);
    let mut payload = Vec::new();
    bytes_field(1, &p, &mut payload);
    payload.extend_from_slice(&[2 << 3, 1]);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
    format!("otpauth-migration://offline?data={}", b64.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"))
}

/// 页面里 `属性="值"` 的值。
fn attr(page: &str, a: &str) -> String {
    let i = page.find(&format!("{a}=\"")).unwrap() + a.len() + 2;
    page[i..].split('"').next().unwrap().to_string()
}

fn code(r: Result<serde_json::Value, ApiError>) -> String {
    r.err().map(|e| e.code).unwrap_or_else(|| "OK".into())
}

#[test]
fn otp_import_show_rename_delete() {
    let env = Env::setup("otp");
    // 种子：RFC 4226 的测试种子（otpauth 链接）、迁移码、Steam 链接、2FAS 备份各一个
    let seed_link = b"12345678901234567890".to_vec();
    let seed_mig = b"migration-seed-0001".to_vec();
    let seed_steam = b"steam-seed-abcdefgh".to_vec();
    let seed_2fas = b"twofas-seed-qrstuvwx".to_vec();
    let seeds = [&seed_link, &seed_mig, &seed_steam, &seed_2fas];

    // ---- root 会话（本机 socket）：两步验证一律拒绝 ----
    let mut root = Client::connect_at(&env.home.join("run/passmanager.sock"), &Hello::Root { v: PROTO_V }).unwrap();
    assert_eq!(code(root.call(&Request::OtpList)), "FORBIDDEN");
    assert_eq!(code(root.call(&Request::OtpDetail { name: "x".into(), reveal: true })), "FORBIDDEN");

    // ---- 网页登录 ----
    let o = env.run(&["login"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let link = stdout(&o).trim().to_string();
    let path = link.split_once(&format!("pm.test:{}", env.web)).unwrap().1.to_string();
    let r = https(&env, "POST", &path, None, form(""));
    assert_eq!(r.status, 303);
    let cookie = r.header("set-cookie").unwrap().split(';').next().unwrap().strip_prefix("__Host-pm=").unwrap().to_string();
    let page = https(&env, "GET", "/otp/import", Some(&cookie), None);
    assert_eq!(page.status, 200);
    assert!(page.body.contains("id=\"drop\""), "服务器上有二维码解码器，导入页有拖放区");
    let csrf = attr(&page.body, "name=\"csrf\" value");

    // ---- 导入：两张二维码图片、一个不是图片的文件、粘贴的 Steam 链接、2FAS 备份（含一个 HOTP） ----
    let link_url = format!("otpauth://totp/Example:alice?secret={}&issuer=Example", b32(&seed_link));
    let png1 = qr_png(&link_url);
    let png2 = qr_png(&migration_link(&seed_mig, "GitHub:bob", "GitHub"));
    let steam = format!("otpauth://steam/Steam:carol?secret={}", b32(&seed_steam));
    let twofas = format!(
        r#"{{"services":[{{"name":"Dropbox","secret":"{}","otp":{{"account":"dave","tokenType":"TOTP"}}}},
           {{"name":"Bank","secret":"{}","otp":{{"account":"erin","tokenType":"HOTP","counter":1}}}}],"schemaVersion":4}}"#,
        b32(&seed_2fas),
        b32(b"hotp-seed-123456")
    );
    let (ct, body) = multipart(&[
        ("csrf", None, csrf.as_bytes()),
        ("images", Some("a.png"), &png1),
        ("images", Some("b.png"), &png2),
        ("images", Some("c.png"), b"\x89PNG\r\n\x1a\nbroken"),
        ("links", None, steam.as_bytes()),
        ("twofas", Some("backup.2fas"), twofas.as_bytes()),
    ]);
    let r = https(&env, "POST", "/otp/import", Some(&cookie), Some((&ct, &body)));
    assert_eq!(r.status, 200, "{}", r.body);
    for n in ["Example:alice", "GitHub:bob", "Steam:carol", "Dropbox:dave"] {
        assert!(r.body.contains(&format!("<code>{n}</code>")), "导入了 {n}");
    }
    assert!(r.body.contains("已导入 4 个"), "{}", r.body);
    assert!(r.body.contains("第 3 张图片") && r.body.contains("PNG 图片已损坏"), "坏图片由子进程报出原因");
    assert!(r.body.contains("Bank:erin") && r.body.contains("HOTP"));
    // 再导入同一张图：库里已有，不重复
    let (ct, body) = multipart(&[("csrf", None, csrf.as_bytes()), ("images", Some("a.png"), &png1)]);
    let r = https(&env, "POST", "/otp/import", Some(&cookie), Some((&ct, &body)));
    assert!(r.body.contains("库里已经有的 1 个"), "{}", r.body);

    // ---- 列表页链接到各账户；详情页的验证码与按种子算出的一致，页面里没有密钥 ----
    let list = https(&env, "GET", "/otp", Some(&cookie), None);
    assert!(list.body.contains("href=\"/otp/a/Example%3Aalice\"") && !list.body.contains("data-copy"), "列表页不显示验证码");
    let steam_p = pm_otp::Params { kind: pm_otp::Kind::Steam, digits: 5, ..Default::default() };
    for (name, seed, p) in [
        ("Example%3Aalice", &seed_link, pm_otp::Params::default()),
        ("GitHub%3Abob", &seed_mig, pm_otp::Params::default()),
        ("Steam%3Acarol", &seed_steam, steam_p),
        ("Dropbox%3Adave", &seed_2fas, pm_otp::Params::default()),
    ] {
        let r = https(&env, "GET", &format!("/otp/a/{name}"), Some(&cookie), None);
        assert_eq!(r.status, 200, "{name}");
        assert!(r.header("content-security-policy").unwrap().contains("script-src 'sha256-"));
        let now: u64 = attr(&r.body, "data-now").parse().unwrap();
        assert_eq!(attr(&r.body, "data-copy"), pm_otp::code::at(seed, &p, now).as_str(), "{name}");
        assert!(!r.body.contains(&b32(seed)), "{name}: 详情页不含密钥");
    }
    // ---- 显示密钥：返回的 Base32 正是那个种子；没有 CSRF 时拒绝 ----
    assert_eq!(https(&env, "POST", "/otp/a/Example%3Aalice/secret", Some(&cookie), form("csrf=wrong")).status, 403);
    let r = https(&env, "POST", "/otp/a/Example%3Aalice/secret", Some(&cookie), form(&format!("csrf={csrf}")));
    assert_eq!(r.status, 200);
    assert!(r.body.contains(&format!("data-copy=\"{}\"", b32(&seed_link))) && r.body.contains("<svg class=\"qr\""));

    // ---- 改名、删除 ----
    let r = https(&env, "POST", "/otp/a/GitHub%3Abob/rename", Some(&cookie), form(&format!("csrf={csrf}&new_name=Work")));
    assert_eq!(r.status, 303);
    let r = https(&env, "POST", "/otp/a/Work/delete", Some(&cookie), form(&format!("csrf={csrf}")));
    assert_eq!(r.status, 303);
    let list = https(&env, "GET", "/otp", Some(&cookie), None);
    assert!(!list.body.contains("Work") && !list.body.contains("GitHub:bob") && list.body.contains("Steam:carol"));

    // ---- 种子不出现在任何响应、服务日志与库文件里 ----
    let log = env.service_log();
    assert!(log.contains("web: otp import added=4") && log.contains("web: otp code name=Steam:carol"), "{log}");
    assert_eq!(log.matches("web: otp reveal name=Example:alice").count(), 1, "显示密钥记了一次日志");
    let vault = std::fs::read(env.home.join("data/vault.pmv")).or_else(|_| {
        // 布局不同时在服务器目录里找库文件
        let mut found = None;
        for e in walk(&env.home) {
            if e.extension().is_some_and(|x| x == "pmv") {
                found = Some(e);
            }
        }
        std::fs::read(found.expect("找不到库文件"))
    });
    let vault = vault.unwrap();
    for s in seeds {
        let b = b32(s);
        assert!(!log.contains(&b) && !log.contains(std::str::from_utf8(s).unwrap()), "日志里没有种子");
        assert!(!vault.windows(s.len()).any(|w| w == s.as_slice()), "库文件里没有种子原文");
        assert!(!vault.windows(b.len()).any(|w| w == b.as_bytes()), "库文件里没有种子的 Base32");
        assert!(!list.body.contains(&b));
    }
    // 服务一直在：坏图片只影响那一张
    assert_eq!(https(&env, "GET", "/otp", Some(&cookie), None).status, 200);
    assert!(!log.contains("panicked"), "{log}");
}

/// 列出目录下的全部文件（递归）。
fn walk(d: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

//! 网页层测试：入口检查、cookie、一次性链接、会话过期、限速、CSRF、密钥不出现在任何响应里、
//! 每个模板的 XSS 注入。服务用内存替身代替。

use super::*;
use axum::body::Body;
use axum::http::{Method, Uri};
use http_body_util::BodyExt;
use pm_proto::{EntryView, Report};
use tower::ServiceExt;

const SECRET: &str = "ghp_SuperSecretValue_0123456789";

/// (视图, 单值密钥, 字段 (名, 值))
type MockEntry = (EntryView, String, Vec<(String, String)>);

#[derive(Default)]
struct Mock {
    /// (视图, 单值密钥, 字段 (名, 值))
    entries: Mutex<Vec<MockEntry>>,
    locked: Mutex<bool>,
    log: Mutex<Vec<String>>,
}

impl Backend for Mock {
    fn call(&self, req: Req) -> BoxFut<'_, Resp> {
        Box::pin(async move {
            self.log.lock().unwrap().push(format!("{req:?}").chars().take(40).collect());
            let locked = *self.locked.lock().unwrap();
            let need_unlocked = matches!(req, Req::Entries | Req::AddEntry { .. } | Req::UpdateEntry { .. } | Req::DeleteEntry { .. });
            if locked && need_unlocked {
                return Resp::err("LOCKED", "locked");
            }
            match req {
                Req::Entries => Resp::ok(self.entries.lock().unwrap().iter().map(|(e, _, _)| e.clone()).collect::<Vec<_>>()),
                Req::AddEntry { entry } => {
                    if entry.domains.iter().any(|d| d == "*.com") {
                        return Resp::err("BAD_REQUEST", "通配符的基础域名不能是公共后缀");
                    }
                    let name = if entry.name.is_empty() {
                        entry.domains.first().map(|d| d.trim_start_matches("*.").to_string()).unwrap_or_else(|| "credential".into())
                    } else {
                        entry.name.clone()
                    };
                    let fields: Vec<(String, String)> =
                        entry.fields.clone().unwrap_or_default().into_iter().map(|f| (f.name, f.value.unwrap_or_default())).collect();
                    if fields.iter().any(|(_, v)| v.is_empty()) {
                        return Resp::err("BAD_REQUEST", "字段没有值");
                    }
                    let kind = if !fields.is_empty() { "fields" } else { entry.kind.as_deref().unwrap_or("password") };
                    let v = EntryView {
                        name,
                        domains: entry.domains,
                        note: entry.note,
                        self_signed: entry.self_signed,
                        auto_accept_host_key: entry.auto_accept_host_key,
                        private_key: kind == "ssh-key",
                        created: 1,
                        updated: 1_700_000_000,
                        kind: kind.into(),
                        fields: fields.iter().map(|(n, _)| n.clone()).collect(),
                        public_key: (kind == "ssh-key").then(|| "ecdsa-sha2-nistp384 SHA256:FAKEFINGERPRINT".to_string()),
                        host_keys: entry.host_keys.clone().unwrap_or_default(),
                        ops: entry.ops.clone().unwrap_or_default(),
                    };
                    self.entries.lock().unwrap().push((v, entry.secret.unwrap_or_default(), fields));
                    Resp::ok("added")
                }
                Req::UpdateEntry { original, entry } => {
                    let mut l = self.entries.lock().unwrap();
                    let Some(e) = l.iter_mut().find(|(e, _, _)| e.name == original) else {
                        return Resp::err("UNKNOWN_CREDENTIAL", "条目不存在");
                    };
                    e.0.domains = entry.domains;
                    e.0.note = entry.note;
                    if let Some(o) = entry.ops {
                        e.0.ops = o;
                    }
                    if let Some(s) = entry.secret {
                        e.1 = s;
                    }
                    if let Some(fs) = entry.fields {
                        // 与服务端相同的语义：按给出的顺序设置，值为空时保留同名旧值，未列出的删除。
                        let mut new = Vec::new();
                        for f in fs {
                            let v = match f.value {
                                Some(v) if !v.is_empty() => v,
                                _ => match e.2.iter().find(|(n, _)| *n == f.name) {
                                    Some((_, old)) => old.clone(),
                                    None => return Resp::err("BAD_REQUEST", format!("字段 {} 没有值", f.name)),
                                },
                            };
                            new.push((f.name, v));
                        }
                        e.0.fields = new.iter().map(|(n, _)| n.clone()).collect();
                        e.2 = new;
                    }
                    Resp::ok("updated")
                }
                Req::DeleteEntry { name } => {
                    self.entries.lock().unwrap().retain(|(e, _, _)| e.name != name);
                    Resp::ok("deleted")
                }
                Req::Tokens => Resp::ok(vec![TokenView { id: "ab12cd34".into(), label: "laptop".into(), created: 0, last_used: None }]),
                Req::RevokeToken { id } => {
                    if id == "ab12cd34" {
                        Resp::ok("revoked")
                    } else {
                        Resp::err("BAD_REQUEST", "令牌不存在")
                    }
                }
                Req::AgentSetup { label, lang } => {
                    let lang = pm_proto::agent_text::Lang::parse(&lang).unwrap();
                    let b = pm_proto::agent_text::BuildInfo { version: "0.3.0".into(), ..Default::default() };
                    let url = format!("pm-enroll://pm.test:8443/{BOOT_CODE}#FPR");
                    let text = pm_proto::agent_text::setup_text(lang, "https://pm.test", BOOT_CODE, &url, &b, 10);
                    Resp::ok(pm_proto::AgentSetupView { id: "e1".into(), label, text, expires_in_secs: 600 })
                }
                Req::EnrollPeek { code, .. } => {
                    if code == BOOT_CODE {
                        Resp::ok(pm_proto::EnrollPeekView { url: format!("pm-enroll://pm.test:8443/{BOOT_CODE}#FPR") })
                    } else {
                        Resp::err("NOT_FOUND", "not found")
                    }
                }
                Req::EnrollCreate { label } => Resp::ok(pm_proto::EnrollView {
                    id: "e1".into(),
                    label,
                    url: "pm-enroll://pm.test:8443/CODE#FPR".into(),
                    expires_in_secs: 600,
                }),
                Req::Enrollments => Resp::ok(vec![PendingEnrollView { id: "e1".into(), label: "x".into(), expires_in_secs: 500 }]),
                Req::EnrollCancel { .. } => Resp::ok("cancelled"),
                Req::Pins => Resp::ok(Vec::<PinView>::new()),
                Req::PendingPins => Resp::ok(Vec::<PendingPinView>::new()),
                Req::TrustPins { .. } => Resp::ok(Vec::<PinView>::new()),
                Req::GetSettings => Resp::ok(SettingsView { auto_lock_hours: 0 }),
                Req::SetSettings { .. } => Resp::ok("saved"),
                Req::Lock => {
                    *self.locked.lock().unwrap() = true;
                    Resp::ok("locked")
                }
                Req::Unlock => {
                    *self.locked.lock().unwrap() = false;
                    Resp::ok("unlocked")
                }
                Req::ServerStatus => Resp::ok(ServerStatusView {
                    domain: "pm.test".into(),
                    web_port: 443,
                    agent_port: 8443,
                    lan: vec!["198.51.100.0/24".into()],
                    locked,
                    initialized: true,
                    vault_mode: "device-only".into(),
                    level: 2,
                    seal_method: "systemd-creds-host".into(),
                    tokens: 1,
                    ..Default::default()
                }),
                Req::Security => Resp::ok(SecurityView {
                    level: 2,
                    method: "systemd-creds-host".into(),
                    description: "host".into(),
                    l1_reason: None,
                    mode: "system".into(),
                    report: Report::default(),
                    runtime_issues: vec![],
                }),
                other => Resp::err("FORBIDDEN", format!("unexpected {other:?}")),
            }
        })
    }
}

/// 测试用的有效注册码（43 个 base64url 字符）。
const BOOT_CODE: &str = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE";

/// 测试用的 Agent 程序目录（两个假程序）。
fn agent_bin_dir() -> std::path::PathBuf {
    static D: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    D.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("pm-web-bins-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("PassManager-x86_64-unknown-linux-gnu"), b"fake-linux-client").unwrap();
        std::fs::write(d.join("PassManager-universal-apple-darwin"), b"fake-mac-client").unwrap();
        d
    })
    .clone()
}

fn state() -> (St, Arc<Mock>) {
    let mock = Arc::new(Mock::default());
    let st = AppState::new(
        mock.clone(),
        LoginLinks::new(),
        WebConfig { domain: "pm.test".into(), port: 443, agent_bin_dir: Some(agent_bin_dir()) },
    );
    (st, mock)
}

struct Resp2 {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn send(st: &St, method: Method, uri: &str, cookie: Option<&str>, form: Option<&str>, extra: &[(&str, &str)]) -> Resp2 {
    // extra 里可以用 ("host", …) 替换默认的 Host。
    let host = extra.iter().find(|(k, _)| *k == "host").map_or("pm.test", |(_, v)| *v);
    let mut b = axum::http::Request::builder().method(method).uri(uri).header("host", host);
    if let Some(c) = cookie {
        b = b.header("cookie", format!("{COOKIE}={c}"));
    }
    for (k, v) in extra.iter().filter(|(k, _)| *k != "host") {
        b = b.header(*k, *v);
    }
    let body = match form {
        Some(f) => {
            b = b.header("content-type", "application/x-www-form-urlencoded");
            Body::from(f.to_string())
        }
        None => Body::empty(),
    };
    let r = router(st.clone()).oneshot(b.body(body).unwrap()).await.unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    Resp2 { status, headers, body: String::from_utf8_lossy(&bytes).into_owned() }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// 用一次性链接登录，返回 (cookie, csrf)。
async fn login(st: &St) -> (String, String) {
    let t = st.links.create();
    let r = send(st, Method::POST, &format!("/l/{t}"), None, Some(""), &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let sc = r.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let cookie = sc.split(';').next().unwrap().strip_prefix(&format!("{COOKIE}=")).unwrap().to_string();
    let page = send(st, Method::GET, "/settings", Some(&cookie), None, &[]).await;
    let i = page.body.find("name=\"csrf\" value=\"").unwrap() + 19;
    let csrf = page.body[i..].split('"').next().unwrap().to_string();
    (cookie, csrf)
}

#[test]
fn host_header_must_match_service() {
    assert!(host_ok("pm.example.com", 443, "pm.example.com"));
    assert!(host_ok("pm.example.com", 443, "PM.EXAMPLE.COM:443"));
    assert!(host_ok("pm.example.com", 443, "pm.example.com."));
    assert!(host_ok("pm.test", 8443, "pm.test:8443"));
    for bad in [
        "pm.example.com:8443",
        "evil.example",
        "pm.example.com.evil.example",
        "203.0.113.55",
        "203.0.113.55:443",
        "[::1]:443",
        "",
        ":443",
        "pm.example.com:443:443",
    ] {
        assert!(!host_ok("pm.example.com", 443, bad), "{bad}");
    }
}

/// 非 443 端口（例如单端口模式的 8121）：Host 必须带这个端口，Origin 也必须是带端口的 https 地址；
/// 生成的地址（origin、一键接入脚本里的下载地址）都带端口。
#[tokio::test]
async fn non_default_port_in_host_origin_and_urls() {
    assert!(host_ok("pm.example.com", 8121, "pm.example.com:8121"));
    assert!(host_ok("pm.example.com", 8121, "PM.example.com.:8121"));
    for bad in ["pm.example.com", "pm.example.com:443", "pm.example.com:8443", "pm.example.com:81210", "evil.example:8121"] {
        assert!(!host_ok("pm.example.com", 8121, bad), "{bad}");
    }
    let cfg = WebConfig { domain: "pm.example.com".into(), port: 8121, agent_bin_dir: None };
    assert_eq!(cfg.origin(), "https://pm.example.com:8121");
    assert_eq!(WebConfig { port: 443, ..cfg }.origin(), "https://pm.example.com");
    let o = "https://pm.example.com:8121".to_string();
    let mk = |host: &str, origin: Option<&str>| {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        if let Some(v) = origin {
            h.insert(header::ORIGIN, HeaderValue::from_str(v).unwrap());
        }
        h
    };
    let g = |m: &Method, h: &HeaderMap| guard_check("pm.example.com", 8121, &o, m, &"/".parse::<Uri>().unwrap(), h);
    assert!(g(&Method::GET, &mk("pm.example.com:8121", None)).is_ok());
    assert!(g(&Method::GET, &mk("pm.example.com", None)).is_err(), "缺少端口");
    assert!(g(&Method::POST, &mk("pm.example.com:8121", Some("https://pm.example.com:8121"))).is_ok());
    for bad in ["https://pm.example.com", "https://pm.example.com:443", "http://pm.example.com:8121"] {
        assert!(g(&Method::POST, &mk("pm.example.com:8121", Some(bad))).is_err(), "{bad}");
    }
    // 一键接入脚本：下载地址带端口。
    let mock = Arc::new(Mock::default());
    let st =
        AppState::new(mock, LoginLinks::new(), WebConfig { domain: "pm.test".into(), port: 8121, agent_bin_dir: Some(agent_bin_dir()) });
    let b = axum::http::Request::builder().method(Method::GET).uri(format!("/a/{BOOT_CODE}")).header("host", "pm.test:8121");
    let r = router(st.clone()).oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(body.contains(&format!("PM_BASE='https://pm.test:8121/a/{BOOT_CODE}'")), "{body}");
    let b = axum::http::Request::builder().method(Method::GET).uri(format!("/a/{BOOT_CODE}")).header("host", "pm.test");
    assert_eq!(router(st).oneshot(b.body(Body::empty()).unwrap()).await.unwrap().status(), StatusCode::FORBIDDEN, "错误的端口");
}

#[test]
fn cross_site_requests_are_rejected() {
    let o = "https://pm.test".to_string();
    let g = |m: &Method, h: &HeaderMap| guard_check("pm.test", 443, &o, m, &"/".parse::<Uri>().unwrap(), h);
    let mk = |pairs: &[(&str, &str)]| {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("pm.test"));
        for (k, v) in pairs {
            h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    };
    let nav = [("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "document")];
    assert!(g(&Method::GET, &mk(&nav)).is_ok(), "点链接打开页面");
    assert!(g(&Method::POST, &mk(&nav)).is_err(), "跨站表单");
    for (k, v) in [("sec-fetch-dest", "iframe"), ("sec-fetch-dest", "script"), ("sec-fetch-mode", "cors"), ("sec-fetch-mode", "no-cors")] {
        let mut p = nav.to_vec();
        p.retain(|(kk, _)| *kk != k);
        p.push((k, v));
        assert!(g(&Method::GET, &mk(&p)).is_err(), "{k}={v}");
    }
    assert!(g(&Method::GET, &mk(&[("sec-fetch-site", "same-site"), ("sec-fetch-mode", "cors")])).is_err());
    for ok in [&[("sec-fetch-site", "same-origin")][..], &[("sec-fetch-site", "none")], &[]] {
        assert!(g(&Method::POST, &mk(ok)).is_ok());
    }
    assert!(g(&Method::POST, &mk(&[("origin", "https://pm.test")])).is_ok());
    for bad in ["null", "https://evil.example", "https://pm.test.evil.example", "http://pm.test", "https://pm.test:8443"] {
        assert!(g(&Method::POST, &mk(&[("origin", bad)])).is_err(), "{bad}");
    }
    assert!(g(&Method::GET, &HeaderMap::new()).is_err(), "没有 Host");
}

#[test]
fn cookie_parsing_and_attributes() {
    let mut h = HeaderMap::new();
    h.insert(header::COOKIE, HeaderValue::from_static("a=1; __Host-pm=tok123; b=2"));
    assert_eq!(cookie_token(&h).as_deref(), Some("tok123"));
    h.insert(header::COOKIE, HeaderValue::from_static("pm=nope"));
    assert!(cookie_token(&h).is_none());
    let c = session_cookie("x", 10);
    let s = c.to_str().unwrap();
    for part in ["__Host-pm=x", "Secure", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=10"] {
        assert!(s.contains(part), "{part}");
    }
    assert!(!s.contains("Domain="), "__Host- cookie 不能带 Domain");
}

#[test]
fn login_links_are_single_use_and_expire() {
    let l = LoginLinks::default();
    let t0 = Instant::now();
    let a = l.create_at(t0);
    assert!(l.valid_at(&a, t0));
    assert!(l.valid_at(&a, t0 + Duration::from_secs(119)), "GET 确认页不消耗");
    assert!(!l.valid_at(&a, t0 + Duration::from_secs(120)), "2 分钟后过期");
    assert!(!l.consume_at(&a, t0 + Duration::from_secs(121)), "过期的不能用");
    assert!(!l.consume_at(&a, t0), "过期检查时已被取出");
    let b = l.create_at(t0);
    assert!(l.consume_at(&b, t0 + Duration::from_secs(5)));
    assert!(!l.consume_at(&b, t0 + Duration::from_secs(6)), "只能用一次");
    assert!(!l.valid("not-a-token") && !l.consume(""));
    // 同时有效的链接最多 8 个，最早的被淘汰。
    let first = l.create_at(t0);
    for _ in 0..8 {
        l.create_at(t0 + Duration::from_secs(1));
    }
    assert!(!l.valid_at(&first, t0 + Duration::from_secs(2)));
}

#[test]
fn sessions_expire_after_idle_and_absolute_limits() {
    let s = Sessions::default();
    let t0 = Instant::now();
    let (tok, csrf) = s.create_at(t0);
    assert_eq!(s.touch_at(&tok, t0 + Duration::from_secs(60)).as_deref(), Some(csrf.as_str()));
    // 空闲 2 小时内持续使用：一直有效，直到登录满 12 小时。
    let mut t = t0;
    for _ in 0..11 {
        t += Duration::from_secs(3600);
        assert!(s.touch_at(&tok, t).is_some());
    }
    assert!(s.touch_at(&tok, t0 + SESSION_ABSOLUTE).is_none(), "绝对过期");
    assert!(s.touch_at(&tok, t0).is_none(), "过期的会话已删除");
    let (tok2, _) = s.create_at(t0);
    assert!(s.touch_at(&tok2, t0 + SESSION_IDLE - Duration::from_secs(1)).is_some());
    let (tok3, _) = s.create_at(t0);
    assert!(s.touch_at(&tok3, t0 + SESSION_IDLE).is_none(), "空闲过期");
    // 会话数量上限：最早的被淘汰。
    let s = Sessions::default();
    let (oldest, _) = s.create_at(t0);
    for i in 0..MAX_SESSIONS {
        s.create_at(t0 + Duration::from_secs(1 + i as u64));
    }
    assert!(s.touch_at(&oldest, t0 + Duration::from_secs(100)).is_none());
}

#[test]
fn rate_limiter() {
    let r = RateLimiter::new(3, Duration::from_secs(60), Duration::from_secs(300));
    let t0 = Instant::now();
    assert!(!r.fail_at("ip:1", t0));
    assert!(!r.fail_at("ip:1", t0));
    assert!(r.fail_at("ip:1", t0), "第 3 次失败锁定");
    assert!(r.blocked_at("ip:1", t0 + Duration::from_secs(299)));
    assert!(!r.blocked_at("ip:1", t0 + Duration::from_secs(301)));
    assert!(!r.blocked_at("ip:2", t0));
    r.fail_at("ip:3", t0);
    r.fail_at("ip:3", t0);
    assert!(!r.fail_at("ip:3", t0 + Duration::from_secs(61)), "窗口过期后重新计数");
}

#[tokio::test]
async fn one_time_link_login_flow() {
    let (st, _) = state();
    // 没有会话：跳转到说明页（没有任何密码表单）。
    let r = send(&st, Method::GET, "/", None, None, &[]).await;
    assert_eq!((r.status, r.headers.get("location").unwrap().to_str().unwrap()), (StatusCode::SEE_OTHER, "/login"));
    let r = send(&st, Method::GET, "/login", None, None, &[]).await;
    assert!(r.body.contains("passmanager login") && !r.body.contains("type=\"password\""));
    // 无效链接。
    assert_eq!(send(&st, Method::GET, "/l/nope", None, None, &[]).await.status, StatusCode::NOT_FOUND);
    // GET 只显示确认页，不消耗；POST 消耗并设置 __Host- cookie；再次 POST 失败。
    let t = st.links.create();
    let g = send(&st, Method::GET, &format!("/l/{t}"), None, None, &[]).await;
    assert_eq!(g.status, StatusCode::OK);
    assert!(g.body.contains(&format!("action=\"/l/{t}\"")));
    assert!(st.links.valid(&t));
    let p = send(&st, Method::POST, &format!("/l/{t}"), None, Some(""), &[]).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    let sc = p.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(sc.starts_with("__Host-pm=") && sc.contains("HttpOnly") && sc.contains("Secure") && sc.contains("SameSite=Strict"));
    assert_eq!(send(&st, Method::POST, &format!("/l/{t}"), None, Some(""), &[]).await.status, StatusCode::NOT_FOUND, "只能用一次");
    // 跨站提交一次性链接（例如别的网站诱导浏览器 POST）：被入口检查拒绝。
    let t2 = st.links.create();
    let x = send(&st, Method::POST, &format!("/l/{t2}"), None, Some(""), &[("origin", "https://evil.example")]).await;
    assert_eq!(x.status, StatusCode::FORBIDDEN);
    assert!(st.links.valid(&t2), "被拒绝的请求不消耗链接");
    // 登录后可以访问；退出后 cookie 失效。
    let (cookie, csrf) = login(&st).await;
    assert_eq!(send(&st, Method::GET, "/", Some(&cookie), None, &[]).await.status, StatusCode::OK);
    assert_eq!(send(&st, Method::POST, "/logout", Some(&cookie), Some("csrf=wrong"), &[]).await.status, StatusCode::FORBIDDEN);
    let out = send(&st, Method::POST, "/logout", Some(&cookie), Some(&format!("csrf={csrf}")), &[]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert!(out.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().contains("Max-Age=0"));
    assert_eq!(send(&st, Method::GET, "/", Some(&cookie), None, &[]).await.status, StatusCode::SEE_OTHER);
    // 伪造的 cookie。
    assert_eq!(send(&st, Method::GET, "/entries", Some("forged"), None, &[]).await.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn invalid_link_attempts_are_rate_limited() {
    let (st, _) = state();
    for _ in 0..10 {
        send(&st, Method::GET, "/l/guess", None, None, &[]).await;
    }
    let t = st.links.create();
    let r = send(&st, Method::GET, &format!("/l/{t}"), None, None, &[]).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "猜测次数过多后连有效链接也暂时拒绝");
}

#[tokio::test]
async fn security_headers_host_check_and_body_limit() {
    let (st, _) = state();
    let r = send(&st, Method::GET, "/login", None, None, &[]).await;
    let csp = r.headers.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.starts_with("default-src 'none'"));
    for h in [
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "cache-control",
        "cross-origin-opener-policy",
    ] {
        assert!(r.headers.contains_key(h), "{h}");
    }
    assert!(!r.body.contains("<script"), "页面没有任何脚本");
    // Host 不对（DNS 重绑定）。
    let req = axum::http::Request::builder().uri("/login").header("host", "evil.example").body(Body::empty()).unwrap();
    assert_eq!(router(st.clone()).oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
    // 请求体超过 64 KiB。
    let (cookie, csrf) = login(&st).await;
    let big = format!("csrf={csrf}&note={}", "a".repeat(FORM_LIMIT + 10));
    assert_eq!(send(&st, Method::POST, "/entries", Some(&cookie), Some(&big), &[]).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    // 静态样式表可以缓存，其他页面不缓存。
    let css = send(&st, Method::GET, "/static/style.css", None, None, &[]).await;
    assert_eq!(css.headers.get("cache-control").unwrap(), "max-age=3600");
}

/// 条目增删改：CSRF 必须正确；密钥写入后不会出现在任何页面或响应中（包括校验失败时重新显示的表单）。
#[tokio::test]
async fn entries_crud_and_secrets_are_write_only() {
    let (st, mock) = state();
    let (cookie, csrf) = login(&st).await;
    let form = format!("csrf={csrf}&name=gh&domains={}&secret={}&note=ci", enc("*.github.com\napi.example.com"), enc(SECRET));
    // 没有 / 错误的 CSRF 令牌。
    let no = form.replace(&format!("csrf={csrf}&"), "");
    assert_eq!(send(&st, Method::POST, "/entries", Some(&cookie), Some(&no), &[]).await.status, StatusCode::FORBIDDEN);
    let bad = form.replace(&csrf, "x");
    assert_eq!(send(&st, Method::POST, "/entries", Some(&cookie), Some(&bad), &[]).await.status, StatusCode::FORBIDDEN);
    assert!(mock.entries.lock().unwrap().is_empty());
    // 没有会话的 POST。
    assert_eq!(send(&st, Method::POST, "/entries", None, Some(&form), &[]).await.status, StatusCode::SEE_OTHER);
    // 新增。
    let r = send(&st, Method::POST, "/entries", Some(&cookie), Some(&form), &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(!r.body.contains(SECRET));
    {
        let l = mock.entries.lock().unwrap();
        assert_eq!(l[0].1, SECRET);
        assert_eq!(l[0].0.domains, vec!["*.github.com".to_string(), "api.example.com".to_string()]);
    }
    // 校验失败：表单重新显示，其他字段保留，密钥不回显。
    let badf = format!("csrf={csrf}&domains={}&secret={}&note=keep-me", enc("*.com"), enc(SECRET));
    let r = send(&st, Method::POST, "/entries", Some(&cookie), Some(&badf), &[]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("keep-me") && r.body.contains("公共后缀") && r.body.contains("重新输入"));
    assert!(!r.body.contains(SECRET));
    // 密钥为空。
    let empty = format!("csrf={csrf}&domains=a.example.com&secret=+");
    assert_eq!(send(&st, Method::POST, "/entries", Some(&cookie), Some(&empty), &[]).await.status, StatusCode::BAD_REQUEST);
    // 编辑：表单不含密钥；留空表示不修改。
    let e = send(&st, Method::GET, "/entries/gh/edit", Some(&cookie), None, &[]).await;
    assert_eq!(e.status, StatusCode::OK);
    assert!(e.body.contains("*.github.com") && e.body.contains("留空表示不修改"));
    let up = format!("csrf={csrf}&name=gh&domains=new.example.com&secret=&note=n2");
    assert_eq!(send(&st, Method::POST, "/entries/gh", Some(&cookie), Some(&up), &[]).await.status, StatusCode::SEE_OTHER);
    assert_eq!(mock.entries.lock().unwrap()[0].1, SECRET, "留空不改密钥");
    assert_eq!(send(&st, Method::GET, "/entries/nope/edit", Some(&cookie), None, &[]).await.status, StatusCode::NOT_FOUND);
    // 所有页面都不包含密钥。
    for p in ["/", "/entries", "/entries/new", "/entries/gh/edit", "/tokens", "/pins", "/settings", "/security", "/entries?done=saved"] {
        let r = send(&st, Method::GET, p, Some(&cookie), None, &[]).await;
        assert_eq!(r.status, StatusCode::OK, "{p}");
        assert!(!r.body.contains(SECRET), "{p} 泄露了密钥");
        assert!(!r.body.contains("SuperSecret"), "{p}");
    }
    // 删除。
    let d = send(&st, Method::POST, "/entries/gh/delete", Some(&cookie), Some(&format!("csrf={csrf}")), &[]).await;
    assert_eq!(d.status, StatusCode::SEE_OTHER);
    assert!(mock.entries.lock().unwrap().is_empty());
    // 锁定后条目页给出提示；解锁后恢复。
    send(&st, Method::POST, "/lock", Some(&cookie), Some(&format!("csrf={csrf}")), &[]).await;
    let r = send(&st, Method::GET, "/entries", Some(&cookie), None, &[]).await;
    assert!(r.body.contains("已锁定"));
    let r = send(&st, Method::GET, "/", Some(&cookie), None, &[]).await;
    assert!(r.body.contains("action=\"/unlock\""));
    send(&st, Method::POST, "/unlock", Some(&cookie), Some(&format!("csrf={csrf}")), &[]).await;
    assert!(!*mock.locked.lock().unwrap());
}

#[tokio::test]
async fn tokens_show_enroll_command_and_revoke() {
    let (st, mock) = state();
    let (cookie, csrf) = login(&st).await;
    let r = send(&st, Method::POST, "/tokens", Some(&cookie), Some(&format!("csrf={csrf}&label=laptop")), &[]).await;
    assert_eq!(r.status, StatusCode::OK);
    // 接入说明：一行命令（HTML 转义后浏览器显示为原文）与给 AI 的规则；没有其他安装方式。
    assert!(r.body.contains("curl --proto &#x27;=https&#x27; --tlsv1.3 -fsSL https:&#x2f;&#x2f;pm.test&#x2f;a&#x2f;"), "{}", r.body);
    assert!(r.body.contains("PassManager agent setup") && r.body.contains("MCP tools"));
    assert_eq!(r.body.matches(BOOT_CODE).count(), 1, "开发构建：只有一行命令里有注册码");
    assert!(!r.body.contains("install-agent.sh") && !r.body.contains("irm "));
    let r = send(&st, Method::POST, "/tokens", Some(&cookie), Some(&format!("csrf={csrf}&label=laptop&lang=zh")), &[]).await;
    assert!(r.body.contains("PassManager 接入说明") && r.body.contains("MCP 工具"));
    let r = send(&st, Method::POST, "/tokens/ab12cd34/revoke", Some(&cookie), Some(&format!("csrf={csrf}")), &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = send(&st, Method::POST, "/tokens/nope/revoke", Some(&cookie), Some(&format!("csrf={csrf}")), &[]).await;
    assert!(r.body.contains("令牌不存在"));
    let r = send(&st, Method::POST, "/enrollments/e1/cancel", Some(&cookie), Some(&format!("csrf={csrf}")), &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = send(&st, Method::POST, "/settings", Some(&cookie), Some(&format!("csrf={csrf}&auto_lock_hours=99999")), &[]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = send(&st, Method::POST, "/settings", Some(&cookie), Some(&format!("csrf={csrf}&auto_lock_hours=6")), &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = send(&st, Method::POST, "/pins/trust", Some(&cookie), Some(&format!("csrf={csrf}&pattern=db1.example.com")), &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let log = mock.log.lock().unwrap().join("\n");
    assert!(log.contains("AgentSetup") && log.contains("RevokeToken") && log.contains("SetSettings { auto_lock_hours: 6 }"));
    // done 参数只映射到固定文字，不反射输入。
    let r = send(&st, Method::GET, "/tokens?done=%3Cscript%3E", Some(&cookie), None, &[]).await;
    assert!(!r.body.contains("<script") && !r.body.contains("&lt;script"));
}

#[test]
fn templates_compile_and_civil_date() {
    let env = templates();
    for (n, _) in TEMPLATES {
        assert!(env.get_template(n).is_ok(), "{n}");
    }
    assert_eq!(civil(0), (1970, 1, 1));
    assert_eq!(civil(19_723), (2024, 1, 1));
    assert_eq!(env.render_str("{{ 1700000000 | datetime }}", ()).unwrap(), "2023-11-14 22:13 UTC");
}

/// 多字段条目：网页新建（字段名可见、值不可见）、只改一个字段时其他字段保持不变、删除字段、新增字段；
/// SSH 私钥条目只显示公钥指纹；没有域名的条目标为"未绑定域名"。
#[tokio::test]
async fn multi_field_entries_and_kinds() {
    let (st, mock) = state();
    let (cookie, csrf) = login(&st).await;
    let create = format!(
        "csrf={csrf}&name=mega&domains=mega.example.com&kind=fields&field_name_0=username&field_value_0={}&field_name_1=password&field_value_1={}&field_name_2=&field_value_2=",
        enc("user@example.com"),
        enc(SECRET)
    );
    assert_eq!(send(&st, Method::POST, "/entries", Some(&cookie), Some(&create), &[]).await.status, StatusCode::SEE_OTHER);
    {
        let l = mock.entries.lock().unwrap();
        assert_eq!(l[0].2, vec![("username".to_string(), "user@example.com".to_string()), ("password".to_string(), SECRET.to_string())]);
    }
    let list = send(&st, Method::GET, "/entries", Some(&cookie), None, &[]).await;
    assert!(list.body.contains("<code>username</code>") && list.body.contains("<code>password</code>"));
    assert!(!list.body.contains(SECRET) && !list.body.contains("user@example.com"));
    let edit = send(&st, Method::GET, "/entries/mega/edit", Some(&cookie), None, &[]).await;
    assert!(edit.body.contains("value=\"username\"") && edit.body.contains("value=\"password\""));
    assert!(!edit.body.contains(SECRET) && !edit.body.contains("user@example.com"), "字段值从不显示");
    // 只改 password，username 留空（保留原值）；再加一个新字段 otp。
    let upd = format!(
        "csrf={csrf}&name=mega&domains=mega.example.com&kind=fields&field_name_0=username&field_value_0=&field_name_1=password&field_value_1=new-pass-123&field_name_2=otp&field_value_2=seed99"
    );
    assert_eq!(send(&st, Method::POST, "/entries/mega", Some(&cookie), Some(&upd), &[]).await.status, StatusCode::SEE_OTHER);
    {
        let l = mock.entries.lock().unwrap();
        assert_eq!(l[0].2[0], ("username".to_string(), "user@example.com".to_string()), "未修改的字段保持不变");
        assert_eq!(l[0].2[1].1, "new-pass-123");
        assert_eq!(l[0].2[2], ("otp".to_string(), "seed99".to_string()));
    }
    // 删除 otp 字段。
    let del = format!(
        "csrf={csrf}&name=mega&domains=mega.example.com&kind=fields&field_name_0=username&field_name_1=password&field_name_2=otp&field_remove_2=1"
    );
    assert_eq!(send(&st, Method::POST, "/entries/mega", Some(&cookie), Some(&del), &[]).await.status, StatusCode::SEE_OTHER);
    assert_eq!(mock.entries.lock().unwrap()[0].2.len(), 2);
    // SSH 私钥条目：只显示公钥指纹；没有域名：未绑定域名。
    let hk = "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    let key = format!(
        "csrf={csrf}&name=adminkey&domains=&kind=ssh-key&host_keys={}&secret={}",
        enc(&format!("{hk}\njunk")),
        enc("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakekeymaterial\n-----END OPENSSH PRIVATE KEY-----")
    );
    assert_eq!(send(&st, Method::POST, "/entries", Some(&cookie), Some(&key), &[]).await.status, StatusCode::SEE_OTHER);
    let list = send(&st, Method::GET, "/entries", Some(&cookie), None, &[]).await;
    assert!(list.body.contains("SHA256:FAKEFINGERPRINT") && list.body.contains("未绑定域名"));
    assert!(!list.body.contains("fakekeymaterial"));
    let edit = send(&st, Method::GET, "/entries/adminkey/edit", Some(&cookie), None, &[]).await;
    assert!(edit.body.contains("公钥指纹") && !edit.body.contains("fakekeymaterial"));
    assert!(edit.body.contains(hk), "主机密钥绑定回显（只有指纹）");
    assert!(mock.log.lock().unwrap().iter().any(|l| l.contains("AddEntry")));
}

/// 用途限定与通配符 / 网段域名：表单勾选 → EntryInput.ops；列表显示"仅 ssh"；编辑页回显勾选；全不选 = 不限。
#[tokio::test]
async fn entry_ops_and_network_domains() {
    let (st, mock) = state();
    let (cookie, csrf) = login(&st).await;
    let create =
        format!("csrf={csrf}&name=init-pw&domains={}&kind=password&secret={}&op_ssh=1", enc("*.example.com\n198.51.100.0/24"), enc(SECRET));
    assert_eq!(send(&st, Method::POST, "/entries", Some(&cookie), Some(&create), &[]).await.status, StatusCode::SEE_OTHER);
    {
        let l = mock.entries.lock().unwrap();
        assert_eq!(l[0].0.ops, vec!["ssh".to_string()]);
        assert_eq!(l[0].0.domains, vec!["*.example.com".to_string(), "198.51.100.0/24".to_string()]);
    }
    let list = send(&st, Method::GET, "/entries", Some(&cookie), None, &[]).await;
    assert!(list.body.contains("仅 ssh") && list.body.contains("198.51.100.0&#x2f;24") && !list.body.contains(SECRET));
    let edit = send(&st, Method::GET, "/entries/init-pw/edit", Some(&cookie), None, &[]).await;
    assert!(edit.body.contains("name=\"op_ssh\" value=\"1\" checked") && !edit.body.contains("name=\"op_http\" value=\"1\" checked"));
    let upd = format!("csrf={csrf}&name=init-pw&domains={}&kind=password", enc("*.example.com"));
    assert_eq!(send(&st, Method::POST, "/entries/init-pw", Some(&cookie), Some(&upd), &[]).await.status, StatusCode::SEE_OTHER);
    assert!(mock.entries.lock().unwrap()[0].0.ops.is_empty(), "全不选表示不限");
}

/// XSS：每个模板里每个可能受用户或配置影响的字段都填成攻击载荷，渲染结果里不能出现未转义的片段，
/// 模板语法也不会被再次求值。
#[test]
fn every_template_escapes_injected_values() {
    let env = templates();
    const P: &str = "\"><script>a()</script><svg/onload=b()>' onfocus=c() x=\"javascript:d()\" {{7*7}}";
    let p = serde_json::Value::String(P.into());
    let entry = serde_json::json!({"name": P, "domains": [P, P], "note": P, "self_signed": true, "auto_accept_host_key": true, "private_key": false, "created": 0, "updated": 0, "kind": "fields", "fields": [P, P], "public_key": P, "ops": [P, P]});
    let key_entry = serde_json::json!({"name": P, "domains": [], "note": P, "self_signed": false, "auto_accept_host_key": false, "private_key": true, "created": 0, "updated": 0, "kind": "ssh-key", "fields": [], "public_key": P});
    let status = serde_json::json!({"domain": P, "web_port": 443, "agent_port": 8443, "lan": [P], "locked": false, "initialized": true,
        "vault_mode": P, "level": 2, "seal_method": P, "tpm_device": false, "tpm_rng": P, "cert_not_after": 0, "cert_error": P,
        "tokens": 1, "pending_enrollments": 1, "server_key_fingerprint": P, "vault_recovered_from_backup": true,
        "allow": [P, P], "ready": false, "issues": [P, P]});
    let finding = serde_json::json!({"id": P, "title": P, "ok": false, "auto_fix": false, "detail": P, "steps": P, "advisory": false});
    let base = serde_json::json!({
        "csrf": P, "nav": P, "conn": {"group": P, "suite": P, "peer": P}, "flash": P, "flash_kind": P, "heading": P, "message": P, "token": P,
        "st": status.clone(), "entries": [entry.clone(), key_entry], "form": {"name": P, "domains": P, "note": P, "self_signed": true, "auto_accept_host_key": true, "kind": P, "fields": [P, P], "new_rows": [2, 3], "host_keys": P, "ops": [P]}, "public_key": P,
        "original": P, "enroll": {"label": P, "url": P, "text": P, "minutes": 10},
        "tokens": [{"id": P, "label": P, "created": 0, "last_used": 0}], "pending": [{"id": P, "label": P, "expires_in_secs": 70,
            "kind": P, "host_port": P, "old_fingerprint": P, "new_fingerprint": P, "seen_at": 0}],
        "pins": [{"kind": P, "host_port": P, "algo": P, "fingerprint": P, "first_seen": 0}],
        "settings": {"auto_lock_hours": P},
        "sec": {"level": 2, "method": P, "description": P, "l1_reason": P, "mode": P, "runtime_issues": [P],
            "report": {"generated": 0, "platform": P, "client_user": P, "findings": [finding], "skipped": P}},
    });
    let mut locked = base.clone();
    locked["st"]["locked"] = true.into();
    locked["st"]["initialized"] = false.into();
    // 证书有效 / 已过期、检查全部通过、各导航项高亮、空列表（空状态）与出错时的条目页。
    let with = |name: &'static str, f: &dyn Fn(&mut serde_json::Value)| {
        let mut b = base.clone();
        f(&mut b);
        (name, b)
    };
    let extra = [
        with("dashboard.html", &|b| {
            b["st"]["cert_not_after"] = 4_102_444_800i64.into();
            b["st"]["ready"] = true.into();
            b["nav"] = "home".into();
        }),
        with("dashboard.html", &|b| b["st"]["cert_not_after"] = 1.into()),
        with("security.html", &|b| {
            b["st"]["ready"] = true.into();
            b["st"]["tpm_device"] = true.into();
            b["sec"]["level"] = 3.into();
            b["nav"] = "security".into();
        }),
        with("entries.html", &|b| {
            b["entries"] = serde_json::json!([]);
            b["flash_kind"] = "err".into();
            b["nav"] = "entries".into();
        }),
        with("entries.html", &|b| b["entries"] = serde_json::json!([])),
        with("tokens.html", &|b| {
            b["tokens"] = serde_json::json!([]);
            b["pending"] = serde_json::json!([]);
            b["enroll"] = serde_json::Value::Null;
        }),
        with("pins.html", &|b| {
            b["pins"] = serde_json::json!([]);
            b["pending"] = serde_json::json!([]);
        }),
    ];
    let cases: Vec<(&str, serde_json::Value)> = TEMPLATES
        .iter()
        .map(|(n, _)| (*n, base.clone()))
        .chain([
            ("dashboard.html", locked),
            ("entry_form.html", {
                let mut b = base.clone();
                b["original"] = serde_json::Value::Null;
                b
            }),
        ])
        .chain(extra)
        .collect();
    for (name, ctx) in cases {
        let out = env.get_template(name).unwrap().render(sv(&ctx)).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        for bad in ["<script>", "<svg/onload", "\"><script", "' onfocus", "\" onfocus", "x=\"javascript:", "href=\"javascript:"] {
            assert!(!out.contains(bad), "{name} 出现未转义的 {bad:?}");
        }
        if name != "base.html" && name != "login.html" {
            assert!(out.contains("&lt;script&gt;") || out.contains("%3Cscript%3E"), "{name} 应渲染到注入值（并已转义）");
        }
        assert!(!out.contains(">49<") && !out.contains(" 49 "), "{name}: 模板语法不能被求值");
        // 页面里的 <svg> / <use> 只能是自己的图标标记（注入值里的 <svg 已被转义）；没有任何外部地址。
        assert!(out.match_indices("<svg").all(|(i, _)| out[i..].starts_with("<svg class=\"")), "{name}: 未知的 <svg");
        assert!(out.match_indices("<use").all(|(i, _)| out[i..].starts_with("<use href=\"#i-")), "{name}: 未知的 <use");
        assert!(!out.contains("http://") && !out.contains("https://"), "{name}: 外部地址");
    }
    let _ = p;
}

async fn boot(st: &St, method: Method, uri: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let b = axum::http::Request::builder().method(method).uri(uri).header("host", "pm.test");
    let r = router(st.clone()).oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
    let (s, h) = (r.status(), r.headers().clone());
    (s, h, r.into_body().collect().await.unwrap().to_bytes().to_vec())
}

/// 一键接入：/a/<注册码> 返回脚本（内嵌服务器上已有程序的 SHA-256 与 pm-enroll URL），/a/<注册码>/bin/<目标> 返回程序；
/// 只接受 GET / HEAD；未知或格式错误的注册码、未知目标 → 404（不说明原因）；限速。
#[tokio::test]
async fn bootstrap_routes() {
    let (st, mock) = state();
    let (s, h, body) = boot(&st, Method::GET, &format!("/a/{BOOT_CODE}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(h.get("content-type").unwrap().to_str().unwrap().starts_with("text/plain"));
    let script = String::from_utf8(body).unwrap();
    assert!(script.contains(&format!("PM_BASE='https://pm.test/a/{BOOT_CODE}'")));
    assert!(script.contains(&format!("PM_ENROLL='pm-enroll://pm.test:8443/{BOOT_CODE}#FPR'")));
    assert!(script.contains(&format!("x86_64-unknown-linux-gnu) sum={} ;;", hex::encode(pm_crypto::sha256(b"fake-linux-client")))));
    assert!(script.contains(&format!("universal-apple-darwin) sum={} ;;", hex::encode(pm_crypto::sha256(b"fake-mac-client")))));
    assert!(!script.contains("aarch64-unknown-linux-gnu) sum="));
    if std::process::Command::new("shellcheck").arg("--version").output().is_ok_and(|o| o.status.success()) {
        let f = agent_bin_dir().join("bootstrap.sh");
        std::fs::write(&f, &script).unwrap();
        let o = std::process::Command::new("shellcheck").arg("-s").arg("sh").arg(&f).output().unwrap();
        assert!(o.status.success(), "shellcheck: {}", String::from_utf8_lossy(&o.stdout));
    }
    let (s, _, body) = boot(&st, Method::HEAD, &format!("/a/{BOOT_CODE}")).await;
    assert_eq!((s, body.len()), (StatusCode::OK, 0));
    assert_eq!(boot(&st, Method::POST, &format!("/a/{BOOT_CODE}")).await.0, StatusCode::METHOD_NOT_ALLOWED);
    let (s, h, body) = boot(&st, Method::GET, &format!("/a/{BOOT_CODE}/bin/x86_64-unknown-linux-gnu")).await;
    assert_eq!((s, body.as_slice()), (StatusCode::OK, &b"fake-linux-client"[..]));
    assert_eq!(h.get("content-length").unwrap(), "17");
    assert_eq!(boot(&st, Method::GET, &format!("/a/{BOOT_CODE}/bin/aarch64-unknown-linux-gnu")).await.0, StatusCode::NOT_FOUND);
    assert_eq!(boot(&st, Method::GET, &format!("/a/{BOOT_CODE}/bin/..%2f..%2fetc%2fpasswd")).await.0, StatusCode::NOT_FOUND);
    let unknown = "Z".repeat(43);
    let (s, _, body) = boot(&st, Method::GET, &format!("/a/{unknown}")).await;
    assert_eq!((s, body.as_slice()), (StatusCode::NOT_FOUND, &b"not found\n"[..]), "不说明原因");
    assert_eq!(boot(&st, Method::GET, &format!("/a/{unknown}/bin/x86_64-unknown-linux-gnu")).await.0, StatusCode::NOT_FOUND);
    assert_eq!(boot(&st, Method::GET, "/a/short").await.0, StatusCode::NOT_FOUND);
    let log = mock.log.lock().unwrap().join("\n");
    assert!(log.contains("EnrollPeek") && !log.contains("EnrollConsume"), "只查询，不消耗");
    // 无效注册码达到上限后，该来源被限速（有效注册码也一样）。
    for _ in 0..10 {
        boot(&st, Method::GET, &format!("/a/{unknown}")).await;
    }
    assert_eq!(boot(&st, Method::GET, &format!("/a/{BOOT_CODE}")).await.0, StatusCode::TOO_MANY_REQUESTS);
    // 访问次数上限。
    let (st2, _) = state();
    let mut last = StatusCode::OK;
    for _ in 0..31 {
        last = boot(&st2, Method::GET, &format!("/a/{BOOT_CODE}")).await.0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // 没有配置程序目录：一律 404。
    let st3 = AppState::new(mock.clone(), LoginLinks::new(), WebConfig { domain: "pm.test".into(), port: 443, agent_bin_dir: None });
    assert_eq!(boot(&st3, Method::GET, &format!("/a/{BOOT_CODE}")).await.0, StatusCode::NOT_FOUND);
}

/// 离线保证：模板、样式表与 favicon 不引用任何外部地址（http/https、协议相对地址、@import、外部字体），
/// 不含脚本、事件处理属性、`javascript:` URL 或可嵌入外部内容的元素；也不含会被 CSP 拦下的内联样式。
#[test]
fn assets_are_offline_and_script_free() {
    fn handler_attr(s: &str) -> Option<String> {
        let b = s.as_bytes();
        for i in 1..b.len().saturating_sub(2) {
            if !(b[i] == b'o' && b[i + 1] == b'n') || !(b[i - 1].is_ascii_whitespace() || b"/\"'".contains(&b[i - 1])) {
                continue;
            }
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_lowercase() {
                j += 1;
            }
            let name_len = j - i - 2;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if name_len >= 3 && j < b.len() && b[j] == b'=' {
                return Some(s[i..j].to_string());
            }
        }
        None
    }
    let mut files: Vec<(&str, &str)> = TEMPLATES.to_vec();
    files.extend(STATIC.iter().map(|(_, p, _, b)| (*p, *b)));
    assert!(files.iter().any(|(n, _)| *n == "/static/style.css") && files.iter().any(|(n, _)| *n == "/static/icon.svg"));
    for (name, src) in files {
        let l = src.to_ascii_lowercase();
        // 独立 SVG 文件必需的命名空间声明只是标识符，不会被请求；只允许在 favicon 里出现这一处。
        let l = if name == "/static/icon.svg" {
            assert_eq!(l.matches("xmlns=").count(), 1);
            l.replacen("xmlns=\"http://www.w3.org/2000/svg\"", "", 1)
        } else {
            l
        };
        for bad in [
            "http:",
            "https:",
            "ftp:",
            "ws:",
            "wss:",
            "javascript:",
            "vbscript:",
            "data:",
            "blob:",
            "file:",
            "<script",
            "<iframe",
            "<frame",
            "<object",
            "<embed",
            "<img",
            "<audio",
            "<video",
            "<source",
            "<base",
            "<meta http-equiv",
            "<style",
            "style=\"",
            "style='",
            "srcset",
            "@import",
            "@font-face",
            "src=\"//",
            "href=\"//",
            "url(//",
            "xlink:href",
            "<foreignobject",
            "<animate",
            "<set ",
            "<handler",
            "rel=\"preconnect",
            "rel=\"prefetch",
            "rel=\"preload",
            "rel=\"dns-prefetch",
            "rel=\"manifest",
        ] {
            assert!(!l.contains(bad), "{name} 含有 {bad:?}");
        }
        assert_eq!(handler_attr(&l), None, "{name} 含有事件处理属性");
        // CSS / SVG 里的 url() 只能引用同一文档内的片段。
        for (i, _) in l.match_indices("url(") {
            assert!(l[i..].starts_with("url(#"), "{name}: {}", &l[i..(i + 20).min(l.len())]);
        }
        // 模板里的链接、表单与资源地址只能是本站路径或页内片段（`{` 开头的是模板表达式，拼出来的也是本站路径）。
        for attr in ["href=\"", "src=\"", "action=\"", "formaction=\""] {
            for (i, _) in l.match_indices(attr) {
                let v = &l[i + attr.len()..];
                assert!(
                    v.starts_with('/') && !v.starts_with("//") || v.starts_with('#') || v.starts_with('{'),
                    "{name}: {attr}{}",
                    &v[..20.min(v.len())]
                );
            }
        }
    }
    // 自检：检查器确实能发现这些写法。
    assert!(handler_attr("<svg onload=x()>").is_some() && handler_attr("<a\nonclick = x>").is_some() && handler_attr("<button>").is_none());
}

/// favicon 与图标：同源 `/static/icon.svg`（CSP 的 `img-src 'self'` 允许，不需要放宽任何指令）；
/// CSP 与其他安全头保持原样；页面图标全部是内联 SVG，不发起额外请求。
#[tokio::test]
async fn favicon_is_same_origin_and_csp_is_unchanged() {
    // CSP 整体固定：没有 script-src、没有 'unsafe-*'、没有 data:/外部来源；图片只允许本站（favicon）。
    assert_eq!(
        CSP,
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'"
    );
    for bad in ["unsafe", "script-src", "data:", "http", "*", "blob:"] {
        assert!(!CSP.contains(bad), "{bad}");
    }
    let (st, _) = state();
    let page = send(&st, Method::GET, "/login", None, None, &[]).await;
    assert_eq!(page.headers.get("content-security-policy").unwrap(), CSP);
    assert!(
        page.body.contains(&format!(
            r#"<link rel="icon" href="/static/icon.svg?v={}" type="image/svg+xml">"#,
            asset_hash(FAVICON_SVG.as_bytes())
        ))
    );
    assert!(page.body.contains(r#"<symbol id="i-terminal""#) && page.body.contains(r##"<use href="#i-terminal">"##));
    let r = send(&st, Method::GET, "/static/icon.svg", None, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, FAVICON_SVG);
    for (k, v) in [
        ("content-type", "image/svg+xml"),
        ("x-content-type-options", "nosniff"),
        ("cross-origin-resource-policy", "same-origin"),
        ("content-security-policy", CSP),
        ("cache-control", "max-age=3600"),
    ] {
        assert_eq!(r.headers.get(k).unwrap(), v, "{k}");
    }
    assert!(r.body.starts_with("<svg xmlns=") && r.body.ends_with("</svg>"));
    // 静态资源也经过入口检查（Host 必须正确）。
    let req = axum::http::Request::builder().uri("/static/icon.svg").header("host", "evil.example").body(Body::empty()).unwrap();
    assert_eq!(router(st.clone()).oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
    // 导航高亮当前页面。
    let (cookie, _) = login(&st).await;
    for (p, href) in
        [("/", "/"), ("/entries", "/entries"), ("/entries/new", "/entries"), ("/tokens", "/tokens"), ("/security", "/security")]
    {
        let r = send(&st, Method::GET, p, Some(&cookie), None, &[]).await;
        assert!(r.body.contains(&format!(r#"<a href="{href}" aria-current="page">"#)), "{p}");
        assert_eq!(r.body.matches("aria-current").count(), 1, "{p}");
    }
}

/// 图标：模板里用到的名字都有定义，sprite 里的定义都在白名单里；未知名字（包括注入尝试）渲染为空。
#[test]
fn icons_are_defined_and_safe() {
    let base = TEMPLATES.iter().find(|(n, _)| *n == "base.html").unwrap().1;
    for n in ICONS {
        assert_eq!(base.matches(&format!(r#"<symbol id="i-{n}" viewBox="0 0 24 24">"#)).count(), 1, "{n}");
    }
    assert_eq!(base.matches("<symbol ").count(), ICONS.len());
    let mut used = std::collections::BTreeSet::new();
    for (name, src) in TEMPLATES {
        for (i, _) in src.match_indices("icon(\"") {
            let n = src[i + 6..].split('"').next().unwrap();
            assert!(ICONS.contains(&n), "{name}: 未定义的图标 {n}");
            used.insert(n);
        }
    }
    assert_eq!(used.len(), ICONS.len(), "没用到的图标：{:?}", ICONS.iter().filter(|n| !used.contains(*n)).collect::<Vec<_>>());
    let env = templates();
    assert_eq!(
        env.render_str(r#"{{ icon("key") }}"#, ()).unwrap(),
        r##"<svg class="i" aria-hidden="true" focusable="false"><use href="#i-key"></use></svg>"##
    );
    for bad in ["nope", "\"><script>", "key\"", "", "../key"] {
        assert_eq!(env.render_str("{{ icon(n) }}", context! { n => bad }).unwrap(), "", "{bad}");
    }
}

/// 浏览器表单提交：Referrer-Policy 必须是 same-origin（响应头与 <meta> 一致）。no-referrer 会让浏览器在
/// 表单 POST 里发送 "Origin: null"，入口检查（正确地）拒绝，网页上的所有表单都无法使用。
#[tokio::test]
async fn referrer_policy_is_same_origin_and_browser_posts_work() {
    assert_eq!(REFERRER_POLICY, "same-origin");
    let (st, _) = state();
    let page = send(&st, Method::GET, "/login", None, None, &[]).await;
    assert_eq!(page.headers.get("referrer-policy").unwrap(), "same-origin");
    assert!(page.body.contains(r#"<meta name="referrer" content="same-origin">"#));
    assert_eq!(page.body.matches("name=\"referrer\"").count(), 1);
    let base = TEMPLATES.iter().find(|(n, _)| *n == "base.html").unwrap().1;
    assert!(!base.contains("no-referrer"));

    // 入口检查仍然严格：Origin: null、外站、错误端口、缺少端口的 Host、跨站 Fetch Metadata 都拒绝。
    let o = "https://pm.test:8121".to_string();
    let hdr = |pairs: &[(&str, &str)]| {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    };
    let g = |h: &HeaderMap| guard_check("pm.test", 8121, &o, &Method::POST, &"/lock".parse::<Uri>().unwrap(), h);
    let same =
        [("host", "pm.test:8121"), ("sec-fetch-site", "same-origin"), ("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "document")];
    assert!(g(&hdr(&[&same[..], &[("origin", "https://pm.test:8121")]].concat())).is_ok());
    for bad in [
        "null",
        "https://evil.example",
        "https://pm.test",
        "https://pm.test:443",
        "http://pm.test:8121",
        "https://pm.test:8121.evil.example",
    ] {
        assert!(g(&hdr(&[&same[..], &[("origin", bad)]].concat())).is_err(), "{bad}");
    }
    assert!(g(&hdr(&[("host", "pm.test"), ("origin", "https://pm.test:8121")])).is_err(), "Host 缺少端口");
    assert!(g(&hdr(&[("host", "evil.example:8121"), ("origin", "https://pm.test:8121")])).is_err(), "Host 不对");
    let cross =
        [("host", "pm.test:8121"), ("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "document")];
    assert!(g(&hdr(&[&cross[..], &[("origin", "https://pm.test:8121")]].concat())).is_err(), "跨站表单");

    // 真实浏览器在 same-origin 策略下发送的同源 POST（非 443 端口）：登录确认、保存条目、锁定都成功。
    let mock = Arc::new(Mock::default());
    let st = AppState::new(mock.clone(), LoginLinks::new(), WebConfig { domain: "pm.test".into(), port: 8121, agent_bin_dir: None });
    let browser = [
        ("host", "pm.test:8121"),
        ("origin", "https://pm.test:8121"),
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
    ];
    let t = st.links.create();
    // 同样的请求带 Origin: null（no-referrer 时浏览器的行为）被拒绝，且不消耗链接。
    let mut null = browser;
    null[1] = ("origin", "null");
    assert_eq!(send(&st, Method::POST, &format!("/l/{t}"), None, Some(""), &null).await.status, StatusCode::FORBIDDEN);
    assert!(st.links.valid(&t));
    let r = send(&st, Method::POST, &format!("/l/{t}"), None, Some(""), &browser).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(!st.links.valid(&t), "POST 消耗链接");
    assert_eq!(send(&st, Method::POST, &format!("/l/{t}"), None, Some(""), &browser).await.status, StatusCode::NOT_FOUND, "只能用一次");
    let cookie = r
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .strip_prefix(&format!("{COOKIE}="))
        .unwrap()
        .to_string();
    let page = send(&st, Method::GET, "/entries/new", Some(&cookie), None, &browser[..1]).await;
    assert_eq!(page.status, StatusCode::OK);
    let i = page.body.find("name=\"csrf\" value=\"").unwrap() + 19;
    let csrf = page.body[i..].split('"').next().unwrap().to_string();
    let form = format!("csrf={csrf}&name=gh&domains=api.example.com&kind=password&secret={}", enc(SECRET));
    let r = send(&st, Method::POST, "/entries", Some(&cookie), Some(&form), &browser).await;
    assert_eq!((r.status, r.headers.get("location").unwrap().to_str().unwrap()), (StatusCode::SEE_OTHER, "/entries?done=saved"));
    assert_eq!(mock.entries.lock().unwrap()[0].1, SECRET);
    let r = send(&st, Method::POST, "/lock", Some(&cookie), Some(&format!("csrf={csrf}")), &browser).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(*mock.locked.lock().unwrap());
    // 同样的保存请求带 Origin: null 或外站 Origin：拒绝（即使 CSRF 令牌正确）。
    for bad in ["null", "https://evil.example"] {
        let mut h = browser;
        h[1] = ("origin", bad);
        assert_eq!(
            send(&st, Method::POST, "/unlock", Some(&cookie), Some(&format!("csrf={csrf}")), &h).await.status,
            StatusCode::FORBIDDEN,
            "{bad}"
        );
    }
    assert!(*mock.locked.lock().unwrap());
}

/// 升级后浏览器不能继续用缓存里的旧样式表：静态资源地址带内容哈希 `?v=`。
#[test]
fn asset_hash_changes_with_content() {
    assert_eq!(asset_hash(b"abc"), "ba7816bf8f", "SHA-256(\"abc\") 的前 10 个十六进制字符");
    let css = STATIC[0].3;
    let h = asset_hash(css.as_bytes());
    assert_eq!(h.len(), 10);
    assert!(h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert_eq!(asset_hash(css.as_bytes()), h, "确定性");
    let mut changed = css.as_bytes().to_vec();
    changed[0] ^= 1;
    assert_ne!(asset_hash(&changed), h, "改一个字节，地址就变");
    assert_ne!(asset_hash(format!("{css} ").as_bytes()), h);
    let v = asset_versions();
    assert_eq!(v.len(), STATIC.len());
    for (k, _, _, b) in STATIC {
        assert_eq!(v[k], asset_hash(b.as_bytes()), "{k}");
    }
    // Cache-Control：只有当前哈希才长期缓存。
    assert_eq!(static_cache_control(Some(&format!("v={h}")), &h), CACHE_IMMUTABLE);
    assert_eq!(static_cache_control(Some(&format!("x=1&v={h}")), &h), CACHE_IMMUTABLE);
    for q in [None, Some(""), Some("v="), Some("v=0000000000"), Some("v=ba7816bf8f"), Some(&format!("v={h}x")), Some(&format!("vv={h}"))] {
        assert_eq!(static_cache_control(q, &h), CACHE_UNVERSIONED, "{q:?}");
    }
}

#[tokio::test]
async fn static_assets_are_versioned_by_content_hash() {
    let css_v = asset_hash(include_str!("../static/style.css").as_bytes());
    let icon_v = asset_hash(FAVICON_SVG.as_bytes());
    // 渲染出的页面（登录前后）都引用当前哈希。
    let base = templates().get_template("login.html").unwrap().render(context! {}).unwrap();
    assert!(base.contains(&format!(r#"<link rel="stylesheet" href="/static/style.css?v={css_v}">"#)), "{base}");
    assert!(base.contains(&format!(r#"<link rel="icon" href="/static/icon.svg?v={icon_v}" type="image/svg+xml">"#)));
    let (st, _) = state();
    let (cookie, _) = login(&st).await;
    for (p, c) in [("/login", None), ("/", Some(cookie.as_str())), ("/entries", Some(cookie.as_str()))] {
        let r = send(&st, Method::GET, p, c, None, &[]).await;
        assert!(
            r.body.contains(&format!("/static/style.css?v={css_v}\"")) && r.body.contains(&format!("/static/icon.svg?v={icon_v}\"")),
            "{p}"
        );
        assert_eq!(r.headers.get("cache-control").unwrap(), "no-store", "页面本身不缓存，所以总是引用当前哈希");
    }
    // 静态路由：带或不带 v、旧的或乱写的 v 都返回当前文件（旧页面不会 404）；安全头不变。
    for (path, ctype, body, cur) in [
        ("/static/style.css", "text/css; charset=utf-8", include_str!("../static/style.css"), css_v.as_str()),
        ("/static/icon.svg", "image/svg+xml", FAVICON_SVG, icon_v.as_str()),
    ] {
        for (q, cache) in [
            (String::new(), CACHE_UNVERSIONED),
            (format!("?v={cur}"), CACHE_IMMUTABLE),
            ("?v=0000000000".to_string(), CACHE_UNVERSIONED),
            ("?v=%3Cscript%3E&x=%ZZ".to_string(), CACHE_UNVERSIONED),
            ("?v".to_string(), CACHE_UNVERSIONED),
        ] {
            let r = send(&st, Method::GET, &format!("{path}{q}"), None, None, &[]).await;
            assert_eq!(r.status, StatusCode::OK, "{path}{q}");
            assert_eq!(r.body, body, "{path}{q}");
            for (k, v) in [
                ("content-type", ctype),
                ("cache-control", cache),
                ("x-content-type-options", "nosniff"),
                ("cross-origin-resource-policy", "same-origin"),
                ("content-security-policy", CSP),
                ("referrer-policy", "same-origin"),
            ] {
                assert_eq!(r.headers.get(k).unwrap(), v, "{path}{q} {k}");
            }
        }
        let req = axum::http::Request::builder().uri(format!("{path}?v={cur}")).header("host", "evil.example").body(Body::empty()).unwrap();
        assert_eq!(router(st.clone()).oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN, "Host 校验");
    }
}

//! 网页管理界面（服务器模式，443 端口，只对局域网开放）。
//!
//! - 服务端渲染，没有 JavaScript；CSP `default-src 'none'`（只允许本站样式表与本站图片，即 favicon）；
//!   图标是 base.html 里的内联 SVG sprite，不加载任何外部资源；
//! - 没有任何密码：只能用服务器上 root 运行 `passmanager login` 打印的一次性链接登录
//!   （2 分钟有效；GET 只显示确认页，POST 才消耗），会话空闲 2 小时、登录满 12 小时失效；
//! - 会话 cookie 为 `__Host-` 前缀、HttpOnly、Secure、SameSite=Strict；所有修改类请求校验 CSRF 令牌、
//!   Origin 与 Fetch Metadata；Host 头必须是本服务域名（防 DNS 重绑定）；请求体上限 64 KiB；
//! - 密钥只能写入：任何页面、任何响应都不包含密钥。
// 处理函数统一用 `Result<_, Response>` 提前返回页面：Response 体积大，但每个请求只出现一次。
#![allow(clippy::result_large_err)]

pub mod bootstrap;
pub mod front;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Extension, Form, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use minijinja::value::Serde;
use minijinja::{Environment, Value, context};
use pm_proto::{EntryInput, EntryView, PendingEnrollView, PendingPinView, PinView, Request as Req, Response as Resp};
use pm_proto::{FieldInput, SecurityView, ServerStatusView, SettingsView, TokenView};
use serde::de::DeserializeOwned;

pub use front::ConnInfo;

fn sv<T: serde::Serialize>(t: T) -> Value {
    Value::from(Serde(t))
}

pub const COOKIE: &str = "__Host-pm";
pub const LINK_TTL: Duration = Duration::from_secs(120);
pub const SESSION_IDLE: Duration = Duration::from_secs(2 * 3600);
pub const SESSION_ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
/// 同时存在的网页会话上限（超过时淘汰最早的）。
pub const MAX_SESSIONS: usize = 16;
/// 网页表单请求体上限。
pub const FORM_LIMIT: usize = 64 << 10;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 网页调用服务的接口（管理会话）。由 pm-service 实现；测试中用内存替身。
pub trait Backend: Send + Sync + 'static {
    fn call(&self, req: Req) -> BoxFut<'_, Resp>;
}

// ---------------- 令牌工具 ----------------

fn new_token() -> String {
    use base64::Engine;
    let raw: [u8; 32] = pm_crypto::rng::random_array().expect("rng");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

fn token_hash(t: &str) -> [u8; 32] {
    pm_crypto::sha256(t.as_bytes())
}

// ---------------- 一次性登录链接 ----------------

/// 一次性登录链接：只在内存中保存令牌的哈希，重启即全部失效。
#[derive(Default)]
pub struct LoginLinks {
    m: Mutex<HashMap<[u8; 32], Instant>>,
}

impl LoginLinks {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 生成新链接，返回令牌（调用方拼成 `{origin}/l/{token}`）。
    pub fn create(&self) -> String {
        self.create_at(Instant::now())
    }

    fn create_at(&self, now: Instant) -> String {
        let token = new_token();
        let mut m = self.m.lock().unwrap();
        m.retain(|_, exp| *exp > now);
        // 同时有效的链接不超过 8 个。
        while m.len() >= 8 {
            let oldest = *m.iter().min_by_key(|(_, e)| **e).unwrap().0;
            m.remove(&oldest);
        }
        m.insert(token_hash(&token), now + LINK_TTL);
        token
    }

    pub fn valid(&self, token: &str) -> bool {
        self.valid_at(token, Instant::now())
    }

    fn valid_at(&self, token: &str, now: Instant) -> bool {
        self.m.lock().unwrap().get(&token_hash(token)).is_some_and(|exp| *exp > now)
    }

    /// 消耗链接：先取出（删除）再检查是否过期，所以同一链接最多成功一次。
    pub fn consume(&self, token: &str) -> bool {
        self.consume_at(token, Instant::now())
    }

    fn consume_at(&self, token: &str, now: Instant) -> bool {
        self.m.lock().unwrap().remove(&token_hash(token)).is_some_and(|exp| exp > now)
    }
}

// ---------------- 限速 ----------------

/// (失败次数, 窗口起点, 锁定截止)。
type LimitEntry = (u32, Instant, Option<Instant>);

/// 失败计数限速：窗口内失败达到上限后锁定一段时间。
pub struct RateLimiter {
    max: u32,
    window: Duration,
    lockout: Duration,
    m: Mutex<HashMap<String, LimitEntry>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration, lockout: Duration) -> Self {
        Self { max, window, lockout, m: Mutex::new(HashMap::new()) }
    }

    pub fn blocked(&self, key: &str) -> bool {
        self.blocked_at(key, Instant::now())
    }

    pub fn blocked_at(&self, key: &str, now: Instant) -> bool {
        matches!(self.m.lock().unwrap().get(key), Some((_, _, Some(until))) if now < *until)
    }

    pub fn fail(&self, key: &str) -> bool {
        self.fail_at(key, Instant::now())
    }

    pub fn fail_at(&self, key: &str, now: Instant) -> bool {
        let mut m = self.m.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, v| now.duration_since(v.1) < self.window || v.2.is_some_and(|u| now < u));
        }
        let e = m.entry(key.to_string()).or_insert((0, now, None));
        if let Some(u) = e.2
            && now >= u
        {
            *e = (0, now, None);
        }
        if now.duration_since(e.1) >= self.window {
            e.0 = 0;
            e.1 = now;
        }
        e.0 += 1;
        if e.0 >= self.max {
            e.2 = Some(now + self.lockout);
            return true;
        }
        false
    }
}

// ---------------- 会话 ----------------

struct WebSession {
    csrf: String,
    created: Instant,
    last: Instant,
}

#[derive(Default)]
pub struct Sessions {
    m: Mutex<HashMap<[u8; 32], WebSession>>,
}

impl Sessions {
    /// 新建会话，返回 (cookie 令牌, CSRF 令牌)。
    fn create_at(&self, now: Instant) -> (String, String) {
        let tok = new_token();
        let csrf = new_token();
        let mut m = self.m.lock().unwrap();
        m.retain(|_, s| alive(s, now));
        while m.len() >= MAX_SESSIONS {
            let oldest = *m.iter().min_by_key(|(_, s)| s.created).unwrap().0;
            m.remove(&oldest);
        }
        m.insert(token_hash(&tok), WebSession { csrf: csrf.clone(), created: now, last: now });
        (tok, csrf)
    }

    /// 查找并续期（更新空闲计时）；过期的会话被删除。
    fn touch_at(&self, tok: &str, now: Instant) -> Option<String> {
        let mut m = self.m.lock().unwrap();
        let k = token_hash(tok);
        let s = m.get_mut(&k)?;
        if !alive(s, now) {
            m.remove(&k);
            return None;
        }
        s.last = now;
        Some(s.csrf.clone())
    }

    fn remove(&self, tok: &str) {
        self.m.lock().unwrap().remove(&token_hash(tok));
    }

    pub fn clear(&self) {
        self.m.lock().unwrap().clear();
    }
}

fn alive(s: &WebSession, now: Instant) -> bool {
    now.duration_since(s.last) < SESSION_IDLE && now.duration_since(s.created) < SESSION_ABSOLUTE
}

// ---------------- 状态与路由 ----------------

pub struct WebConfig {
    /// 例如 `pm.example.com`。
    pub domain: String,
    pub port: u16,
    /// 一键接入用的 Agent 程序目录（`PassManager-<目标>`）；None 表示不提供一键接入。
    pub agent_bin_dir: Option<std::path::PathBuf>,
}

impl WebConfig {
    pub fn origin(&self) -> String {
        if self.port == 443 { format!("https://{}", self.domain) } else { format!("https://{}:{}", self.domain, self.port) }
    }
}

pub struct AppState {
    pub backend: Arc<dyn Backend>,
    pub links: Arc<LoginLinks>,
    pub cfg: WebConfig,
    env: Environment<'static>,
    sessions: Sessions,
    link_limiter: RateLimiter,
    bins: bootstrap::BinCache,
    /// `/a/` 的访问次数（每个来源）。
    boot_limiter: RateLimiter,
    /// `/a/` 的无效注册码次数（每个来源）。
    boot_fail_limiter: RateLimiter,
}

pub type St = Arc<AppState>;

impl AppState {
    pub fn new(backend: Arc<dyn Backend>, links: Arc<LoginLinks>, cfg: WebConfig) -> St {
        Arc::new(Self {
            backend,
            links,
            cfg,
            env: templates(),
            sessions: Sessions::default(),
            // 每个来源 10 分钟内 10 次无效链接 → 锁定 15 分钟。
            link_limiter: RateLimiter::new(10, Duration::from_secs(600), Duration::from_secs(900)),
            // 每个来源 10 分钟内最多 30 次 /a/ 请求、10 次无效注册码 → 锁定 15 分钟。
            bins: bootstrap::BinCache::default(),
            boot_limiter: RateLimiter::new(30, Duration::from_secs(600), Duration::from_secs(900)),
            boot_fail_limiter: RateLimiter::new(10, Duration::from_secs(600), Duration::from_secs(900)),
        })
    }
}

pub fn templates() -> Environment<'static> {
    let mut env = Environment::new();
    env.set_auto_escape_callback(|n| if n.ends_with(".html") { minijinja::AutoEscape::Html } else { minijinja::AutoEscape::None });
    for (n, s) in TEMPLATES {
        env.add_template(n, s).expect("模板语法");
    }
    // 距今还有多少天（向下取整；已过去为负数）。
    env.add_filter("days_left", |ts: i64| {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        (ts - now).div_euclid(86400)
    });
    // 图标：只接受 ICONS 里的固定名字（模板里写死的常量），输出引用 base.html 内联 sprite 的 <svg>。
    env.add_function("icon", |name: &str| match ICONS.iter().find(|n| **n == name) {
        Some(n) => {
            Value::from_safe_string(format!(r##"<svg class="i" aria-hidden="true" focusable="false"><use href="#i-{n}"></use></svg>"##))
        }
        None => Value::from(""),
    });
    env.add_filter("datetime", |ts: i64| {
        let d = ts.div_euclid(86400);
        let s = ts.rem_euclid(86400);
        let (y, m, dd) = civil(d);
        format!("{y:04}-{m:02}-{dd:02} {:02}:{:02} UTC", s / 3600, s % 3600 / 60)
    });
    env
}

/// base.html 内联 sprite 里的图标（`<symbol id="i-名字">`）。
pub const ICONS: &[&str] = &[
    "shield", "key", "lock", "unlock", "server", "token", "link", "settings", "warning", "check", "copy", "trash", "activity", "plus",
    "edit", "logout", "info", "clock", "x", "terminal",
];

/// 网站图标（同源，`img-src 'self'`）：盾牌与锁孔。只有图形元素，没有脚本、样式或外部引用。
pub const FAVICON_SVG: &str = concat!(
    r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">"##,
    r##"<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3149c4"/><stop offset="1" stop-color="#6d4ae8"/></linearGradient></defs>"##,
    r##"<rect width="64" height="64" rx="14" fill="url(#g)"/>"##,
    r##"<path d="M32 9 15 15.6v12.6c0 10.2 7.1 19.2 17 22.8 9.9-3.6 17-12.6 17-22.8V15.6z" fill="#fff"/>"##,
    r##"<path d="M32 21.5a5.2 5.2 0 0 0-2.6 9.7L27.8 40h8.4l-1.6-8.8a5.2 5.2 0 0 0-2.6-9.7z" fill="#3149c4"/>"##,
    "</svg>"
);

/// 静态资源：(路径, Content-Type, 内容)。都只读、可缓存，不需要会话。
pub const STATIC: &[(&str, &str, &str)] = &[
    ("/static/style.css", "text/css; charset=utf-8", include_str!("../static/style.css")),
    ("/static/icon.svg", "image/svg+xml", FAVICON_SVG),
];

/// 模板对应的导航项（顶栏高亮当前页面，`aria-current="page"`）。
fn nav_of(template: &str) -> &'static str {
    match template {
        "dashboard.html" => "home",
        "entries.html" | "entry_form.html" => "entries",
        "tokens.html" => "tokens",
        "pins.html" => "pins",
        "settings.html" => "settings",
        "security.html" => "security",
        _ => "",
    }
}

pub const TEMPLATES: &[(&str, &str)] = &[
    ("base.html", include_str!("../templates/base.html")),
    ("message.html", include_str!("../templates/message.html")),
    ("login.html", include_str!("../templates/login.html")),
    ("link.html", include_str!("../templates/link.html")),
    ("dashboard.html", include_str!("../templates/dashboard.html")),
    ("entries.html", include_str!("../templates/entries.html")),
    ("entry_form.html", include_str!("../templates/entry_form.html")),
    ("tokens.html", include_str!("../templates/tokens.html")),
    ("pins.html", include_str!("../templates/pins.html")),
    ("settings.html", include_str!("../templates/settings.html")),
    ("security.html", include_str!("../templates/security.html")),
];

/// 天数（自 1970-01-01）→ 公历日期。
pub fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn router(st: St) -> Router {
    let mut r = Router::new();
    for (path, ctype, body) in STATIC {
        r = r.route(path, get(move || async move { ([(header::CONTENT_TYPE, *ctype), (header::CACHE_CONTROL, "max-age=3600")], *body) }));
    }
    r.route("/", get(dashboard))
        .route("/login", get(login_page))
        .route("/l/{token}", get(link_page).post(link_post))
        .route("/logout", post(logout))
        .route("/lock", post(lock))
        .route("/unlock", post(unlock))
        .route("/entries", get(entries).post(entry_create))
        .route("/entries/new", get(entry_new))
        .route("/entries/{name}/edit", get(entry_edit))
        .route("/entries/{name}", post(entry_update))
        .route("/entries/{name}/delete", post(entry_delete))
        .route("/tokens", get(tokens).post(token_create))
        .route("/tokens/{id}/revoke", post(token_revoke))
        .route("/enrollments/{id}/cancel", post(enroll_cancel))
        .route("/pins", get(pins))
        .route("/pins/trust", post(pins_trust))
        .route("/settings", get(settings).post(settings_post))
        .route("/security", get(security))
        .route("/a/{code}", get(boot_script))
        .route("/a/{code}/bin/{target}", get(boot_bin))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(axum::extract::DefaultBodyLimit::max(FORM_LIMIT))
        .layer(axum::middleware::from_fn_with_state(st.clone(), request_guard))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(st)
}

// ---------------- 请求入口检查 ----------------

/// - Host 必须是本服务的域名和端口（防 DNS 重绑定）；
/// - Fetch Metadata：浏览器标明"跨站"的请求只允许 GET 顶层导航（点链接），拒绝跨站表单、嵌入与 fetch；
/// - 修改类请求带 Origin 时必须是本站。
async fn request_guard(State(st): State<St>, req: Request, next: axum::middleware::Next) -> Response {
    if let Err(why) = guard_check(&st.cfg.domain, st.cfg.port, &st.cfg.origin(), req.method(), req.uri(), req.headers()) {
        return (StatusCode::FORBIDDEN, why).into_response();
    }
    next.run(req).await
}

pub fn guard_check(
    domain: &str,
    port: u16,
    origin: &str,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    h: &HeaderMap,
) -> Result<(), &'static str> {
    let host = h.get(header::HOST).and_then(|v| v.to_str().ok()).or_else(|| uri.authority().map(|a| a.as_str())).unwrap_or("");
    if !host_ok(domain, port, host) {
        return Err("unknown host");
    }
    let hv = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("");
    let safe = matches!(*method, axum::http::Method::GET | axum::http::Method::HEAD);
    match hv("sec-fetch-site") {
        "" | "same-origin" | "none" => {}
        _ => {
            let nav = hv("sec-fetch-mode") == "navigate" && matches!(hv("sec-fetch-dest"), "document" | "");
            if !(safe && nav) {
                return Err("cross-site request");
            }
        }
    }
    if !safe
        && let Some(o) = h.get(header::ORIGIN)
        && o.to_str().ok() != Some(origin)
    {
        return Err("cross-origin request");
    }
    Ok(())
}

/// Host 头只接受 `域名:端口`（端口 443 时也接受只写域名），域名不区分大小写，可带结尾的点。
pub fn host_ok(domain: &str, port: u16, host: &str) -> bool {
    let (name, p) = match host.rsplit_once(':') {
        Some((n, p)) if !n.ends_with(']') || n.starts_with('[') => (n, Some(p)),
        _ => (host, None),
    };
    let name = name.strip_suffix('.').unwrap_or(name);
    let port_ok = match p {
        Some(p) => p.parse::<u16>().ok() == Some(port),
        None => port == 443,
    };
    port_ok && name.eq_ignore_ascii_case(domain)
}

/// 与 base.html 的 `<meta name="referrer">` 一致。
pub const REFERRER_POLICY: &str = "same-origin";

pub const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'";

async fn security_headers(req: Request, next: axum::middleware::Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    for (k, v) in [
        ("content-security-policy", CSP),
        ("strict-transport-security", "max-age=31536000"),
        ("x-content-type-options", "nosniff"),
        // same-origin：发往本站的请求带完整来源（浏览器提交表单时 Origin 才是真实来源；no-referrer 会让
        // 浏览器发送 "Origin: null"，被入口检查拒绝），发往其他站点的请求不带 Referer。
        ("referrer-policy", REFERRER_POLICY),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("x-permitted-cross-domain-policies", "none"),
        ("x-robots-tag", "noindex, nofollow"),
        ("cache-control", "no-store"),
        (
            "permissions-policy",
            "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), display-capture=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()",
        ),
    ] {
        h.entry(k).or_insert(HeaderValue::from_static(v));
    }
    r
}

// ---------------- 会话辅助 ----------------

fn cookie_token(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(&format!("{COOKIE}=")).map(|s| s.to_string()))
}

fn session_cookie(token: &str, max_age: u64) -> HeaderValue {
    HeaderValue::from_str(&format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}")).unwrap()
}

struct Ctx {
    csrf: String,
    conn: Option<ConnInfo>,
}

fn require(st: &AppState, h: &HeaderMap, conn: &Option<Extension<ConnInfo>>) -> Result<Ctx, Response> {
    let tok = cookie_token(h).ok_or_else(|| Redirect::to("/login").into_response())?;
    let csrf = st.sessions.touch_at(&tok, Instant::now()).ok_or_else(|| Redirect::to("/login").into_response())?;
    Ok(Ctx { csrf, conn: conn.as_ref().map(|c| c.0.clone()) })
}

/// 修改类请求：会话 + CSRF 令牌（Origin 已在入口检查）。
fn require_post(st: &AppState, h: &HeaderMap, conn: &Option<Extension<ConnInfo>>, form: &HashMap<String, String>) -> Result<Ctx, Response> {
    let c = require(st, h, conn)?;
    let ok = form.get("csrf").is_some_and(|v| pm_crypto::ct_eq(v.as_bytes(), c.csrf.as_bytes()));
    if !ok {
        return Err((StatusCode::FORBIDDEN, "CSRF token mismatch").into_response());
    }
    Ok(c)
}

fn render(st: &AppState, name: &str, ctx: Value) -> Response {
    match st.env.get_template(name).and_then(|t| t.render(ctx)) {
        Ok(s) => Html(s).into_response(),
        Err(e) => {
            eprintln!("[PassManager] template {name}: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
        }
    }
}

fn page(st: &AppState, c: &Ctx, name: &str, extra: Value) -> Response {
    let base = context! { csrf => c.csrf.clone(), conn => sv(&c.conn), nav => nav_of(name) };
    render(st, name, context! { ..extra, ..base })
}

fn message(st: &AppState, c: Option<&Ctx>, code: StatusCode, heading: &str, msg: &str) -> Response {
    let ctx = match c {
        Some(c) => context! { csrf => c.csrf.clone(), conn => sv(&c.conn), heading, message => msg },
        None => context! { heading, message => msg },
    };
    let mut r = render(st, "message.html", ctx);
    *r.status_mut() = code;
    r
}

/// 调用服务；返回数据或 (错误码, 信息)。
async fn call<T: DeserializeOwned>(st: &AppState, req: Req) -> Result<T, (String, String)> {
    let r = st.backend.call(req).await;
    if r.ok {
        serde_json::from_value(r.data.unwrap_or(serde_json::Value::Null)).map_err(|e| ("INTERNAL".into(), e.to_string()))
    } else {
        Err((r.code.unwrap_or_else(|| "ERROR".into()), r.message.unwrap_or_default()))
    }
}

fn err_text(e: &(String, String)) -> String {
    match e.0.as_str() {
        "LOCKED" => "密码库已锁定，请先在\"状态\"页解锁。".into(),
        "NOT_READY" => "安全检查未通过，密码库保持锁定。请查看\"安全状态\"。".into(),
        "NOT_INITIALIZED" => "密码库尚未初始化：在服务器上以 root 运行 passmanager init。".into(),
        _ => e.1.clone(),
    }
}

/// POST 成功后跳转（303），提示文字由固定的代码决定，不反射任何输入。
fn done(path: &str, code: &str) -> Response {
    Redirect::to(&format!("{path}?done={code}")).into_response()
}

fn done_text(code: Option<&str>) -> Option<&'static str> {
    Some(match code? {
        "saved" => "已保存。",
        "deleted" => "已删除。",
        "revoked" => "令牌已吊销，立即失效。",
        "cancelled" => "注册码已作废。",
        "trusted" => "已清除记录，下次连接时重新记录指纹。",
        "locked" => "已锁定。",
        "unlocked" => "已解锁。",
        _ => return None,
    })
}

#[derive(serde::Deserialize, Default)]
struct DoneQ {
    done: Option<String>,
}

fn flash_ctx(q: &DoneQ) -> Value {
    match done_text(q.done.as_deref()) {
        Some(t) => context! { flash => t, flash_kind => "ok" },
        None => context! {},
    }
}

fn err_flash(e: &(String, String)) -> Value {
    context! { flash => err_text(e), flash_kind => "err" }
}

fn ip_of(conn: &Option<Extension<ConnInfo>>) -> String {
    conn.as_ref().map(|c| c.peer.ip().to_string()).unwrap_or_default()
}

// ---------------- 登录 ----------------

async fn login_page(State(st): State<St>, conn: Option<Extension<ConnInfo>>) -> Response {
    render(&st, "login.html", context! { conn => sv(conn.map(|c| c.0)) })
}

/// GET 只显示确认按钮，不消耗令牌（防止链接预览、预取把它用掉）。
async fn link_page(State(st): State<St>, Path(token): Path<String>, conn: Option<Extension<ConnInfo>>) -> Response {
    let ip = ip_of(&conn);
    if st.link_limiter.blocked(&ip) {
        return message(&st, None, StatusCode::TOO_MANY_REQUESTS, "尝试次数过多", "请 15 分钟后再试。");
    }
    if !st.links.valid(&token) {
        st.link_limiter.fail(&ip);
        return message(
            &st,
            None,
            StatusCode::NOT_FOUND,
            "链接无效",
            "登录链接不存在、已使用或已过期（有效期 2 分钟）。请在服务器上重新运行 passmanager login。",
        );
    }
    render(&st, "link.html", context! { token, conn => sv(conn.map(|c| c.0)) })
}

async fn link_post(State(st): State<St>, Path(token): Path<String>, conn: Option<Extension<ConnInfo>>) -> Response {
    let ip = ip_of(&conn);
    if st.link_limiter.blocked(&ip) {
        return message(&st, None, StatusCode::TOO_MANY_REQUESTS, "尝试次数过多", "请 15 分钟后再试。");
    }
    if !st.links.consume(&token) {
        st.link_limiter.fail(&ip);
        return message(&st, None, StatusCode::NOT_FOUND, "链接无效", "登录链接不存在、已使用或已过期。");
    }
    let (tok, _csrf) = st.sessions.create_at(Instant::now());
    eprintln!("[PassManager] web login from {ip}");
    let mut r = Redirect::to("/").into_response();
    r.headers_mut().insert(header::SET_COOKIE, session_cookie(&tok, SESSION_ABSOLUTE.as_secs()));
    r
}

async fn logout(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Form(f): Form<HashMap<String, String>>) -> Response {
    if let Err(r) = require_post(&st, &h, &conn, &f) {
        return r;
    }
    if let Some(t) = cookie_token(&h) {
        st.sessions.remove(&t);
    }
    let mut r = Redirect::to("/login").into_response();
    r.headers_mut().insert(header::SET_COOKIE, session_cookie("", 0));
    r.headers_mut().insert("clear-site-data", HeaderValue::from_static("\"cache\", \"cookies\""));
    r
}

// ---------------- 状态 / 锁定 ----------------

async fn dashboard(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Query(q): Query<DoneQ>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let status: ServerStatusView = match call(&st, Req::ServerStatus).await {
        Ok(s) => s,
        Err(e) => return message(&st, Some(&c), StatusCode::INTERNAL_SERVER_ERROR, "无法读取状态", &err_text(&e)),
    };
    let n = call::<Vec<EntryView>>(&st, Req::Entries).await.map(|v| v.len().to_string()).unwrap_or_else(|_| "—".into());
    page(&st, &c, "dashboard.html", context! { st => sv(&status), entries => n, ..flash_ctx(&q) })
}

async fn lock(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Form(f): Form<HashMap<String, String>>) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<serde_json::Value>(&st, Req::Lock).await {
        Ok(_) => done("/", "locked"),
        Err(e) => message(&st, Some(&c), StatusCode::BAD_REQUEST, "锁定失败", &err_text(&e)),
    }
}

async fn unlock(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Form(f): Form<HashMap<String, String>>) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<serde_json::Value>(&st, Req::Unlock).await {
        Ok(_) => done("/", "unlocked"),
        Err(e) => message(&st, Some(&c), StatusCode::BAD_REQUEST, "解锁失败", &err_text(&e)),
    }
}

// ---------------- 条目 ----------------

async fn entries(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Query(q): Query<DoneQ>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<Vec<EntryView>>(&st, Req::Entries).await {
        Ok(list) => page(&st, &c, "entries.html", context! { entries => sv(&list), ..flash_ctx(&q) }),
        Err(e) => page(&st, &c, "entries.html", context! { entries => sv(Vec::<EntryView>::new()), ..err_flash(&e) }),
    }
}

/// 新增字段的空行数。
const NEW_FIELD_ROWS: usize = 3;
/// 表单最多处理的字段行数。
const MAX_FIELD_ROWS: usize = 64;

#[derive(serde::Serialize, Default)]
struct EntryForm {
    name: String,
    domains: String,
    note: String,
    self_signed: bool,
    auto_accept_host_key: bool,
    /// password / ssh-key / fields
    kind: String,
    /// 已有字段名（值从不显示）。
    fields: Vec<String>,
    new_rows: Vec<usize>,
    /// SSH 私钥条目：允许 ssh-agent 桥签名的主机密钥指纹（每行一个）。
    host_keys: String,
    /// 限定的用途（`http` / `ssh` / `git`；全不选表示不限）。
    ops: Vec<String>,
}

/// 解析表单：返回（表单回显，单值密钥，字段列表）。
fn form_of(f: &HashMap<String, String>) -> (EntryForm, Option<String>, Option<Vec<FieldInput>>) {
    let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
    let kind = match g("kind").as_str() {
        "ssh-key" => "ssh-key",
        "fields" => "fields",
        _ => "password",
    }
    .to_string();
    let secret = f.get("secret").filter(|s| !s.trim().is_empty()).map(|s| s.replace("\r\n", "\n"));
    let mut fields = Vec::new();
    let mut names = Vec::new();
    for i in 0..MAX_FIELD_ROWS {
        let name = g(&format!("field_name_{i}"));
        let value = f.get(&format!("field_value_{i}")).map(|v| v.replace("\r\n", "\n")).filter(|v| !v.is_empty());
        let remove = f.get(&format!("field_remove_{i}")).is_some_and(|v| v == "1");
        if name.is_empty() || remove {
            continue;
        }
        names.push(name.clone());
        fields.push(FieldInput { name, value });
    }
    let form = EntryForm {
        name: g("name"),
        domains: g("domains"),
        note: g("note"),
        self_signed: f.get("self_signed").is_some_and(|v| v == "1"),
        auto_accept_host_key: f.get("auto_accept_host_key").is_some_and(|v| v == "1"),
        kind: kind.clone(),
        fields: names,
        new_rows: vec![],
        host_keys: g("host_keys"),
        ops: pm_vault_ops().iter().filter(|o| f.get(&format!("op_{o}")).is_some_and(|v| v == "1")).map(|o| o.to_string()).collect(),
    };
    let fields = (kind == "fields").then_some(fields);
    let secret = if kind == "fields" { None } else { secret };
    (form, secret, fields)
}

/// 可选的用途（与服务端 `pm_vault::OPS` 一致）。
fn pm_vault_ops() -> [&'static str; 3] {
    ["http", "ssh", "git"]
}

fn with_rows(mut form: EntryForm) -> EntryForm {
    let start = form.fields.len();
    form.new_rows = (start..start + NEW_FIELD_ROWS).collect();
    form
}

fn input_of(form: &EntryForm, secret: Option<String>, fields: Option<Vec<FieldInput>>) -> EntryInput {
    EntryInput {
        name: form.name.clone(),
        secret,
        domains: form
            .domains
            .split(|c: char| c == '\n' || c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        note: form.note.clone(),
        self_signed: form.self_signed,
        auto_accept_host_key: form.auto_accept_host_key,
        kind: (form.kind != "fields").then(|| form.kind.clone()),
        fields,
        host_keys: (form.kind == "ssh-key")
            .then(|| form.host_keys.split_whitespace().filter(|s| s.starts_with("SHA256:")).map(str::to_string).collect()),
        ops: Some(form.ops.clone()),
    }
}

async fn entry_new(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    page(&st, &c, "entry_form.html", context! { form => sv(with_rows(EntryForm { kind: "password".into(), ..Default::default() })) })
}

async fn entry_edit(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Path(name): Path<String>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let list = match call::<Vec<EntryView>>(&st, Req::Entries).await {
        Ok(l) => l,
        Err(e) => return message(&st, Some(&c), StatusCode::BAD_REQUEST, "无法读取条目", &err_text(&e)),
    };
    let Some(e) = list.into_iter().find(|e| e.name == name) else {
        return message(&st, Some(&c), StatusCode::NOT_FOUND, "条目不存在", "条目不存在或已被删除。");
    };
    let form = EntryForm {
        name: e.name.clone(),
        domains: e.domains.join("\n"),
        note: e.note,
        self_signed: e.self_signed,
        auto_accept_host_key: e.auto_accept_host_key,
        kind: if e.kind.is_empty() { "password".into() } else { e.kind.clone() },
        fields: e.fields.clone(),
        new_rows: vec![],
        host_keys: e.host_keys.join("\n"),
        ops: e.ops.clone(),
    };
    page(&st, &c, "entry_form.html", context! { form => sv(with_rows(form)), original => e.name, public_key => e.public_key })
}

/// 校验失败时重新显示表单：保留其他字段，但**不回显密钥**（需要重新输入）。
fn form_error(st: &AppState, c: &Ctx, form: EntryForm, original: Option<String>, e: &(String, String)) -> Response {
    let msg = format!("{}（为安全起见，密钥需要重新输入）", err_text(e));
    let mut r = page(st, c, "entry_form.html", context! { form => sv(with_rows(form)), original, flash => msg, flash_kind => "err" });
    *r.status_mut() = StatusCode::BAD_REQUEST;
    r
}

async fn entry_create(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (form, secret, fields) = form_of(&f);
    if secret.is_none() && fields.as_ref().is_none_or(|f| f.is_empty()) {
        return form_error(&st, &c, form, None, &("BAD_REQUEST".into(), "密钥不能为空".into()));
    }
    match call::<serde_json::Value>(&st, Req::AddEntry { entry: input_of(&form, secret, fields) }).await {
        Ok(_) => done("/entries", "saved"),
        Err(e) => form_error(&st, &c, form, None, &e),
    }
}

async fn entry_update(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Path(name): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (form, secret, fields) = form_of(&f);
    match call::<serde_json::Value>(&st, Req::UpdateEntry { original: name.clone(), entry: input_of(&form, secret, fields) }).await {
        Ok(_) => done("/entries", "saved"),
        Err(e) => form_error(&st, &c, form, Some(name), &e),
    }
}

async fn entry_delete(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Path(name): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<serde_json::Value>(&st, Req::DeleteEntry { name }).await {
        Ok(_) => done("/entries", "deleted"),
        Err(e) => message(&st, Some(&c), StatusCode::BAD_REQUEST, "删除失败", &err_text(&e)),
    }
}

// ---------------- 令牌与注册码 ----------------

async fn tokens_page(st: &AppState, c: &Ctx, extra: Value) -> Response {
    let list: Vec<TokenView> = call(st, Req::Tokens).await.unwrap_or_default();
    let pending: Vec<PendingEnrollView> = call(st, Req::Enrollments).await.unwrap_or_default();
    page(st, c, "tokens.html", context! { tokens => sv(&list), pending => sv(&pending), ..extra })
}

async fn tokens(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Query(q): Query<DoneQ>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    tokens_page(&st, &c, flash_ctx(&q)).await
}

// ---------------- 一键接入（/a/<注册码>） ----------------

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

/// 限速并查询注册码（不消耗）。成功时返回完整的 `pm-enroll://` URL。
async fn boot_check(st: &AppState, conn: &Option<Extension<ConnInfo>>, code: &str, what: &str) -> Result<String, Response> {
    let peer = conn.as_ref().map(|c| c.0.peer.ip().to_string()).unwrap_or_else(|| "unknown".into());
    if st.boot_limiter.blocked(&peer) || st.boot_fail_limiter.blocked(&peer) {
        return Err((StatusCode::TOO_MANY_REQUESTS, "too many requests\n").into_response());
    }
    st.boot_limiter.fail(&peer);
    if st.cfg.agent_bin_dir.is_none() || !bootstrap::code_ok(code) {
        st.boot_fail_limiter.fail(&peer);
        return Err(not_found());
    }
    match call::<pm_proto::EnrollPeekView>(st, Req::EnrollPeek { code: code.into(), what: what.into(), peer }).await {
        Ok(v) => Ok(v.url),
        Err(_) => {
            st.boot_fail_limiter.fail(&conn.as_ref().map(|c| c.0.peer.ip().to_string()).unwrap_or_else(|| "unknown".into()));
            Err(not_found())
        }
    }
}

async fn boot_script(State(st): State<St>, conn: Option<Extension<ConnInfo>>, Path(code): Path<String>) -> Response {
    let url = match boot_check(&st, &conn, &code, "script").await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let dir = st.cfg.agent_bin_dir.clone().unwrap_or_default();
    let bins = st.bins.scan(&dir);
    let base = format!("{}/a/{code}", st.cfg.origin());
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], bootstrap::sh_script(&base, &url, &bins)).into_response()
}

async fn boot_bin(State(st): State<St>, conn: Option<Extension<ConnInfo>>, Path((code, target)): Path<(String, String)>) -> Response {
    if !bootstrap::TARGETS.contains(&target.as_str()) {
        return not_found();
    }
    if let Err(r) = boot_check(&st, &conn, &code, &format!("binary {target}")).await {
        return r;
    }
    let dir = st.cfg.agent_bin_dir.clone().unwrap_or_default();
    let Some(b) = st.bins.scan(&dir).into_iter().find(|b| b.target == target) else { return not_found() };
    let Ok(f) = tokio::fs::File::open(&b.path).await else { return not_found() };
    let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(f));
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream")), (header::CONTENT_LENGTH, HeaderValue::from(b.size))],
        body,
    )
        .into_response()
}

/// 网页上"新建令牌"实际生成的是一次性注册码：令牌本身只在 Agent 注册时生成并经双层加密通道送达，
/// 不会出现在网页上。
async fn token_create(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let label = f.get("label").map(|s| s.trim().to_string()).unwrap_or_default();
    let lang = if f.get("lang").is_some_and(|l| l == "zh") { "zh" } else { "en" };
    match call::<pm_proto::AgentSetupView>(&st, Req::AgentSetup { label, lang: lang.into() }).await {
        Ok(v) => {
            let enroll = context! { label => v.label, text => v.text, minutes => v.expires_in_secs / 60 };
            tokens_page(&st, &c, context! { enroll }).await
        }
        Err(e) => tokens_page(&st, &c, err_flash(&e)).await,
    }
}

async fn token_revoke(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Path(id): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<serde_json::Value>(&st, Req::RevokeToken { id }).await {
        Ok(_) => done("/tokens", "revoked"),
        Err(e) => tokens_page(&st, &c, err_flash(&e)).await,
    }
}

async fn enroll_cancel(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Path(id): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<serde_json::Value>(&st, Req::EnrollCancel { id }).await {
        Ok(_) => done("/tokens", "cancelled"),
        Err(e) => tokens_page(&st, &c, err_flash(&e)).await,
    }
}

// ---------------- 主机指纹 ----------------

async fn pins_page(st: &AppState, c: &Ctx, extra: Value) -> Response {
    let pins: Result<Vec<PinView>, _> = call(st, Req::Pins).await;
    let pending: Vec<PendingPinView> = call(st, Req::PendingPins).await.unwrap_or_default();
    match pins {
        Ok(p) => page(st, c, "pins.html", context! { pins => sv(&p), pending => sv(&pending), ..extra }),
        Err(e) => page(st, c, "pins.html", context! { pins => sv(Vec::<PinView>::new()), pending => sv(&pending), ..err_flash(&e) }),
    }
}

async fn pins(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Query(q): Query<DoneQ>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    pins_page(&st, &c, flash_ctx(&q)).await
}

async fn pins_trust(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let pattern = f.get("pattern").map(|s| s.trim().to_string()).unwrap_or_default();
    if pattern.is_empty() {
        return pins_page(&st, &c, context! { flash => "请输入主机名。", flash_kind => "err" }).await;
    }
    match call::<serde_json::Value>(&st, Req::TrustPins { pattern }).await {
        Ok(_) => done("/pins", "trusted"),
        Err(e) => pins_page(&st, &c, err_flash(&e)).await,
    }
}

// ---------------- 设置 / 安全状态 ----------------

async fn settings(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>, Query(q): Query<DoneQ>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match call::<SettingsView>(&st, Req::GetSettings).await {
        Ok(s) => page(&st, &c, "settings.html", context! { settings => sv(&s), ..flash_ctx(&q) }),
        Err(e) => message(&st, Some(&c), StatusCode::BAD_REQUEST, "无法读取设置", &err_text(&e)),
    }
}

async fn settings_post(
    State(st): State<St>,
    h: HeaderMap,
    conn: Option<Extension<ConnInfo>>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let c = match require_post(&st, &h, &conn, &f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(hours) = f.get("auto_lock_hours").and_then(|v| v.trim().parse::<u32>().ok()).filter(|h| *h <= 720) else {
        return message(&st, Some(&c), StatusCode::BAD_REQUEST, "保存失败", "小时数必须是 0~720 的整数。");
    };
    match call::<serde_json::Value>(&st, Req::SetSettings { auto_lock_hours: hours }).await {
        Ok(_) => done("/settings", "saved"),
        Err(e) => message(&st, Some(&c), StatusCode::BAD_REQUEST, "保存失败", &err_text(&e)),
    }
}

async fn security(State(st): State<St>, h: HeaderMap, conn: Option<Extension<ConnInfo>>) -> Response {
    let c = match require(&st, &h, &conn) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let sec: SecurityView = match call(&st, Req::Security).await {
        Ok(s) => s,
        Err(e) => return message(&st, Some(&c), StatusCode::INTERNAL_SERVER_ERROR, "无法读取安全状态", &err_text(&e)),
    };
    let status: ServerStatusView = call(&st, Req::ServerStatus).await.unwrap_or_default();
    page(&st, &c, "security.html", context! { sec => sv(&sec), st => sv(&status) })
}

#[cfg(test)]
mod tests;

//! `passmanager run --http` 的服务端：本机程序的 HTTPS API 请求经客户端的本地中继、双层加密通道转到这里，
//! 由服务器按条目的中继策略检查、带上凭据、请求上游，再把脱敏后的回答流式送回。凭据从不离开服务器。
//!
//! - 打开（`RelayOpen`）：按 origin 找到凭据与它的策略，登记一次运行（运行编号、上限、计数都在服务器上）；
//! - 每个请求（`Relay`）：方法与路径必须在策略之内；丢弃本机程序发来的任何凭据（认证头、`key` 之类的查询参数、Cookie），
//!   按策略加上真实凭据；上游的主机、端口与 TLS 名称来自凭据的绑定，不来自请求；只跟随同源、而且仍在策略之内的重定向；
//! - 回答：要求上游不压缩（`Accept-Encoding: identity`），上游仍压缩时先解压（gzip / deflate；其他编码拒绝）；
//!   响应头只放行白名单；状态行、响应头与响应体里的一切密钥（所有编码形式）与别名地址都被替换，流式数据按滑动窗口处理；
//! - 等待上游期间每 10 秒发一个心跳帧：客户端借此发现本机程序已断开，连接关闭后这里取消上游请求；
//! - 日志只记：origin、方法、路径的最后一段、状态、字节数、耗时与替换次数。不记请求头、请求体、令牌或凭据。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use pm_proto::{GitHead, RELAY_DATA, RELAY_END, RELAY_ERROR, RELAY_HEAD, RELAY_KEEPALIVE, Response};
use pm_vault::relay::{self as policy, BodyRule, RelayPolicy};
use pm_vault::{OP_HTTP, Payload, PinKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;
use zeroize::Zeroizing;

use crate::redact::{Redactor, StreamRedact};
use crate::{ApiErr, err, http};

/// 请求体上限（整体缓冲：要检查请求体规则，也要先计入字节上限）。
pub const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;
/// 单个回答的上限（解压之后）。
const MAX_RESPONSE: u64 = 4 * 1024 * 1024 * 1024;
/// 每帧数据的大小。
const CHUNK: usize = 64 * 1024;
/// 等上游的响应头、以及两块响应数据之间最长等多久（大模型的长请求至少要能跑 15 分钟）。
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// 心跳间隔。
const KEEPALIVE: Duration = Duration::from_secs(10);
/// 运行编号闲置多久后作废（客户端异常退出、没有发 RelayClose 时）。
const RUN_IDLE: Duration = Duration::from_secs(12 * 3600);
/// 同时登记的运行数上限。
const MAX_RUNS: usize = 256;
/// "每天"的上限按 24 小时的窗口计算（从窗口里的第一个请求开始）。
const DAY: Duration = Duration::from_secs(24 * 3600);
/// 最多跟随几次同源重定向。
const MAX_REDIRECTS: usize = 3;

/// 本机程序可能用来带凭据的请求头：一律丢弃，凭据只由服务器按策略加上。
const CREDENTIAL_HEADERS: &[&str] = &["authorization", "proxy-authorization", "x-api-key", "x-goog-api-key", "api-key", "cookie"];
/// 由服务器自己决定、或会把一个回答切成几段（绕过脱敏）的请求头：不转发。
const HOP_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "accept-encoding",
    "range",
    "if-range",
];
/// 带凭据的查询参数：丢弃。
const KEY_PARAMS: &[&str] = &["key", "api_key", "apikey", "access_token"];
/// 默认放行给本机程序的响应头（策略可以按名称再加）。
const DEFAULT_RESPONSE_HEADERS: &[&str] = &["content-type", "cache-control", "retry-after", "x-request-id", "request-id", "x-should-retry"];

// ---- 运行登记与计数 ----

/// 一次 `passmanager run` 的一个 origin。
pub struct Run {
    /// 凭据的引用名（只用于服务器日志与计数，不发给客户端）。
    pub entry: String,
    /// 给客户端与日志的写法：`https://主机[:端口]` 或 `alias://名称`。
    pub label: String,
    pub host: String,
    pub port: u16,
    /// 别名的基础路径（没有末尾的 `/`）；直接写 origin 时为空。
    pub base_path: String,
    /// 客户端要求的上限（0 = 沿用策略）。
    pub max_requests: u64,
    pub max_bytes: u64,
    /// 客户端追加的请求体规则（与策略的规则都要满足）。
    pub require: Vec<BodyRule>,
    pub requests: u64,
    pub bytes: u64,
    last_used: Instant,
}

/// 一个凭据在当前 24 小时窗口里的用量。
struct Daily {
    since: Instant,
    requests: u64,
    bytes: u64,
}

/// 全部运行与每个凭据的用量（在内存里；服务重启后重新计数）。
#[derive(Default)]
pub struct Runs {
    runs: HashMap<String, Run>,
    daily: HashMap<String, Daily>,
}

/// 生效的上限（0 = 不限）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub requests_run: u64,
    pub bytes_run: u64,
    pub requests_day: u64,
    pub bytes_day: u64,
}

/// 超过上限时的错误：说出是哪一个上限。
fn over(what: &str, n: u64) -> ApiErr {
    err("RATE_LIMIT", format!("{what} reached ({n}); further requests are refused"))
}

impl Runs {
    /// 登记一次运行，返回运行编号（随机 128 位）。先清掉闲置太久的。
    pub fn insert(&mut self, run: Run) -> Result<String, ApiErr> {
        self.runs.retain(|_, r| r.last_used.elapsed() < RUN_IDLE);
        if self.runs.len() >= MAX_RUNS {
            return Err(err("RATE_LIMIT", "too many open relay runs; finish some commands first"));
        }
        let raw: [u8; 16] = pm_crypto::rng::random_array().map_err(|e| err("INTERNAL", e.to_string()))?;
        let id = hex::encode(raw);
        self.runs.insert(id.clone(), run);
        Ok(id)
    }

    /// 作废运行编号。
    pub fn close(&mut self, id: &str) -> bool {
        self.runs.remove(id).is_some()
    }

    pub fn get(&self, id: &str) -> Option<&Run> {
        self.runs.get(id)
    }

    /// 这个凭据的 24 小时窗口（过期就重新开始）。
    fn daily(&mut self, entry: &str) -> &mut Daily {
        let d = self.daily.entry(entry.to_string()).or_insert_with(|| Daily { since: Instant::now(), requests: 0, bytes: 0 });
        if d.since.elapsed() >= DAY {
            *d = Daily { since: Instant::now(), requests: 0, bytes: 0 };
        }
        d
    }

    /// 放行一个请求：请求数与字节数（请求体）都不超过上限时计入，否则返回 RATE_LIMIT。
    pub fn admit(&mut self, id: &str, entry: &str, lim: Limits, req_bytes: u64) -> Result<(), ApiErr> {
        let run = self.runs.get(id).ok_or_else(unknown_run)?;
        let (rr, rb) = (run.requests, run.bytes);
        let d = self.daily(entry);
        let (dr, db) = (d.requests, d.bytes);
        if lim.requests_run > 0 && rr >= lim.requests_run {
            return Err(over("the per-run request limit", lim.requests_run));
        }
        if lim.bytes_run > 0 && rb + req_bytes > lim.bytes_run {
            return Err(over("the per-run byte limit", lim.bytes_run));
        }
        if lim.requests_day > 0 && dr >= lim.requests_day {
            return Err(over("the 24-hour request limit of this credential", lim.requests_day));
        }
        if lim.bytes_day > 0 && db + req_bytes > lim.bytes_day {
            return Err(over("the 24-hour byte limit of this credential", lim.bytes_day));
        }
        let d = self.daily(entry);
        d.requests += 1;
        d.bytes += req_bytes;
        let run = self.runs.get_mut(id).ok_or_else(unknown_run)?;
        run.requests += 1;
        run.bytes += req_bytes;
        run.last_used = Instant::now();
        Ok(())
    }

    /// 计入回答的字节；超过字节上限时返回 RATE_LIMIT（回答到此为止）。
    pub fn add(&mut self, id: &str, entry: &str, lim: Limits, n: u64) -> Result<(), ApiErr> {
        let d = self.daily(entry);
        d.bytes += n;
        let db = d.bytes;
        let rb = match self.runs.get_mut(id) {
            Some(r) => {
                r.bytes += n;
                r.last_used = Instant::now();
                r.bytes
            }
            None => 0,
        };
        if lim.bytes_run > 0 && rb > lim.bytes_run {
            return Err(over("the per-run byte limit", lim.bytes_run));
        }
        if lim.bytes_day > 0 && db > lim.bytes_day {
            return Err(over("the 24-hour byte limit of this credential", lim.bytes_day));
        }
        Ok(())
    }
}

fn unknown_run() -> ApiErr {
    err("UNKNOWN_RUN", "this relay run has ended; start the command again")
}

/// 计数器：一个请求用到的那一份。
pub struct Meter {
    pub runs: Arc<Mutex<Runs>>,
    pub id: String,
    pub entry: String,
    pub lim: Limits,
}

impl Meter {
    fn admit(&self, req_bytes: u64) -> Result<(), ApiErr> {
        self.runs.lock().unwrap_or_else(|e| e.into_inner()).admit(&self.id, &self.entry, self.lim, req_bytes)
    }
    fn add(&self, n: u64) -> Result<(), ApiErr> {
        self.runs.lock().unwrap_or_else(|e| e.into_inner()).add(&self.id, &self.entry, self.lim, n)
    }
}

// ---- 打开一次运行 ----

/// 解析 origin：`https://主机[:端口]`（不能有路径、查询串、用户信息）或 `alias://名称`。
/// 返回（给客户端的写法，主机，端口，基础路径）。
pub fn parse_origin(payload: &Payload, origin: &str) -> Result<(String, String, u16, String), ApiErr> {
    let o = origin.trim();
    if let Some(name) = o.strip_prefix(http::ALIAS_SCHEME) {
        let name = name.trim_end_matches('/');
        if name.is_empty() || name.contains(['/', '?', '#', '\\']) {
            return Err(err("BAD_URL", "write the alias as alias://<name> (no path)"));
        }
        let a = payload.alias(name).ok_or_else(|| err("UNKNOWN_ALIAS", format!("no alias \"{name}\"")))?;
        let (host, port, base) = pm_vault::alias_parts(&a.url).ok_or_else(|| err("INTERNAL", "stored alias is not valid"))?;
        return Ok((format!("{}{name}", http::ALIAS_SCHEME), host, port, base));
    }
    let bad = || err("BAD_URL", "an origin is https://<host>[:<port>] with no path, query or user name");
    let u = Url::parse(o).map_err(|_| bad())?;
    if u.scheme() != "https" {
        return Err(err("USE_HTTPS", "only https origins can be relayed"));
    }
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() || !matches!(u.path(), "" | "/")
    {
        return Err(bad());
    }
    let host = http::host_string(&u).ok_or_else(bad)?;
    let port = u.port_or_known_default().unwrap_or(443);
    http::alias_guard(payload, &host)?;
    let label = if port == 443 { format!("https://{host}") } else { format!("https://{host}:{port}") };
    Ok((label, host, port, String::new()))
}

/// 这台主机的凭据与它的策略。没有策略时说明怎么办（不说条目名：别名的主机名可能就是条目名）。
fn entry_and_policy<'a>(
    payload: &'a Payload,
    host: &str,
    port: u16,
    label: &str,
) -> Result<(&'a pm_vault::Entry, &'a RelayPolicy), ApiErr> {
    let e = http::select_by_host(payload, host, port, OP_HTTP)
        .map_err(|e| if e.code == "NO_CREDENTIAL" { err("NO_CREDENTIAL", format!("no stored credential for {label}")) } else { e })?;
    let p = payload.relay(&e.name).ok_or_else(|| {
        err(
            "NO_RELAY_POLICY",
            format!("the credential for {label} has no relay policy, so it cannot be used through passmanager run --http"),
        )
    })?;
    Ok((e, p))
}

/// `RelayOpen`：检查 origin、凭据与策略，以及客户端的规则；返回要登记的运行。
pub fn open(payload: &Payload, origin: &str, max_requests: u64, max_bytes: u64, require: &[String]) -> Result<Run, ApiErr> {
    let (label, host, port, base_path) = parse_origin(payload, origin)?;
    let (e, _) = entry_and_policy(payload, &host, port, &label)?;
    let mut rules = Vec::new();
    for r in require {
        rules.push(policy::parse_require(r).map_err(|m| err("BAD_REQUEST", m))?);
    }
    Ok(Run {
        entry: e.name.clone(),
        label,
        host,
        port,
        base_path,
        max_requests,
        max_bytes,
        require: policy::merge_rules(rules),
        requests: 0,
        bytes: 0,
        last_used: Instant::now(),
    })
}

// ---- 准备一个请求 ----

/// 准备好的请求（在库锁之内取出，之后不再持有锁）。
pub struct Plan {
    pub label: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    /// 上游的路径与查询串（别名时已接上基础路径；带凭据的查询参数已去掉）。
    pub path: String,
    /// 路径的最后一段（日志只记这个）。
    pub last: String,
    pub headers: Vec<(String, String)>,
    pub auth_name: String,
    pub auth_value: Zeroizing<String>,
    /// 策略与这次运行的请求体规则（每组都要满足）。
    pub rules: Vec<Vec<BodyRule>>,
    pub response_headers: Vec<String>,
    pub policy: RelayPolicy,
    pub base_path: String,
    pub self_signed: bool,
    pub expected_pin: Option<String>,
    pub redactor: Arc<Redactor>,
    pub meter: Meter,
}

/// 路径的最后一段（没有就是 `/`）：日志只记这么多。
pub fn last_segment(path: &str) -> String {
    let p = path.split('?').next().unwrap_or_default().trim_end_matches('/');
    let seg = p.rsplit('/').next().unwrap_or_default();
    if seg.is_empty() { "/".into() } else { seg.chars().take(64).collect() }
}

/// 去掉带凭据的查询参数，其余的原样保留（不重新编码）。
pub fn strip_key_params(q: &str) -> String {
    q.split('&')
        .filter(|kv| {
            let k = kv.split('=').next().unwrap_or_default();
            let k = percent_encoding::percent_decode_str(&k.replace('+', " ")).decode_utf8_lossy().to_ascii_lowercase();
            !KEY_PARAMS.contains(&k.as_str())
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// 转发给上游的请求头：去掉凭据、逐跳头与认证头本身，其余原样。
pub fn forward_headers(h: &[(String, String)], auth_name: &str) -> Vec<(String, String)> {
    h.iter()
        .filter(|(k, _)| {
            let k = k.to_ascii_lowercase();
            !CREDENTIAL_HEADERS.contains(&k.as_str()) && !HOP_HEADERS.contains(&k.as_str()) && !k.starts_with("proxy-") && k != auth_name
        })
        .cloned()
        .collect()
}

/// 准备一个请求：运行要存在；凭据仍是打开时那个；方法与路径在策略之内；加上认证头。
pub fn prepare(
    payload: &Payload,
    runs: &Arc<Mutex<Runs>>,
    id: &str,
    method: &str,
    path_q: &str,
    headers: &[(String, String)],
    redactor: Arc<Redactor>,
) -> Result<Plan, ApiErr> {
    let (label, host, port, base_path, entry, run_req, run_bytes, run_rules) = {
        let g = runs.lock().unwrap_or_else(|e| e.into_inner());
        let r = g.get(id).ok_or_else(unknown_run)?;
        (r.label.clone(), r.host.clone(), r.port, r.base_path.clone(), r.entry.clone(), r.max_requests, r.max_bytes, r.require.clone())
    };
    let method = method.to_ascii_uppercase();
    if !policy::RELAY_METHODS.contains(&method.as_str()) {
        return Err(err("FORBIDDEN", format!("method {method} is not relayed")));
    }
    if !path_q.starts_with('/') || path_q.contains('#') {
        return Err(err("BAD_REQUEST", "invalid path"));
    }
    let (path, query) = match path_q.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_q, None),
    };
    let full = if base_path.is_empty() {
        path.to_string()
    } else if path == "/" {
        base_path.clone()
    } else {
        format!("{base_path}{path}")
    };
    let (e, pol) = entry_and_policy(payload, &host, port, &label)?;
    if e.name != entry {
        return Err(err("UNKNOWN_RUN", "the credential for this origin changed; start the command again"));
    }
    policy::path_allowed(pol, &method, &full)
        .map_err(|_| err("FORBIDDEN", format!("{method} {} is not allowed by the relay policy of {label}", last_segment(&full))))?;
    let (auth_name, template, ph) = policy::parse_auth(&pol.auth).map_err(|m| err("INTERNAL", m))?;
    let value = if e.fields.is_empty() { e.secret.clone() } else { e.field(&ph).map(|f| f.value.clone()).unwrap_or_default() };
    if value.is_empty() || value.chars().any(|c| c.is_control()) {
        return Err(err("BAD_REQUEST", "the stored credential cannot be sent in a header"));
    }
    // 模板里恰好一个 {{…}}（parse_auth 已检查）：把它整个换成凭据
    let (a, b) = (template.find("{{").unwrap_or(0), template.find("}}").map(|i| i + 2).unwrap_or(0));
    let mut auth_value = Zeroizing::new(String::with_capacity(template.len() + value.len()));
    auth_value.push_str(&template[..a]);
    auth_value.push_str(&value);
    auth_value.push_str(&template[b..]);
    let path = match query.map(strip_key_params) {
        Some(q) if !q.is_empty() => format!("{full}?{q}"),
        _ => full.clone(),
    };
    let lim = Limits {
        requests_run: policy::narrow(pol.max_requests_run, run_req),
        bytes_run: policy::narrow(pol.max_bytes_run, run_bytes),
        requests_day: pol.max_requests_day,
        bytes_day: pol.max_bytes_day,
    };
    let rules = [pol.require.clone(), run_rules].into_iter().filter(|r| !r.is_empty()).collect();
    let mut response_headers: Vec<String> = DEFAULT_RESPONSE_HEADERS.iter().map(|s| s.to_string()).collect();
    response_headers.extend(pol.response_headers.iter().cloned());
    let expected_pin =
        if e.self_signed { payload.pin(PinKind::Https, &format!("{host}:{port}")).map(|p| p.fingerprint.clone()) } else { None };
    Ok(Plan {
        label,
        host,
        port,
        method,
        last: last_segment(&full),
        path,
        headers: forward_headers(headers, &auth_name),
        auth_name,
        auth_value,
        rules,
        response_headers,
        policy: pol.clone(),
        base_path,
        self_signed: e.self_signed,
        expected_pin,
        redactor,
        meter: Meter { runs: runs.clone(), id: id.to_string(), entry, lim },
    })
}

// ---- 请求体规则 ----

/// 严格的 JSON：对象里有重复的键就报错（上游可能取另一个值，规则就被绕过了）。
struct Strict(serde_json::Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = serde_json::Value;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E> {
        Ok(serde_json::Number::from_f64(v).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null))
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(v.into())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut v = Vec::new();
        while let Some(Strict(x)) = seq.next_element()? {
            v.push(x);
        }
        Ok(serde_json::Value::Array(v))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut m = serde_json::Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if m.contains_key(&k) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            let Strict(v) = map.next_value()?;
            m.insert(k, v);
        }
        Ok(serde_json::Value::Object(m))
    }
}

/// 请求体是否满足全部规则组。值是字符串时比较字符串本身，其他类型比较它的 JSON 写法（如 `1`、`true`）。
/// 规则只约束带请求体的请求（例如 GET /models 没有可选的模型）；有请求体时它必须是满足规则、没有重复键的 JSON。
pub fn check_body(groups: &[Vec<BodyRule>], body: &[u8]) -> Result<(), String> {
    if groups.is_empty() || body.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let Strict(v) = serde_json::from_slice::<Strict>(body)
        .map_err(|_| "the request body must be one JSON object without duplicate keys".to_string())?;
    for rule in groups.iter().flatten() {
        let mut cur = &v;
        for k in rule.key.split('.') {
            cur = cur.get(k).ok_or_else(|| format!("the request body must set {}", rule.key))?;
        }
        let got = match cur {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if !rule.values.contains(&got) {
            return Err(format!("the request body breaks the rule json:{} (allowed: {})", rule.key, rule.values.join(", ")));
        }
    }
    Ok(())
}

// ---- 回答的处理 ----

/// 上游仍压缩了回答时的解压器（HTTP 的 deflate 是 zlib 格式）。
enum Decoder {
    None,
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Zlib(flate2::write::ZlibDecoder<Vec<u8>>),
}

fn decoder(encoding: &str) -> Result<Decoder, String> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        "" | "identity" => Ok(Decoder::None),
        "gzip" | "x-gzip" => Ok(Decoder::Gzip(flate2::write::GzDecoder::new(Vec::new()))),
        "deflate" => Ok(Decoder::Zlib(flate2::write::ZlibDecoder::new(Vec::new()))),
        other => Err(format!("the upstream compressed its answer with {other} although identity was requested; refused")),
    }
}

impl Decoder {
    fn feed(&mut self, d: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::Write;
        match self {
            Decoder::None => Ok(d.to_vec()),
            Decoder::Gzip(g) => {
                g.write_all(d)?;
                Ok(std::mem::take(g.get_mut()))
            }
            Decoder::Zlib(z) => {
                z.write_all(d)?;
                Ok(std::mem::take(z.get_mut()))
            }
        }
    }
    fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            Decoder::None => Ok(Vec::new()),
            Decoder::Gzip(g) => g.finish(),
            Decoder::Zlib(z) => z.finish(),
        }
    }
}

/// 放行给本机程序的响应头：只有白名单里的名称；值同样脱敏（替换次数计入 `count`）。
fn response_headers(h: &hyper::HeaderMap, allow: &[String], red: &Redactor, count: &mut usize) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in h {
        if !allow.iter().any(|a| a == k.as_str()) {
            continue;
        }
        let Ok(v) = v.to_str() else { continue };
        let (val, n) = red.redact(v.as_bytes());
        *count += n;
        out.push((k.to_string(), String::from_utf8_lossy(&val).into_owned()));
    }
    out
}

/// 同源重定向的目标：解析 Location；主机、端口必须相同，别名的基础路径之内，而且仍在策略之内。
fn redirect_target(p: &Plan, method: &str, current: &str, location: &str) -> Result<String, String> {
    let base = Url::parse(&format!("https://{}:{}{current}", p.host, p.port)).map_err(|e| e.to_string())?;
    let u = base.join(location).map_err(|_| "the upstream sent an invalid redirect".to_string())?;
    let same =
        u.scheme() == "https" && http::host_string(&u).as_deref() == Some(p.host.as_str()) && u.port_or_known_default() == Some(p.port);
    if !same || !u.username().is_empty() {
        return Err("the upstream redirected to another origin; redirects to other origins are never followed".into());
    }
    let path = u.path();
    let inside = p.base_path.is_empty() || path == p.base_path || path.starts_with(&format!("{}/", p.base_path));
    if !inside || policy::path_allowed(&p.policy, method, path).is_err() {
        return Err("the upstream redirected to a path outside the relay policy; not followed".into());
    }
    Ok(match u.query().map(strip_key_params) {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    })
}

// ---- 通道帧 ----

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> std::io::Result<Vec<u8>> {
    let len = s.read_u32().await? as usize;
    if len > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// 写一帧：类型字节 + 内容。
async fn frame<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, body: &[u8]) -> std::io::Result<()> {
    w.write_u32(body.len() as u32 + 1).await?;
    w.write_u8(kind).await?;
    w.write_all(body).await?;
    w.flush().await
}

/// 结果：日志行，以及首次看到的自签证书指纹（调用方记录到指纹库）。
pub struct Outcome {
    pub line: String,
    pub observed_pin: Option<(String, String)>,
}

/// 统计（只用于日志）。
#[derive(Default)]
struct Stats {
    status: u16,
    sent: u64,
    received: u64,
    redactions: usize,
}

/// 等一个 future 完成；期间每 10 秒发心跳，本机程序断开（`cancel` 结束）或超时就放弃。
async fn wait<F: std::future::Future, W: AsyncWrite + Unpin>(
    fut: F,
    wr: &mut W,
    cancel: &mut tokio::sync::watch::Receiver<()>,
    limit: Duration,
) -> Result<F::Output, ApiErr> {
    tokio::pin!(fut);
    let deadline = tokio::time::sleep(limit);
    tokio::pin!(deadline);
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + KEEPALIVE, KEEPALIVE);
    loop {
        tokio::select! {
            v = &mut fut => return Ok(v),
            _ = tick.tick() => {
                if frame(wr, RELAY_KEEPALIVE, &[]).await.is_err() {
                    return Err(err("CANCELLED", "the local program disconnected"));
                }
            }
            _ = cancel.changed() => return Err(err("CANCELLED", "the local program disconnected")),
            _ = &mut deadline => return Err(err("UPSTREAM_ERROR", "the upstream did not answer in time")),
        }
    }
}

/// 执行一个请求。调用方已回复"可以继续"；之后是请求体帧（空帧结束），回复是带类型的帧（见 `pm_proto::RELAY_*`）。
pub async fn serve<S: AsyncRead + AsyncWrite + Send + 'static>(s: S, p: Plan) -> Outcome {
    let t0 = Instant::now();
    let (mut rd, mut wr) = tokio::io::split(s);
    let observed = Arc::new(std::sync::Mutex::new(None));
    let mut st = Stats::default();
    // 请求体：整体读入（有上限）。
    let body = async {
        let mut body = Vec::new();
        loop {
            let f = read_frame(&mut rd, CHUNK).await.map_err(|_| err("DISCONNECTED", "reading the request body failed"))?;
            if f.is_empty() {
                return Ok(body);
            }
            if body.len() + f.len() > MAX_REQUEST_BODY {
                return Err(err("TOO_LARGE", format!("the request body is larger than {} MiB", MAX_REQUEST_BODY >> 20)));
            }
            body.extend_from_slice(&f);
        }
    }
    .await;
    // 请求体读完之后，客户端不再发送任何东西：连接一断（本机程序走了），cancel 就结束。
    let (tx, mut cancel) = tokio::sync::watch::channel(());
    let watcher = tokio::spawn(async move {
        let _ = read_frame(&mut rd, 0).await;
        drop(tx);
    });
    let mut red = StreamRedact::new(p.redactor.clone());
    let r = match body {
        Ok(b) => run(&mut wr, &p, b, &mut cancel, &mut red, &mut st, observed.clone()).await,
        Err(e) => Err(e),
    };
    st.redactions = red.count;
    let code = match &r {
        Ok(()) => {
            let _ = frame(&mut wr, RELAY_END, &[]).await;
            "OK".to_string()
        }
        Err(e) => {
            // 错误信息同样脱敏（上游的错误里可能有 URL）。
            let resp = Response::err(&e.code, p.redactor.redact_str(&e.message));
            let _ = frame(&mut wr, RELAY_ERROR, &serde_json::to_vec(&resp).unwrap_or_default()).await;
            e.code.clone()
        }
    };
    watcher.abort();
    let pin = if p.self_signed && p.expected_pin.is_none() { observed.lock().unwrap().clone() } else { None };
    Outcome {
        line: format!(
            "relay: entry={} origin={} method={} last={} status={} result={code} in={} out={} ms={} redactions={}",
            p.meter.entry,
            p.label,
            p.method,
            p.last,
            st.status,
            st.sent,
            st.received,
            t0.elapsed().as_millis(),
            st.redactions
        ),
        observed_pin: pin.map(|fp| (format!("{}:{}", p.host, p.port), fp)),
    }
}

/// 检查、请求上游（含同源重定向）、把回答流式送回。
async fn run<W: AsyncWrite + Unpin>(
    wr: &mut W,
    p: &Plan,
    body: Vec<u8>,
    cancel: &mut tokio::sync::watch::Receiver<()>,
    red: &mut StreamRedact,
    st: &mut Stats,
    observed: Arc<std::sync::Mutex<Option<String>>>,
) -> Result<(), ApiErr> {
    check_body(&p.rules, &body).map_err(|m| err("FORBIDDEN", m))?;
    p.meter.admit(body.len() as u64)?;
    st.sent = body.len() as u64;
    let mut method = p.method.clone();
    let mut path = p.path.clone();
    let mut body = Bytes::from(body);
    let mut hops = 0;
    let resp = loop {
        let fut = send(p, &method, &path, body.clone(), observed.clone());
        let resp = wait(fut, wr, cancel, UPSTREAM_TIMEOUT).await??;
        let status = resp.status().as_u16();
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            break resp;
        }
        let loc = resp.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        // 301/302/303 之后改用 GET、不带请求体（与浏览器相同）；307/308 保持方法与请求体
        if (301..=303).contains(&status) && method != "HEAD" {
            method = "GET".into();
            body = Bytes::new();
        }
        if hops >= MAX_REDIRECTS {
            return Err(err("UPSTREAM_ERROR", "too many redirects"));
        }
        path = redirect_target(p, &method, path.split('?').next().unwrap_or("/"), &loc).map_err(|m| err("UPSTREAM_ERROR", m))?;
        hops += 1;
    };
    st.status = resp.status().as_u16();
    let enc = resp.headers().get_all("content-encoding").iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join(",");
    if enc.contains(',') {
        return Err(err("UPSTREAM_ERROR", "the upstream used several content encodings; refused"));
    }
    let mut dec = decoder(&enc).map_err(|m| err("UPSTREAM_ERROR", m))?;
    let head = GitHead { status: st.status, headers: response_headers(resp.headers(), &p.response_headers, &p.redactor, &mut red.count) };
    frame(wr, RELAY_HEAD, &serde_json::to_vec(&head).unwrap_or_default())
        .await
        .map_err(|_| err("CANCELLED", "the local program disconnected"))?;
    let mut body = resp.into_body();
    use http_body_util::BodyExt as _;
    loop {
        let next = wait(body.frame(), wr, cancel, UPSTREAM_TIMEOUT).await?;
        let Some(f) = next else { break };
        let f = f.map_err(|e| err("UPSTREAM_ERROR", format!("reading the answer failed: {e}")))?;
        let Ok(d) = f.into_data() else { continue };
        let plain = dec.feed(&d).map_err(|_| err("UPSTREAM_ERROR", "the compressed answer is corrupt"))?;
        emit(wr, p, red, st, &plain).await?;
    }
    let rest = dec.finish().map_err(|_| err("UPSTREAM_ERROR", "the compressed answer is corrupt"))?;
    emit(wr, p, red, st, &rest).await?;
    let tail = red.finish();
    send_data(wr, &tail).await?;
    Ok(())
}

/// 一块明文：计入字节、脱敏、发出。
async fn emit<W: AsyncWrite + Unpin>(wr: &mut W, p: &Plan, red: &mut StreamRedact, st: &mut Stats, plain: &[u8]) -> Result<(), ApiErr> {
    if plain.is_empty() {
        return Ok(());
    }
    st.received += plain.len() as u64;
    if st.received > MAX_RESPONSE {
        return Err(err("TOO_LARGE", "the answer is too large"));
    }
    p.meter.add(plain.len() as u64)?;
    let out = red.feed(plain);
    send_data(wr, &out).await
}

async fn send_data<W: AsyncWrite + Unpin>(wr: &mut W, d: &[u8]) -> Result<(), ApiErr> {
    for c in d.chunks(CHUNK) {
        frame(wr, RELAY_DATA, c).await.map_err(|_| err("CANCELLED", "the local program disconnected"))?;
    }
    Ok(())
}

/// 连接上游并发送请求，返回响应头（响应体之后再读）。
async fn send(
    p: &Plan,
    method: &str,
    path: &str,
    body: Bytes,
    observed: Arc<std::sync::Mutex<Option<String>>>,
) -> Result<hyper::Response<hyper::body::Incoming>, ApiErr> {
    let (host, port) = (p.host.as_str(), p.port);
    let tcp = tokio::time::timeout(Duration::from_secs(20), tokio::net::TcpStream::connect((host, port)))
        .await
        .map_err(|_| err("UPSTREAM_ERROR", format!("connection to {} timed out", p.label)))?
        .map_err(|e| err("UPSTREAM_ERROR", format!("connection to {} failed: {e}", p.label)))?;
    let cfg = crate::git::client_tls(p.self_signed, p.expected_pin.clone(), observed)?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| err("BAD_REQUEST", "invalid host name"))?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await.map_err(|e| {
        if e.to_string().contains(http::PIN_MISMATCH_MARKER) {
            err(
                "HOST_KEY_CHANGED",
                format!(
                    "TLS certificate of {} changed; nothing was sent. Ask the user to trust the new certificate in PassManager.",
                    p.label
                ),
            )
        } else {
            err("UPSTREAM_ERROR", format!("TLS handshake with {} failed: {e}", p.label))
        }
    })?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
        .await
        .map_err(|e| err("UPSTREAM_ERROR", format!("HTTP handshake failed: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let host_hdr = if port == 443 { host.to_string() } else { format!("{host}:{port}") };
    let mut rb = hyper::Request::builder().method(method).uri(path).header("host", host_hdr).header("accept-encoding", "identity");
    for (k, v) in &p.headers {
        rb = rb.header(k.as_str(), v.as_str());
    }
    rb = rb.header(p.auth_name.as_str(), p.auth_value.as_str());
    let req = rb.body(http_body_util::Full::new(body)).map_err(|_| err("BAD_REQUEST", "invalid request header"))?;
    sender.send_request(req).await.map_err(|e| err("UPSTREAM_ERROR", format!("upstream request failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(k: &str, v: &[&str]) -> BodyRule {
        BodyRule { key: k.into(), values: v.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn body_rules() {
        let g = vec![vec![rule("model", &["a", "b"])], vec![rule("model", &["b"]), rule("opt.n", &["1"])]];
        assert!(check_body(&g, br#"{"model":"b","opt":{"n":1}}"#).is_ok());
        assert!(check_body(&g, br#"{"model":"a","opt":{"n":1}}"#).is_err(), "第二组只允许 b");
        assert!(check_body(&g, br#"{"model":"b"}"#).is_err(), "缺少 opt.n");
        assert!(check_body(&g, br#"{"model":"b","model":"x","opt":{"n":1}}"#).is_err(), "重复的键");
        assert!(check_body(&g, br#"{"model":"b","opt":{"n":1,"n":2}}"#).is_err(), "嵌套里重复的键");
        assert!(check_body(&g, b"not json").is_err());
        assert!(check_body(&g, b"model=a").is_err(), "表单编码的请求体也要是 JSON");
        assert!(check_body(&g, b"").is_ok() && check_body(&g, b" \n").is_ok(), "没有请求体（GET）不受规则约束");
        assert!(check_body(&[], b"anything").is_ok(), "没有规则不看请求体");
    }

    #[test]
    fn query_and_header_filters() {
        assert_eq!(strip_key_params("a=1&key=x&API_KEY=y&b=2&access%5Ftoken=z&apikey"), "a=1&b=2");
        assert_eq!(strip_key_params("q=key"), "q=key");
        let h = vec![
            ("Authorization".to_string(), "Bearer dummy".to_string()),
            ("X-Api-Key".into(), "d".into()),
            ("Cookie".into(), "c".into()),
            ("Content-Type".into(), "application/json".into()),
            ("Accept-Encoding".into(), "gzip".into()),
            ("Range".into(), "bytes=0-1".into()),
            ("Proxy-Foo".into(), "x".into()),
            ("X-Custom-Auth".into(), "dummy".into()),
            ("OpenAI-Beta".into(), "assistants=v2".into()),
        ];
        assert_eq!(
            forward_headers(&h, "x-custom-auth"),
            vec![("Content-Type".to_string(), "application/json".to_string()), ("OpenAI-Beta".into(), "assistants=v2".into())]
        );
        assert_eq!(
            (last_segment("/api/v1/chat/completions?x=1"), last_segment("/"), last_segment("/a/")),
            ("completions".into(), "/".into(), "a".into())
        );
    }

    #[test]
    fn decoders() {
        use std::io::Write;
        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        g.write_all(b"hello gzip").unwrap();
        let gz = g.finish().unwrap();
        let mut d = decoder("GZIP").unwrap();
        let mut out = Vec::new();
        for c in gz.chunks(3) {
            out.extend(d.feed(c).unwrap());
        }
        out.extend(d.finish().unwrap());
        assert_eq!(out, b"hello gzip");
        assert!(matches!(decoder(" identity "), Ok(Decoder::None)) && matches!(decoder(""), Ok(Decoder::None)));
        assert!(decoder("br").is_err() && decoder("zstd").is_err());
    }

    #[test]
    fn runs_and_limits() {
        let mut r = Runs::default();
        let mk = || Run {
            entry: "e".into(),
            label: "https://api.example.com".into(),
            host: "api.example.com".into(),
            port: 443,
            base_path: String::new(),
            max_requests: 0,
            max_bytes: 0,
            require: vec![],
            requests: 0,
            bytes: 0,
            last_used: Instant::now(),
        };
        let a = r.insert(mk()).unwrap();
        let b = r.insert(mk()).unwrap();
        assert!(a != b && a.len() == 32);
        let lim = Limits { requests_run: 2, bytes_run: 100, requests_day: 3, bytes_day: 0 };
        assert!(r.admit(&a, "e", lim, 10).is_ok() && r.admit(&a, "e", lim, 10).is_ok());
        let e = r.admit(&a, "e", lim, 10).unwrap_err();
        assert!(e.code == "RATE_LIMIT" && e.message.contains("per-run request limit"), "{}", e.message);
        // 另一次运行有自己的计数，但同一凭据的 24 小时上限是共用的
        assert!(r.admit(&b, "e", lim, 10).is_ok());
        assert!(r.admit(&b, "e", lim, 10).unwrap_err().message.contains("24-hour request limit"));
        // 字节：回答把运行推过上限
        let lim = Limits { bytes_run: 100, ..Default::default() };
        let c = r.insert(mk()).unwrap();
        assert!(r.admit(&c, "e", lim, 90).is_ok());
        assert!(r.add(&c, "e", lim, 10).is_ok());
        assert!(r.add(&c, "e", lim, 1).unwrap_err().message.contains("per-run byte limit"));
        assert!(r.admit(&c, "e", lim, 1).is_err(), "已到字节上限：下一个请求也拒绝");
        // 关闭之后编号作废
        assert!(r.close(&a) && !r.close(&a));
        assert_eq!(r.admit(&a, "e", lim, 0).unwrap_err().code, "UNKNOWN_RUN");
    }

    fn payload() -> Payload {
        let e = pm_vault::Entry {
            name: "or".into(),
            secret: Zeroizing::new("sk-or-secret-value".into()),
            domains: vec!["api.example.com".into()],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: vec![],
            host_keys: vec![],
            ops: vec!["http".into()],
        };
        let pol = RelayPolicy {
            entry: "or".into(),
            allow: vec!["POST /api/v1/chat/completions".into(), "GET /api/v1/models".into()],
            auth: "authorization: Bearer {{secret}}".into(),
            require: vec![rule("model", &["m1"])],
            response_headers: vec!["x-extra".into()],
            max_requests_run: 5,
            max_bytes_run: 0,
            max_requests_day: 50,
            max_bytes_day: 0,
        };
        Payload { entries: vec![e], relay: vec![pol], ..Default::default() }
    }

    #[test]
    fn open_and_prepare() {
        let p = payload();
        assert_eq!(parse_origin(&p, "https://API.example.com/").unwrap().0, "https://api.example.com");
        assert_eq!(parse_origin(&p, "https://api.example.com:8443").unwrap().0, "https://api.example.com:8443");
        for bad in ["http://api.example.com", "https://api.example.com/v1", "https://u@api.example.com", "https://api.example.com?x=1"] {
            assert!(parse_origin(&p, bad).is_err(), "{bad}");
        }
        assert_eq!(open(&p, "https://other.example.com", 0, 0, &[]).err().unwrap().code, "NO_CREDENTIAL");
        let mut no_pol = p.clone();
        no_pol.relay.clear();
        assert_eq!(open(&no_pol, "https://api.example.com", 0, 0, &[]).err().unwrap().code, "NO_RELAY_POLICY");
        assert!(open(&p, "https://api.example.com", 0, 0, &["model=x".into()]).is_err());

        let runs = Arc::new(Mutex::new(Runs::default()));
        let run = open(&p, "https://api.example.com", 3, 0, &["json:model=m1".into()]).unwrap();
        let id = runs.lock().unwrap().insert(run).unwrap();
        let red = Arc::new(Redactor::empty());
        let hdrs = vec![("Authorization".to_string(), "Bearer dummy".to_string()), ("Content-Type".into(), "application/json".into())];
        let plan = prepare(&p, &runs, &id, "post", "/api/v1/chat/completions?key=dummy&stream=1", &hdrs, red.clone()).unwrap();
        assert_eq!(
            (plan.method.as_str(), plan.path.as_str(), plan.last.as_str()),
            ("POST", "/api/v1/chat/completions?stream=1", "completions")
        );
        assert_eq!((plan.auth_name.as_str(), plan.auth_value.as_str()), ("authorization", "Bearer sk-or-secret-value"));
        assert_eq!(plan.headers, vec![("Content-Type".to_string(), "application/json".to_string())]);
        assert_eq!(plan.meter.lim, Limits { requests_run: 3, bytes_run: 0, requests_day: 50, bytes_day: 0 }, "客户端只能收窄");
        assert_eq!(plan.rules.len(), 2);
        assert!(plan.response_headers.contains(&"x-extra".to_string()) && plan.response_headers.contains(&"content-type".to_string()));
        // 策略之外：其他路径、方法、管理接口
        for (m, path) in
            [("GET", "/api/v1/chat/completions"), ("POST", "/api/v1/keys"), ("GET", "/api/v1/models/../keys"), ("CONNECT", "/x")]
        {
            assert_eq!(prepare(&p, &runs, &id, m, path, &[], red.clone()).err().unwrap().code, "FORBIDDEN", "{m} {path}");
        }
        assert_eq!(prepare(&p, &runs, "nope", "GET", "/api/v1/models", &[], red.clone()).err().unwrap().code, "UNKNOWN_RUN");
        // 重定向：同源且在策略之内才跟随
        assert_eq!(redirect_target(&plan, "GET", "/api/v1/chat/completions", "/api/v1/models?key=x").unwrap(), "/api/v1/models");
        assert!(redirect_target(&plan, "GET", "/a", "https://evil.example.net/api/v1/models").is_err());
        assert!(redirect_target(&plan, "GET", "/a", "https://api.example.com:8443/api/v1/models").is_err());
        assert!(redirect_target(&plan, "GET", "/a", "/api/v1/keys").is_err());
        assert!(redirect_target(&plan, "POST", "/a", "/api/v1/models").is_err(), "方法不在策略之内");
    }

    #[test]
    fn alias_origins_hide_the_host() {
        let mut p = payload();
        p.aliases.push(pm_vault::Alias { name: "llm".into(), url: "https://api.example.com/api".into(), note: String::new() });
        // 设了别名的主机不能直接写
        assert_eq!(parse_origin(&p, "https://api.example.com").err().unwrap().code, "ALIAS_ONLY");
        assert_eq!(parse_origin(&p, "alias://llm/x").err().unwrap().code, "BAD_URL");
        assert_eq!(parse_origin(&p, "alias://none").err().unwrap().code, "UNKNOWN_ALIAS");
        let run = open(&p, "alias://llm", 0, 0, &[]).unwrap();
        assert_eq!((run.label.as_str(), run.base_path.as_str()), ("alias://llm", "/api"));
        let runs = Arc::new(Mutex::new(Runs::default()));
        let id = runs.lock().unwrap().insert(run).unwrap();
        let plan = prepare(&p, &runs, &id, "GET", "/v1/models", &[], Arc::new(Redactor::empty())).unwrap();
        assert_eq!(plan.path, "/api/v1/models", "接上别名的基础路径");
        assert!(redirect_target(&plan, "GET", "/api/v1/models", "/other/v1/models").is_err(), "离开别名的基础路径");
    }
}

//! `passmanager run --http <origin> …`：让本机程序（OpenAI 兼容的 SDK、CLI、curl……）在一条命令的时间里调用需要凭据的 HTTPS API。
//!
//! - 每个 origin 在 127.0.0.1 的随机端口上开一个本地中继，路径以一次性令牌开头；令牌不对直接回 403，不发任何请求；
//! - 中继不持有凭据，也不连上游：每个请求经双层加密通道交给服务器，由服务器按凭据的策略检查、加上凭据、请求上游，
//!   把脱敏后的回答流式送回（SSE 事件逐个到达）；
//! - 程序从环境变量拿到地址（`--env-url NAME=/路径` → `http://127.0.0.1:<端口>/<令牌>/路径`）和一个没有用的占位密钥
//!   （`--env-key NAME`：只为让程序发出认证头；服务器会丢掉它）；
//! - 本机程序断开时，下一个心跳（最多 10 秒）就关闭到服务器的连接，服务器随之取消上游请求；
//! - 命令结束后运行编号作废，端口随进程关闭。令牌从不打印。

use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pm_proto::{GitHead, RelayRunView, Request};

use crate::git_proxy::{ChunkedReader, ChunkedWriter, read_head};

/// 本机程序发来、不转发的请求头：认证（服务器按策略加上真实凭据）、逐跳头。
const DROP_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
    "cookie",
    "host",
    "connection",
    "keep-alive",
    "content-length",
    "transfer-encoding",
    "expect",
    "te",
    "upgrade",
];

/// 不能用作 `--env-url` / `--env-key` 的变量名：会改变命令本身怎样运行。
const RESERVED_ENV: &[&str] = &["PATH", "HOME", "SHELL", "SSH_AUTH_SOCK", "IFS", "ENV", "BASH_ENV"];

/// `run --http` 的选项。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Opts {
    pub origins: Vec<String>,
    pub env_url: Vec<String>,
    pub env_key: Vec<String>,
    pub max_requests: u64,
    pub max_bytes: u64,
    pub require: Vec<String>,
}

/// 环境变量名：字母、数字、下划线，不以数字开头，不是保留的名字，也不以 LD_ / DYLD_ / GIT_ 开头。
pub fn valid_env_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && !b[0].is_ascii_digit()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && !RESERVED_ENV.contains(&n)
        && !["LD_", "DYLD_", "GIT_"].iter().any(|p| n.starts_with(p))
}

/// 规范化 origin：`https://主机[:端口]`（去掉末尾的 `/`，主机转小写）或 `alias://名称`。服务器会再检查一次。
pub fn normalize_origin(o: &str) -> Result<String, String> {
    let o = o.trim().trim_end_matches('/');
    let bad = || format!("--http 写成 https://<主机>[:<端口>] 或 alias://<名称>，不带路径：{o}");
    if let Some(name) = o.strip_prefix("alias://") {
        if name.is_empty() || name.contains(['/', '?', '#', '@', '\\']) {
            return Err(bad());
        }
        return Ok(format!("alias://{name}"));
    }
    let rest = o.get(..8).filter(|p| p.eq_ignore_ascii_case("https://")).map(|_| &o[8..]).ok_or_else(bad)?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', '\\']) || rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad());
    }
    Ok(format!("https://{}", rest.to_ascii_lowercase()))
}

/// 拆开 `--env-url NAME=[origin|]路径`：返回（变量名，origin 的序号，路径）。只有一个 origin 时可以省略它。
pub fn parse_env_url(s: &str, origins: &[String]) -> Result<(String, usize, String), String> {
    let (name, value) = s.split_once('=').ok_or_else(|| format!("--env-url 写成 NAME=/路径：{s}"))?;
    if !valid_env_name(name) {
        return Err(format!("变量名不可用：{name}"));
    }
    let (idx, path) = match value.split_once('|') {
        Some((o, p)) => {
            let o = normalize_origin(o)?;
            let i = origins.iter().position(|x| *x == o).ok_or_else(|| format!("{name} 用到的 {o} 不在 --http 里"))?;
            (i, p)
        }
        None if origins.len() == 1 => (0, value),
        None => return Err(format!("有多个 --http 时写成 {name}=<origin>|<路径>")),
    };
    if !(path.is_empty() || path.starts_with('/')) || path.chars().any(|c| c.is_whitespace() || c.is_control() || c == '#') {
        return Err(format!("{name} 的路径要以 / 开头：{path}"));
    }
    Ok((name.to_string(), idx, path.trim_end_matches('/').to_string()))
}

/// 检查全部选项，返回规范化后的 origin。
pub fn check(o: &Opts) -> Result<Vec<String>, String> {
    if o.origins.is_empty() {
        if !o.env_url.is_empty() || !o.env_key.is_empty() || o.max_requests > 0 || o.max_bytes > 0 || !o.require.is_empty() {
            return Err("--env-url、--env-key、--max-requests、--max-bytes、--require 要和 --http 一起用".into());
        }
        return Ok(vec![]);
    }
    let mut origins = Vec::new();
    for x in &o.origins {
        let n = normalize_origin(x)?;
        if origins.contains(&n) {
            return Err(format!("--http {n} 写了两次"));
        }
        origins.push(n);
    }
    let mut names: Vec<String> = Vec::new();
    for u in &o.env_url {
        names.push(parse_env_url(u, &origins)?.0);
    }
    for k in &o.env_key {
        if !valid_env_name(k) {
            return Err(format!("变量名不可用：{k}"));
        }
        names.push(k.clone());
    }
    if let Some(d) = names.iter().enumerate().find(|(i, n)| names[..*i].contains(n)).map(|(_, n)| n) {
        return Err(format!("变量 {d} 写了两次"));
    }
    if o.env_url.is_empty() {
        return Err("用 --env-url NAME=/路径 告诉程序中继的地址".into());
    }
    Ok(origins)
}

/// 请求路径去掉一次性令牌：`/<令牌>`、`/<令牌>/…` 或 `/<令牌>?…`（常数时间比较）。返回 origin 之后的路径（总以 `/` 开头）。
pub fn strip_token(target: &str, token: &str) -> Option<String> {
    let rest = target.strip_prefix('/')?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    if !pm_crypto::ct_eq(&rest.as_bytes()[..end], token.as_bytes()) {
        return None;
    }
    let after = &rest[end..];
    Some(if after.starts_with('/') { after.to_string() } else { format!("/{after}") })
}

/// 服务器的错误码对应的 HTTP 状态。
pub fn status_for(code: &str) -> u16 {
    match code {
        "FORBIDDEN" | "NO_RELAY_POLICY" | "NO_CREDENTIAL" | "ALIAS_ONLY" | "OP_NOT_ALLOWED" | "USE_HTTPS" | "UNKNOWN_ALIAS" => 403,
        "RATE_LIMIT" => 429,
        "TOO_LARGE" => 413,
        "BAD_REQUEST" | "BAD_URL" => 400,
        "UNKNOWN_RUN" => 410,
        _ => 502,
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// 中继自己的错误回答：JSON（OpenAI 兼容的 SDK 能读出 message）。
fn reply_error(s: &mut TcpStream, status: u16, code: &str, msg: &str) {
    let body = serde_json::json!({"error": {"message": format!("PassManager: {msg}"), "type": "passmanager", "code": code}}).to_string();
    let _ = write!(
        s,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        reason(status),
        body.len()
    );
}

/// 交给命令的环境变量（名称，值）。
pub type EnvVars = Vec<(String, String)>;

/// 一个打开的中继（给 `run` 用：结束时关闭运行编号）。
pub struct Opened {
    pub run: String,
}

/// 交给命令的环境变量：`--env-url` 指向对应 origin 的中继（端口、令牌、路径），`--env-key` 是一个没有用的占位值。
pub fn child_env(o: &Opts, origins: &[String], relays: &[(u16, String)], dummy: &str) -> Result<EnvVars, String> {
    let mut env = Vec::new();
    for u in &o.env_url {
        let (name, i, path) = parse_env_url(u, origins)?;
        let (port, token) = &relays[i];
        env.push((name, format!("http://127.0.0.1:{port}/{token}{path}")));
    }
    for k in &o.env_key {
        env.push((k.clone(), dummy.to_string()));
    }
    Ok(env)
}

/// 打开全部中继，返回（交给命令的环境变量，打开的中继）。
pub fn start(o: &Opts) -> Result<(EnvVars, Vec<Opened>), String> {
    let origins = check(o)?;
    let mut relays = Vec::new();
    let mut opened: Vec<Opened> = Vec::new();
    for origin in &origins {
        let mut c = match crate::remote::connect_if_configured() {
            Some(Ok(c)) => c,
            Some(Err(e)) => return Err(format!("{}: {}", e.code, e.message)),
            None => return Err("没有远程配置：先运行 passmanager enroll '<注册码>'".into()),
        };
        let req =
            Request::RelayOpen { origin: origin.clone(), max_requests: o.max_requests, max_bytes: o.max_bytes, require: o.require.clone() };
        let v: RelayRunView = match c.call_as(&req) {
            Ok(v) => v,
            Err(e) => {
                close(&opened);
                return Err(format!("{origin}：{}: {}", e.code, e.message));
            }
        };
        // 一次性令牌与随机端口：只在这条命令运行期间有效
        let token = crate::git_proxy::new_token()?;
        let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("无法打开本机中继：{e}"))?;
        let port = l.local_addr().map_err(|e| e.to_string())?.port();
        relays.push((port, token.clone()));
        let (run, label) = (v.run.clone(), v.origin.clone());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { continue };
                let (token, run, label) = (token.clone(), run.clone(), label.clone());
                std::thread::spawn(move || serve_conn(s, &token, &run, &label, &crate::remote::connect_if_configured));
            }
        });
        opened.push(Opened { run: v.run });
    }
    // 占位密钥：不是秘密，离开这次运行就没有意义（服务器会丢掉它）
    let dummy = format!("pm-relay-{}", crate::git_proxy::new_token()?);
    let env = child_env(o, &origins, &relays, &dummy)?;
    Ok((env, opened))
}

/// 路径的最后一段（日志只记这个）。
pub fn last_segment(path: &str) -> String {
    let p = path.split('?').next().unwrap_or_default().trim_end_matches('/');
    let seg = p.rsplit('/').next().unwrap_or_default();
    if seg.is_empty() { "/".into() } else { seg.chars().take(64).collect() }
}

/// 命令结束：作废全部运行编号（失败也不影响退出码；服务器会在闲置 12 小时后自动作废）。
pub fn close(opened: &[Opened]) {
    for o in opened {
        if let Some(Ok(mut c)) = crate::remote::connect_if_configured() {
            let _ = c.call(&Request::RelayClose { run: o.run.clone() });
        }
    }
}

/// 处理本机程序的一个连接（每个连接一个请求）。
pub fn serve_conn(
    mut s: TcpStream,
    token: &str,
    run: &str,
    label: &str,
    connect: &dyn Fn() -> Option<Result<pm_proto::Client, pm_proto::ApiError>>,
) {
    if !s.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
        return;
    }
    let _ = s.set_read_timeout(Some(Duration::from_secs(120)));
    let Ok(rd) = s.try_clone() else { return };
    let mut r = BufReader::new(rd);
    let head = match read_head(&mut r) {
        Ok(h) => h,
        Err(e) => return reply_error(&mut s, 400, "BAD_REQUEST", &e),
    };
    // 令牌不对：403，不发任何请求
    let Some(path) = strip_token(&head.target, token) else {
        return reply_error(&mut s, 403, "FORBIDDEN", "forbidden");
    };
    let header = |k: &str| head.headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str());
    if header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        let _ = s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    let mut body: Box<dyn Read> = if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        Box::new(ChunkedReader::new(r))
    } else {
        let n: u64 = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        Box::new(r.take(n))
    };
    let headers: Vec<(String, String)> =
        head.headers.iter().filter(|(k, _)| !DROP_HEADERS.contains(&k.to_ascii_lowercase().as_str())).cloned().collect();
    let mut client = match connect() {
        Some(Ok(c)) => c,
        Some(Err(e)) => return reply_error(&mut s, 502, &e.code, &e.message),
        None => return reply_error(&mut s, 502, "NOT_ENROLLED", "no remote configuration (run passmanager enroll first)"),
    };
    // 本机程序断开（读到 EOF）就记下来：收到下一个心跳或数据帧时放弃这个请求。
    let gone = Arc::new(AtomicBool::new(false));
    if let Ok(w) = s.try_clone() {
        let g = gone.clone();
        std::thread::spawn(move || {
            let _ = w.set_read_timeout(None);
            let mut b = [0u8; 1];
            // peek 不取走数据；返回 0 表示对方关闭了连接
            if matches!(w.peek(&mut b), Ok(0) | Err(_)) {
                g.store(true, Ordering::SeqCst);
            }
        });
    }
    let req = Request::Relay { run: run.to_string(), method: head.method.clone(), path: path.clone(), headers };
    let (Ok(mut out_head), Ok(out_body)) = (s.try_clone(), s.try_clone()) else { return };
    let mut started = false;
    let mut on_head = |h: &GitHead| -> std::io::Result<()> {
        started = true;
        write!(out_head, "HTTP/1.1 {} {}\r\n", h.status, reason(h.status))?;
        for (k, v) in &h.headers {
            write!(out_head, "{k}: {v}\r\n")?;
        }
        out_head.write_all(b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")?;
        out_head.flush()
    };
    let mut w = ChunkedWriter(out_body);
    let g = gone.clone();
    let result = client.relay(&req, &mut body, &mut on_head, &mut w, &move || g.load(Ordering::SeqCst));
    let last = last_segment(&path);
    match result {
        Ok(()) => {
            let _ = s.write_all(b"0\r\n\r\n");
        }
        Err(e) if !started => {
            eprintln!("[PassManager run] {label} {} {last}: {}", head.method, e.code);
            reply_error(&mut s, status_for(&e.code), &e.code, &e.message);
        }
        // 回答已经开始：只能中断连接（本机程序会看到不完整的回答）
        Err(e) => eprintln!("[PassManager run] {label} {} {last}: stream aborted ({})", head.method, e.code),
    }
    let _ = s.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(origins: &[&str], urls: &[&str], keys: &[&str]) -> Opts {
        Opts {
            origins: origins.iter().map(|s| s.to_string()).collect(),
            env_url: urls.iter().map(|s| s.to_string()).collect(),
            env_key: keys.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn origins_and_env_names() {
        assert_eq!(normalize_origin("https://OpenRouter.ai/").unwrap(), "https://openrouter.ai");
        assert_eq!(normalize_origin("https://api.example.com:8443").unwrap(), "https://api.example.com:8443");
        assert_eq!(normalize_origin("alias://llm").unwrap(), "alias://llm");
        for bad in
            ["http://a.example.com", "https://a.example.com/v1", "https://u@a.example.com", "alias://", "alias://a/b", "openrouter.ai"]
        {
            assert!(normalize_origin(bad).is_err(), "{bad}");
        }
        assert!(valid_env_name("OPENAI_BASE_URL") && valid_env_name("_x1"));
        for bad in ["", "1A", "A-B", "PATH", "LD_PRELOAD", "DYLD_X", "GIT_DIR", "SSH_AUTH_SOCK"] {
            assert!(!valid_env_name(bad), "{bad}");
        }
    }

    #[test]
    fn env_url_forms() {
        let one = vec!["https://openrouter.ai".to_string()];
        assert_eq!(parse_env_url("JW_URL=/api/v1/", &one).unwrap(), ("JW_URL".into(), 0, "/api/v1".into()));
        assert_eq!(parse_env_url("BASE=", &one).unwrap().2, "");
        let two = vec!["https://openrouter.ai".to_string(), "alias://llm".to_string()];
        assert_eq!(parse_env_url("B=alias://llm|/v1", &two).unwrap(), ("B".into(), 1, "/v1".into()));
        assert_eq!(parse_env_url("A=https://OPENROUTER.ai/|/api", &two).unwrap().1, 0);
        assert!(parse_env_url("A=/v1", &two).is_err(), "多个 origin 时要写 origin|");
        assert!(parse_env_url("A=https://other.example.com|/v1", &two).is_err());
        assert!(
            parse_env_url("A=v1", &one).is_err() && parse_env_url("noequals", &one).is_err() && parse_env_url("PATH=/x", &one).is_err()
        );
    }

    #[test]
    fn options_are_checked_together() {
        assert_eq!(check(&Opts::default()).unwrap(), Vec::<String>::new());
        assert!(check(&opts(&[], &["A=/x"], &[])).is_err(), "--env-url 要和 --http 一起用");
        assert!(check(&Opts { max_requests: 1, ..Default::default() }).is_err());
        assert!(check(&opts(&["https://a.example.com"], &[], &["K"])).is_err(), "没有 --env-url");
        assert!(
            check(&opts(&["https://a.example.com", "https://A.example.com/"], &["A=https://a.example.com|/"], &[])).is_err(),
            "重复的 origin"
        );
        assert!(check(&opts(&["https://a.example.com"], &["A=/x"], &["A"])).is_err(), "重复的变量");
        let o = opts(&["https://a.example.com", "alias://b"], &["U1=https://a.example.com|/v1", "U2=alias://b|"], &["K1", "K2"]);
        let origins = check(&o).unwrap();
        let env = child_env(&o, &origins, &[(1111, "t1".into()), (2222, "t2".into())], "pm-relay-x").unwrap();
        assert_eq!(
            env,
            vec![
                ("U1".to_string(), "http://127.0.0.1:1111/t1/v1".to_string()),
                ("U2".into(), "http://127.0.0.1:2222/t2".into()),
                ("K1".into(), "pm-relay-x".into()),
                ("K2".into(), "pm-relay-x".into()),
            ]
        );
    }

    #[test]
    fn token_prefix_and_statuses() {
        assert_eq!(strip_token("/tok/api/v1/models?x=1", "tok").as_deref(), Some("/api/v1/models?x=1"));
        assert_eq!(strip_token("/tok", "tok").as_deref(), Some("/"));
        assert_eq!(strip_token("/tok?x=1", "tok").as_deref(), Some("/?x=1"));
        assert_eq!(strip_token("/tokX/api", "tok"), None);
        assert_eq!(strip_token("/api/tok", "tok"), None);
        assert_eq!(strip_token("tok/api", "tok"), None);
        assert_eq!(
            (status_for("RATE_LIMIT"), status_for("FORBIDDEN"), status_for("NO_RELAY_POLICY"), status_for("TOO_LARGE")),
            (429, 403, 403, 413)
        );
        assert_eq!((status_for("UPSTREAM_ERROR"), status_for("BAD_REQUEST"), status_for("UNKNOWN_RUN")), (502, 400, 410));
        assert_eq!((last_segment("/api/v1/models?x"), last_segment("/")), ("models".to_string(), "/".to_string()));
    }
}

//! git 凭据注入代理的服务端：Agent 机器上的 `passmanager git-proxy` 把 git 的 smart-HTTP 请求经双层加密通道
//! 转到这里，由服务器带上条目里的访问令牌（PAT）向上游发起 HTTPS 请求，请求体与响应体都是流式的（大包不受帧大小限制）。
//!
//! 规则：只允许 HTTPS；只允许 smart-HTTP 的三类请求（`info/refs?service=…`、`git-upload-pack`、`git-receive-pack`）；
//! 目标主机必须属于条目绑定的域名；不跟随任何重定向；丢弃客户端发来的 Authorization / Cookie；
//! 令牌（`Authorization: Basic base64(用户名:PAT)`，用户名默认 `x-access-token`，可用多字段条目的 `username` 字段指定）
//! 绝不出现在响应与错误里：小的文本响应按全部编码脱敏，流式响应里一旦出现令牌原文就中止连接。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use pm_proto::{GitHead, Response};
use pm_vault::{Entry, PinKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;
use zeroize::Zeroizing;

use crate::redact::Redactor;
use crate::{ApiErr, err, http, log};

/// 每帧最大字节数（与内层通道的帧一致）。
pub const CHUNK: usize = 64 * 1024;
/// 单次请求体 / 响应体的上限。
pub const MAX_BODY: u64 = 4 * 1024 * 1024 * 1024;
/// 非 2xx 或文本类响应：整体缓冲后脱敏的上限。
const MAX_TEXT: usize = 1024 * 1024;

/// git smart-HTTP 的请求类型。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Service {
    InfoRefs,
    UploadPack,
    ReceivePack,
}

/// 校验 URL 与方法：只允许 smart-HTTP 的三类请求。返回（服务类型，主机，端口）。
pub fn check_url(method: &str, url: &str) -> Result<(Service, Url, String, u16), ApiErr> {
    let u = Url::parse(url).map_err(|_| err("BAD_REQUEST", "invalid URL"))?;
    if u.scheme() != "https" {
        return Err(err("USE_HTTPS", "only https:// git remotes are supported"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(err("BAD_REQUEST", "credentials in the URL are not allowed"));
    }
    let host = http::host_string(&u).ok_or_else(|| err("BAD_REQUEST", "URL has no host"))?;
    let port = u.port_or_known_default().unwrap_or(443);
    let path = u.path();
    let svc = if path.ends_with("/info/refs") {
        let q = u.query().unwrap_or("");
        if method != "GET" || !(q == "service=git-upload-pack" || q == "service=git-receive-pack") {
            return Err(err("FORBIDDEN", "only smart-HTTP info/refs requests are allowed"));
        }
        Service::InfoRefs
    } else if path.ends_with("/git-upload-pack") && method == "POST" && u.query().is_none() {
        Service::UploadPack
    } else if path.ends_with("/git-receive-pack") && method == "POST" && u.query().is_none() {
        Service::ReceivePack
    } else {
        return Err(err("FORBIDDEN", "only git smart-HTTP requests (info/refs, git-upload-pack, git-receive-pack) are allowed"));
    };
    if path.contains("/../") || path.contains("/./") {
        return Err(err("BAD_REQUEST", "invalid path"));
    }
    Ok((svc, u, host, port))
}

/// 条目里的用户名与令牌。
pub fn credentials(e: &Entry) -> Result<(String, Zeroizing<String>), ApiErr> {
    if e.is_private_key() {
        return Err(err("BAD_REQUEST", format!("\"{}\" is an SSH key, not an HTTPS token", e.name)));
    }
    if e.fields.is_empty() {
        return Ok(("x-access-token".into(), e.secret.clone()));
    }
    let user = e.field("username").map(|f| f.value.to_string()).unwrap_or_else(|| "x-access-token".into());
    let tok = e
        .field("token")
        .or_else(|| e.field("password"))
        .map(|f| f.value.clone())
        .ok_or_else(|| err("BAD_REQUEST", format!("\"{}\" has no token or password field", e.name)))?;
    Ok((user, tok))
}

/// 转发给上游的请求头（白名单）。
fn allowed_request_header(k: &str) -> bool {
    matches!(
        k.to_ascii_lowercase().as_str(),
        "accept" | "accept-encoding" | "content-type" | "content-encoding" | "git-protocol" | "user-agent" | "accept-language"
    )
}

/// 回给 git 的响应头（白名单）。
pub fn allowed_response_header(k: &str) -> bool {
    matches!(k.to_ascii_lowercase().as_str(), "content-type" | "content-encoding" | "cache-control" | "expires" | "pragma")
}

/// 在流式数据中检测令牌原文（跨块边界：保留上一块末尾 len-1 字节）。
pub struct LeakScan {
    needle: Zeroizing<Vec<u8>>,
    tail: Vec<u8>,
}

impl LeakScan {
    pub fn new(secret: &str) -> Self {
        Self { needle: Zeroizing::new(secret.as_bytes().to_vec()), tail: Vec::new() }
    }

    /// 返回 true 表示发现了令牌。
    pub fn feed(&mut self, chunk: &[u8]) -> bool {
        let n = self.needle.len();
        if n == 0 {
            return false;
        }
        let mut buf = std::mem::take(&mut self.tail);
        buf.extend_from_slice(chunk);
        let found = buf.windows(n).any(|w| w == self.needle.as_slice());
        let keep = n.saturating_sub(1).min(buf.len());
        self.tail = buf[buf.len() - keep..].to_vec();
        found
    }
}

/// 通道请求体：从客户端帧读出的数据块。
struct ChanBody(tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>);

impl http_body::Body for ChanBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
        self.0.poll_recv(cx).map(|o| o.map(|r| r.map(http_body::Frame::data)))
    }
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> std::io::Result<Vec<u8>> {
    let len = s.read_u32().await? as usize;
    if len > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> std::io::Result<()> {
    s.write_u32(data.len() as u32).await?;
    s.write_all(data).await?;
    s.flush().await
}

/// 选好的条目与连接参数（在库锁之内取出，之后不再持有锁）。
pub struct Plan {
    pub entry_name: String,
    pub user: String,
    pub token: Zeroizing<String>,
    pub self_signed: bool,
    pub expected_pin: Option<String>,
    pub redactor: Arc<Redactor>,
}

/// 在库中选择条目（按主机与端口）。
pub fn plan(payload: &pm_vault::Payload, host: &str, port: u16, redactor: Arc<Redactor>) -> Result<Plan, ApiErr> {
    let e = http::select_by_host(payload, host, port, pm_vault::OP_GIT)?;
    let (user, token) = credentials(e)?;
    let expected_pin =
        if e.self_signed { payload.pin(PinKind::Https, &format!("{host}:{port}")).map(|p| p.fingerprint.clone()) } else { None };
    Ok(Plan { entry_name: e.name.clone(), user, token, self_signed: e.self_signed, expected_pin, redactor })
}

fn tls_config(p: &Plan, observed: Arc<Mutex<Option<String>>>) -> Result<rustls::ClientConfig, ApiErr> {
    let mut cfg = if p.self_signed {
        http::pin_tls_config(p.expected_pin.clone(), observed)?
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| err("INTERNAL", e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// 发送错误回复（第一帧）并结束。
async fn send_err<W: AsyncWrite + Unpin>(w: &mut W, e: &ApiErr, red: Option<&Redactor>) {
    let msg = red.map(|r| r.redact_str(&e.message)).unwrap_or_else(|| e.message.clone());
    let resp = Response::err(&e.code, msg);
    let _ = write_frame(w, &serde_json::to_vec(&resp).unwrap_or_default()).await;
}

/// 结果：审计记录，以及首次看到的自签证书指纹（调用方记录到指纹库）。
pub struct Outcome {
    pub audit: Option<String>,
    pub observed_pin: Option<String>,
}

/// 执行一次代理请求。调用方已回复"可以继续"；`s` 是该连接剩余的流：之后依次是请求体帧（空帧结束），
/// 回复是一帧 JSON（GitHead 或错误），随后是响应体帧（空帧结束）。
pub async fn proxy<S: AsyncRead + AsyncWrite + Send + 'static>(
    s: S,
    method: String,
    url: Url,
    headers: Vec<(String, String)>,
    svc: Service,
    p: Plan,
) -> Outcome {
    let observed = Arc::new(Mutex::new(None));
    let audit = proxy_inner(s, method, url, headers, svc, &p, observed.clone()).await;
    let observed_pin = if p.self_signed && p.expected_pin.is_none() { observed.lock().unwrap().clone() } else { None };
    Outcome { audit, observed_pin }
}

async fn proxy_inner<S: AsyncRead + AsyncWrite + Send + 'static>(
    s: S,
    method: String,
    url: Url,
    headers: Vec<(String, String)>,
    svc: Service,
    p: &Plan,
    observed: Arc<Mutex<Option<String>>>,
) -> Option<String> {
    let (mut rd, mut wr) = tokio::io::split(s);
    let host = http::host_string(&url).unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(443);
    // 请求体：后台任务把客户端帧转进通道。
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    let reader = tokio::spawn(async move {
        let mut total: u64 = 0;
        loop {
            match read_frame(&mut rd, CHUNK).await {
                Ok(f) if f.is_empty() => break,
                Ok(f) => {
                    total += f.len() as u64;
                    if total > MAX_BODY {
                        let _ = tx.send(Err(std::io::Error::other("request body too large"))).await;
                        break;
                    }
                    if tx.send(Ok(Bytes::from(f))).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
        total
    });
    let result = upstream(&method, &url, &headers, p, rx, observed).await;
    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            reader.abort();
            if e.message.contains(http::PIN_MISMATCH_MARKER) {
                send_err(&mut wr, &err("HOST_KEY_CHANGED", format!("TLS certificate of {host}:{port} changed; nothing was sent. Ask the user to trust the new certificate in PassManager.")), None).await;
            } else {
                send_err(&mut wr, &e, Some(&p.redactor)).await;
            }
            return None;
        }
    };
    let status = resp.status().as_u16();
    if (300..400).contains(&status) {
        send_err(
            &mut wr,
            &err("UPSTREAM_ERROR", format!("upstream answered with a redirect ({status}); redirects are not followed")),
            None,
        )
        .await;
        return None;
    }
    let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let mut head_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| allowed_response_header(k.as_str()))
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect();
    let streaming = (200..300).contains(&status) && ctype.starts_with("application/x-git-");
    let mut body = resp.into_body();
    use http_body_util::BodyExt as _;
    if !streaming {
        // 文本或错误响应：缓冲后按全部编码脱敏。
        let mut buf = Vec::new();
        while let Some(f) = body.frame().await {
            let Ok(f) = f else { break };
            if let Ok(d) = f.into_data() {
                buf.extend_from_slice(&d);
                if buf.len() > MAX_TEXT {
                    break;
                }
            }
        }
        let (red, _) = p.redactor.redact(&buf);
        head_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
        let head = GitHead { status, headers: head_headers };
        if write_frame(&mut wr, &serde_json::to_vec(&Response::ok(head)).unwrap_or_default()).await.is_err() {
            return None;
        }
        for c in red.chunks(CHUNK) {
            if write_frame(&mut wr, c).await.is_err() {
                return None;
            }
        }
        let _ = write_frame(&mut wr, &[]).await;
        let sent = reader.await.unwrap_or(0);
        return Some(format!(
            "git-proxy: entry={} host={host}:{port} service={svc:?} status={status} in={sent} out={}",
            p.entry_name,
            red.len()
        ));
    }
    let head = GitHead { status, headers: head_headers };
    if write_frame(&mut wr, &serde_json::to_vec(&Response::ok(head)).unwrap_or_default()).await.is_err() {
        return None;
    }
    let mut scan = LeakScan::new(&p.token);
    let mut out: u64 = 0;
    while let Some(f) = body.frame().await {
        let Ok(f) = f else { return None };
        let Ok(d) = f.into_data() else { continue };
        if scan.feed(&d) {
            log("git-proxy: upstream response contained the token; connection aborted");
            return None;
        }
        out += d.len() as u64;
        if out > MAX_BODY {
            return None;
        }
        for c in d.chunks(CHUNK) {
            if write_frame(&mut wr, c).await.is_err() {
                return None;
            }
        }
    }
    let _ = write_frame(&mut wr, &[]).await;
    let sent = reader.await.unwrap_or(0);
    Some(format!("git-proxy: entry={} host={host}:{port} service={svc:?} status={status} in={sent} out={out}", p.entry_name))
}

async fn upstream(
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    p: &Plan,
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
    observed: Arc<Mutex<Option<String>>>,
) -> Result<hyper::Response<hyper::body::Incoming>, ApiErr> {
    let host = http::host_string(url).ok_or_else(|| err("BAD_REQUEST", "URL has no host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let tcp = tokio::time::timeout(Duration::from_secs(20), tokio::net::TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| err("UPSTREAM_ERROR", format!("connection to {host}:{port} timed out")))?
        .map_err(|e| err("UPSTREAM_ERROR", format!("connection to {host}:{port} failed: {e}")))?;
    let cfg = tls_config(p, observed)?;
    let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| err("BAD_REQUEST", "invalid host name"))?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .map_err(|e| err("UPSTREAM_ERROR", format!("TLS handshake with {host}:{port} failed: {e}")))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
        .await
        .map_err(|e| err("UPSTREAM_ERROR", format!("HTTP handshake failed: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let path_q = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let host_hdr = if port == 443 { host.clone() } else { format!("{host}:{port}") };
    let mut rb = hyper::Request::builder().method(method).uri(path_q).header("host", host_hdr);
    for (k, v) in headers.iter().filter(|(k, _)| allowed_request_header(k)) {
        rb = rb.header(k.as_str(), v.as_str());
    }
    let auth = Zeroizing::new(format!("Basic {}", STANDARD.encode(format!("{}:{}", p.user, p.token.as_str()))));
    rb = rb.header("authorization", auth.as_str());
    let body = ChanBody(rx);
    let req = rb.body(body).map_err(|e| err("BAD_REQUEST", e.to_string()))?;
    let resp = tokio::time::timeout(Duration::from_secs(600), sender.send_request(req))
        .await
        .map_err(|_| err("UPSTREAM_ERROR", "upstream timed out"))?
        .map_err(|e| err("UPSTREAM_ERROR", format!("upstream request failed: {e}")))?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_smart_http_requests() {
        let ok = |m: &str, u: &str| check_url(m, u).map(|(s, ..)| s);
        assert_eq!(ok("GET", "https://git.example.com/a/b.git/info/refs?service=git-upload-pack").unwrap(), Service::InfoRefs);
        assert_eq!(ok("GET", "https://git.example.com:8121/r/x/info/refs?service=git-receive-pack").unwrap(), Service::InfoRefs);
        assert_eq!(ok("POST", "https://git.example.com/a/b.git/git-upload-pack").unwrap(), Service::UploadPack);
        assert_eq!(ok("POST", "https://git.example.com/a/b.git/git-receive-pack").unwrap(), Service::ReceivePack);
        for (m, u, code) in [
            ("GET", "http://git.example.com/a/info/refs?service=git-upload-pack", "USE_HTTPS"),
            ("GET", "https://git.example.com/a/info/refs", "FORBIDDEN"),
            ("GET", "https://git.example.com/a/info/refs?service=other", "FORBIDDEN"),
            ("POST", "https://git.example.com/a/info/refs?service=git-upload-pack", "FORBIDDEN"),
            ("GET", "https://git.example.com/a/git-upload-pack", "FORBIDDEN"),
            ("POST", "https://git.example.com/api/v3/user", "FORBIDDEN"),
            ("GET", "https://git.example.com/", "FORBIDDEN"),
            ("POST", "https://u:p@git.example.com/a/git-upload-pack", "BAD_REQUEST"),
            ("POST", "https://git.example.com/a/git-upload-pack?x=1", "FORBIDDEN"),
        ] {
            assert_eq!(check_url(m, u).err().unwrap().code, code, "{m} {u}");
        }
    }

    #[test]
    fn leak_scan_across_chunk_boundaries() {
        let mut s = LeakScan::new("ghp_SECRET123");
        assert!(!s.feed(b"0000 packdata ghp_SEC"));
        assert!(s.feed(b"RET123 more"), "跨块");
        let mut s = LeakScan::new("ghp_SECRET123");
        for c in b"xxghp_SECRET1".chunks(1) {
            assert!(!s.feed(c));
        }
        assert!(s.feed(b"23"));
        let mut s = LeakScan::new("tok");
        assert!(!s.feed(&vec![0u8; 100_000]));
        assert!(!LeakScan::new("").feed(b"anything"));
    }

    #[test]
    fn credentials_from_entries() {
        let mk = |secret: &str, fields: &[(&str, &str)]| Entry {
            name: "gh".into(),
            secret: Zeroizing::new(secret.into()),
            domains: vec![],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: fields.iter().map(|(n, v)| pm_vault::Field { name: n.to_string(), value: Zeroizing::new(v.to_string()) }).collect(),
            host_keys: vec![],
            ops: vec![],
        };
        let (u, t) = credentials(&mk("ghp_x", &[])).unwrap();
        assert_eq!((u.as_str(), t.as_str()), ("x-access-token", "ghp_x"));
        let (u, t) = credentials(&mk("", &[("username", "bot"), ("token", "glpat-y")])).unwrap();
        assert_eq!((u.as_str(), t.as_str()), ("bot", "glpat-y"));
        let (u, t) = credentials(&mk("", &[("password", "pw")])).unwrap();
        assert_eq!((u.as_str(), t.as_str()), ("x-access-token", "pw"));
        assert!(credentials(&mk("", &[("username", "u")])).is_err());
        assert!(credentials(&mk("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----", &[])).is_err());
        assert!(allowed_request_header("Git-Protocol") && !allowed_request_header("Authorization") && !allowed_request_header("cookie"));
        assert!(
            allowed_response_header("Content-Type")
                && !allowed_response_header("set-cookie")
                && !allowed_response_header("www-authenticate")
        );
    }
}

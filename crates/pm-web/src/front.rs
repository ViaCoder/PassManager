//! 网页端的连接入口（单层 TLS：浏览器默认设置做不了第二层）：
//! - 来源地址不在允许的局域网网段 → 立即关闭（不握手）；
//! - 每个来源与全局的连接数上限；握手超时；
//! - TLS 1.3 + 混合后量子组 + AES-256-GCM（见 `pm_net::tls`），ALPN h2 / http/1.1；
//! - 明文 HTTP 只回一个跳转到 https 的 301。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const HEAD_LIMIT: usize = 8192;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const TLS_HANDSHAKE: u8 = 0x16;

/// 每个请求都能拿到的连接信息（页面上显示本次连接的后量子算法）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnInfo {
    pub peer: SocketAddr,
    pub group: String,
    pub suite: String,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub per_ip: usize,
    pub global: usize,
    pub h2_streams: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self { per_ip: 16, global: 128, h2_streams: 64 }
    }
}

/// 允许连接的来源判断（服务器模式：配置的局域网网段与允许列表）。
pub type Allow = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// 已完成握手的 TLS 连接。
pub type TlsConn = tokio_rustls::server::TlsStream<TcpStream>;

/// 单端口模式：协商出 `pm-inner/1` 的连接交给它（Agent 通道）；其余（h2、http/1.1、没有 ALPN）都是网页。
pub type InnerHandler = Arc<dyn Fn(TlsConn, SocketAddr) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

/// 单端口模式的服务端 ALPN 列表。网页协议在前：同时提供网页协议与 `pm-inner/1` 的客户端得到网页，
/// 只有只请求 `pm-inner/1` 的客户端（PassManager Agent）进入 Agent 通道。
pub const SINGLE_PORT_ALPN: [&[u8]; 3] = [b"h2", b"http/1.1", pm_net::tls::ALPN_INNER];

#[derive(Default)]
struct ConnTracker {
    per_ip: std::sync::Mutex<HashMap<IpAddr, usize>>,
    total: AtomicUsize,
}

struct ConnSlot {
    t: Arc<ConnTracker>,
    ip: IpAddr,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.t.total.fetch_sub(1, Ordering::SeqCst);
        let mut m = self.t.per_ip.lock().unwrap();
        if let Some(n) = m.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

impl ConnTracker {
    fn acquire(self: &Arc<Self>, ip: IpAddr, l: &Limits) -> Option<ConnSlot> {
        let mut m = self.per_ip.lock().unwrap();
        let n = m.entry(ip).or_insert(0);
        if *n >= l.per_ip || self.total.load(Ordering::SeqCst) >= l.global {
            if *n == 0 {
                m.remove(&ip);
            }
            return None;
        }
        *n += 1;
        self.total.fetch_add(1, Ordering::SeqCst);
        Some(ConnSlot { t: self.clone(), ip })
    }
}

#[derive(Clone)]
pub struct Front {
    pub tls: TlsAcceptor,
    /// 对外地址（小写），如 `pm.example.com` 或 `pm.example.com:8443`，用于明文请求的跳转。
    pub authority: String,
    pub limits: Limits,
    pub allow: Allow,
    conns: Arc<ConnTracker>,
    inner: Option<InnerHandler>,
}

impl Front {
    pub fn new(tls: TlsAcceptor, host: &str, port: u16, allow: Allow) -> Self {
        let authority = if port == 443 { host.to_ascii_lowercase() } else { format!("{}:{port}", host.to_ascii_lowercase()) };
        Self { tls, authority, limits: Limits::default(), allow, conns: Arc::default(), inner: None }
    }

    /// 单端口模式：协商出 `pm-inner/1` 的连接交给 `h`（TLS 配置的 ALPN 列表应为 [`SINGLE_PORT_ALPN`]）。
    pub fn with_inner(mut self, h: InnerHandler) -> Self {
        self.inner = Some(h);
        self
    }

    pub fn with_limits(mut self, l: Limits) -> Self {
        self.limits = l;
        self
    }

    pub async fn serve(self, listener: TcpListener, app: Router) {
        loop {
            let Ok((tcp, peer)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            if !(self.allow)(peer.ip()) {
                drop(tcp);
                continue;
            }
            let Some(slot) = self.conns.acquire(peer.ip(), &self.limits) else {
                drop(tcp);
                continue;
            };
            let f = self.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let _ = f.handle(tcp, peer, app).await;
            });
        }
    }

    async fn handle(&self, tcp: TcpStream, peer: SocketAddr, app: Router) -> std::io::Result<()> {
        let _ = tcp.set_nodelay(true);
        let mut first = [0u8; 1];
        let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, tcp.peek(&mut first)).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
        if n == 1 && first[0] != TLS_HANDSHAKE {
            return self.redirect_plain(tcp).await;
        }
        let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.tls.accept(tcp)).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
        // 按协商出的 ALPN 分流：只有 pm-inner/1 进入 Agent 通道，其他一律是网页。
        if tls.get_ref().1.alpn_protocol() == Some(pm_net::tls::ALPN_INNER) {
            if let Some(h) = &self.inner {
                h(tls, peer).await;
            }
            return Ok(());
        }
        let (group, suite) = {
            let c = tls.get_ref().1;
            (
                format!("{:?}", c.negotiated_key_exchange_group().map(|g| g.name())),
                format!("{:?}", c.negotiated_cipher_suite().map(|s| s.suite())),
            )
        };
        let info = ConnInfo { peer, group: pm_net::tls::short_name(group), suite: pm_net::tls::short_name(suite) };
        let svc = hyper_util::service::TowerToHyperService::new(app.layer(axum::Extension(info)));
        let mut b = auto::Builder::new(TokioExecutor::new());
        b.http1().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(30));
        b.http2()
            .timer(hyper_util::rt::TokioTimer::new())
            .max_concurrent_streams(self.limits.h2_streams)
            .keep_alive_interval(Duration::from_secs(60))
            .keep_alive_timeout(Duration::from_secs(20));
        b.serve_connection(TokioIo::new(tls), svc).await.map_err(std::io::Error::other)
    }

    /// 明文 HTTP：只回 301 到同一路径的 https 地址（路径里只允许可见 ASCII，否则跳到首页）。
    async fn redirect_plain(&self, mut tcp: TcpStream) -> std::io::Result<()> {
        let head = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_head(&mut tcp)).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
        let path = parse_request_path(&head)
            .filter(|p| p.starts_with('/') && p.bytes().all(|b| (0x21..0x7f).contains(&b)))
            .unwrap_or_else(|| "/".into());
        let resp = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}{path}\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            self.authority
        );
        tcp.write_all(resp.as_bytes()).await?;
        tcp.shutdown().await
    }
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.push(b[0]);
        if buf.len() > HEAD_LIMIT {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    Ok(buf)
}

fn parse_request_path(head: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(head).ok()?;
    let line = s.split("\r\n").next()?;
    let mut it = line.split(' ');
    let (m, p, v) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || !v.starts_with("HTTP/1.") || m.is_empty() || p.is_empty() {
        return None;
    }
    Some(p.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_path_parsing() {
        assert_eq!(parse_request_path(b"GET /a HTTP/1.1\r\n\r\n").as_deref(), Some("/a"));
        assert!(parse_request_path(b"GET / HTTP/2\r\n\r\n").is_none());
        assert!(parse_request_path(b"GET  / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request_path(b"\xff\r\n\r\n").is_none());
    }

    #[test]
    fn connection_limits() {
        let t = Arc::new(ConnTracker::default());
        let l = Limits { per_ip: 2, global: 3, h2_streams: 10 };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let a = t.acquire(ip("198.51.100.2"), &l).unwrap();
        let _b = t.acquire(ip("198.51.100.2"), &l).unwrap();
        assert!(t.acquire(ip("198.51.100.2"), &l).is_none(), "每个来源的上限");
        let _c = t.acquire(ip("198.51.100.3"), &l).unwrap();
        assert!(t.acquire(ip("198.51.100.4"), &l).is_none(), "全局上限");
        drop(a);
        assert!(t.acquire(ip("198.51.100.4"), &l).is_some(), "释放后可以再连");
    }

    /// 起一个 Front（自签证书 pm.test），网页返回 "WEB"，单端口时 pm-inner/1 的连接写 "INNER"。返回（端口，CA，inner 计数）。
    async fn start(single: bool) -> (u16, String, Arc<AtomicUsize>) {
        let (cert, key) = pm_net::tls::self_signed(&["pm.test"]);
        let certs = pm_net::tls::CertStore::new();
        certs.set_pem(&cert, &key).unwrap();
        let alpn: Vec<&[u8]> = if single { SINGLE_PORT_ALPN.to_vec() } else { vec![b"h2", b"http/1.1"] };
        let cfg = pm_net::tls::server_config(certs, &alpn);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let mut f = Front::new(TlsAcceptor::from(cfg), "pm.test", port, Arc::new(|_| true));
        if single {
            let h = hits.clone();
            f = f.with_inner(Arc::new(move |mut tls, _peer| {
                let h = h.clone();
                Box::pin(async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    let _ = tls.write_all(b"INNER").await;
                    let _ = tls.shutdown().await;
                })
            }));
        }
        let app = Router::new().route("/", axum::routing::get(|| async { "WEB" }));
        tokio::spawn(f.serve(l, app));
        (port, cert, hits)
    }

    /// 以给定的 ALPN 连接：返回（协商出的 ALPN，读到的内容）；握手失败返回 Err。
    async fn connect(port: u16, ca: &str, alpn: &[&[u8]], http_get: bool) -> Result<(Option<Vec<u8>>, String), String> {
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from_pem_slice(ca.as_bytes()).unwrap()).unwrap();
        let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(pm_net::tls::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls =
            tokio_rustls::TlsConnector::from(Arc::new(c)).connect("pm.test".try_into().unwrap(), tcp).await.map_err(|e| e.to_string())?;
        let negotiated = tls.get_ref().1.alpn_protocol().map(|a| a.to_vec());
        if http_get {
            tls.write_all(format!("GET / HTTP/1.1\r\nHost: pm.test:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        }
        let mut out = Vec::new();
        if http_get || negotiated.as_deref() == Some(pm_net::tls::ALPN_INNER) {
            let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut out)).await;
        }
        Ok((negotiated, String::from_utf8_lossy(&out).into_owned()))
    }

    /// 单端口模式按 ALPN 分流：只请求 pm-inner/1 的连接进入 Agent 通道；h2、http/1.1、没有 ALPN、
    /// 以及同时提供网页协议与 pm-inner/1 的（浏览器式）连接都是网页，从不进入 Agent 通道。
    #[tokio::test]
    async fn single_port_alpn_dispatch() {
        let (port, ca, hits) = start(true).await;
        let (alpn, body) = connect(port, &ca, &[pm_net::tls::ALPN_INNER], false).await.unwrap();
        assert_eq!((alpn.as_deref(), body.as_str()), (Some(pm_net::tls::ALPN_INNER), "INNER"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let (alpn, body) = connect(port, &ca, &[b"http/1.1"], true).await.unwrap();
        assert_eq!(alpn.as_deref(), Some(&b"http/1.1"[..]));
        assert!(body.starts_with("HTTP/1.1 200") && body.ends_with("WEB"), "{body}");
        let (_, body) = connect(port, &ca, &[], true).await.unwrap();
        assert!(body.starts_with("HTTP/1.1 200") && body.ends_with("WEB"), "没有 ALPN 时是网页：{body}");
        let (alpn, _) = connect(port, &ca, &[b"h2", b"http/1.1"], false).await.unwrap();
        assert_eq!(alpn.as_deref(), Some(&b"h2"[..]));
        let (alpn, body) = connect(port, &ca, &[b"http/1.1", pm_net::tls::ALPN_INNER], true).await.unwrap();
        assert_eq!(alpn.as_deref(), Some(&b"http/1.1"[..]), "网页协议优先");
        assert!(body.ends_with("WEB"));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "浏览器式的连接从不进入 Agent 通道");
    }

    /// 两端口模式的网页监听：Agent 客户端（只请求 pm-inner/1）握手失败，不会被当作网页或 Agent 处理。
    #[tokio::test]
    async fn web_only_listener_rejects_agent_alpn() {
        let (port, ca, hits) = start(false).await;
        assert!(connect(port, &ca, &[pm_net::tls::ALPN_INNER], false).await.is_err());
        let (_, body) = connect(port, &ca, &[b"http/1.1"], true).await.unwrap();
        assert!(body.ends_with("WEB"));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}

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

/// 允许连接的来源判断（服务器模式：配置的局域网网段）。
pub type Allow = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

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
}

impl Front {
    pub fn new(tls: TlsAcceptor, host: &str, port: u16, allow: Allow) -> Self {
        let authority = if port == 443 { host.to_ascii_lowercase() } else { format!("{}:{port}", host.to_ascii_lowercase()) };
        Self { tls, authority, limits: Limits::default(), allow, conns: Arc::default() }
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
}

//! Agent 端（阻塞式）连接：TCP（只用 IPv4）→ TLS 1.3（混合后量子组 + AES-256-GCM，校验证书）
//! → 内层握手（固定的服务端公钥指纹）。

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

use crate::inner::{self, EXPORTER_LABEL, EXPORTER_LEN, InnerError, InnerStream, ServerPublic};
use crate::tls;

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 单次请求的最长等待（SSH 命令、慢速 HTTPS 目标）。
pub const IO_TIMEOUT: Duration = Duration::from_secs(600);

/// 连接目标。`connect_addr` 用于测试（SNI 仍是 `host`）。
#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub connect_addr: Option<SocketAddr>,
    /// 额外信任的 CA（PEM，测试用）；生产环境只信任公共根证书。
    pub extra_ca_pem: Option<String>,
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// 只解析 IPv4 地址（服务器关闭了 IPv6）。
pub fn resolve_ipv4(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let v: Vec<SocketAddr> = (host, port).to_socket_addrs()?.filter(|a| a.is_ipv4()).collect();
    if v.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{host} 没有 IPv4 地址")));
    }
    Ok(v)
}

/// 建立外层 TLS，并确认协商结果符合策略（混合后量子组 + AES-256-GCM-SHA384 + 内层 ALPN）。
pub fn tls_connect(t: &Target) -> io::Result<TlsStream> {
    let addrs = match t.connect_addr {
        Some(a) => vec![a],
        None => resolve_ipv4(&t.host, t.port)?,
    };
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    let mut tcp = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = e,
        }
    }
    let tcp = tcp.ok_or(last)?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;
    let _ = tcp.set_nodelay(true);
    let cfg = tls::client_config(t.extra_ca_pem.as_deref()).map_err(io_err)?;
    let name = ServerName::try_from(t.host.clone()).map_err(io_err)?;
    let conn = ClientConnection::new(Arc::clone(&cfg), name).map_err(io_err)?;
    let mut s = StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    let group = s.conn.negotiated_key_exchange_group().map(|g| g.name());
    let suite = s.conn.negotiated_cipher_suite().map(|c| c.suite());
    if !tls::negotiated_ok(group, suite) || s.conn.alpn_protocol() != Some(tls::ALPN_INNER) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "TLS negotiation does not meet the post-quantum policy"));
    }
    Ok(s)
}

pub fn exporter(s: &TlsStream) -> io::Result<[u8; EXPORTER_LEN]> {
    s.conn.export_keying_material([0u8; EXPORTER_LEN], EXPORTER_LABEL, None).map_err(io_err)
}

/// 下载服务端公钥包并核对指纹（注册时使用）。
pub fn fetch_server_public(t: &Target, fpr: &[u8; inner::FPR_LEN]) -> Result<ServerPublic, InnerError> {
    let mut s = tls_connect(t)?;
    let bundle = inner::fetch_bundle(&mut s)?;
    ServerPublic::from_bundle(&bundle, fpr)
}

/// 建立双层加密的会话流（`Read + Write`），之后按本地协议收发帧。
pub fn connect(t: &Target, server: &ServerPublic) -> Result<InnerStream<TlsStream>, InnerError> {
    let s = tls_connect(t)?;
    let e = exporter(&s)?;
    InnerStream::connect(s, server, &e)
}

/// 编译期断言：会话流可以当作 `Read + Write + Send` 使用（pm-proto 客户端要求）。
#[allow(dead_code)]
fn assert_send() {
    fn is<T: Read + Write + Send>() {}
    is::<InnerStream<TlsStream>>();
}

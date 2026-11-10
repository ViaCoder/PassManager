//! PassManager 网络层（局域网在线版）：
//! - [`tls`]：外层 TLS 1.3 策略（只允许混合后量子密钥交换 + AES-256-GCM-SHA384）、可热替换的证书；
//! - [`acme`]：Let's Encrypt DNS-01（Cloudflare）签发与续期判断；
//! - [`inner`]：Agent 通道的第二层（ML-KEM-1024 + Classic McEliece 6688128，ChaCha20-Poly1305 帧）；
//! - [`enroll`]：一次性注册码 `pm-enroll://…`。

pub mod acme;
pub mod client;
pub mod enroll;
pub mod inner;
pub mod tls;

use std::time::Duration;

/// TCP keepalive 开始探测前的空闲时间。
pub const KEEPALIVE_TIME: Duration = Duration::from_secs(30);
/// 两次探测之间的间隔（Linux 默认探测 9 次：对端宕机或断网后约 2 分钟内读写报错）。
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// 打开 TCP keepalive：不设整体超时的长请求靠它发现对端机器宕掉或网络断开，而不是永远等下去。
pub fn keepalive<'a, S>(s: &'a S) -> std::io::Result<()>
where
    socket2::SockRef<'a>: From<&'a S>,
{
    // 空闲 30 秒后开始探测，每 10 秒一次
    let ka = socket2::TcpKeepalive::new().with_time(KEEPALIVE_TIME).with_interval(KEEPALIVE_INTERVAL);
    // 设置到这个已连接的 socket 上（不改变它的所有权）
    socket2::SockRef::from(s).set_tcp_keepalive(&ka)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_turns_on_so_keepalive() {
        // 一对本地 TCP 连接
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        // 新连接默认没有 keepalive
        assert!(!socket2::SockRef::from(&c).keepalive().unwrap());
        keepalive(&c).unwrap();
        // 打开后内核报告已开启
        assert!(socket2::SockRef::from(&c).keepalive().unwrap());
    }
}

//! 经客户端网络连接 SSH 主机（服务器连不到、客户端连得到）。
//!
//! 1. 请求处理到一半，服务器在原来的 Agent 连接上发一帧 [`DialAsk`]（主机、端口、一次性票据）。
//! 2. 客户端从自己的网络连上目标，再开一条 Agent 连接，用同一个令牌和这张票据握手（[`pm_proto::Hello::Dial`]）。
//! 3. 服务器把这条连接交给等待中的 SSH 连接：握手、主机密钥核对与认证都在服务器上端到端完成，
//!    客户端只转发 SSH 自己加密的字节，看不到口令、私钥签名或命令输出。
//!
//! 票据：128 位随机数，只能用一次，只认发起请求的那个令牌，最多等 [`WAIT`]。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use pm_proto::DialAsk;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use crate::{ApiErr, err};

/// 等客户端开转发连接的最长时间（客户端连目标最多 15 秒，再加上和服务器握手）。
pub(crate) const WAIT: Duration = Duration::from_secs(25);
/// 客户端带回的失败原因最多保留的字符数。
const MAX_REASON: usize = 200;

/// 转发连接需要的能力（russh 的 `connect_stream` 要求同样的约束）。
pub trait DialIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DialIo for T {}

/// 客户端送来的转发连接。
pub type DialStream = Box<dyn DialIo + Send + Unpin>;

/// 等待方收到的结果：转发连接，或客户端带回的失败原因。
type DialResult = Result<DialStream, String>;

/// 一条声明了 `dial` 的 Agent 连接：它的令牌 id，和把转发要求写回这条连接的通道。
#[derive(Clone)]
pub(crate) struct DialCtx {
    pub token_id: String,
    pub asks: mpsc::UnboundedSender<DialAsk>,
}

tokio::task_local! {
    /// 正在处理的请求来自哪条连接（只在能转发的连接上、SSH 类请求期间设置）。
    pub(crate) static DIALER: DialCtx;
}

/// 等待中的一张票据。
struct Pending {
    token_id: String,
    tx: oneshot::Sender<DialResult>,
}

/// 票据登记表。
#[derive(Default)]
pub(crate) struct Dials {
    map: Mutex<HashMap<String, Pending>>,
}

impl Dials {
    /// 登记一张新票据，返回票据和等待结果的接收端。
    fn open(&self, token_id: &str) -> Result<(String, oneshot::Receiver<DialResult>), ApiErr> {
        // 128 位随机票据，十六进制
        let ticket = hex::encode(pm_crypto::rng::random_array::<16>().map_err(|_| err("INTERNAL", "random"))?);
        let (tx, rx) = oneshot::channel();
        self.map.lock().unwrap().insert(ticket.clone(), Pending { token_id: token_id.to_string(), tx });
        Ok((ticket, rx))
    }

    /// 去掉一张票据（等待结束时，不论结果）。
    fn close(&self, ticket: &str) {
        self.map.lock().unwrap().remove(ticket);
    }

    /// 票据存在并且属于这个令牌（确认握手之前检查，对不上就静默断开）。
    pub(crate) fn has(&self, ticket: &str, token_id: &str) -> bool {
        self.map.lock().unwrap().get(ticket).is_some_and(|p| p.token_id == token_id)
    }

    /// 客户端送来转发连接或失败原因：票据存在且属于同一个令牌时交给等待方并作废票据，返回是否接受。
    pub(crate) fn deliver(&self, ticket: &str, token_id: &str, r: DialResult) -> bool {
        let mut map = self.map.lock().unwrap();
        // 票据不对、或属于别的令牌：不动它（真正的客户端还能用）
        if !map.get(ticket).is_some_and(|p| p.token_id == token_id) {
            return false;
        }
        let Some(p) = map.remove(ticket) else { return false };
        // 等待方已经超时离开时发送失败，同样算作没接受
        p.tx.send(r).is_ok()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

/// 客户端带回的失败原因：去掉控制字符，最多 [`MAX_REASON`] 个字符（它会出现在给 Agent 的错误里）。
pub(crate) fn clean_reason(s: &str) -> String {
    let t: String = s.chars().filter(|c| !c.is_control()).take(MAX_REASON).collect();
    if t.trim().is_empty() { "unknown error".into() } else { t }
}

/// 请发起请求的客户端从它的网络连接 `host:port`，返回客户端送来的转发连接。
/// 只能在声明了 `dial` 的 Agent 连接上处理 SSH 类请求时调用（见 server.rs）；否则返回 RELAY_UNAVAILABLE。
pub(crate) async fn request_stream(dials: &Dials, host: &str, port: u16) -> Result<DialStream, ApiErr> {
    let hp = format!("{host}:{port}");
    // 这条连接不能转发：本机的 Agent、root 命令行，或者旧版本的客户端
    let Ok(ctx) = DIALER.try_with(|d| d.clone()) else {
        return Err(err(
            "RELAY_UNAVAILABLE",
            format!(
                "{hp} is reached through the client's network, but this client cannot relay connections (a PassManager \
                 process older than the server, or not a remote client). Ask the user to restart the agent so that it runs \
                 the current PassManager."
            ),
        ));
    };
    let (ticket, rx) = dials.open(&ctx.token_id)?;
    // 把要求写回原来的连接（server.rs 收到后发出 {"dial": ...} 一帧）
    if ctx.asks.send(DialAsk { ticket: ticket.clone(), host: host.to_string(), port }).is_err() {
        dials.close(&ticket);
        return Err(err("RELAY_UNAVAILABLE", format!("{hp} is reached through the client's network, but the client is gone")));
    }
    let r = tokio::time::timeout(WAIT, rx).await;
    dials.close(&ticket);
    match r {
        Ok(Ok(Ok(stream))) => Ok(stream),
        // 客户端自己没连上目标：和直连失败一样是网络问题
        Ok(Ok(Err(reason))) => Err(err("UPSTREAM_ERROR", format!("the client could not connect to {hp}: {reason}"))),
        _ => Err(err("RELAY_UNAVAILABLE", format!("the client did not open the relay connection to {hp} in time"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn stream() -> (DialStream, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(1024);
        (Box::new(a), b)
    }

    #[tokio::test]
    async fn tickets_are_single_use_and_bound_to_the_token() {
        let d = Dials::default();
        let (t, mut rx) = d.open("tok-a").unwrap();
        // 32 个十六进制字符（128 位）
        assert_eq!(t.len(), 32);
        // 别的令牌、错的票据：不接受，票据仍然有效
        assert!(d.has(&t, "tok-a") && !d.has(&t, "tok-b") && !d.has("0000", "tok-a"));
        assert!(!d.deliver(&t, "tok-b", Err("x".into())));
        assert!(!d.deliver("0000", "tok-a", Err("x".into())));
        assert_eq!(d.len(), 1);
        // 同一个令牌：接受一次，等待方收到连接
        let (s, mut peer) = stream();
        assert!(d.deliver(&t, "tok-a", Ok(s)));
        let mut got = rx.try_recv().unwrap().unwrap();
        got.write_all(b"hi").await.unwrap();
        let mut b = [0u8; 2];
        peer.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hi");
        // 再用一次：票据已经作废
        assert!(!d.deliver(&t, "tok-a", Err("again".into())));
        assert_eq!(d.len(), 0);
        // close 去掉没人用的票据
        let (t2, _rx2) = d.open("tok-a").unwrap();
        assert_ne!(t, t2);
        d.close(&t2);
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn reasons_are_short_and_plain() {
        assert_eq!(clean_reason("connection refused"), "connection refused");
        assert_eq!(clean_reason("a\nb\x1b[31m"), "ab[31m");
        assert_eq!(clean_reason(&"x".repeat(500)).len(), MAX_REASON);
        assert_eq!(clean_reason(" \n"), "unknown error");
    }

    #[tokio::test]
    async fn request_stream_needs_a_relaying_connection() {
        let d = Dials::default();
        // 不在能转发的连接上：RELAY_UNAVAILABLE，不登记票据
        let e = request_stream(&d, "h.example.com", 22).await.err().unwrap();
        assert_eq!(e.code, "RELAY_UNAVAILABLE");
        assert_eq!(d.len(), 0);
    }

    #[tokio::test]
    async fn request_stream_gets_the_clients_connection_or_reason() {
        let d = std::sync::Arc::new(Dials::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let ctx = DialCtx { token_id: "tok".into(), asks: tx };
        // 假客户端：收到要求后先送来一条连接，下一次送来失败原因
        let d2 = d.clone();
        tokio::spawn(async move {
            let mut n = 0;
            while let Some(ask) = rx.recv().await {
                assert_eq!((ask.host.as_str(), ask.port), ("h.example.com", 2222));
                n += 1;
                let r = if n == 1 { Ok(stream().0) } else { Err("connection refused".into()) };
                assert!(d2.deliver(&ask.ticket, "tok", r));
            }
        });
        DIALER
            .scope(ctx, async {
                assert!(request_stream(&d, "h.example.com", 2222).await.is_ok());
                let e = request_stream(&d, "h.example.com", 2222).await.err().unwrap();
                assert_eq!(e.code, "UPSTREAM_ERROR");
                assert!(e.message.contains("could not connect to h.example.com:2222: connection refused"), "{}", e.message);
            })
            .await;
        // 用过的票据都已去掉
        assert_eq!(d.len(), 0);
    }
}

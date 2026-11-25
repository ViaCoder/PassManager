//! 客户端一侧的"经客户端网络连接 SSH 主机"：服务器连不到、这台机器连得到的主机。
//! 只有 Agent 显式要求（MCP 的 `via_client`、CLI 的 `--via-client`，用户明确同意后才用）时服务器才会发来转发要求。
//!
//! 服务器在 SSH 类请求处理到一半时发来一个转发要求（主机、端口、一次性票据）。这里：
//! 1. 只接受这个请求本身的第一跳（跳板，或没有跳板时的目标），别的主机一律拒绝：服务器不能借这台机器去探别处；
//! 2. 从这台机器的网络连上目标；
//! 3. 用同一个令牌和票据另开一条双层加密的连接回服务器（`Hello::Dial`），在两者之间原样转发字节。
//!
//! 转发的是 SSH 自己加密的字节：口令、私钥签名和命令输出都在服务器与目标之间端到端加密，这里看不到。

use std::time::Duration;

use pm_net::client::Target;
use pm_net::inner::ServerPublic;
use pm_proto::{DialAsk, Hello, PROTO_V, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

/// 连目标的最长等待（服务器最多等 25 秒）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 等服务器确认转发连接的最长时间。
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// 请求的第一跳：`跳板>目标` 时是跳板，否则是目标。不是 SSH 类请求或目标写错时为 None。
pub fn first_hop(req: &Request) -> Option<(String, u16)> {
    let t = req.ssh_target()?;
    // 和服务器同一个解析（主机名同样规范化），比较才有意义
    let (jump, dest) = pm_service::ssh::parse_route(t).ok()?;
    let d = jump.unwrap_or(dest);
    Some((d.host, d.port))
}

/// 服务器的要求是否就是这个请求的第一跳。
pub fn allowed(req: &Request, ask: &DialAsk) -> bool {
    first_hop(req).is_some_and(|(h, p)| h == ask.host && p == ask.port)
}

/// 生成给 [`pm_proto::Client::with_dialer`] 的回调。每个要求在自己的线程里处理，请求本身照常等回复。
pub fn dialer(target: Target, server: ServerPublic, token: Zeroizing<String>) -> pm_proto::Dialer {
    Box::new(move |req: &Request, ask: &DialAsk| {
        // 先在这里判断（请求只在回调期间可用）
        let ok = allowed(req, ask);
        let (target, server, token, ask) = (target.clone(), server.clone(), token.clone(), ask.clone());
        // 后台线程：一个小的 tokio 运行时，转发到任一端关闭为止（命令结束时进程退出，线程随之结束）
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
            rt.block_on(relay(&target, &server, &token, &ask, ok));
        });
    })
}

/// 连目标（这台机器的网络）。错误写成一句话，服务器会把它放进给 Agent 的错误里。
async fn connect_target(host: &str, port: u16) -> Result<tokio::net::TcpStream, String> {
    match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => {
            // 交互式命令的小包立即发出
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(format!("connection to {host}:{port} failed: {e}")),
        Err(_) => Err(format!("connection to {host}:{port} timed out")),
    }
}

/// 写一帧（4 字节长度 + 内容，和本地协议一样）。
async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    w.write_u32(data.len() as u32).await?;
    w.write_all(data).await?;
    w.flush().await
}

/// 读服务器的确认帧（很短，限 4 KiB）。
async fn read_ack<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> std::io::Result<()> {
    let n = r.read_u32().await? as usize;
    if n > 4096 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ack too large"));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(())
}

/// 执行一个转发要求：连目标，连服务器并握手，然后双向转发。失败时也连一次服务器，带上原因（服务器不必空等）。
async fn relay(target: &Target, server: &ServerPublic, token: &str, ask: &DialAsk, ok: bool) {
    // 1. 目标：只接受这个请求自己的第一跳
    let up = if ok {
        connect_target(&ask.host, ask.port).await
    } else {
        Err(format!("the client refused to connect to {}:{}: it is not the target of this request", ask.host, ask.port))
    };
    // 2. 服务器：和普通请求同样的双层加密，只是可以同时读写
    let Ok(mut pm) = pm_net::client::connect_async(target, server).await else { return };
    let error = up.as_ref().err().cloned().unwrap_or_default();
    let hello = Hello::Dial { v: PROTO_V, token: token.to_string(), ticket: ask.ticket.clone(), error };
    // 握手里有令牌：序列化结果用完清零
    let Ok(bytes) = serde_json::to_vec(&hello).map(Zeroizing::new) else { return };
    if write_frame(&mut pm, &bytes).await.is_err() {
        return;
    }
    // 失败的要求到此为止。写入只是交给了加密的后台任务，运行时一结束它就被取消：
    // 等服务器读完原因并关闭连接（读到 EOF）再返回，原因才真正送到
    let Ok(mut up) = up else {
        let mut b = [0u8; 1];
        let _ = tokio::time::timeout(ACK_TIMEOUT, pm.read(&mut b)).await;
        return;
    };
    // 3. 服务器确认后开始转发（票据对不上时服务器静默断开，这里读到 EOF）
    if !matches!(tokio::time::timeout(ACK_TIMEOUT, read_ack(&mut pm)).await, Ok(Ok(()))) {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut up, &mut pm).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh(target: &str) -> Request {
        Request::Ssh { target: target.into(), command: "true".into() }
    }

    fn ask(host: &str, port: u16) -> DialAsk {
        DialAsk { ticket: "t".into(), host: host.into(), port }
    }

    #[test]
    fn first_hop_is_the_jump_or_the_target() {
        // 没有跳板：目标本身，默认端口 22，主机名规范化
        assert_eq!(first_hop(&ssh("root@DB1.example.com")), Some(("db1.example.com".into(), 22)));
        // 有跳板：跳板
        assert_eq!(first_hop(&ssh("u@jump.example.com:2222>root@db1.example.com")), Some(("jump.example.com".into(), 2222)));
        // scp 上传与下载同样
        let up = Request::Upload { target: "name/u@198.51.100.7:2200".into(), path: "/p".into(), data_base64: String::new() };
        assert_eq!(first_hop(&up), Some(("198.51.100.7".into(), 2200)));
        // 不是 SSH 类请求，或目标写错
        assert_eq!(first_hop(&Request::Status), None);
        assert_eq!(first_hop(&ssh("a>b>c")), None);
    }

    #[test]
    fn only_the_requests_own_first_hop_is_dialed() {
        let req = ssh("u@jump.example.com:2222>root@db1.example.com");
        assert!(allowed(&req, &ask("jump.example.com", 2222)));
        // 目标（经跳板才能到）、别的端口、别的主机：都拒绝
        assert!(!allowed(&req, &ask("db1.example.com", 22)));
        assert!(!allowed(&req, &ask("jump.example.com", 22)));
        assert!(!allowed(&req, &ask("198.51.100.9", 2222)));
        assert!(!allowed(&Request::Status, &ask("jump.example.com", 2222)));
    }

    #[tokio::test]
    async fn target_errors_are_one_short_sentence() {
        // 本机一个刚关闭的端口：连接被拒，错误里有主机和端口
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let e = connect_target("127.0.0.1", port).await.unwrap_err();
        assert!(e.starts_with(&format!("connection to 127.0.0.1:{port} failed")), "{e}");
        // 能连上的端口：成功
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(connect_target("127.0.0.1", port).await.is_ok());
    }

    #[tokio::test]
    async fn frames_and_acks() {
        // 写出的帧：4 字节大端长度 + 内容
        let mut out = Vec::new();
        write_frame(&mut out, b"hello").await.unwrap();
        assert_eq!(out, [0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o']);
        // 确认帧照常读完；过长的拒绝；空的流是错误
        assert!(read_ack(&mut &out[..]).await.is_ok());
        assert!(read_ack(&mut &[0u8, 0, 0x20, 0][..]).await.is_err());
        assert!(read_ack(&mut &b""[..]).await.is_err());
    }
}

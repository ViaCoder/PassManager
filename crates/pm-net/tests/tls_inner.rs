//! 真实 TLS 上的双层通道：外层策略（拒绝纯经典密钥交换、弱套件），内层握手、固定指纹、
//! 中间人转发（不同 TLS 连接 → exporter 不同）失败、帧被篡改时连接关闭。

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use pm_net::client::{self, Target};
use pm_net::inner::{self, InnerError, ServerKeys, ServerPublic};
use pm_net::tls::{self, CertStore};
use rustls::crypto::aws_lc_rs::{self as prov, cipher_suite, kx_group};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn keys() -> &'static ServerKeys {
    static K: OnceLock<ServerKeys> = OnceLock::new();
    K.get_or_init(|| ServerKeys::generate().unwrap())
}

fn rt() -> &'static tokio::runtime::Runtime {
    static R: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    R.get_or_init(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap())
}

struct Srv {
    addr: SocketAddr,
    ca: String,
}

/// 内层回显服务：把收到的每段应用数据原样返回（前面加 "echo:"）。
fn start_server() -> Srv {
    let (cert, key) = tls::self_signed(&["pm.test"]);
    let cs = CertStore::new();
    cs.set_pem(&cert, &key).unwrap();
    let acceptor = TlsAcceptor::from(tls::server_config(cs, &[tls::ALPN_INNER]));
    let l = rt().block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let addr = l.local_addr().unwrap();
    rt().spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else { break };
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acc.accept(tcp).await else { return };
                let Ok(Some(mut app)) = inner::server::accept_tls(tls, keys()).await else { return };
                let mut buf = vec![0u8; 300_000];
                loop {
                    let n = match app.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let mut out = b"echo:".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    if app.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Srv { addr, ca: cert }
}

fn target(s: &Srv) -> Target {
    Target { host: "pm.test".into(), port: s.addr.port(), connect_addr: Some(s.addr), extra_ca_pem: Some(s.ca.clone()) }
}

fn public() -> ServerPublic {
    ServerPublic::from_bundle(keys().bundle(), &keys().fingerprint()).unwrap()
}

#[test]
fn double_layer_roundtrip_and_key_fetch() {
    let s = start_server();
    let t = target(&s);
    // 注册：下载公钥包并核对指纹；指纹不对时拒绝。
    let p = client::fetch_server_public(&t, &keys().fingerprint()).unwrap();
    assert_eq!(p.fpr, keys().fingerprint());
    let mut wrong = keys().fingerprint();
    wrong[3] ^= 1;
    assert!(matches!(client::fetch_server_public(&t, &wrong), Err(InnerError::Fingerprint)));
    // 会话：小数据与跨多帧的大数据。
    let mut c = client::connect(&t, &p).unwrap();
    c.write_all(b"ping").unwrap();
    c.flush().unwrap();
    let mut b = [0u8; 9];
    c.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"echo:ping");
    let big: Vec<u8> = (0..150_000u32).map(|i| (i * 7) as u8).collect();
    c.write_all(&big).unwrap();
    c.flush().unwrap();
    // 回显服务按读到的块加 "echo:" 前缀；大数据相邻字节总是相差 7，不可能包含 "echo:"。
    let mut got = Vec::new();
    while split_echo(&got).len() < big.len() {
        let mut chunk = vec![0u8; 100_000];
        let n = c.read(&mut chunk).unwrap();
        assert!(n > 0, "unexpected EOF");
        got.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(split_echo(&got), big);
}

fn split_echo(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(b"echo:") {
            i += 5;
            continue;
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

/// 只支持经典密钥交换或弱套件的客户端：外层握手失败。
#[test]
fn classical_or_weak_tls_clients_are_rejected() {
    let s = start_server();
    let try_with = |groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>, suites: Vec<rustls::SupportedCipherSuite>| {
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from_pem_slice(s.ca.as_bytes()).unwrap()).unwrap();
        let p = rustls::crypto::CryptoProvider { kx_groups: groups, cipher_suites: suites, ..prov::default_provider() };
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(p))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![tls::ALPN_INNER.to_vec()];
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), "pm.test".try_into().unwrap()).unwrap();
        let mut tcp = std::net::TcpStream::connect(s.addr).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut ok = true;
        while conn.is_handshaking() {
            if conn.complete_io(&mut tcp).is_err() {
                ok = false;
                break;
            }
        }
        ok
    };
    assert!(try_with(vec![kx_group::X25519MLKEM768, kx_group::X25519], vec![cipher_suite::TLS13_AES_256_GCM_SHA384]));
    assert!(!try_with(vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1], vec![cipher_suite::TLS13_AES_256_GCM_SHA384]));
    for suite in [cipher_suite::TLS13_AES_128_GCM_SHA256, cipher_suite::TLS13_CHACHA20_POLY1305_SHA256] {
        assert!(!try_with(vec![kx_group::X25519MLKEM768], vec![suite]), "{suite:?}");
    }
    // 不信任的证书（没有额外 CA，只信任公共根证书）：客户端拒绝。
    let mut t = target(&s);
    t.extra_ca_pem = None;
    assert!(client::tls_connect(&t).is_err());
}

/// 中间人：终止客户端的 TLS（假设它能拿到受信任的证书），再用自己的 TLS 连到服务端，原样转发内层字节。
/// 两条 TLS 的 exporter 不同 → 客户端发现服务端的 tag 不对，握手失败。
#[test]
fn relaying_through_another_tls_connection_fails() {
    let s = start_server();
    let (mcert, mkey) = tls::self_signed(&["pm.test"]);
    let cs = CertStore::new();
    cs.set_pem(&mcert, &mkey).unwrap();
    let acceptor = TlsAcceptor::from(tls::server_config(cs, &[tls::ALPN_INNER]));
    let l = rt().block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let maddr = l.local_addr().unwrap();
    let upstream = target(&s);
    rt().spawn(async move {
        let Ok((tcp, _)) = l.accept().await else { return };
        let Ok(mut down) = acceptor.accept(tcp).await else { return };
        // 上游连接用阻塞客户端（在阻塞线程里），通过 channel 中转。
        let (tx_up, rx_up) = std::sync::mpsc::channel::<Vec<u8>>();
        let (tx_down, mut rx_down) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let Ok(mut up) = client::tls_connect(&upstream) else { return };
            up.sock.set_read_timeout(Some(std::time::Duration::from_millis(50))).unwrap();
            loop {
                while let Ok(d) = rx_up.try_recv() {
                    if up.write_all(&d).and_then(|_| up.flush()).is_err() {
                        return;
                    }
                }
                let mut b = [0u8; 4096];
                match up.read(&mut b) {
                    Ok(0) => return,
                    Ok(n) => {
                        if tx_down.send(b[..n].to_vec()).is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => return,
                }
            }
        });
        let mut buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                r = down.read(&mut buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if tx_up.send(buf[..n].to_vec()).is_err() { break; } }
                },
                d = rx_down.recv() => match d {
                    Some(d) => { if down.write_all(&d).await.is_err() { break; } let _ = down.flush().await; }
                    None => break,
                },
            }
        }
    });
    let t = Target { host: "pm.test".into(), port: maddr.port(), connect_addr: Some(maddr), extra_ca_pem: Some(mcert) };
    // 公钥包可以被转发（它本来就是公开的）……
    let p = public();
    // ……但会话握手必然失败。
    match client::connect(&t, &p) {
        Err(InnerError::Auth) => {}
        Err(e) => panic!("expected Auth failure, got {e}"),
        Ok(_) => panic!("relayed session must fail"),
    }
}

/// 帧被篡改：服务端关闭连接，客户端读到 EOF 或错误（而不是被篡改的数据）。
#[test]
fn tampered_frame_closes_the_connection() {
    let s = start_server();
    let t = target(&s);
    let mut tls_s = client::tls_connect(&t).unwrap();
    let e = client::exporter(&tls_s).unwrap();
    let (hs, msg) = inner::ClientHandshake::start(&public()).unwrap();
    tls_s.write_all(&msg).unwrap();
    tls_s.flush().unwrap();
    let mut reply = [0u8; inner::SERVER_REPLY_LEN];
    tls_s.read_exact(&mut reply).unwrap();
    let (mut sess, tag) = hs.finish(&reply, &e).unwrap();
    tls_s.write_all(&tag).unwrap();
    let mut frame = sess.send.seal(b"hello").unwrap();
    let last = frame.len() - 1;
    frame[last] ^= 1;
    tls_s.write_all(&frame).unwrap();
    tls_s.flush().unwrap();
    let mut b = [0u8; 64];
    let r = tls_s.read(&mut b);
    assert!(matches!(r, Ok(0) | Err(_)), "server must close, got {r:?}");
    // 垃圾请求头：同样直接断开，不回任何内容。
    let mut raw = client::tls_connect(&t).unwrap();
    raw.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    raw.flush().unwrap();
    assert!(matches!(raw.read(&mut b), Ok(0) | Err(_)));
}

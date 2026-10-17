//! 跳板 SSH 端到端（真实服务进程，Linux）：
//! - 目标写成 `跳板>目标`：跳板用口令条目、目标用私钥条目，每一跳只用绑定到它自己的凭据；
//! - 跳板只收到 direct-tcpip 转发请求（目标的 host:port），收不到目标的凭据，目标也收不到跳板的口令；
//! - CLI `-J` 与 lookup 的路由写法；
//! - 跳板拒绝转发：UPSTREAM_ERROR，消息里写明经由哪个跳板；
//! - 目标或跳板的主机密钥变化：HOST_KEY_CHANGED，变化的那一跳不发送任何认证数据，跳板变化时也不请求转发；
//! - 输出与服务日志不含秘密。
#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};

const JUMP_PW: &str = "JumpPw-7c41!";

/// 两台测试服务器共用的事件记录（"名称 事件 参数"）。
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

/// 测试服务器：口令或公钥认证；exec 回显命令；`forward` 为真时接受 direct-tcpip（只转发到本机）。
struct S {
    name: &'static str,
    password: Option<String>,
    allowed: Option<russh::keys::PublicKey>,
    forward: bool,
    log: Log,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl S {
    fn new(name: &'static str, password: Option<&str>, allowed: Option<russh::keys::PublicKey>, forward: bool, log: &Log) -> Self {
        Self { name, password: password.map(str::to_string), allowed, forward, log: log.clone(), channels: HashMap::new() }
    }
    fn key_ok(&self, k: &russh::keys::PublicKey) -> Auth {
        if self.allowed.as_ref().is_some_and(|a| a.key_data() == k.key_data()) { Auth::Accept } else { Auth::reject() }
    }
}

impl russh::server::Handler for S {
    type Error = russh::Error;

    async fn auth_password(&mut self, u: &str, p: &str) -> Result<Auth, Self::Error> {
        self.log.push(format!("{} password {u}", self.name));
        Ok(if self.password.as_deref() == Some(p) { Auth::Accept } else { Auth::reject() })
    }
    async fn auth_publickey_offered(&mut self, u: &str, k: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        self.log.push(format!("{} publickey {u}", self.name));
        Ok(self.key_ok(k))
    }
    async fn auth_publickey(&mut self, _u: &str, k: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        Ok(self.key_ok(k))
    }
    async fn channel_open_session(&mut self, channel: Channel<Msg>, reply: ChannelOpenHandle, _s: &mut Session) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, format!("{} ran: {}\n", self.name, String::from_utf8_lossy(data)).into_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _orig_addr: &str,
        _orig_port: u32,
        reply: ChannelOpenHandle,
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.push(format!("{} forward {host}:{port}", self.name));
        if !self.forward || !matches!(host, "localhost" | "127.0.0.1") {
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }
        let Ok(mut tcp) = tokio::net::TcpStream::connect(("127.0.0.1", port as u16)).await else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut ch = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut ch, &mut tcp).await;
        });
        Ok(())
    }
}

struct Srv {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

/// 加固配置：只有 mlkem768x25519-sha256、P-384 主机密钥、aes256-gcm、hmac-sha2-512-etm。
fn serve(rt: &tokio::runtime::Runtime, port: u16, host_key: &Path, mk: impl Fn() -> S + Send + Sync + 'static) -> Srv {
    use russh::keys::ssh_key::{Algorithm, EcdsaCurve};
    use std::borrow::Cow;
    let key = russh::keys::decode_secret_key(&std::fs::read_to_string(host_key).unwrap(), None).unwrap();
    let mut preferred = russh::Preferred::DEFAULT.clone();
    preferred.kex = Cow::Owned(vec![
        russh::kex::MLKEM768X25519_SHA256,
        russh::kex::EXTENSION_SUPPORT_AS_SERVER,
        russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
    ]);
    preferred.key = Cow::Owned(vec![Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }]);
    preferred.cipher = Cow::Owned(vec![russh::cipher::AES_256_GCM]);
    preferred.mac = Cow::Owned(vec![russh::mac::HMAC_SHA512_ETM]);
    let cfg = Arc::new(russh::server::Config {
        keys: vec![key],
        preferred,
        methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey, russh::MethodKind::Password][..]),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    let l = rt.block_on(tokio::net::TcpListener::bind(("127.0.0.1", port))).unwrap();
    let port = l.local_addr().unwrap().port();
    let mk = Arc::new(mk);
    let task = rt.spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
            let (cfg, mk) = (cfg.clone(), mk.clone());
            tokio::spawn(async move {
                if let Ok(r) = russh::server::run_stream(cfg, s, mk()).await {
                    let _ = r.await;
                }
            });
        }
    });
    Srv { port, task }
}

#[test]
fn ssh_through_jump_host() {
    if !have("ssh-keygen") {
        eprintln!("跳过：没有 ssh-keygen");
        return;
    }
    let env = Env::setup("sshjump");
    let kd = env.base.join("keys");
    std::fs::create_dir_all(&kd).unwrap();
    let (jhost, _) = keygen(&kd, "jhost", "");
    let (thost, _) = keygen(&kd, "thost", "");
    let (other, _) = keygen(&kd, "other", "");
    let (client, _) = keygen(&kd, "client", "");
    let client_pem = std::fs::read_to_string(&client).unwrap();
    let client_pub = russh::keys::decode_secret_key(&client_pem, None).unwrap().public_key().clone();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let log = Log::default();
    let mk_target = {
        let (log, k) = (log.clone(), client_pub.clone());
        move || S::new("target", None, Some(k.clone()), false, &log)
    };
    let mk_jump = {
        let log = log.clone();
        move || S::new("jump", Some(JUMP_PW), None, true, &log)
    };
    let tgt = serve(&rt, 0, &thost, mk_target.clone());
    let jmp = serve(&rt, 0, &jhost, mk_jump.clone());
    let (dj, dt) = (format!("localhost:{}", jmp.port), format!("localhost:{}", tgt.port));
    let mut outputs = String::new();

    // 跳板：口令条目；目标：私钥条目（另绑一个跳板不会转发的地址，用于测试拒绝转发）。
    let o = env.run_stdin(&["import", "--name", "jumppw", "--domain", &dj], format!("{JUMP_PW}\n").as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    let o = env
        .run_stdin(&["import", "--name", "tkey", "--kind", "ssh-key", "--domain", &dt, "--domain", "198.51.100.7"], client_pem.as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    let route = format!("deploy@{dj}>deploy@{dt}");

    // ---- 经跳板执行：每一跳只用自己的凭据 ----
    let o = env.agent(&["ssh", &route, "uptime"]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success() && stdout(&o).contains("target ran: uptime"), "{}{}", stdout(&o), stderr(&o));
    let events = log.take();
    assert!(events.contains(&"jump password deploy".to_string()), "{events:?}");
    assert!(events.contains(&format!("jump forward localhost:{}", tgt.port)), "{events:?}");
    assert!(events.contains(&"target publickey deploy".to_string()), "{events:?}");
    assert!(!events.iter().any(|e| e == "jump publickey deploy" || e == "target password deploy"), "凭据串到了另一跳：{events:?}");

    // ---- CLI -J 与 lookup ----
    let o = env.agent(&["ssh", "-J", &format!("deploy@{dj}"), &format!("deploy@{dt}"), "id"]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success() && stdout(&o).contains("target ran: id"), "{}{}", stdout(&o), stderr(&o));
    let o = env.agent(&["lookup", &route]);
    let out = stdout(&o);
    outputs += &out;
    assert!(o.status.success() && out.contains("jumppw") && out.contains("tkey") && out.contains(&route), "{out}");

    // ---- 跳板拒绝转发：写明经由哪个跳板 ----
    log.take();
    let o = env.agent(&["ssh", &format!("deploy@{dj}>deploy@198.51.100.7"), "uptime"]);
    let out = stdout(&o) + &stderr(&o);
    outputs += &out;
    assert!(!o.status.success() && out.contains("UPSTREAM_ERROR") && out.contains(&format!("via {dj}")), "{out}");
    assert!(log.take().contains(&"jump forward 198.51.100.7:22".to_string()));

    // ---- 目标主机密钥变化：拒绝，目标收不到任何认证 ----
    tgt.task.abort();
    std::thread::sleep(Duration::from_millis(200));
    let tgt2 = serve(&rt, tgt.port, &other, mk_target.clone());
    let o = env.agent(&["ssh", &route, "uptime"]);
    let out = stdout(&o) + &stderr(&o);
    outputs += &out;
    assert!(!o.status.success() && out.contains("HOST_KEY_CHANGED") && out.contains(&dt), "{out}");
    let events = log.take();
    assert!(!events.iter().any(|e| e.starts_with("target ")), "主机密钥变化后目标不应收到认证：{events:?}");

    // ---- 跳板主机密钥变化：拒绝，跳板收不到口令，也不请求转发 ----
    jmp.task.abort();
    std::thread::sleep(Duration::from_millis(200));
    let jmp2 = serve(&rt, jmp.port, &other, mk_jump.clone());
    let o = env.agent(&["ssh", &route, "uptime"]);
    let out = stdout(&o) + &stderr(&o);
    outputs += &out;
    assert!(!o.status.success() && out.contains("HOST_KEY_CHANGED") && out.contains(&dj), "{out}");
    assert!(log.take().is_empty(), "主机密钥变化后跳板不应收到口令或转发请求");

    outputs += &env.service_log();
    let key_line = client_pem.lines().nth(1).unwrap();
    let bad = leaks(&outputs, &[JUMP_PW, key_line]);
    assert!(bad.is_empty(), "{bad:?}");
    drop((tgt2, jmp2));
}

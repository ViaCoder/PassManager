//! 服务器模式（局域网在线版）的运行时：注册码、网页登录链接、证书、两个网络监听。
//!
//! - 443：网页管理（单层 TLS，见 pm-web）；
//! - 8443：Agent 通道 = 外层 TLS + 内层 ML-KEM-1024/McEliece 会话，内层包装成 `AsyncRead + AsyncWrite`
//!   后直接交给现有的 `handle_conn`。网络连接只接受 `Hello::Token` 与 `Hello::Enroll`；
//!   `Password` / `Setup` / `Root` 一律静默拒绝；来源地址不在允许的网段时连握手都不做。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pm_net::inner::ServerKeys;
use pm_net::tls::CertStore;
use pm_platform::ServerConfig;
use pm_proto::{EnrollView, PendingEnrollView};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::server::{Peer, handle_conn};
use crate::server_files as sf;
use crate::{Shared, log};

/// 注册码有效期。
pub const ENROLL_TTL: Duration = Duration::from_secs(600);
/// 同时未使用的注册码上限。
pub const MAX_PENDING_ENROLL: usize = 32;
/// Agent 通道的并发连接上限。
pub const MAX_AGENT_CONNS: usize = 64;
/// 注册失败的限速：每个来源 10 分钟内最多 10 次失败，之后锁定 15 分钟（锁定期间有效的注册码也不受理、不被消耗）。
pub const ENROLL_MAX_FAILURES: u32 = 10;
pub const ENROLL_FAIL_WINDOW: Duration = Duration::from_secs(600);
pub const ENROLL_LOCKOUT: Duration = Duration::from_secs(900);

/// 用注册码兑换的结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Redeem {
    /// 成功（注册码已作废），返回标签。
    Ok(String),
    /// 未知、已使用、已作废或已过期的注册码（计入失败次数）。
    Invalid,
    /// 这个来源失败次数过多，暂时不受理。
    Blocked,
}

struct Pending {
    id: String,
    label: String,
    expires: Instant,
}

#[derive(Default)]
pub(crate) struct CertState {
    pub not_after: Option<i64>,
    pub error: Option<String>,
}

pub(crate) struct Online {
    pub cfg: ServerConfig,
    pub links: Arc<pm_web::LoginLinks>,
    pub keys: Arc<ServerKeys>,
    pub certs: Arc<CertStore>,
    pub cert_state: Mutex<CertState>,
    enrolls: Mutex<HashMap<[u8; 32], Pending>>,
    enroll_failures: pm_web::RateLimiter,
}

impl Online {
    pub fn new(cfg: ServerConfig, keys: ServerKeys) -> Self {
        Self {
            cfg,
            links: pm_web::LoginLinks::new(),
            keys: Arc::new(keys),
            certs: CertStore::new(),
            cert_state: Mutex::new(CertState::default()),
            enrolls: Mutex::new(HashMap::new()),
            enroll_failures: pm_web::RateLimiter::new(ENROLL_MAX_FAILURES, ENROLL_FAIL_WINDOW, ENROLL_LOCKOUT),
        }
    }

    pub fn web_origin(&self) -> String {
        pm_web::WebConfig { domain: self.cfg.domain.clone(), port: self.cfg.web_port, agent_bin_dir: None }.origin()
    }

    /// 应用层来源检查（与防火墙使用同一份列表：局域网网段 + 允许列表；本机回环总是允许）。
    pub fn allowed(&self, ip: IpAddr) -> bool {
        self.cfg.source_allowed(ip)
    }

    /// 新建注册码。返回给调用方的 URL 只出现这一次；服务端只保存 SHA-256。
    pub fn enroll_create(&self, label: &str) -> Result<EnrollView, String> {
        self.enroll_create_at(label, Instant::now())
    }

    fn enroll_create_at(&self, label: &str, now: Instant) -> Result<EnrollView, String> {
        let label: String = label.trim().chars().filter(|c| !c.is_control()).take(64).collect();
        if label.is_empty() {
            return Err("标签不能为空".into());
        }
        let code = pm_net::enroll::new_code().map_err(|e| e.to_string())?;
        let id = hex::encode(pm_crypto::rng::random_array::<4>().map_err(|e| e.to_string())?);
        let mut m = self.enrolls.lock().unwrap();
        m.retain(|_, p| p.expires > now);
        if m.len() >= MAX_PENDING_ENROLL {
            return Err(format!("未使用的注册码已达上限（{MAX_PENDING_ENROLL} 个），请先作废或等待过期"));
        }
        m.insert(pm_crypto::sha256(code.as_bytes()), Pending { id: id.clone(), label: label.clone(), expires: now + ENROLL_TTL });
        let url =
            pm_net::enroll::EnrollUrl { host: self.cfg.domain.clone(), port: self.cfg.agent_port, code, fpr: self.keys.fingerprint() };
        Ok(EnrollView { id, label, url: url.to_string(), expires_in_secs: ENROLL_TTL.as_secs() })
    }

    /// 查询注册码（**不消耗**）：有效时返回（ID，完整的 `pm-enroll://` URL）。用于网页的一键安装脚本。
    pub fn enroll_peek(&self, code: &str) -> Option<(String, String)> {
        self.enroll_peek_at(code, Instant::now())
    }

    fn enroll_peek_at(&self, code: &str, now: Instant) -> Option<(String, String)> {
        if code.len() != pm_net::enroll::CODE_LEN {
            return None;
        }
        let m = self.enrolls.lock().unwrap();
        let p = m.get(&pm_crypto::sha256(code.as_bytes())).filter(|p| p.expires > now)?;
        let url = pm_net::enroll::EnrollUrl {
            host: self.cfg.domain.clone(),
            port: self.cfg.agent_port,
            code: code.to_string(),
            fpr: self.keys.fingerprint(),
        };
        Some((p.id.clone(), url.to_string()))
    }

    /// 消耗注册码：先取出（删除）再检查是否过期，所以同一注册码最多成功一次。返回标签。
    /// 服务只经 [`Online::enroll_redeem`]（按来源限速）调用。
    #[cfg(test)]
    pub fn enroll_consume(&self, code: &str) -> Option<String> {
        self.enroll_consume_at(code, Instant::now())
    }

    fn enroll_consume_at(&self, code: &str, now: Instant) -> Option<String> {
        let p = self.enrolls.lock().unwrap().remove(&pm_crypto::sha256(code.as_bytes()))?;
        (p.expires > now).then_some(p.label)
    }

    /// 按来源限速地兑换注册码：锁定中的来源直接拒绝（不查询、不消耗）；失败计入该来源的失败次数。
    /// 取出与作废在同一把锁内完成，并发兑换同一个注册码时只有一个成功。
    pub fn enroll_redeem(&self, code: &str, source: &str) -> Redeem {
        self.enroll_redeem_at(code, source, Instant::now())
    }

    fn enroll_redeem_at(&self, code: &str, source: &str, now: Instant) -> Redeem {
        if self.enroll_failures.blocked_at(source, now) {
            return Redeem::Blocked;
        }
        match self.enroll_consume_at(code, now) {
            Some(label) => Redeem::Ok(label),
            None => {
                self.enroll_failures.fail_at(source, now);
                Redeem::Invalid
            }
        }
    }

    pub fn enroll_list(&self) -> Vec<PendingEnrollView> {
        let now = Instant::now();
        let mut m = self.enrolls.lock().unwrap();
        m.retain(|_, p| p.expires > now);
        let mut v: Vec<PendingEnrollView> = m
            .values()
            .map(|p| PendingEnrollView {
                id: p.id.clone(),
                label: p.label.clone(),
                expires_in_secs: p.expires.duration_since(now).as_secs(),
            })
            .collect();
        v.sort_by(|a, b| a.label.cmp(&b.label));
        v
    }

    pub fn enroll_cancel(&self, id: &str) -> bool {
        let mut m = self.enrolls.lock().unwrap();
        let before = m.len();
        m.retain(|_, p| p.id != id);
        m.len() != before
    }

    pub fn pending_count(&self) -> usize {
        self.enroll_list().len()
    }
}

// ---------------- 证书 ----------------

fn now() -> i64 {
    pm_vault::now() as i64
}

/// 装入已保存的证书（仍在有效期内即可，哪怕快到期、续期暂时失败）。
pub(crate) fn load_stored_cert(shared: &Shared, on: &Online) {
    let Ok(dk) = shared.device_key() else { return };
    load_stored_cert_into(&shared.layout, dk, on);
}

fn load_stored_cert_into(layout: &pm_platform::Layout, dk: &[u8; 32], on: &Online) {
    match sf::load_cert(layout, dk) {
        Ok(Some((chain, key))) => {
            if pm_net::acme::still_valid(&chain, now()) && on.certs.set_pem(&chain, &key).is_ok() {
                on.cert_state.lock().unwrap().not_after = pm_net::tls::cert_not_after(&chain);
            } else {
                on.cert_state.lock().unwrap().error = Some("已保存的证书已过期或无法使用".into());
            }
        }
        Ok(None) => {}
        Err(e) => on.cert_state.lock().unwrap().error = Some(e),
    }
}

/// 需要时申请 / 续期证书。`force` 忽略退避（root 手动触发）。返回是否签发了新证书。
pub async fn renew_if_needed(
    layout: &pm_platform::Layout,
    cfg: &ServerConfig,
    dk: &[u8; 32],
    certs: &CertStore,
    force: bool,
) -> Result<bool, String> {
    if cfg.acme_directory.is_empty() {
        return Ok(false);
    }
    let current = std::fs::read_to_string(sf::cert_path(layout)).ok();
    if !force && !pm_net::acme::needs_renewal(current.as_deref(), now(), cfg.renew_days) {
        return Ok(false);
    }
    let mut st = sf::load_acme_state(layout);
    if !force && st.failures > 0 && now() - st.last_attempt < pm_net::acme::backoff_secs(st.failures - 1) as i64 {
        return Err(format!("上次申请失败，{} 秒后重试", pm_net::acme::backoff_secs(st.failures - 1) as i64 - (now() - st.last_attempt)));
    }
    let dns = if let Some(api) = cfg.dns.strip_prefix("challtest:") {
        pm_net::acme::Dns::ChallTest { api: api.to_string() }
    } else {
        let token =
            sf::load_cf_token(layout, dk)?.ok_or("没有 Cloudflare token（安装时经 stdin 传入：passmanager init --cf-token-stdin）")?;
        pm_net::acme::Dns::cloudflare(token)
    };
    let acme_cfg = pm_net::acme::AcmeCfg {
        directory: cfg.acme_directory.clone(),
        root_pem: cfg.acme_root_pem.clone(),
        domain: cfg.domain.clone(),
        propagation: if cfg.dns == "cloudflare" { Duration::from_secs(20) } else { Duration::ZERO },
    };
    st.last_attempt = now();
    let saved = sf::load_acme_account(layout, dk);
    match pm_net::acme::issue(&acme_cfg, &dns, saved.as_deref().map(|s| s.as_str())).await {
        Ok(issued) => {
            if let Some(a) = &issued.new_account {
                sf::store_acme_account(layout, dk, a)?;
            }
            certs.set_pem(&issued.chain_pem, &issued.key_pem)?;
            sf::store_cert(layout, dk, &issued.chain_pem, &issued.key_pem)?;
            st.failures = 0;
            sf::store_acme_state(layout, &st);
            Ok(true)
        }
        Err(e) => {
            st.failures = st.failures.saturating_add(1);
            sf::store_acme_state(layout, &st);
            Err(e.to_string())
        }
    }
}

/// 后台续期：每 6 小时检查一次；失败按退避重试，不影响服务运行（已保存的证书在有效期内继续使用）。
pub(crate) async fn cert_loop(shared: Arc<Shared>) {
    let Some(on) = shared.online.as_ref() else { return };
    loop {
        if let Ok(dk) = shared.device_key() {
            match renew_if_needed(&shared.layout, &on.cfg, dk, &on.certs, false).await {
                Ok(true) => {
                    log("TLS certificate issued/renewed");
                    let na = std::fs::read_to_string(sf::cert_path(&shared.layout)).ok().and_then(|c| pm_net::tls::cert_not_after(&c));
                    *on.cert_state.lock().unwrap() = CertState { not_after: na, error: None };
                }
                Ok(false) => {}
                Err(e) => {
                    log(&format!("certificate renewal failed: {e}"));
                    on.cert_state.lock().unwrap().error = Some(e);
                }
            }
        }
        let st = sf::load_acme_state(&shared.layout);
        let wait = if st.failures > 0 { pm_net::acme::backoff_secs(st.failures - 1) } else { 6 * 3600 };
        tokio::time::sleep(Duration::from_secs(wait.clamp(60, 6 * 3600))).await;
    }
}

// ---------------- 监听 ----------------

/// Agent 通道（8443）。
pub(crate) async fn serve_agents(shared: Arc<Shared>, listener: TcpListener) {
    let Some(on) = shared.online.as_ref() else { return };
    let acceptor = TlsAcceptor::from(pm_net::tls::server_config(on.certs.clone(), &[pm_net::tls::ALPN_INNER]));
    if let Err(e) = pm_net::tls::check_policy(&pm_net::tls::server_config(on.certs.clone(), &[pm_net::tls::ALPN_INNER])) {
        log(&format!("TLS policy self-check failed: {e}"));
        return;
    }
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        // 不在局域网网段：不握手、不回任何内容。
        if !on.allowed(peer.ip()) {
            drop(tcp);
            continue;
        }
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_AGENT_CONNS {
            active.fetch_sub(1, Ordering::SeqCst);
            drop(tcp);
            continue;
        }
        let (shared, acceptor, keys, active) = (shared.clone(), acceptor.clone(), on.keys.clone(), active.clone());
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            if let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(15), acceptor.accept(tcp)).await
                && let Ok(Some(stream)) = pm_net::inner::server::accept_tls(tls, &keys).await
            {
                handle_conn(shared, stream, Peer { elevated: false, allowed: true, network: true, addr: Some(peer.ip()) }).await;
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// 网页（默认 443）。
pub(crate) async fn serve_web(shared: Arc<Shared>, listener: TcpListener) {
    serve_web_with(shared, listener, false).await
}

/// 单端口模式：一个 TLS 监听，按协商出的 ALPN 分流——`pm-inner/1` 进入 Agent 通道（与两端口模式的 Agent 端口
/// 完全相同的内层握手与 TLS exporter 绑定），h2 / http/1.1 / 没有 ALPN 是网页。
pub(crate) async fn serve_single(shared: Arc<Shared>, listener: TcpListener) {
    serve_web_with(shared, listener, true).await
}

async fn serve_web_with(shared: Arc<Shared>, listener: TcpListener, single: bool) {
    let Some(on) = shared.online.as_ref() else { return };
    let alpn: Vec<&[u8]> = if single { pm_web::front::SINGLE_PORT_ALPN.to_vec() } else { vec![b"h2", b"http/1.1"] };
    let cfg = pm_net::tls::server_config(on.certs.clone(), &alpn);
    if let Err(e) = pm_net::tls::check_policy(&cfg) {
        log(&format!("TLS policy self-check failed: {e}"));
        return;
    }
    let backend: Arc<dyn pm_web::Backend> = Arc::new(WebBackend(shared.clone()));
    let st = pm_web::AppState::new(
        backend,
        on.links.clone(),
        pm_web::WebConfig {
            domain: on.cfg.domain.clone(),
            port: on.cfg.web_port,
            agent_bin_dir: Some(shared.layout.data_dir.join("agent-bin")),
        },
    );
    let scfg = on.cfg.clone();
    let allow: pm_web::front::Allow = Arc::new(move |ip| scfg.source_allowed(ip));
    let mut front = pm_web::front::Front::new(TlsAcceptor::from(cfg), &on.cfg.domain, on.cfg.web_port, allow);
    if single {
        let (sh, keys) = (shared.clone(), on.keys.clone());
        let active = Arc::new(AtomicUsize::new(0));
        front = front.with_inner(Arc::new(move |tls, peer| {
            let (sh, keys, active) = (sh.clone(), keys.clone(), active.clone());
            Box::pin(async move {
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_AGENT_CONNS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    return;
                }
                if let Ok(Some(stream)) = pm_net::inner::server::accept_tls(tls, &keys).await {
                    handle_conn(sh, stream, Peer { elevated: false, allowed: true, network: true, addr: Some(peer.ip()) }).await;
                }
                active.fetch_sub(1, Ordering::SeqCst);
            })
        }));
    }
    front.serve(listener, pm_web::router(st)).await;
}

/// 网页调用服务：管理会话（不能取明文、不能生成登录链接）。
struct WebBackend(Arc<Shared>);

impl pm_web::Backend for WebBackend {
    fn call(&self, req: pm_proto::Request) -> pm_web::BoxFut<'_, pm_proto::Response> {
        Box::pin(async move { self.0.dispatch(&crate::Session::Web, req).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn online() -> Online {
        static K: std::sync::OnceLock<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>)> = std::sync::OnceLock::new();
        let (b, s) = K.get_or_init(|| {
            let k = ServerKeys::generate().unwrap();
            (k.bundle().to_vec(), k.secret_bytes())
        });
        Online::new(
            ServerConfig { domain: "pm.test".into(), lan: vec!["198.51.100.0/24".into()], ..Default::default() },
            ServerKeys::from_parts(b, s).unwrap(),
        )
    }

    #[test]
    fn enrollment_codes_are_single_use_and_expire_after_ten_minutes() {
        let on = online();
        let t0 = Instant::now();
        let v = on.enroll_create_at("laptop", t0).unwrap();
        let u = pm_net::enroll::EnrollUrl::parse(&v.url).unwrap();
        assert_eq!((u.host.as_str(), u.port, u.fpr), ("pm.test", 8443, on.keys.fingerprint()));
        assert_eq!(v.expires_in_secs, 600);
        // 查询不消耗；过期后查不到。
        let (pid, purl) = on.enroll_peek_at(&u.code, t0 + Duration::from_secs(10)).unwrap();
        assert_eq!(purl, v.url);
        assert!(!pid.is_empty());
        assert!(on.enroll_peek_at(&u.code, t0 + Duration::from_secs(20)).is_some(), "查询不消耗");
        assert!(on.enroll_peek_at(&u.code, t0 + Duration::from_secs(600)).is_none(), "过期");
        assert!(on.enroll_peek_at("short", t0).is_none());
        assert_eq!(on.enroll_consume_at(&u.code, t0 + Duration::from_secs(599)).as_deref(), Some("laptop"));
        assert!(on.enroll_peek_at(&u.code, t0 + Duration::from_secs(30)).is_none(), "使用后查不到");
        assert!(on.enroll_consume_at(&u.code, t0 + Duration::from_secs(600)).is_none(), "只能用一次");
        let v2 = on.enroll_create_at("x", t0).unwrap();
        let c2 = pm_net::enroll::EnrollUrl::parse(&v2.url).unwrap().code;
        assert!(on.enroll_consume_at(&c2, t0 + Duration::from_secs(600)).is_none(), "10 分钟后过期");
        assert!(on.enroll_consume_at(&c2, t0).is_none(), "过期检查时已被取出");
        assert!(on.enroll_consume("garbage").is_none());
        // 标签：去掉控制字符、截断、不能为空。
        assert!(on.enroll_create("  \n ").is_err());
        let v3 = on.enroll_create(&format!("a\u{1b}[31mb{}", "x".repeat(100))).unwrap();
        assert!(v3.label.starts_with("a[31mb") && v3.label.chars().count() == 64);
        // 列表与作废。
        assert_eq!(on.enroll_list().len(), 1);
        assert!(on.enroll_cancel(&v3.id));
        assert!(!on.enroll_cancel(&v3.id));
        assert_eq!(on.pending_count(), 0);
        let c3 = pm_net::enroll::EnrollUrl::parse(&v3.url).unwrap().code;
        assert!(on.enroll_consume(&c3).is_none(), "作废后不能使用");
        // 上限。
        for i in 0..MAX_PENDING_ENROLL {
            on.enroll_create(&format!("n{i}")).unwrap();
        }
        assert!(on.enroll_create("one-too-many").is_err());
    }

    /// 注册码：256 位随机（43 个 base64url 字符）；服务端只保存 SHA-256；10 分钟过期；只能兑换一次。
    #[test]
    fn enrollment_code_strength_and_storage() {
        let on = online();
        let t0 = Instant::now();
        let v = on.enroll_create_at("laptop", t0).unwrap();
        let code = pm_net::enroll::EnrollUrl::parse(&v.url).unwrap().code;
        assert_eq!(code.len(), 43, "32 字节随机数（256 位）");
        let m = on.enrolls.lock().unwrap();
        assert!(m.contains_key(&pm_crypto::sha256(code.as_bytes())), "只保存哈希");
        assert!(m.values().all(|p| p.id != code && p.label != code));
        drop(m);
        assert_eq!(on.enroll_redeem_at(&code, "198.51.100.7", t0 + ENROLL_TTL), Redeem::Invalid, "过期");
        let v = on.enroll_create_at("laptop", t0).unwrap();
        let code = pm_net::enroll::EnrollUrl::parse(&v.url).unwrap().code;
        assert_eq!(on.enroll_redeem_at(&code, "198.51.100.7", t0), Redeem::Ok("laptop".into()));
        assert_eq!(on.enroll_redeem_at(&code, "198.51.100.7", t0), Redeem::Invalid, "已使用");
    }

    /// 并发兑换同一个注册码：恰好一个成功。
    #[test]
    fn concurrent_redeem_succeeds_exactly_once() {
        let on = Arc::new(online());
        for round in 0..20 {
            let v = on.enroll_create(&format!("r{round}")).unwrap();
            let code = pm_net::enroll::EnrollUrl::parse(&v.url).unwrap().code;
            let barrier = Arc::new(std::sync::Barrier::new(16));
            let handles: Vec<_> = (0..16)
                .map(|i| {
                    let (on, code, barrier) = (on.clone(), code.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        on.enroll_redeem(&code, &format!("198.51.{round}.{i}"))
                    })
                })
                .collect();
            let results: Vec<Redeem> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert_eq!(results.iter().filter(|r| matches!(r, Redeem::Ok(_))).count(), 1, "{results:?}");
            assert_eq!(results.iter().filter(|r| **r == Redeem::Invalid).count(), 15);
        }
    }

    /// 失败次数限速：同一来源 10 次失败后锁定 15 分钟；锁定期间有效的注册码也不受理、不被消耗；其他来源不受影响。
    #[test]
    fn failed_redeems_are_rate_limited_per_source() {
        let on = online();
        let t0 = Instant::now();
        let v = on.enroll_create_at("laptop", t0).unwrap();
        let code = pm_net::enroll::EnrollUrl::parse(&v.url).unwrap().code;
        let bad = "A".repeat(43);
        for i in 0..ENROLL_MAX_FAILURES {
            assert_eq!(on.enroll_redeem_at(&bad, "198.51.100.66", t0 + Duration::from_secs(i as u64)), Redeem::Invalid);
        }
        let t1 = t0 + Duration::from_secs(20);
        assert_eq!(on.enroll_redeem_at(&code, "198.51.100.66", t1), Redeem::Blocked, "锁定中");
        assert!(on.enroll_peek_at(&code, t1).is_some(), "锁定时不消耗注册码");
        assert_eq!(on.enroll_redeem_at(&code, "198.51.100.66", t1 + ENROLL_LOCKOUT - Duration::from_secs(30)), Redeem::Blocked);
        let t2 = t0 + Duration::from_secs(9) + ENROLL_LOCKOUT + Duration::from_secs(1);
        let v2 = on.enroll_create_at("other", t2).unwrap();
        let code2 = pm_net::enroll::EnrollUrl::parse(&v2.url).unwrap().code;
        assert_eq!(on.enroll_redeem_at(&code2, "198.51.100.66", t2), Redeem::Ok("other".into()), "锁定结束");
        assert_eq!(on.enroll_redeem_at(&bad, "198.51.100.67", t1), Redeem::Invalid, "其他来源只计自己的失败");
    }

    fn layout(dir: &std::path::Path) -> pm_platform::Layout {
        pm_platform::Layout {
            mode: pm_platform::Mode::User,
            data_dir: dir.join("data"),
            run_dir: dir.join("run"),
            socket: dir.join("run/s"),
        }
    }

    fn cert_valid_for(days: i64) -> (String, String) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["pm.test".to_string()]).unwrap();
        let (y, m, d) = pm_web::civil((now() + days * 86400).div_euclid(86400));
        p.not_after = rcgen::date_time_ymd(y as i32, m as u8, d as u8);
        p.not_before = rcgen::date_time_ymd(2000, 1, 1);
        (p.self_signed(&key).unwrap().pem(), key.serialize_pem())
    }

    /// 续期失败不影响启动：已保存的证书只要没过期就装入使用；过期的不装入并给出提示。
    #[test]
    fn stored_certificate_is_used_while_valid() {
        let dir = tempfile::tempdir().unwrap();
        let l = layout(dir.path());
        let dk = [1u8; 32];
        let on = online();
        load_stored_cert_into(&l, &dk, &on);
        assert!(!on.certs.has_cert() && on.cert_state.lock().unwrap().error.is_none(), "还没有证书");
        let (c, k) = cert_valid_for(3);
        sf::store_cert(&l, &dk, &c, &k).unwrap();
        load_stored_cert_into(&l, &dk, &on);
        assert!(on.certs.has_cert(), "快到期（3 天）但仍有效：照常使用");
        assert!(on.cert_state.lock().unwrap().not_after.is_some());
        let on2 = online();
        let (c, k) = cert_valid_for(-1);
        sf::store_cert(&l, &dk, &c, &k).unwrap();
        load_stored_cert_into(&l, &dk, &on2);
        assert!(!on2.certs.has_cert());
        assert!(on2.cert_state.lock().unwrap().error.as_deref().unwrap().contains("过期"));
        let on3 = online();
        load_stored_cert_into(&l, &[2u8; 32], &on3);
        assert!(on3.cert_state.lock().unwrap().error.is_some(), "别的设备密钥解不开私钥");
    }

    /// 申请失败按退避处理：失败次数持久化；退避期内不再访问 CA；force 立即重试。
    #[tokio::test]
    async fn renewal_backoff_and_skips() {
        let dir = tempfile::tempdir().unwrap();
        let l = layout(dir.path());
        let dk = [1u8; 32];
        let certs = CertStore::new();
        let mut cfg = ServerConfig { domain: "pm.test".into(), acme_directory: String::new(), ..Default::default() };
        assert_eq!(renew_if_needed(&l, &cfg, &dk, &certs, false).await, Ok(false), "没有配置 ACME");
        // 证书还很新：不访问 CA。
        cfg.acme_directory = "http://127.0.0.1:1/dir".into();
        let (c, k) = cert_valid_for(80);
        sf::store_cert(&l, &dk, &c, &k).unwrap();
        assert_eq!(renew_if_needed(&l, &cfg, &dk, &certs, false).await, Ok(false));
        // 需要续期但没有 Cloudflare token：明确报错。
        let (c, k) = cert_valid_for(5);
        sf::store_cert(&l, &dk, &c, &k).unwrap();
        assert!(renew_if_needed(&l, &cfg, &dk, &certs, false).await.unwrap_err().contains("Cloudflare token"));
        // CA 连不上：失败计数 +1；退避期内直接返回，不再请求；force 立即重试。
        cfg.dns = "challtest:http://127.0.0.1:1".into();
        assert!(renew_if_needed(&l, &cfg, &dk, &certs, false).await.is_err());
        let st = sf::load_acme_state(&l);
        assert_eq!(st.failures, 1);
        let e = renew_if_needed(&l, &cfg, &dk, &certs, false).await.unwrap_err();
        assert!(e.contains("秒后重试"), "{e}");
        assert_eq!(sf::load_acme_state(&l).failures, 1, "退避期内没有发起请求");
        assert!(renew_if_needed(&l, &cfg, &dk, &certs, true).await.is_err());
        assert_eq!(sf::load_acme_state(&l).failures, 2);
    }

    /// 本机有 Pebble 时：经 renew_if_needed 签发，证书链明文、私钥与 ACME 账号用设备密钥封存保存；
    /// 重启后（新的 CertStore）从保存的文件装入；未到续期窗口时不再签发。
    #[tokio::test]
    async fn renewal_with_pebble_stores_sealed_files() {
        let Some(pb) = pm_net::acme::testing::Pebble::start().await else {
            eprintln!("跳过：没有 pebble");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let l = layout(dir.path());
        let dk = [7u8; 32];
        let cfg = ServerConfig {
            domain: "pm.passmanager.test".into(),
            acme_directory: pb.directory.clone(),
            acme_root_pem: Some(pb.root_pem.clone()),
            dns: format!("challtest:{}", pb.challtest),
            ..Default::default()
        };
        let certs = CertStore::new();
        assert_eq!(renew_if_needed(&l, &cfg, &dk, &certs, false).await, Ok(true));
        assert!(certs.has_cert());
        assert!(sf::load_acme_account(&l, &dk).is_some());
        assert!(!std::fs::read(sf::tls_key_path(&l)).unwrap().windows(11).any(|w| w == b"PRIVATE KEY"));
        assert_eq!(sf::load_acme_state(&l).failures, 0);
        let on = online();
        load_stored_cert_into(&l, &dk, &on);
        assert!(on.certs.has_cert());
        assert_eq!(renew_if_needed(&l, &cfg, &dk, &CertStore::new(), false).await, Ok(false));
    }

    #[test]
    fn lan_check_uses_configured_ranges() {
        let on = online();
        assert!(on.allowed("198.51.100.20".parse().unwrap()));
        assert!(!on.allowed("203.0.113.20".parse().unwrap()));
        assert!(on.allowed("127.0.0.1".parse().unwrap()), "本机回环总是允许（0.3.5 起）");
        assert!(!on.allowed("127.0.0.2".parse().unwrap()));
        assert!(on.allowed("::1".parse().unwrap()), "本机回环总是允许");
        assert!(!on.allowed("2001:db8::1".parse().unwrap()));
        assert_eq!(on.web_origin(), "https://pm.test");
    }

    /// 单端口模式（8121）：网页地址、注册码 URL 与接入说明里的一行命令都带端口；允许列表进入应用层检查。
    #[test]
    fn single_port_urls_and_allow_list() {
        let base = online();
        let mut cfg = base.cfg.clone();
        cfg.web_port = 8121;
        cfg.agent_port = 8121;
        cfg.allow = vec!["203.0.113.7".into(), "2001:db8::/32".into()];
        let on = Online::new(cfg, ServerKeys::from_parts(base.keys.bundle(), &base.keys.secret_bytes()).unwrap());
        assert_eq!(on.web_origin(), "https://pm.test:8121");
        let v = on.enroll_create("laptop").unwrap();
        assert!(v.url.starts_with("pm-enroll://pm.test:8121/"), "{}", v.url);
        let code = pm_net::enroll::EnrollUrl::parse(&v.url).unwrap().code;
        let text =
            pm_proto::agent_text::setup_text(pm_proto::agent_text::Lang::En, &on.web_origin(), &code, &v.url, &Default::default(), 10);
        assert!(text.contains(&format!("https://pm.test:8121/a/{code}")), "{text}");
        assert!(on.allowed("203.0.113.7".parse().unwrap()) && on.allowed("2001:db8::9".parse().unwrap()));
        assert!(on.allowed("198.51.100.20".parse().unwrap()) && !on.allowed("203.0.113.8".parse().unwrap()));
        // 默认端口：不写 :443；Agent 端口照常写。
        let d = online();
        assert!(d.enroll_create("x").unwrap().url.starts_with("pm-enroll://pm.test:8443/"));
    }
}

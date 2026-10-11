//! 外层 TLS 策略（网页与 Agent 通道共用）：
//! - 只允许 TLS 1.3；
//! - 密钥交换只允许"经典 ECDH + ML-KEM"混合组：X25519MLKEM768（Chrome、Safari、OpenSSL 3.5 默认）、SecP256r1MLKEM768；
//! - 只允许 TLS_AES_256_GCM_SHA384；
//! - 证书 ECDSA P-384（Let's Encrypt DNS-01）；不接受 0-RTT。
//!
//! 证书可热替换（续期后无需重启）。

use std::sync::{Arc, RwLock};

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self as prov, cipher_suite, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, NamedGroup, ServerConfig};

pub const HYBRID_GROUPS: [NamedGroup; 2] = [NamedGroup::X25519MLKEM768, NamedGroup::secp256r1MLKEM768];
pub const SUITE: rustls::CipherSuite = rustls::CipherSuite::TLS13_AES_256_GCM_SHA384;
/// Agent 通道的 ALPN（与网页端分开，避免把一个端口的连接转发到另一个端口还能成功握手）。
pub const ALPN_INNER: &[u8] = b"pm-inner/1";

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![kx_group::X25519MLKEM768, kx_group::SECP256R1MLKEM768],
        ..prov::default_provider()
    }
}

/// 可热替换的证书。
#[derive(Debug, Default)]
pub struct CertStore {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl CertStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_pem(&self, chain_pem: &str, key_pem: &str) -> Result<(), String> {
        use rustls::pki_types::pem::PemObject;
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(chain_pem.as_bytes()).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
        if chain.is_empty() {
            return Err("证书链为空".into());
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| e.to_string())?;
        let signing = prov::default_provider().key_provider.load_private_key(key).map_err(|e| e.to_string())?;
        let ck = CertifiedKey::new(chain, signing);
        // 私钥必须与证书匹配，否则握手时才出错。
        ck.keys_match().map_err(|e| format!("证书与私钥不匹配：{e}"))?;
        *self.current.write().unwrap() = Some(Arc::new(ck));
        Ok(())
    }

    pub fn has_cert(&self) -> bool {
        self.current.read().unwrap().is_some()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().unwrap().clone()
    }
}

/// 服务端配置。`alpn`：网页用 h2 + http/1.1，Agent 通道用 [`ALPN_INNER`]。
pub fn server_config(certs: Arc<CertStore>, alpn: &[&[u8]]) -> Arc<ServerConfig> {
    let mut c = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(certs);
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    c.max_early_data_size = 0; // 不接受 0-RTT（可重放）
    c.send_tls13_tickets = 2;
    Arc::new(c)
}

/// 启动自检：配置里的每个组都必须是混合后量子组，恰好一个指定的密码套件，不允许 0-RTT。
pub fn check_policy(c: &ServerConfig) -> Result<(), String> {
    let p = c.crypto_provider();
    if p.kx_groups.is_empty() {
        return Err("没有密钥交换组".into());
    }
    for g in &p.kx_groups {
        if !HYBRID_GROUPS.contains(&g.name()) {
            return Err(format!("不允许的密钥交换组 {:?}", g.name()));
        }
    }
    if p.cipher_suites.len() != 1 || p.cipher_suites[0].suite() != SUITE {
        return Err("密码套件不符合策略".into());
    }
    if c.max_early_data_size != 0 {
        return Err("不允许 0-RTT".into());
    }
    Ok(())
}

/// Agent 端（客户端）配置：同样的策略；信任 Mozilla 根证书（webpki-root-certs）与可选的额外 CA（测试用）。
pub fn client_config(extra_ca_pem: Option<&str>) -> Result<Arc<ClientConfig>, String> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    let (_ok, _bad) = roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
    if let Some(pem) = extra_ca_pem {
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(c.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        }
    }
    let mut c = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![ALPN_INNER.to_vec()];
    c.enable_early_data = false;
    Ok(Arc::new(c))
}

/// 连接协商结果是否符合策略（客户端在发送任何内层数据之前再确认一次）。
pub fn negotiated_ok(group: Option<NamedGroup>, suite: Option<rustls::CipherSuite>) -> bool {
    group.is_some_and(|g| HYBRID_GROUPS.contains(&g)) && suite == Some(SUITE)
}

/// 生成自签名证书（测试与导入前的占位）。返回 (证书 PEM, 私钥 PEM)。
pub fn self_signed(hosts: &[&str]) -> (String, String) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let params = rcgen::CertificateParams::new(hosts.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

/// 证书到期时间（Unix 秒）。
pub fn cert_not_after(chain_pem: &str) -> Option<i64> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes()).ok()?;
    let cert = pem.parse_x509().ok()?;
    Some(cert.validity().not_after.timestamp())
}

/// 显示用的名称：`Some(X25519MLKEM768)` → `X25519MLKEM768`。
pub fn short_name(s: String) -> String {
    s.trim_start_matches("Some(").trim_end_matches(')').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_passes_policy_and_variants_fail() {
        let cs = CertStore::new();
        let (c, k) = self_signed(&["pm.test"]);
        cs.set_pem(&c, &k).unwrap();
        assert!(cs.has_cert());
        check_policy(&server_config(cs.clone(), &[b"h2"])).unwrap();
        check_policy(&server_config(cs, &[ALPN_INNER])).unwrap();
        let mk = |p: CryptoProvider| {
            ServerConfig::builder_with_provider(Arc::new(p))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(CertStore::new())
        };
        assert!(
            check_policy(&mk(CryptoProvider { cipher_suites: vec![cipher_suite::TLS13_CHACHA20_POLY1305_SHA256], ..provider() })).is_err()
        );
        assert!(check_policy(&mk(CryptoProvider { kx_groups: vec![kx_group::X25519], ..provider() })).is_err());
        assert!(check_policy(&mk(CryptoProvider { kx_groups: vec![kx_group::MLKEM1024], ..provider() })).is_err(), "纯 ML-KEM 不是混合");
        let mut early = (*server_config(CertStore::new(), &[])).clone();
        early.max_early_data_size = 1024;
        assert!(check_policy(&early).is_err());
    }

    #[test]
    fn cert_store_rejects_garbage_and_mismatched_key() {
        let cs = CertStore::new();
        assert!(cs.set_pem("nope", "nope").is_err());
        let (c1, _) = self_signed(&["a.test"]);
        let (_, k2) = self_signed(&["b.test"]);
        assert!(cs.set_pem(&c1, &k2).is_err(), "私钥与证书不匹配");
        assert!(!cs.has_cert());
        assert!(cert_not_after(&c1).unwrap() > 0);
        assert!(cert_not_after("garbage").is_none());
    }

    #[test]
    fn client_config_and_negotiation_check() {
        let c = client_config(None).unwrap();
        assert_eq!(c.alpn_protocols, vec![ALPN_INNER.to_vec()]);
        let (pem, _) = self_signed(&["x.test"]);
        assert!(client_config(Some(&pem)).is_ok());
        assert!(client_config(Some("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")).is_err());
        assert!(negotiated_ok(Some(NamedGroup::X25519MLKEM768), Some(SUITE)));
        assert!(negotiated_ok(Some(NamedGroup::secp256r1MLKEM768), Some(SUITE)));
        assert!(!negotiated_ok(Some(NamedGroup::X25519), Some(SUITE)));
        assert!(!negotiated_ok(Some(NamedGroup::X25519MLKEM768), Some(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)));
        assert!(!negotiated_ok(None, None));
        assert_eq!(short_name("Some(X25519MLKEM768)".into()), "X25519MLKEM768");
    }
}

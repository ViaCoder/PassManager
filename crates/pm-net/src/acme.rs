//! Let's Encrypt DNS-01：通过 Cloudflare API 写 TXT 记录（服务器只在局域网可达，80/443 不对外）。
//! 证书私钥为 ECDSA P-384。与存储解耦：调用方负责持久化
//! （证书链明文、私钥与账号凭据用设备密钥封存，原子写入）。

use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME：{0}")]
    Acme(String),
    #[error("DNS：{0}")]
    Dns(String),
}

pub type Result<T> = std::result::Result<T, AcmeError>;

fn acme<E: std::fmt::Display>(e: E) -> AcmeError {
    AcmeError::Acme(e.to_string())
}

/// 错误及其全部 source 链（reqwest 的顶层错误只有"error sending request"）。
pub fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push('：');
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

/// DNS 提供方：生产用 Cloudflare，测试用 Pebble 的 challtestsrv。
pub enum Dns {
    Cloudflare { token: Zeroizing<String>, api: String },
    ChallTest { api: String },
}

pub const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

impl Dns {
    pub fn cloudflare(token: Zeroizing<String>) -> Self {
        Dns::Cloudflare { token, api: CLOUDFLARE_API.into() }
    }

    fn http() -> reqwest::Client {
        reqwest::Client::builder().timeout(Duration::from_secs(30)).build().expect("http client")
    }

    /// 区域名：取 FQDN 的最后两段（pm.example.com → example.com）。
    pub fn zone_of(fqdn: &str) -> String {
        let parts: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
        parts[parts.len().saturating_sub(2)..].join(".")
    }

    async fn cf(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value> {
        let Dns::Cloudflare { token, api } = self else { unreachable!() };
        let mut rb = Self::http().request(method, format!("{api}{path}")).bearer_auth(token.as_str());
        if let Some(b) = body {
            rb = rb.header("content-type", "application/json").body(b.to_string());
        }
        let r = rb.send().await.map_err(|e| AcmeError::Dns(chain(&e)))?;
        let text = r.text().await.map_err(|e| AcmeError::Dns(chain(&e)))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| AcmeError::Dns(format!("Cloudflare 响应不是 JSON：{e}")))?;
        if v["success"].as_bool() != Some(true) {
            return Err(AcmeError::Dns(format!("Cloudflare API 失败：{}", v["errors"])));
        }
        Ok(v)
    }

    async fn post_json(url: String, body: Value) -> Result<()> {
        Self::http()
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| AcmeError::Dns(chain(&e)))?;
        Ok(())
    }

    /// 写入 TXT 记录，返回删除时用的句柄。
    pub async fn set_txt(&self, fqdn: &str, value: &str) -> Result<String> {
        match self {
            Dns::Cloudflare { .. } => {
                let zone = Self::zone_of(fqdn);
                let z = self.cf(reqwest::Method::GET, &format!("/zones?name={zone}"), None).await?;
                let zid = z["result"][0]["id"]
                    .as_str()
                    .ok_or_else(|| AcmeError::Dns(format!("找不到区域 {zone}（检查 token 权限）")))?
                    .to_string();
                let r = self
                    .cf(
                        reqwest::Method::POST,
                        &format!("/zones/{zid}/dns_records"),
                        Some(json!({"type": "TXT", "name": fqdn, "content": value, "ttl": 60})),
                    )
                    .await?;
                let rid = r["result"]["id"].as_str().ok_or_else(|| AcmeError::Dns("缺少记录 id".into()))?;
                Ok(format!("{zid}/{rid}"))
            }
            Dns::ChallTest { api } => {
                Self::post_json(format!("{api}/set-txt"), json!({"host": format!("{fqdn}."), "value": value})).await?;
                Ok(fqdn.to_string())
            }
        }
    }

    pub async fn del_txt(&self, handle: &str) -> Result<()> {
        match self {
            Dns::Cloudflare { .. } => {
                let (zid, rid) = handle.split_once('/').ok_or_else(|| AcmeError::Dns("句柄无效".into()))?;
                self.cf(reqwest::Method::DELETE, &format!("/zones/{zid}/dns_records/{rid}"), None).await.map(|_| ())
            }
            Dns::ChallTest { api } => Self::post_json(format!("{api}/clear-txt"), json!({"host": format!("{handle}.")})).await,
        }
    }
}

pub struct AcmeCfg {
    pub directory: String,
    /// 测试时信任 Pebble 的自签根证书。
    pub root_pem: Option<std::path::PathBuf>,
    pub domain: String,
    /// 写入 TXT 后等待多久再通知 CA 验证（Cloudflare 一般几秒内全球生效）。
    pub propagation: Duration,
}

/// 签发结果。
pub struct Issued {
    pub chain_pem: String,
    pub key_pem: Zeroizing<String>,
    /// 新建账号时的凭据（JSON），调用方应封存保存；沿用旧账号时为 None。
    pub new_account: Option<Zeroizing<String>>,
}

/// CSR：主题为空（rcgen 默认的 CN 会被 Let's Encrypt 拒绝），域名只放在 SAN。
fn csr_der(domain: &str, key: &rcgen::KeyPair) -> Result<Vec<u8>> {
    let mut p = rcgen::CertificateParams::new(vec![domain.to_string()]).map_err(acme)?;
    p.distinguished_name = rcgen::DistinguishedName::new();
    Ok(p.serialize_request(key).map_err(acme)?.der().to_vec())
}

async fn account(cfg: &AcmeCfg, saved: Option<&str>) -> Result<(Account, Option<Zeroizing<String>>)> {
    let builder = || match &cfg.root_pem {
        Some(p) => Account::builder_with_root(p).map_err(acme),
        None => Account::builder().map_err(acme),
    };
    if let Some(raw) = saved
        && let Ok(creds) = serde_json::from_str::<AccountCredentials>(raw)
        && let Ok(a) = builder()?.from_credentials(creds).await
    {
        return Ok((a, None));
    }
    let (a, creds) = builder()?
        .create(&NewAccount { contact: &[], terms_of_service_agreed: true, only_return_existing: false }, cfg.directory.clone(), None)
        .await
        .map_err(acme)?;
    Ok((a, Some(Zeroizing::new(serde_json::to_string(&creds).map_err(acme)?))))
}

/// 签发证书：DNS-01，P-384 私钥。`saved_account` 为之前保存的账号凭据（JSON）。
pub async fn issue(cfg: &AcmeCfg, dns: &Dns, saved_account: Option<&str>) -> Result<Issued> {
    let (acct, new_account) = account(cfg, saved_account).await?;
    let ids = [Identifier::Dns(cfg.domain.clone())];
    let mut order = acct.new_order(&NewOrder::new(&ids)).await.map_err(acme)?;
    let mut handles = Vec::new();
    let setup: Result<()> = async {
        let mut auths = order.authorizations();
        while let Some(a) = auths.next().await {
            let mut a = a.map_err(acme)?;
            match a.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                s => return Err(AcmeError::Acme(format!("授权状态 {s:?}"))),
            }
            let mut ch = a.challenge(ChallengeType::Dns01).ok_or_else(|| AcmeError::Acme("没有 dns-01 挑战".into()))?;
            let fqdn = format!("_acme-challenge.{}", cfg.domain);
            handles.push(dns.set_txt(&fqdn, &ch.key_authorization().dns_value()).await?);
            tokio::time::sleep(cfg.propagation).await;
            ch.set_ready().await.map_err(acme)?;
        }
        Ok(())
    }
    .await;
    let result = async {
        setup?;
        let st = order.poll_ready(&RetryPolicy::default()).await.map_err(acme)?;
        if st != OrderStatus::Ready {
            return Err(AcmeError::Acme(format!("订单状态 {st:?}")));
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).map_err(acme)?;
        let csr = csr_der(&cfg.domain, &key)?;
        order.finalize_csr(&csr).await.map_err(acme)?;
        let chain = order.poll_certificate(&RetryPolicy::default()).await.map_err(acme)?;
        Ok((chain, Zeroizing::new(key.serialize_pem())))
    }
    .await;
    // 无论成败都清理 TXT 记录。
    for h in handles {
        let _ = dns.del_txt(&h).await;
    }
    let (chain_pem, key_pem) = result?;
    Ok(Issued { chain_pem, key_pem, new_account })
}

/// 是否需要（重新）签发：没有证书、无法解析、已过期或剩余有效期不足 `renew_days` 天。
pub fn needs_renewal(chain_pem: Option<&str>, now: i64, renew_days: u32) -> bool {
    match chain_pem.and_then(crate::tls::cert_not_after) {
        Some(t) => t - now <= renew_days as i64 * 86400,
        None => true,
    }
}

/// 证书仍然有效（未过期）：续期失败时可以先用它启动。
pub fn still_valid(chain_pem: &str, now: i64) -> bool {
    crate::tls::cert_not_after(chain_pem).is_some_and(|t| t > now)
}

/// 失败后的退避：10 分钟起每次翻倍，最多 6 小时（避免反复请求 Let's Encrypt 触发限速）。
pub fn backoff_secs(consecutive_failures: u32) -> u64 {
    (600u64 << consecutive_failures.min(6)).min(6 * 3600)
}

/// 测试工具：本机有 Pebble（`~/.local/opt/pebble`）时启动 Pebble + challtestsrv。
#[cfg(any(test, feature = "test-hooks"))]
pub mod testing {
    use std::path::PathBuf;
    use std::time::Duration;

    pub struct Pebble {
        pub directory: String,
        pub root_pem: PathBuf,
        /// challtestsrv 管理接口（`Dns::ChallTest` / `challtest:<url>`）。
        pub challtest: String,
        _procs: Vec<Kill>,
        _dir: tempfile::TempDir,
    }

    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    impl Pebble {
        pub async fn start() -> Option<Self> {
            let dir = PathBuf::from(std::env::var_os("HOME")?).join(".local/opt/pebble");
            if !dir.join("pebble").exists() || !dir.join("pebble-challtestsrv").exists() {
                return None;
            }
            let (acme_port, mgmt, dns_port, cts_mgmt) = (free_port(), free_port(), free_port(), free_port());
            let t = tempfile::tempdir().ok()?;
            let cfg = serde_json::json!({"pebble": {
                "listenAddress": format!("127.0.0.1:{acme_port}"), "managementListenAddress": format!("127.0.0.1:{mgmt}"),
                "certificate": dir.join("test/certs/localhost/cert.pem"), "privateKey": dir.join("test/certs/localhost/key.pem"),
                "httpPort": 5002, "tlsPort": 5001, "ocspResponderURL": "", "externalAccountBindingRequired": false,
                "keyAlgorithm": "ecdsa", "profiles": {"default": {"description": "d", "validityPeriod": 7776000}}}});
            std::fs::write(t.path().join("pebble.json"), cfg.to_string()).ok()?;
            let null = std::process::Stdio::null;
            let cts = Kill(
                std::process::Command::new(dir.join("pebble-challtestsrv"))
                    .args(["-dnsserver", &format!("127.0.0.1:{dns_port}"), "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""])
                    .args(["-management", &format!("127.0.0.1:{cts_mgmt}")])
                    .stdout(null())
                    .stderr(null())
                    .spawn()
                    .ok()?,
            );
            let pebble = Kill(
                std::process::Command::new(dir.join("pebble"))
                    .args(["-config", t.path().join("pebble.json").to_str()?, "-dnsserver", &format!("127.0.0.1:{dns_port}")])
                    .env("PEBBLE_VA_NOSLEEP", "1")
                    .env("PEBBLE_WFE_NONCEREJECT", "0")
                    .env("PEBBLE_AUTHZREUSE", "0")
                    .stdout(null())
                    .stderr(null())
                    .spawn()
                    .ok()?,
            );
            for _ in 0..100 {
                if std::net::TcpStream::connect(("127.0.0.1", acme_port)).is_ok()
                    && std::net::TcpStream::connect(("127.0.0.1", cts_mgmt)).is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Some(Self {
                directory: format!("https://127.0.0.1:{acme_port}/dir"),
                root_pem: dir.join("test/certs/pebble.minica.pem"),
                challtest: format!("http://127.0.0.1:{cts_mgmt}"),
                _procs: vec![pebble, cts],
                _dir: t,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{delete, get, post};
    use std::sync::{Arc, Mutex};

    fn now() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
    }

    fn cert_valid_for(days: i64) -> String {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["pm.test".to_string()]).unwrap();
        let (y, m, d) = civil((now() + days * 86400).div_euclid(86400));
        p.not_after = rcgen::date_time_ymd(y as i32, m as u8, d as u8);
        p.not_before = rcgen::date_time_ymd(2000, 1, 1);
        p.self_signed(&key).unwrap().pem()
    }

    /// 天数（自 1970-01-01）→ 公历日期。
    fn civil(z: i64) -> (i64, u32, u32) {
        let z = z + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let y = yoe + era * 400;
        (if m <= 2 { y + 1 } else { y }, m, d)
    }

    #[test]
    fn renewal_decisions() {
        let n = now();
        assert!(needs_renewal(None, n, 30));
        assert!(needs_renewal(Some("garbage"), n, 30));
        let c10 = cert_valid_for(10);
        assert!(needs_renewal(Some(&c10), n, 30), "剩 10 天，窗口 30 天");
        assert!(!needs_renewal(Some(&c10), n, 5));
        assert!(still_valid(&c10, n), "续期失败时仍可用来启动");
        let expired = cert_valid_for(-2);
        assert!(!still_valid(&expired, n));
        assert!(needs_renewal(Some(&expired), n, 0));
        assert_eq!(backoff_secs(0), 600);
        assert_eq!(backoff_secs(1), 1200);
        assert_eq!(backoff_secs(5), 19_200);
        assert_eq!(backoff_secs(6), 6 * 3600);
        assert_eq!(backoff_secs(1000), 6 * 3600);
    }

    #[test]
    fn csr_has_empty_subject_and_only_the_domain_san() {
        use x509_parser::prelude::*;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let der = csr_der("pm.example.com", &key).unwrap();
        let (_, csr) = X509CertificationRequest::from_der(&der).unwrap();
        assert_eq!(csr.certification_request_info.subject.iter_attributes().count(), 0);
        let mut sans = Vec::new();
        for ext in csr.requested_extensions().unwrap() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for n in &san.general_names {
                    sans.push(format!("{n:?}"));
                }
            }
        }
        assert_eq!(sans, vec!["DNSName(\"pm.example.com\")".to_string()]);
    }

    #[test]
    fn zone() {
        assert_eq!(Dns::zone_of("_acme-challenge.pm.example.com"), "example.com");
        assert_eq!(Dns::zone_of("example.com."), "example.com");
    }

    /// 用本地假 Cloudflare API 检查请求格式（Bearer token、区域查找、TXT 创建与删除）。
    #[tokio::test]
    async fn cloudflare_requests() {
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let (l1, l2, l3) = (log.clone(), log.clone(), log.clone());
        let app = axum::Router::new()
            .route(
                "/zones",
                get(move |h: axum::http::HeaderMap, q: axum::extract::RawQuery| async move {
                    l1.lock().unwrap().push(format!("GET zones {} {}", q.0.unwrap_or_default(), h["authorization"].to_str().unwrap()));
                    axum::Json(json!({"success": true, "result": [{"id": "Z1"}]}))
                }),
            )
            .route(
                "/zones/Z1/dns_records",
                post(move |axum::Json(b): axum::Json<Value>| async move {
                    l2.lock().unwrap().push(format!("POST {} {} {}", b["type"], b["name"], b["content"]));
                    axum::Json(json!({"success": true, "result": {"id": "R9"}}))
                }),
            )
            .route(
                "/zones/Z1/dns_records/R9",
                delete(move || async move {
                    l3.lock().unwrap().push("DELETE R9".into());
                    axum::Json(json!({"success": true, "result": {}}))
                }),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let dns = Dns::Cloudflare { token: Zeroizing::new("tok".into()), api: format!("http://127.0.0.1:{port}") };
        let h = dns.set_txt("_acme-challenge.pm.example.com", "VAL").await.unwrap();
        assert_eq!(h, "Z1/R9");
        dns.del_txt(&h).await.unwrap();
        assert!(dns.del_txt("no-slash").await.is_err());
        let log = log.lock().unwrap();
        assert_eq!(log[0], "GET zones name=example.com Bearer tok");
        assert_eq!(log[1], "POST \"TXT\" \"_acme-challenge.pm.example.com\" \"VAL\"");
        assert_eq!(log[2], "DELETE R9");
    }

    #[tokio::test]
    async fn cloudflare_error_is_reported() {
        let app = axum::Router::new()
            .route("/zones", get(|| async { axum::Json(json!({"success": false, "errors": [{"message": "bad token"}]})) }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let dns = Dns::Cloudflare { token: Zeroizing::new("x".into()), api: format!("http://127.0.0.1:{port}") };
        let e = dns.set_txt("a.example.com", "v").await.unwrap_err().to_string();
        assert!(e.contains("bad token"), "{e}");
        // 连不上（服务没启动）也只是返回错误。
        let dead = Dns::Cloudflare { token: Zeroizing::new("x".into()), api: "http://127.0.0.1:1".into() };
        assert!(dead.set_txt("a.example.com", "v").await.is_err());
    }

    /// 本机有 Pebble（Let's Encrypt 官方测试 CA）时：DNS-01 完整签发一次，并复用保存的账号再签一次。
    #[tokio::test]
    async fn pebble_dns01_end_to_end() {
        let Some(pb) = testing::Pebble::start().await else {
            eprintln!("跳过：没有 pebble");
            return;
        };
        let cfg = AcmeCfg {
            directory: pb.directory.clone(),
            root_pem: Some(pb.root_pem.clone()),
            domain: "pm.passmanager.test".into(),
            propagation: Duration::ZERO,
        };
        let dns = Dns::ChallTest { api: pb.challtest.clone() };
        let first = issue(&cfg, &dns, None).await.unwrap();
        let acct = first.new_account.clone().expect("新账号凭据");
        assert!(first.key_pem.contains("PRIVATE KEY"));
        assert!(!needs_renewal(Some(&first.chain_pem), now(), 30));
        let (_, p) = x509_parser::pem::parse_x509_pem(first.chain_pem.as_bytes()).unwrap();
        let c = p.parse_x509().unwrap();
        assert!(format!("{:?}", c.subject_alternative_name().unwrap().unwrap().value).contains("pm.passmanager.test"));
        crate::tls::CertStore::new().set_pem(&first.chain_pem, &first.key_pem).unwrap();
        // 复用保存的账号：不再新建。
        let second = issue(&cfg, &dns, Some(&acct)).await.unwrap();
        assert!(second.new_account.is_none());
        assert_ne!(second.chain_pem, first.chain_pem);
    }
}

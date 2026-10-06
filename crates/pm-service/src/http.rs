//! HTTPS 执行器。
//!
//! - 只支持 HTTPS；不跟随跨主机重定向。
//! - 请求中必须至少引用一个 `{{name}}`，且 URL 主机必须匹配所有被引用条目的域名。
//! - 自签证书条目：不走公共 CA，改为固定服务器证书公钥（SPKI）的 SHA-256，首次连接时记录。
//! - 响应删除 Set-Cookie 与认证类头，正文与头部都经过脱敏。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use pm_proto::HttpResult;
use pm_vault::{AUTO_PLACEHOLDER, Entry, Payload, domain};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::redact::Redactor;
use crate::template;
use crate::{ApiErr, err};

const MAX_BODY: usize = 10 * 1024 * 1024;
const PIN_MARKER: &str = "PM_PIN_MISMATCH";
const STRIP_HEADERS: &[&str] =
    &["set-cookie", "set-cookie2", "authorization", "proxy-authorization", "authentication-info", "proxy-authentication-info"];
const ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// URL 中替换密钥时使用的编码集（保留 RFC 3986 unreserved 字符）。
const URL_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

pub struct Prepared {
    method: reqwest::Method,
    url: Url,
    headers: Vec<(String, Zeroizing<String>)>,
    body: Option<Zeroizing<String>>,
    pub host: String,
    pub port: u16,
    pub self_signed: bool,
    pub names: Vec<String>,
}

impl Prepared {
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn host_string(u: &Url) -> Option<String> {
    Some(match u.host()? {
        Host::Domain(d) => domain::normalize_host(d),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    })
}

/// 按主机选出唯一匹配的凭据。
pub fn select_by_host<'a>(payload: &'a Payload, host: &str) -> Result<&'a Entry, ApiErr> {
    let m: Vec<&Entry> = payload.entries.iter().filter(|e| domain::matches_any(&e.domains, host)).collect();
    match m.as_slice() {
        [one] => Ok(one),
        [] => Err(err("NO_CREDENTIAL", format!("no stored credential for {host}. Ask the user to add one in PassManager."))),
        many => Err(err(
            "AMBIGUOUS",
            format!(
                "several credentials match {host}: {}. Pick one by name (see list for notes).",
                many.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")
            ),
        )),
    }
}

/// 按引用名或主机选择凭据，并确认它允许用于该主机。
pub fn select(payload: &Payload, name: Option<&str>, host: &str) -> Result<Entry, ApiErr> {
    let e = match name {
        None => select_by_host(payload, host)?,
        Some(n) if n == AUTO_PLACEHOLDER => select_by_host(payload, host)?,
        Some(n) => payload.entry(n).ok_or_else(|| err("UNKNOWN_CREDENTIAL", format!("no credential \"{n}\"")))?,
    };
    if !domain::matches_any(&e.domains, host) {
        return Err(err("DOMAIN_MISMATCH", format!("\"{}\" only works with {}", e.name, e.domains.join(", "))));
    }
    Ok(e.clone())
}

fn collect_names(url: &str, headers: &[(String, String)], body: Option<&str>) -> Vec<String> {
    let mut names = template::find_names(url);
    let more = headers
        .iter()
        .flat_map(|(k, v)| template::find_names(k).into_iter().chain(template::find_names(v)))
        .chain(body.map(template::find_names).unwrap_or_default());
    for n in more {
        if !names.contains(&n) {
            names.push(n);
        }
    }
    names
}

/// 校验请求并代入密钥（需要已解锁的载荷）。
/// `{{secret}}` 按 URL 主机自动选择凭据；`{{引用名}}` 指定凭据（同一主机有多个凭据时使用）。
pub fn prepare(payload: &Payload, method: &str, url: &str, headers: &[(String, String)], body: Option<&str>) -> Result<Prepared, ApiErr> {
    let method_up = method.trim().to_ascii_uppercase();
    if !ALLOWED_METHODS.contains(&method_up.as_str()) {
        return Err(err("BAD_REQUEST", format!("unsupported HTTP method {method}")));
    }
    let names = collect_names(url, headers, body);
    if names.is_empty() {
        return Err(err(
            "BAD_REQUEST",
            "No {{secret}} placeholder found. Put {{secret}} where the secret belongs (header, body or query). For requests that need no secret, use your normal HTTP tools.",
        ));
    }

    // 先用占位符的"哑值"解析 URL，确定协议、主机与端口（禁止在主机部分使用占位符）。
    let dummy = template::substitute(url, |_| Some("pmph".into())).unwrap_or_default();
    let parsed = Url::parse(&dummy).map_err(|e| err("BAD_REQUEST", format!("invalid URL: {e}")))?;
    if parsed.scheme() == "http" {
        return Err(err("USE_HTTPS", "plain HTTP is not supported; use an https:// URL"));
    }
    if parsed.scheme() != "https" {
        return Err(err("USE_HTTPS", format!("unsupported URL scheme {}; use https://", parsed.scheme())));
    }
    let host = host_string(&parsed).ok_or_else(|| err("BAD_REQUEST", "URL has no host"))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(err("BAD_REQUEST", "credentials in the URL authority are not allowed; use a header or query placeholder"));
    }

    let mut resolved: Vec<(String, Entry)> = Vec::new();
    for n in &names {
        resolved.push((n.clone(), select(payload, Some(n), &host)?));
    }
    let lookup = |n: &str| resolved.iter().find(|(p, _)| p == n).map(|(_, e)| e.secret.to_string());
    let real_url = Zeroizing::new(
        template::substitute(url, |n| lookup(n).map(|s| percent_encoding::utf8_percent_encode(&s, URL_ENCODE).to_string()))
            .map_err(|n| err("UNKNOWN_CREDENTIAL", format!("no credential \"{n}\"")))?,
    );
    let real = Url::parse(&real_url).map_err(|_| err("BAD_REQUEST", "invalid URL after substitution"))?;
    if real.scheme() != "https" || host_string(&real).as_deref() != Some(host.as_str()) || real.port_or_known_default() != Some(port) {
        return Err(err("BAD_REQUEST", "placeholders are not allowed in the URL scheme, host or port"));
    }
    let mut hs = Vec::new();
    for (k, v) in headers {
        let k2 = template::substitute(k, lookup).map_err(|n| err("UNKNOWN_CREDENTIAL", n))?;
        let v2 = Zeroizing::new(template::substitute(v, lookup).map_err(|n| err("UNKNOWN_CREDENTIAL", n))?);
        if k2.contains(['\r', '\n']) || v2.contains(['\r', '\n']) {
            return Err(err("BAD_REQUEST", "header names/values must not contain line breaks"));
        }
        hs.push((k2, v2));
    }
    let body = match body {
        Some(b) => Some(Zeroizing::new(template::substitute(b, lookup).map_err(|n| err("UNKNOWN_CREDENTIAL", n))?)),
        None => None,
    };
    Ok(Prepared {
        method: reqwest::Method::from_bytes(method_up.as_bytes()).map_err(|_| err("BAD_REQUEST", "bad method"))?,
        url: real,
        headers: hs,
        body,
        host,
        port,
        self_signed: resolved.iter().any(|(_, e)| e.self_signed),
        names: resolved.iter().map(|(_, e)| e.name.clone()).collect(),
    })
}

// ---- 证书指纹固定 ----

/// (tag, 完整 TLV, 内容, 剩余)
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn der_next(buf: &[u8]) -> Option<Tlv<'_>> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let (len, hdr) = if buf[1] & 0x80 == 0 {
        (buf[1] as usize, 2)
    } else {
        let n = (buf[1] & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut l = 0usize;
        for b in &buf[2..2 + n] {
            l = (l << 8) | *b as usize;
        }
        (l, 2 + n)
    };
    if buf.len() < hdr + len {
        return None;
    }
    Some((tag, &buf[..hdr + len], &buf[hdr..hdr + len], &buf[hdr + len..]))
}

/// 提取证书中的 SubjectPublicKeyInfo（完整 DER）。
pub fn spki(cert: &[u8]) -> Option<&[u8]> {
    let (_, _, cert_body, _) = der_next(cert)?;
    let (_, _, tbs, _) = der_next(cert_body)?;
    let mut rest = tbs;
    let (tag, _, _, r) = der_next(rest)?;
    rest = if tag == 0xa0 { r } else { tbs };
    // serial, signature, issuer, validity, subject
    for _ in 0..5 {
        rest = der_next(rest)?.3;
    }
    let (tag, full, _, _) = der_next(rest)?;
    (tag == 0x30).then_some(full)
}

pub fn spki_fingerprint(cert: &[u8]) -> String {
    let data = spki(cert).unwrap_or(cert);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(pm_crypto::sha256(data)))
}

#[derive(Debug)]
struct PinVerifier {
    expected: Option<String>,
    observed: Arc<Mutex<Option<String>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = spki_fingerprint(end_entity.as_ref());
        *self.observed.lock().unwrap() = Some(fp.clone());
        match &self.expected {
            Some(exp) if *exp != fp => Err(rustls::Error::General(PIN_MARKER.into())),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub enum Outcome {
    Done { result: HttpResult, observed_pin: Option<String> },
    PinMismatch { observed: String },
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

/// 执行请求（不持有库锁）。`expected_pin` 仅用于自签证书条目。
pub async fn execute(p: Prepared, expected_pin: Option<String>, redactor: &Redactor) -> Result<Outcome, ApiErr> {
    let orig_host = p.host.clone();
    let orig_port = p.port;
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.stop();
        }
        let u = attempt.url();
        if u.scheme() == "https" && host_string(u).as_deref() == Some(orig_host.as_str()) && u.port_or_known_default() == Some(orig_port) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    let mut builder = reqwest::Client::builder()
        .redirect(policy)
        .https_only(true)
        .no_proxy()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(180))
        .user_agent(concat!("PassManager/", env!("CARGO_PKG_VERSION")));
    let observed = Arc::new(Mutex::new(None));
    if p.self_signed {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = PinVerifier { expected: expected_pin.clone(), observed: observed.clone(), provider: provider.clone() };
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| err("INTERNAL", e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        builder = builder.tls_backend_preconfigured(cfg);
    }
    let client = builder.build().map_err(|e| err("INTERNAL", format!("http client: {e}")))?;
    let mut rb = client.request(p.method.clone(), p.url.clone());
    for (k, v) in &p.headers {
        rb = rb.header(k.as_str(), v.as_str());
    }
    if let Some(b) = &p.body {
        rb = rb.body(b.to_string());
    }
    let resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            let chain = error_chain(&e);
            if chain.contains(PIN_MARKER) {
                let obs = observed.lock().unwrap().clone().unwrap_or_default();
                return Ok(Outcome::PinMismatch { observed: obs });
            }
            let msg = redactor.redact_str(&error_chain(&e.without_url()));
            return Err(err("UPSTREAM_ERROR", format!("request to {} failed: {msg}", p.host)));
        }
    };
    let status = resp.status().as_u16();
    let mut headers = Vec::new();
    for (k, v) in resp.headers() {
        let name = k.as_str().to_ascii_lowercase();
        if STRIP_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let val = String::from_utf8_lossy(v.as_bytes());
        headers.push((name, redactor.redact_str(&val)));
    }
    let mut resp = resp;
    let mut body = Vec::new();
    let mut truncated = false;
    loop {
        match resp.chunk().await {
            Ok(Some(c)) => {
                if body.len() + c.len() > MAX_BODY {
                    body.extend_from_slice(&c[..MAX_BODY - body.len()]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&c);
            }
            Ok(None) => break,
            Err(e) => {
                let msg = redactor.redact_str(&error_chain(&e.without_url()));
                return Err(err("UPSTREAM_ERROR", format!("reading response failed: {msg}")));
            }
        }
    }
    let (body, _n) = redactor.redact(&body);
    let (body, body_base64) = match String::from_utf8(body) {
        Ok(s) => (s, false),
        Err(e) => (STANDARD.encode(e.into_bytes()), true),
    };
    let observed_pin = observed.lock().unwrap().clone();
    Ok(Outcome::Done { result: HttpResult { status, headers, body, body_base64, truncated }, observed_pin })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pm_vault::Entry;

    fn payload() -> Payload {
        let mut p = Payload::default();
        p.entries.push(Entry {
            name: "github".into(),
            secret: Zeroizing::new("tok/en?&=1".into()),
            domains: vec!["*.github.com".into()],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
        });
        p
    }

    #[test]
    fn prepare_rules() {
        let p = payload();
        let ok =
            prepare(&p, "get", "https://api.github.com/user?t={{github}}", &[("Authorization".into(), "Bearer {{github}}".into())], None)
                .unwrap();
        assert_eq!(ok.host, "api.github.com");
        assert_eq!(ok.url.query(), Some("t=tok%2Fen%3F%26%3D1"));
        assert_eq!(ok.headers[0].1.as_str(), "Bearer tok/en?&=1");
        let e = |r: Result<Prepared, ApiErr>| r.err().unwrap().code;
        assert_eq!(e(prepare(&p, "GET", "http://api.github.com/{{github}}", &[], None)), "USE_HTTPS");
        assert_eq!(e(prepare(&p, "GET", "https://evil.com/{{github}}", &[], None)), "DOMAIN_MISMATCH");
        assert_eq!(e(prepare(&p, "GET", "https://github.com.evil.com/{{github}}", &[], None)), "DOMAIN_MISMATCH");
        assert_eq!(e(prepare(&p, "GET", "https://{{github}}.github.com/", &[], None)), "BAD_REQUEST");
        assert_eq!(e(prepare(&p, "GET", "https://api.github.com/", &[], None)), "BAD_REQUEST");
        assert_eq!(e(prepare(&p, "GET", "https://api.github.com/{{nope}}", &[], None)), "UNKNOWN_CREDENTIAL");
        assert_eq!(e(prepare(&p, "GET", "https://x:{{github}}@api.github.com/", &[], None)), "BAD_REQUEST");
        assert_eq!(e(prepare(&p, "TRACE", "https://api.github.com/{{github}}", &[], None)), "BAD_REQUEST");
    }
}

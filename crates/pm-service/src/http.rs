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
    /// URL 以占位符开头（例如 `{{ai.base_url}}`）时，对 Agent 的消息与日志用这个占位符代替真实的主机。
    pub label: Option<String>,
}

impl Prepared {
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub(crate) fn host_string(u: &Url) -> Option<String> {
    Some(match u.host()? {
        Host::Domain(d) => domain::normalize_host(d),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    })
}

/// 匹配主机与端口、允许该用途、且满足 `filter` 的条目中最具体的那个（见 `domain::Spec`）。
/// 同样具体的有多个时报 AMBIGUOUS（只列出引用名，不含任何密钥内容）。
pub fn best_entry<'a>(
    payload: &'a Payload,
    host: &str,
    port: u16,
    op: &str,
    filter: impl Fn(&Entry) -> bool,
) -> Result<Option<&'a Entry>, ApiErr> {
    let mut best: Option<domain::Spec> = None;
    let mut tied: Vec<&Entry> = Vec::new();
    for e in payload.entries.iter().filter(|e| e.allows(op) && filter(e)) {
        let Some(s) = domain::best_match(&e.domains, host, Some(port)) else { continue };
        match best {
            Some(b) if s < b => {}
            Some(b) if s == b => tied.push(e),
            _ => {
                best = Some(s);
                tied = vec![e];
            }
        }
    }
    match tied.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        many => Err(err(
            "AMBIGUOUS",
            format!(
                "several credentials match {host} equally well: {}",
                many.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")
            ),
        )),
    }
}

/// 没有可用条目时的错误：区分"没有"与"有，但不允许这种用途"。
fn none_err(payload: &Payload, host: &str, port: u16, op: &str) -> ApiErr {
    if payload.entries.iter().any(|e| !e.allows(op) && domain::matches_any_port(&e.domains, host, port)) {
        return err("OP_NOT_ALLOWED", format!("the stored credential for {host} may not be used for {op} requests"));
    }
    // 只陈述事实；下一步（导入或告诉用户）由客户端附加的 Next: 说明。
    err("NO_CREDENTIAL", format!("no stored credential for {host}"))
}

/// 按主机选出最具体的凭据。
pub fn select_by_host<'a>(payload: &'a Payload, host: &str, port: u16, op: &str) -> Result<&'a Entry, ApiErr> {
    best_entry(payload, host, port, op, |_| true)?.ok_or_else(|| none_err(payload, host, port, op))
}

fn check_domain(e: &Entry, host: &str, port: u16, op: &str) -> Result<(), ApiErr> {
    if e.domains.is_empty() {
        return Err(err("DOMAIN_MISMATCH", format!("\"{}\" is not bound to any domain yet", e.name)));
    }
    if !domain::matches_any_port(&e.domains, host, port) {
        // 不列出条目绑定的其他域名（Agent 只需要知道"不能用于这个主机"）。
        return Err(err("DOMAIN_MISMATCH", format!("\"{}\" is not bound to {host}", e.name)));
    }
    if !e.allows(op) {
        return Err(err("OP_NOT_ALLOWED", format!("\"{}\" may not be used for {op} requests", e.name)));
    }
    Ok(())
}

/// 按引用名或主机选择凭据，并确认它允许用于该主机、端口与用途。
pub fn select(payload: &Payload, name: Option<&str>, host: &str, port: u16, op: &str) -> Result<Entry, ApiErr> {
    let e = match name {
        None => select_by_host(payload, host, port, op)?,
        Some(n) if n == AUTO_PLACEHOLDER => select_by_host(payload, host, port, op)?,
        Some(n) => payload.entry(n).ok_or_else(|| err("UNKNOWN_CREDENTIAL", format!("no credential \"{n}\"")))?,
    };
    check_domain(e, host, port, op)?;
    Ok(e.clone())
}

/// SSH 登录用的凭据：（私钥条目，口令条目）。
/// 没有指定引用名时：私钥条目与口令条目各取最具体的一个；先用私钥认证，服务器仍提供口令方式时再用口令。
/// 有私钥条目时，口令条目的歧义不算错误（只是不再回退到口令）。
pub fn ssh_credentials(payload: &Payload, name: Option<&str>, host: &str, port: u16) -> Result<(Option<Entry>, Option<Entry>), ApiErr> {
    let op = pm_vault::OP_SSH;
    if let Some(n) = name.filter(|n| *n != AUTO_PLACEHOLDER) {
        let e = select(payload, Some(n), host, port, op)?;
        return Ok(if e.is_private_key() { (Some(e), None) } else { (None, Some(e)) });
    }
    let key = best_entry(payload, host, port, op, |e| e.is_private_key())?;
    let pw = best_entry(payload, host, port, op, |e| !e.is_private_key() && e.password().is_some_and(|p| !p.is_empty()));
    let pw = if key.is_some() { pw.ok().flatten() } else { pw? };
    if key.is_none() && pw.is_none() {
        // 例如只有没有 password 字段的多字段条目：沿用原来的选择（之后认证会被拒绝）。
        let e = select_by_host(payload, host, port, op)?;
        return Ok((None, Some(e.clone())));
    }
    Ok((key.cloned(), pw.cloned()))
}

fn has_fields_error(e: &Entry) -> ApiErr {
    err(
        "BAD_REQUEST",
        format!(
            "\"{}\" has fields ({}); write {{{{{}.<field>}}}} (or {{{{<field>}}}} when only this credential matches the host)",
            e.name,
            e.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", "),
            e.name
        ),
    )
}

/// 占位符解析结果：条目，以及字段名（None 表示整个单值密钥）。
pub struct Resolved {
    pub entry: Entry,
    pub field: Option<String>,
}

impl Resolved {
    pub fn value(&self) -> Zeroizing<String> {
        match &self.field {
            None => self.entry.secret.clone(),
            Some(f) => self.entry.field(f).map(|x| x.value.clone()).unwrap_or_default(),
        }
    }
}

/// 解析占位符 `token`（目标主机与端口已知）：
/// - `secret`：按主机自动选择的单值凭据（多字段条目报错，提示写字段名）；
/// - `<引用名>`：指定的单值凭据；
/// - `<引用名>.<字段>`：指定条目的字段（引用名本身可以含点，取最长匹配）；
/// - `<字段>`：只有一个条目匹配该主机时，该条目的字段。
///
/// 错误信息不会列出其他条目的字段。
pub fn resolve(payload: &Payload, token: &str, host: &str, port: u16, op: &str) -> Result<Resolved, ApiErr> {
    if token == AUTO_PLACEHOLDER {
        let e = select_by_host(payload, host, port, op)?;
        if !e.fields.is_empty() {
            return Err(has_fields_error(e));
        }
        return Ok(Resolved { entry: e.clone(), field: None });
    }
    if let Some(e) = payload.entry(token) {
        check_domain(e, host, port, op)?;
        if !e.fields.is_empty() {
            return Err(has_fields_error(e));
        }
        return Ok(Resolved { entry: e.clone(), field: None });
    }
    let mut by_prefix: Vec<&Entry> =
        payload.entries.iter().filter(|e| token.len() > e.name.len() + 1 && token.starts_with(&format!("{}.", e.name))).collect();
    by_prefix.sort_by_key(|e| std::cmp::Reverse(e.name.len()));
    if let Some(e) = by_prefix.first() {
        let field = &token[e.name.len() + 1..];
        check_domain(e, host, port, op)?;
        return match e.field(field) {
            Some(_) => Ok(Resolved { entry: (*e).clone(), field: Some(field.to_string()) }),
            None => Err(err("UNKNOWN_FIELD", format!("\"{}\" has no field \"{field}\"", e.name))),
        };
    }
    // `{{字段}}`：匹配该主机的多字段条目中最具体的那个。
    match best_entry(payload, host, port, op, |e| !e.fields.is_empty()) {
        Ok(Some(one)) if one.field(token).is_some() => Ok(Resolved { entry: one.clone(), field: Some(token.to_string()) }),
        Ok(Some(one)) => Err(err("UNKNOWN_FIELD", format!("\"{}\" has no field \"{token}\"", one.name))),
        Ok(None) => Err(err("UNKNOWN_CREDENTIAL", format!("no credential or field \"{token}\" for {host}"))),
        Err(_) => Err(err("AMBIGUOUS", format!("several credentials with fields match {host}; write {{{{<name>.{token}}}}}"))),
    }
}

/// 在一段文本中代入占位符（SSH 命令用；HTTP 有自己的编码规则）。
pub fn substitute_all(payload: &Payload, text: &str, host: &str, port: u16, op: &str) -> Result<(Zeroizing<String>, Vec<String>), ApiErr> {
    let mut resolved: Vec<(String, Resolved)> = Vec::new();
    for n in template::find_names(text) {
        let r = resolve(payload, &n, host, port, op)?;
        resolved.push((n, r));
    }
    let out = template::substitute(text, |n| resolved.iter().find(|(p, _)| p == n).map(|(_, r)| r.value().to_string()))
        .map_err(|n| err("UNKNOWN_CREDENTIAL", format!("no credential \"{n}\"")))?;
    Ok((Zeroizing::new(out), resolved.iter().map(|(_, r)| r.entry.name.clone()).collect()))
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

    // URL 以占位符开头（{{条目}} 或 {{条目.字段}}，其值是完整的 https 基础地址）：原样代入后再解析。
    if let Some((lead, rest)) = leading_placeholder(url) {
        return prepare_with_base(payload, &method_up, &lead, rest, headers, body);
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

    let mut resolved: Vec<(String, Resolved)> = Vec::new();
    for n in &names {
        resolved.push((n.clone(), resolve(payload, n, &host, port, pm_vault::OP_HTTP)?));
    }
    let lookup = |n: &str| resolved.iter().find(|(p, _)| p == n).map(|(_, r)| r.value().to_string());
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
        self_signed: resolved.iter().any(|(_, r)| r.entry.self_signed),
        names: resolved.iter().map(|(_, r)| r.entry.name.clone()).collect(),
        label: None,
    })
}

/// URL 开头的占位符：返回（名称，其后的文本）。只认紧接在开头的 `{{…}}`。
fn leading_placeholder(url: &str) -> Option<(String, &str)> {
    let u = url.trim_start();
    let inner = u.strip_prefix("{{")?;
    let end = inner.find("}}")?;
    let name = inner[..end].trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return None;
    }
    Some((name.to_string(), &inner[end + 2..]))
}

/// 按名称取得开头占位符的条目与值（不检查主机：主机正是由这个值决定的；之后再按最终的主机检查绑定）。
/// 只接受显式的 `{{条目}}` / `{{条目.字段}}`；`{{secret}}` 与裸字段名依赖主机选择，不能放在开头。
fn resolve_named(payload: &Payload, token: &str) -> Result<Resolved, ApiErr> {
    if token == AUTO_PLACEHOLDER {
        return Err(err("BAD_REQUEST", "a placeholder at the start of the URL must name the entry: {{entry}} or {{entry.field}}"));
    }
    if let Some(e) = payload.entry(token) {
        if !e.fields.is_empty() {
            return Err(has_fields_error(e));
        }
        return Ok(Resolved { entry: e.clone(), field: None });
    }
    let mut by_prefix: Vec<&Entry> =
        payload.entries.iter().filter(|e| token.len() > e.name.len() + 1 && token.starts_with(&format!("{}.", e.name))).collect();
    by_prefix.sort_by_key(|e| std::cmp::Reverse(e.name.len()));
    let Some(e) = by_prefix.first() else {
        return Err(err(
            "UNKNOWN_CREDENTIAL",
            format!("no credential \"{token}\" (a placeholder at the start of the URL must be {{{{entry}}}} or {{{{entry.field}}}})"),
        ));
    };
    let field = &token[e.name.len() + 1..];
    match e.field(field) {
        Some(_) => Ok(Resolved { entry: (*e).clone(), field: Some(field.to_string()) }),
        None => Err(err("UNKNOWN_FIELD", format!("\"{}\" has no field \"{field}\"", e.name))),
    }
}

/// URL 以占位符开头时的准备：值必须是不带用户信息的绝对 https URL；值原样代入（不做百分号编码），其后的文本照原样追加；
/// 代入后的主机与端口必须与值本身的一致（后缀不能改变主机），并满足提供该值的条目以及其他所有占位符的域名绑定。
/// 错误信息只提到占位符名称，从不包含值本身。
fn prepare_with_base(
    payload: &Payload,
    method_up: &str,
    lead: &str,
    rest: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> Result<Prepared, ApiErr> {
    let label = format!("{{{{{lead}}}}}");
    let bad = |why: &str| err("BAD_URL", format!("the value of {label} {why}"));
    let base_r = resolve_named(payload, lead)?;
    if !base_r.entry.allows(pm_vault::OP_HTTP) {
        return Err(err("OP_NOT_ALLOWED", format!("\"{}\" may not be used for http requests", base_r.entry.name)));
    }
    let base = base_r.value();
    if base.is_empty() || base.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad("is not a URL (it contains whitespace or control characters)"));
    }
    let base_url = Url::parse(&base).map_err(|_| bad("is not an absolute URL"))?;
    if base_url.scheme() != "https" {
        return Err(err("USE_HTTPS", format!("the value of {label} is not an https:// URL")));
    }
    if !base_url.username().is_empty() || base_url.password().is_some() {
        return Err(bad("contains credentials (user info); not allowed"));
    }
    let host = host_string(&base_url).ok_or_else(|| bad("has no host"))?;
    let port = base_url.port_or_known_default().unwrap_or(443);
    // 开头的值所属条目必须绑定到它自己的主机。
    check_domain(&base_r.entry, &host, port, pm_vault::OP_HTTP).map_err(|e| {
        if e.code == "DOMAIN_MISMATCH" {
            err("DOMAIN_MISMATCH", format!("the URL in {label} points to a host that \"{}\" is not bound to", base_r.entry.name))
        } else {
            e
        }
    })?;
    // 其他占位符（后缀、请求头、请求体）照常按最终的主机解析与编码。
    let mut names = template::find_names(rest);
    for n in collect_names("", headers, body) {
        if !names.contains(&n) {
            names.push(n);
        }
    }
    let mut resolved: Vec<(String, Resolved)> = vec![];
    for n in &names {
        resolved.push((n.clone(), resolve(payload, n, &host, port, pm_vault::OP_HTTP)?));
    }
    let lookup = |n: &str| resolved.iter().find(|(p, _)| p == n).map(|(_, r)| r.value().to_string());
    let suffix = Zeroizing::new(
        template::substitute(rest, |n| lookup(n).map(|s| percent_encoding::utf8_percent_encode(&s, URL_ENCODE).to_string()))
            .map_err(|n| err("UNKNOWN_CREDENTIAL", format!("no credential \"{n}\"")))?,
    );
    let full = Zeroizing::new(format!("{}{}", base.as_str(), suffix.as_str()));
    let real = Url::parse(&full).map_err(|_| err("BAD_URL", format!("{label} followed by the rest of the URL is not a valid URL")))?;
    if real.scheme() != "https"
        || host_string(&real).as_deref() != Some(host.as_str())
        || real.port_or_known_default() != Some(port)
        || !real.username().is_empty()
        || real.password().is_some()
    {
        return Err(err("BAD_URL", format!("the text after {label} must not change the scheme, host, port or user info")));
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
    let mut entries = vec![base_r.entry.name.clone()];
    entries.extend(resolved.iter().map(|(_, r)| r.entry.name.clone()));
    Ok(Prepared {
        method: reqwest::Method::from_bytes(method_up.as_bytes()).map_err(|_| err("BAD_REQUEST", "bad method"))?,
        url: real,
        headers: hs,
        body,
        host,
        port,
        self_signed: base_r.entry.self_signed || resolved.iter().any(|(_, r)| r.entry.self_signed),
        names: entries,
        label: Some(label),
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

/// 自签证书条目的 TLS 配置：首次连接记录证书公钥指纹，之后必须一致（`observed` 写入本次看到的指纹）。
pub(crate) fn pin_tls_config(expected: Option<String>, observed: Arc<Mutex<Option<String>>>) -> Result<rustls::ClientConfig, ApiErr> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = PinVerifier { expected, observed, provider: provider.clone() };
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| err("INTERNAL", e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

pub(crate) const PIN_MISMATCH_MARKER: &str = PIN_MARKER;

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
            let target = p.label.clone().unwrap_or_else(|| p.host.clone());
            return Err(err("UPSTREAM_ERROR", format!("request to {target} failed: {msg}")));
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
            fields: vec![],
            host_keys: vec![],
            ops: vec![],
        });
        p
    }

    fn fields_payload() -> Payload {
        let fld = |n: &str, v: &str| pm_vault::Field { name: n.into(), value: Zeroizing::new(v.into()) };
        let mut p = payload();
        p.entries.push(Entry {
            name: "mega".into(),
            secret: Zeroizing::new(String::new()),
            domains: vec!["mega.example.com".into(), "*.api.example.net".into()],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: vec![fld("username", "me@example.com"), fld("password", "p&ss w0rd")],
            host_keys: vec![],
            ops: vec![],
        });
        p.entries.push(Entry {
            name: "db.example.com".into(),
            secret: Zeroizing::new("dbpass".into()),
            domains: vec!["db.example.com:5432".into()],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: vec![],
            host_keys: vec![],
            ops: vec![],
        });
        p.entries.push(Entry {
            name: "unbound".into(),
            secret: Zeroizing::new("x".into()),
            domains: vec![],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: vec![],
            host_keys: vec![],
            ops: vec![],
        });
        p
    }

    /// 多字段占位符：{{name.field}}、只有一个条目匹配时的 {{field}}、{{secret}} 对多字段条目报错、
    /// 未知字段报错且不列出其他条目的字段、带端口的域名、未绑定域名的条目。
    #[test]
    fn field_placeholders() {
        let p = fields_payload();
        let r = prepare(
            &p,
            "POST",
            "https://mega.example.com/login?u={{mega.username}}",
            &[("X-P".into(), "{{password}}".into())],
            Some("{\"u\":\"{{username}}\"}"),
        )
        .unwrap();
        assert_eq!(r.url.query(), Some("u=me%40example.com"));
        assert_eq!(r.headers[0].1.as_str(), "p&ss w0rd");
        assert_eq!(r.body.as_deref().map(|b| b.as_str()), Some("{\"u\":\"me@example.com\"}"));
        let e = |r: Result<Prepared, ApiErr>| r.err().unwrap();
        let x = e(prepare(&p, "GET", "https://mega.example.com/{{secret}}", &[], None));
        assert_eq!(x.code, "BAD_REQUEST");
        assert!(x.message.contains("username, password") && x.message.contains("{{mega.<field>}}"), "{}", x.message);
        let x = e(prepare(&p, "GET", "https://mega.example.com/{{mega.pin}}", &[], None));
        assert_eq!(x.code, "UNKNOWN_FIELD");
        assert!(!x.message.contains("username"), "不泄露字段列表以外的信息");
        assert_eq!(e(prepare(&p, "GET", "https://mega.example.com/{{pin}}", &[], None)).code, "UNKNOWN_FIELD");
        // 别的主机不能用这个条目的字段；也不会说出 mega 有哪些字段。
        let x = e(prepare(&p, "GET", "https://api.github.com/{{password}}", &[], None));
        assert_eq!(x.code, "UNKNOWN_CREDENTIAL");
        assert!(!x.message.contains("mega"));
        assert_eq!(e(prepare(&p, "GET", "https://api.github.com/{{mega.password}}", &[], None)).code, "DOMAIN_MISMATCH");
        // 引用名含点（自动生成的名字）：整个名字优先，其次最长前缀 + 字段。
        let r = resolve(&p, "db.example.com", "db.example.com", 5432, pm_vault::OP_HTTP).unwrap();
        assert_eq!(r.value().as_str(), "dbpass");
        assert_eq!(
            resolve(&p, "db.example.com", "db.example.com", 5433, pm_vault::OP_HTTP).err().unwrap().code,
            "DOMAIN_MISMATCH",
            "端口不符"
        );
        assert_eq!(resolve(&p, "unbound", "x.example.com", 443, pm_vault::OP_HTTP).err().unwrap().code, "DOMAIN_MISMATCH");
        assert!(resolve(&p, "unbound", "x.example.com", 443, pm_vault::OP_HTTP).err().unwrap().message.contains("not bound"));
        // SSH 命令代入。
        let (cmd, names) =
            substitute_all(&p, "printf '%s' '{{password}}' | login {{mega.username}}", "mega.example.com", 22, pm_vault::OP_SSH).unwrap();
        assert_eq!(cmd.as_str(), "printf '%s' 'p&ss w0rd' | login me@example.com");
        assert_eq!(names, vec!["mega".to_string(), "mega".to_string()]);
        assert_eq!(substitute_all(&p, "echo {{nope}}", "mega.example.com", 22, pm_vault::OP_SSH).err().unwrap().code, "UNKNOWN_FIELD");
        let (plain, _) = substitute_all(&p, "uptime", "mega.example.com", 22, pm_vault::OP_SSH).unwrap();
        assert_eq!(plain.as_str(), "uptime");
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

    fn ent(name: &str, secret: &str, domains: &[&str], ops: &[&str]) -> Entry {
        Entry {
            name: name.into(),
            secret: Zeroizing::new(secret.into()),
            domains: domains.iter().map(|d| pm_vault::domain::validate_pattern(d).unwrap()).collect(),
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: vec![],
            host_keys: vec![],
            ops: ops.iter().map(|o| o.to_string()).collect(),
        }
    }

    const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----";

    /// 多个条目匹配同一目标：精确主机 > 更长的通配符 > 前缀更长的网段；同级时报 AMBIGUOUS（只列出引用名）。
    #[test]
    fn most_specific_entry_wins() {
        let mut p = Payload::default();
        p.entries.push(ent("lan24", "a", &["198.51.100.0/24"], &[]));
        p.entries.push(ent("lan28", "b", &["198.51.100.0/28"], &[]));
        p.entries.push(ent("host7", "c", &["198.51.100.7"], &[]));
        p.entries.push(ent("wild", "d", &["*.example.com"], &[]));
        p.entries.push(ent("wild-lab", "e", &["*.lab.example.com"], &[]));
        p.entries.push(ent("db1", "f", &["db1.lab.example.com"], &[]));
        p.entries.push(ent("apex", "g", &["example.com"], &[]));
        fn pick_in(p: &Payload, h: &str) -> Result<String, ApiErr> {
            select_by_host(p, h, 443, pm_vault::OP_HTTP).map(|e| e.name.clone())
        }
        let pick = |h: &str| pick_in(&p, h);
        assert_eq!(pick("198.51.100.7").unwrap(), "host7");
        assert_eq!(pick("198.51.100.8").unwrap(), "lan28");
        assert_eq!(pick("198.51.100.200").unwrap(), "lan24");
        assert_eq!(pick("db1.lab.example.com").unwrap(), "db1");
        assert_eq!(pick("db2.lab.example.com").unwrap(), "wild-lab");
        assert_eq!(pick("www.example.com").unwrap(), "wild");
        assert_eq!(pick("example.com").unwrap(), "apex", "通配符不匹配顶点域名");
        assert_eq!(pick("198.51.101.1").unwrap_err().code, "NO_CREDENTIAL");
        assert_eq!(pick("ab.example.org").unwrap_err().code, "NO_CREDENTIAL");
        // 同样具体 → 歧义，错误里只有引用名。
        p.entries.push(ent("wild-2", "SECRET-VALUE", &["*.example.com"], &[]));
        let x = pick_in(&p, "www.example.com").unwrap_err();
        assert_eq!(x.code, "AMBIGUOUS");
        assert!(x.message.contains("wild, wild-2") && !x.message.contains("SECRET-VALUE") && !x.message.contains("\"d\""), "{}", x.message);
        assert_eq!(pick_in(&p, "db1.lab.example.com").unwrap(), "db1", "更具体的条目不受影响");
        // 带端口的更具体。
        p.entries.push(ent("wild-443", "h", &["*.example.com:443"], &[]));
        assert_eq!(pick_in(&p, "www.example.com").unwrap(), "wild-443");
    }

    /// 用途限定：只允许 ssh 的口令不能代入 HTTP 请求，也不会被 {{secret}} 选中。
    #[test]
    fn op_restriction() {
        let mut p = Payload::default();
        p.entries.push(ent("init-pw", "initial-pass", &["*.example.com", "198.51.100.0/24"], &["ssh"]));
        let x = prepare(&p, "GET", "https://www.example.com/?p={{secret}}", &[], None).err().unwrap();
        assert_eq!(x.code, "OP_NOT_ALLOWED");
        assert!(!x.message.contains("initial-pass"));
        let x = prepare(&p, "GET", "https://www.example.com/?p={{init-pw}}", &[], None).err().unwrap();
        assert_eq!(x.code, "OP_NOT_ALLOWED");
        // 只说明不能用于这种用途，不列出条目允许的用途。
        assert!(x.message.contains("may not be used for http") && !x.message.contains("ssh"), "{}", x.message);
        assert_eq!(select_by_host(&p, "198.51.100.9", 22, pm_vault::OP_SSH).unwrap().name, "init-pw");
        assert_eq!(select_by_host(&p, "198.51.100.9", 22, pm_vault::OP_GIT).unwrap_err().code, "OP_NOT_ALLOWED");
        let (cmd, _) = substitute_all(&p, "echo {{init-pw}}", "a.example.com", 22, pm_vault::OP_SSH).unwrap();
        assert_eq!(cmd.as_str(), "echo initial-pass");
        // 有一个不限用途的条目时，HTTP 用它。
        p.entries.push(ent("api", "tok", &["*.example.com"], &["http"]));
        assert_eq!(select_by_host(&p, "a.example.com", 443, pm_vault::OP_HTTP).unwrap().name, "api");
        assert_eq!(select_by_host(&p, "a.example.com", 22, pm_vault::OP_SSH).unwrap().name, "init-pw");
    }

    /// SSH：私钥条目优先，口令条目作为回退；指定引用名时只用该条目。
    #[test]
    fn ssh_key_before_password() {
        let mut p = Payload::default();
        p.entries.push(ent("init-pw", "initial-pass", &["*.example.com", "198.51.100.0/24"], &["ssh"]));
        let names = |r: (Option<Entry>, Option<Entry>)| (r.0.map(|e| e.name), r.1.map(|e| e.name));
        assert_eq!(names(ssh_credentials(&p, None, "db1.example.com", 22).unwrap()), (None, Some("init-pw".into())));
        p.entries.push(ent("db1-key", KEY, &["db1.example.com"], &[]));
        p.entries.push(ent("lan-key", KEY, &["198.51.100.0/24"], &[]));
        assert_eq!(names(ssh_credentials(&p, None, "db1.example.com", 22).unwrap()), (Some("db1-key".into()), Some("init-pw".into())));
        assert_eq!(names(ssh_credentials(&p, None, "198.51.100.4", 22).unwrap()), (Some("lan-key".into()), Some("init-pw".into())));
        assert_eq!(names(ssh_credentials(&p, None, "db2.example.com", 22).unwrap()), (None, Some("init-pw".into())));
        assert_eq!(names(ssh_credentials(&p, Some("init-pw"), "db1.example.com", 22).unwrap()), (None, Some("init-pw".into())));
        assert_eq!(names(ssh_credentials(&p, Some("db1-key"), "db1.example.com", 22).unwrap()), (Some("db1-key".into()), None));
        assert_eq!(ssh_credentials(&p, Some("db1-key"), "db2.example.com", 22).unwrap_err().code, "DOMAIN_MISMATCH");
        // 口令条目有歧义时：有私钥就只用私钥；没有私钥则报错。
        p.entries.push(ent("init-pw-2", "other", &["*.example.com"], &["ssh"]));
        assert_eq!(names(ssh_credentials(&p, None, "db1.example.com", 22).unwrap()), (Some("db1-key".into()), None));
        assert_eq!(ssh_credentials(&p, None, "db2.example.com", 22).unwrap_err().code, "AMBIGUOUS");
        assert_eq!(ssh_credentials(&p, None, "nothing.example.org", 22).unwrap_err().code, "NO_CREDENTIAL");
    }

    const GW: &str = "https://gateway.example.com/v1/acct-7f3e/gw-secret/compat/chat/completions";

    fn gw_entry(name: &str, base: &str, domains: &[&str]) -> Entry {
        let fld = |n: &str, v: &str| pm_vault::Field { name: n.into(), value: Zeroizing::new(v.into()) };
        let mut e = ent(name, "", domains, &[]);
        e.fields = vec![fld("base_url", base), fld("api_key", "sk-gw-0123456789")];
        e
    }

    /// URL 以 {{条目.字段}} 开头：值原样代入（不编码），后缀照原样追加，主机由值决定并按条目的绑定检查。
    #[test]
    fn leading_base_url_placeholder() {
        let mut p = Payload::default();
        p.entries.push(gw_entry("ai", GW, &["gateway.example.com"]));
        let r = prepare(&p, "POST", "{{ai.base_url}}", &[("Authorization".into(), "Bearer {{ai.api_key}}".into())], Some("{}")).unwrap();
        assert_eq!(r.url.as_str(), GW, "原样代入");
        assert_eq!((r.host.as_str(), r.port), ("gateway.example.com", 443));
        assert_eq!(r.headers[0].1.as_str(), "Bearer sk-gw-0123456789");
        assert_eq!(r.label.as_deref(), Some("{{ai.base_url}}"));
        assert_eq!(r.names, vec!["ai".to_string(), "ai".to_string()]);
        let r = prepare(&p, "GET", "{{ai.base_url}}/models?x=1", &[], None).unwrap();
        assert_eq!(r.url.as_str(), format!("{GW}/models?x=1"), "后缀照原样追加");
        // 后缀里的其他占位符仍然百分号编码。
        let r = prepare(&p, "GET", "{{ai.base_url}}?k={{ai.api_key}}&u={{ai.base_url}}", &[], None).unwrap();
        assert!(r.url.as_str().starts_with(&format!("{GW}?k=sk-gw-0123456789&u=https%3A%2F%2Fgateway.example.com%2Fv1")), "{}", r.url);
        // 中间位置的占位符：与以前一样百分号编码。
        let r = prepare(&p, "GET", "https://gateway.example.com/q?u={{ai.base_url}}", &[], None).unwrap();
        assert!(r.url.query().unwrap().starts_with("u=https%3A%2F%2Fgateway.example.com%2Fv1%2Facct-7f3e"));
        assert_eq!(r.label, None);
        // 大小写与末尾的点：按规范化后的主机比较。
        let mut p2 = Payload::default();
        p2.entries.push(gw_entry("ai", "https://GATEWAY.Example.com./v1", &["gateway.example.com"]));
        assert_eq!(prepare(&p2, "GET", "{{ai.base_url}}", &[], None).unwrap().host, "gateway.example.com");
    }

    /// 拒绝：主机不在条目的绑定内、不是 https、带用户信息、后缀改变主机、以 @ 结尾的值、
    /// 依赖主机选择的 {{secret}} 放在开头、scheme 之后的占位符、只允许 ssh 的条目。错误信息从不包含值本身。
    #[test]
    fn leading_base_url_rejections_never_echo_the_value() {
        let cases: Vec<(&str, &str, &str, &[&str])> = vec![
            ("https://evil.example/v1/acct-7f3e/x", "{{ai.base_url}}", "DOMAIN_MISMATCH", &["gateway.example.com"]),
            ("http://gateway.example.com/v1/acct-7f3e", "{{ai.base_url}}", "USE_HTTPS", &["gateway.example.com"]),
            ("https://user-acct-7f3e:pw@gateway.example.com/v1", "{{ai.base_url}}", "BAD_URL", &["gateway.example.com"]),
            ("https://gateway.example.com", "{{ai.base_url}}@evil.example/acct-7f3e", "BAD_URL", &["gateway.example.com"]),
            ("https://gateway.example.com", "{{ai.base_url}}:8443/acct-7f3e", "BAD_URL", &["gateway.example.com"]),
            ("https://gateway.example.com@", "{{ai.base_url}}acct-7f3e.evil.example/", "BAD_URL", &["gateway.example.com"]),
            ("https://gateway.example.com/acct-7f3e path", "{{ai.base_url}}", "BAD_URL", &["gateway.example.com"]),
            ("not a url acct-7f3e", "{{ai.base_url}}", "BAD_URL", &["gateway.example.com"]),
            ("https://gateway.example.com:8443/acct-7f3e", "{{ai.base_url}}", "DOMAIN_MISMATCH", &["gateway.example.com:443"]),
        ];
        for (value, url, code, doms) in cases {
            let mut p = Payload::default();
            p.entries.push(gw_entry("ai", value, doms));
            let e = prepare(&p, "GET", url, &[], None).err().unwrap_or_else(|| panic!("{value} {url}"));
            assert_eq!(e.code, code, "{value} {url}: {}", e.message);
            assert!(!e.message.contains("acct-7f3e") && !e.message.contains(value), "错误信息不包含值：{}", e.message);
        }
        let mut p = Payload::default();
        p.entries.push(gw_entry("ai", GW, &["gateway.example.com"]));
        let e = prepare(&p, "GET", "{{secret}}/x", &[], None).err().unwrap();
        assert_eq!(e.code, "BAD_REQUEST");
        let e = prepare(&p, "GET", "https://{{ai.base_url}}", &[], None).err().unwrap();
        assert!(
            matches!(e.code.as_str(), "BAD_REQUEST" | "DOMAIN_MISMATCH") && !e.message.contains("acct-7f3e"),
            "scheme 之后的占位符仍然禁止：{}",
            e.message
        );
        assert_eq!(prepare(&p, "GET", "{{ai.nope}}", &[], None).err().unwrap().code, "UNKNOWN_FIELD");
        let mut ssh_only = gw_entry("ai2", GW, &["gateway.example.com"]);
        ssh_only.ops = vec!["ssh".into()];
        p.entries.push(ssh_only);
        assert_eq!(prepare(&p, "GET", "{{ai2.base_url}}", &[], None).err().unwrap().code, "OP_NOT_ALLOWED");
        // 其他占位符也按最终的主机检查绑定。
        p.entries.push(ent("other", "o-secret", &["elsewhere.example"], &[]));
        assert_eq!(prepare(&p, "GET", "{{ai.base_url}}?t={{other}}", &[], None).err().unwrap().code, "DOMAIN_MISMATCH");
    }

    /// 多字段条目的每个字段（包括 base_url）都进入脱敏：响应里出现基础地址时被替换。
    #[test]
    fn base_url_is_redacted_in_responses() {
        let e = gw_entry("ai", GW, &["gateway.example.com"]);
        let values = e.secret_values();
        assert!(values.iter().any(|(l, v)| l == "ai.base_url" && *v == GW));
        let r = crate::redact::Redactor::build(values.iter().map(|(l, v)| (l.as_str(), *v)));
        let out = r.redact_str(&format!("{{\"error\":\"unknown route {GW}\",\"key\":\"sk-gw-0123456789\"}}"));
        assert!(!out.contains("acct-7f3e") && !out.contains("sk-gw-0123456789"), "{out}");
        assert!(out.contains("[REDACTED:ai.base_url]") && out.contains("[REDACTED:ai.api_key]"));
    }
}

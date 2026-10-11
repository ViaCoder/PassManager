//! 域名规则（条目绑定的目标）。
//!
//! - `example.com`：只匹配它自己。
//! - `*.example.com`：匹配至少多一层的子域名（`a.example.com`、`a.b.example.com`），**不**匹配 `example.com` 本身
//!   （需要时单独列出），也不匹配 `badexample.com`、`example.com.evil.net` 这类形似的名称。
//!   `*` 只能是最左边的整个标签；`*.` 之后至少要有两个标签，且不能是公共后缀（`*`、`*.com`、`*.co.uk`、`*.github.io` 都拒绝）。
//! - IP 地址：精确匹配。
//! - 网段（CIDR）：`198.51.100.0/24`、`2001:db8::/48`，只匹配**字面 IP** 目标——Agent 用域名访问时不会解析后再匹配网段。
//!   主机位必须为 0；IPv4 前缀至少 /8，IPv6 至少 /32（防止过宽）。IPv4 网段不匹配 IPv6 地址（包括 IPv4 映射地址），反之亦然。
//! - 以上任一形式都可以加 `:端口`（例如 `db1.example.com:2222`、`[::1]:22`、`[2001:db8::/48]:22`），只匹配该端口；不写端口时匹配任意端口。
//!
//! 比较前统一规范化：小写、去掉末尾的点、国际化域名转为 punycode（IDNA）。
//! 多个条目都匹配同一目标时，按"具体程度"选择（见 [`Spec`]）：精确主机 > 更长的通配符 > 前缀更长的网段；同级时带端口的更具体。

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("empty domain")]
    Empty,
    #[error("invalid characters in domain `{0}` (use ASCII / punycode)")]
    InvalidChars(String),
    #[error("pattern `{0}` is too broad (public suffix)")]
    TooBroad(String),
    #[error("invalid port in `{0}`")]
    InvalidPort(String),
    #[error("invalid network `{0}` (host bits must be zero, e.g. 198.51.100.0/24)")]
    InvalidNetwork(String),
}

/// 匹配的具体程度，可直接比较大小（越大越具体）：(类别, 长度, 是否限定端口)。
/// 类别：3 = 精确主机或 IP，2 = 通配符（长度 = `*.` 之后的标签数），1 = 网段（长度 = 前缀长度）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Spec {
    pub class: u8,
    pub len: u32,
    pub port: bool,
}

/// 拆出可选的端口：`host:port`、`[v6]:port`；IPv6 裸地址（多个冒号）视为没有端口。
fn split_port(p: &str) -> (String, Option<&str>) {
    if let Some(rest) = p.strip_prefix('[')
        && let Some((h, after)) = rest.split_once(']')
    {
        return (h.to_string(), after.strip_prefix(':'));
    }
    if p.matches(':').count() == 1 {
        let (h, port) = p.split_once(':').unwrap();
        return (h.to_string(), Some(port));
    }
    (p.to_string(), None)
}

/// 已规范化的模式拆成（主机模式，可选端口）。
pub fn pattern_parts(pattern: &str) -> (String, Option<u16>) {
    let (h, port) = split_port(pattern);
    (h, port.and_then(|p| p.parse().ok()))
}

/// 规范化主机名：去掉空白、IPv6 方括号与末尾的点，小写；IP 地址写成标准形式；国际化域名转为 punycode。
/// 无法转换的名称原样（小写）返回，之后的校验会拒绝它、匹配也不会成功。
pub fn normalize_host(host: &str) -> String {
    let h = host.trim();
    let h = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(h);
    let h = h.trim_end_matches('.').to_lowercase();
    if let Ok(ip) = h.parse::<IpAddr>() {
        return ip.to_string();
    }
    if h.is_ascii() {
        return h;
    }
    idna::domain_to_ascii(&h).ok().filter(|a| !a.is_empty()).unwrap_or(h)
}

fn valid_label_chars(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// 解析网段 `地址/前缀`（不检查宽度）。
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = s.split_once('/')?;
    let ip: IpAddr = a.parse().ok()?;
    if l.is_empty() || !l.bytes().all(|b| b.is_ascii_digit()) || l.len() > 3 {
        return None;
    }
    let len: u8 = l.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some((ip, len))
}

fn mask_bits(ip: IpAddr, len: u8) -> (u128, u128) {
    match ip {
        IpAddr::V4(v) => {
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
            (u32::from(v) as u128, m as u128)
        }
        IpAddr::V6(v) => {
            let m = if len == 0 { 0 } else { u128::MAX << (128 - len as u32) };
            (u128::from(v), m)
        }
    }
}

fn cidr_contains(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    if net.is_ipv4() != ip.is_ipv4() {
        return false;
    }
    let (n, m) = mask_bits(net, len);
    let (a, _) = mask_bits(ip, len);
    a & m == n & m
}

/// 校验并规范化一个域名模式（可带 `:端口`）。
pub fn validate_pattern(pattern: &str) -> Result<String, DomainError> {
    let raw = pattern.trim().to_lowercase();
    let (host, port) = split_port(&raw);
    let Some(port) = port else { return validate_host_pattern(pattern) };
    let port: u16 = port.parse().ok().filter(|p| *p != 0).ok_or_else(|| DomainError::InvalidPort(raw.clone()))?;
    let h = validate_host_pattern(&host)?;
    Ok(if h.contains(':') { format!("[{h}]:{port}") } else { format!("{h}:{port}") })
}

fn validate_host_pattern(pattern: &str) -> Result<String, DomainError> {
    let t = pattern.trim();
    if t.contains('/') {
        let t = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(t);
        let (ip, len) = parse_cidr(t).ok_or_else(|| DomainError::InvalidNetwork(t.to_string()))?;
        let (n, m) = mask_bits(ip, len);
        if n & !m != 0 {
            return Err(DomainError::InvalidNetwork(t.to_string()));
        }
        if len < if ip.is_ipv4() { 8 } else { 32 } {
            return Err(DomainError::TooBroad(t.to_string()));
        }
        return Ok(format!("{ip}/{len}"));
    }
    let p = match t.strip_prefix("*.") {
        Some(base) => format!("*.{}", normalize_host(base)),
        None => normalize_host(t),
    };
    if p.is_empty() {
        return Err(DomainError::Empty);
    }
    if let Ok(ip) = p.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if let Some(base) = p.strip_prefix("*.") {
        if !valid_label_chars(base) {
            return Err(DomainError::InvalidChars(p.clone()));
        }
        // 通配符的基底至少两个标签，且必须是"可注册域名"或其子域，不能是公共后缀。
        if base.split('.').count() < 2 || psl::domain_str(base).is_none() {
            return Err(DomainError::TooBroad(p));
        }
        return Ok(p);
    }
    if p.contains('*') || !valid_label_chars(&p) {
        return Err(DomainError::InvalidChars(p));
    }
    // 精确匹配只对应一台主机，本身并不宽泛；只拒绝 ICANN 顶级后缀本身（如 `com`、`co.uk`），
    // 允许公共后缀列表私有段中的主机名（如 `httpbin.org`、`github.io`）和内网单标签主机名。
    // 宽泛与否由通配符规则把关：`*.github.io` 等仍会被拒绝。
    if let Some(s) = psl::suffix(p.as_bytes())
        && s.typ() == Some(psl::Type::Icann)
        && s.as_bytes() == p.as_bytes()
    {
        return Err(DomainError::TooBroad(p));
    }
    Ok(p)
}

/// 目标（主机，可选端口）与模式的匹配程度；不匹配时为 None。`port = None` 表示忽略端口。
pub fn specificity(pattern: &str, host: &str, port: Option<u16>) -> Option<Spec> {
    let (hp, pport) = pattern_parts(pattern);
    if let (Some(want), Some(got)) = (pport, port)
        && want != got
    {
        return None;
    }
    let with_port = pport.is_some() && port.is_some();
    let host = normalize_host(host);
    let target_ip = host.parse::<IpAddr>().ok();
    let (class, len) = if hp.contains('/') {
        let (net, len) = parse_cidr(&hp)?;
        // 网段只匹配字面 IP，不解析域名。
        cidr_contains(net, len, target_ip?).then_some((1, len as u32))?
    } else if let Some(base) = hp.strip_prefix("*.") {
        if target_ip.is_some() {
            return None;
        }
        let ok = host.len() > base.len() + 1 && host.ends_with(base) && host.as_bytes()[host.len() - base.len() - 1] == b'.';
        ok.then_some((2, base.split('.').count() as u32))?
    } else {
        let same = match (hp.parse::<IpAddr>(), target_ip) {
            (Ok(a), Some(b)) => a == b,
            (Err(_), None) => normalize_host(&hp) == host,
            _ => false,
        };
        same.then_some((3, 0))?
    };
    Some(Spec { class, len, port: with_port })
}

/// 一组模式中最具体的匹配。
pub fn best_match(patterns: &[String], host: &str, port: Option<u16>) -> Option<Spec> {
    patterns.iter().filter_map(|p| specificity(p, host, port)).max()
}

/// 主机是否匹配模式（忽略模式中的端口；两者都应已规范化）。
pub fn matches(pattern: &str, host: &str) -> bool {
    specificity(pattern, host, None).is_some()
}

/// 主机是否匹配任一模式（忽略端口）。
pub fn matches_any(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|p| matches(p, host))
}

/// 主机与端口是否匹配模式：模式带端口时端口必须相同。
pub fn matches_port(pattern: &str, host: &str, port: u16) -> bool {
    specificity(pattern, host, Some(port)).is_some()
}

/// 主机与端口是否匹配任一模式。
pub fn matches_any_port(patterns: &[String], host: &str, port: u16) -> bool {
    patterns.iter().any(|p| matches_port(p, host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        assert_eq!(validate_pattern("*.Example.com.").unwrap(), "*.example.com");
        assert!(validate_pattern("*").is_err());
        assert!(validate_pattern("*.com").is_err());
        assert!(validate_pattern("*.co.uk").is_err());
        assert!(validate_pattern("*.github.io").is_err());
        assert!(validate_pattern("com").is_err());
        assert!(validate_pattern("co.uk").is_err());
        assert_eq!(validate_pattern("github.io").unwrap(), "github.io");
        assert_eq!(validate_pattern("httpbin.org").unwrap(), "httpbin.org");
        assert!(validate_pattern("*.httpbin.org").is_err());
        assert!(validate_pattern("*.lan").is_err());
        assert!(validate_pattern("*.corp.lan").is_ok());
        assert!(validate_pattern("nas").is_ok());
        assert!(validate_pattern("a*.example.com").is_err());
        assert!(validate_pattern("bad host.com").is_err());
        assert_eq!(validate_pattern("[::1]").unwrap(), "::1");
        assert_eq!(validate_pattern("10.0.0.5").unwrap(), "10.0.0.5");
    }

    #[test]
    fn matching() {
        let p = validate_pattern("*.example.com").unwrap();
        assert!(!matches(&p, "example.com"), "通配符不匹配顶点域名（0.2.0 起）");
        assert!(matches(&p, "a.b.example.com"));
        assert!(matches(&p, "API.Example.com."));
        assert!(!matches(&p, "example.com.evil.org"));
        assert!(!matches(&p, "badexample.com"));
        let e = validate_pattern("api.github.com").unwrap();
        assert!(matches(&e, "api.github.com"));
        assert!(!matches(&e, "github.com"));
        assert!(matches("::1", "[::1]"));
        assert!(matches("::1", "0:0:0:0:0:0:0:1"));
    }

    #[test]
    fn host_port_patterns() {
        assert_eq!(validate_pattern("DB1.example.com:2222").unwrap(), "db1.example.com:2222");
        assert_eq!(validate_pattern("*.example.com:443").unwrap(), "*.example.com:443");
        assert_eq!(validate_pattern("[::1]:22").unwrap(), "[::1]:22");
        assert_eq!(validate_pattern("192.0.2.7:8443").unwrap(), "192.0.2.7:8443");
        assert_eq!(validate_pattern("::1").unwrap(), "::1", "裸 IPv6 不是 host:port");
        for bad in ["a.example.com:0", "a.example.com:70000", "a.example.com:x", "a.example.com:", "*.com:443", ":22"] {
            assert!(validate_pattern(bad).is_err(), "{bad}");
        }
        let p = validate_pattern("db1.example.com:2222").unwrap();
        assert!(matches_port(&p, "db1.example.com", 2222));
        assert!(!matches_port(&p, "db1.example.com", 22));
        assert!(!matches_port(&p, "db2.example.com", 2222));
        assert!(matches(&p, "db1.example.com"), "忽略端口的匹配（信任指纹等）");
        let any = validate_pattern("db1.example.com").unwrap();
        assert!(matches_port(&any, "db1.example.com", 1) && matches_port(&any, "db1.example.com", 65535));
        assert!(matches_port("[::1]:22", "::1", 22) && !matches_port("[::1]:22", "::1", 23));
        assert!(matches_any_port(&[p, any], "db1.example.com", 22));
        assert!(!matches_any_port(&[], "db1.example.com", 22));
    }

    #[test]
    fn wildcard_table() {
        let w = validate_pattern("*.Example.COM.").unwrap();
        assert_eq!(w, "*.example.com");
        for (host, want) in [
            ("a.example.com", true),
            ("a.b.example.com", true),
            ("A.Example.Com.", true),
            ("x-1.example.com", true),
            ("example.com", false),
            ("example.com.", false),
            ("badexample.com", false),
            ("a.badexample.com", false),
            ("example.com.evil.net", false),
            ("a.example.com.evil.net", false),
            ("example.org", false),
            (".example.com", false),
            ("198.51.100.1", false),
        ] {
            assert_eq!(matches(&w, host), want, "{host}");
        }
        // 顶点域名要单独列出。
        let apex = validate_pattern("example.com").unwrap();
        assert!(matches(&apex, "EXAMPLE.com.") && !matches(&apex, "a.example.com"));
        // 拒绝：裸 *、公共后缀、只有一个标签、* 不在最左边或不是整个标签。
        for bad in [
            "*",
            "*.",
            "*.com",
            "*.gy",
            "*.co.uk",
            "*.github.io",
            "*.lan",
            "a.*.example.com",
            "*a.example.com",
            "a*.example.com",
            "*.*.example.com",
            "example.*",
            "**.example.com",
        ] {
            assert!(validate_pattern(bad).is_err(), "{bad}");
        }
        assert!(validate_pattern("*.corp.lan").is_ok());
        assert!(validate_pattern("*.sub.example.co.uk").is_ok());
    }

    #[test]
    fn idna_normalization() {
        let w = validate_pattern("*.Bücher.example").unwrap();
        assert_eq!(w, "*.xn--bcher-kva.example");
        assert!(matches(&w, "shop.bücher.example"));
        assert!(matches(&w, "shop.xn--bcher-kva.example"));
        assert!(matches(&w, "SHOP.BÜCHER.EXAMPLE."));
        assert!(!matches(&w, "bücher.example"));
        let e = validate_pattern("xn--bcher-kva.example").unwrap();
        assert!(matches(&e, "Bücher.example"));
        assert_eq!(normalize_host("[2001:DB8::1]"), "2001:db8::1");
        assert_eq!(normalize_host("2001:db8:0:0:0:0:0:1"), "2001:db8::1");
    }

    #[test]
    fn cidr_table() {
        let n = validate_pattern("198.51.100.0/24").unwrap();
        assert_eq!(n, "198.51.100.0/24");
        for (host, want) in [
            ("198.51.100.0", true),
            ("198.51.100.1", true),
            ("198.51.100.255", true),
            ("198.51.101.0", false),
            ("198.51.99.255", false),
            ("::ffff:198.51.100.1", false),
            ("2001:db8::1", false),
            ("host.example.com", false),
            ("198.51.100.1.example.com", false),
        ] {
            assert_eq!(matches(&n, host), want, "{host}");
        }
        let one = validate_pattern("203.0.113.7/32").unwrap();
        assert!(matches(&one, "203.0.113.7") && !matches(&one, "203.0.113.8"));
        let v6 = validate_pattern("2001:DB8::/48").unwrap();
        assert_eq!(v6, "2001:db8::/48");
        assert!(matches(&v6, "2001:db8:0:ffff::1") && matches(&v6, "[2001:db8::]"));
        assert!(!matches(&v6, "2001:db9::1") && !matches(&v6, "198.51.100.1"));
        let v6p = validate_pattern("[2001:db8::/48]:22").unwrap();
        assert_eq!(v6p, "[2001:db8::/48]:22");
        assert!(matches_port(&v6p, "2001:db8::5", 22) && !matches_port(&v6p, "2001:db8::5", 23));
        let v4p = validate_pattern("198.51.100.0/24:2222").unwrap();
        assert_eq!(v4p, "198.51.100.0/24:2222");
        assert!(matches_port(&v4p, "198.51.100.9", 2222) && !matches_port(&v4p, "198.51.100.9", 22));
        for bad in [
            "198.51.100.1/24",
            "198.51.100.0/33",
            "198.51.100.0/",
            "198.51.100.0/x",
            "0.0.0.0/0",
            "198.0.0.0/7",
            "2001:db8::/129",
            "::/0",
            "2001::/16",
            "example.com/24",
            "198.51.100.0/24/1",
        ] {
            assert!(validate_pattern(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn specificity_order() {
        let s = |p: &str, h: &str, port: Option<u16>| specificity(&validate_pattern(p).unwrap(), h, port);
        let exact = s("db1.example.com", "db1.example.com", Some(22)).unwrap();
        let exact_port = s("db1.example.com:22", "db1.example.com", Some(22)).unwrap();
        let w3 = s("*.lab.example.com", "db1.lab.example.com", Some(22)).unwrap();
        let w2 = s("*.example.com", "db1.lab.example.com", Some(22)).unwrap();
        let w2_port = s("*.example.com:22", "db1.lab.example.com", Some(22)).unwrap();
        assert!(exact_port > exact && exact > w3 && w3 > w2_port && w2_port > w2);
        let ip = s("198.51.100.7", "198.51.100.7", Some(22)).unwrap();
        let n28 = s("198.51.100.0/28", "198.51.100.7", Some(22)).unwrap();
        let n24 = s("198.51.100.0/24", "198.51.100.7", Some(22)).unwrap();
        assert!(ip > n28 && n28 > n24);
        assert!(w2 > n28, "任何通配符都比网段具体（两者不会同时匹配同一目标）");
        assert_eq!(best_match(&["*.example.com".into(), "db1.example.com".into()], "db1.example.com", Some(22)), Some(exact));
        assert_eq!(best_match(&[], "db1.example.com", None), None);
        assert_eq!(s("db1.example.com:2222", "db1.example.com", Some(22)), None);
        assert!(s("db1.example.com:2222", "db1.example.com", None).is_some(), "忽略端口时");
    }
}

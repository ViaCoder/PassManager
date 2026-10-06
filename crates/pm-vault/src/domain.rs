//! 域名规则。
//!
//! - `example.com`：只匹配它自己。
//! - `*.example.com`：匹配 `example.com` 本身及其任意层级的子域名。
//! - IP 地址：精确匹配。
//! - 过宽的模式（`*`、`*.com`、`*.co.uk`、`*.github.io`、单独的公共后缀）一律拒绝，依据公共后缀列表（含私有后缀）。

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("empty domain")]
    Empty,
    #[error("invalid characters in domain `{0}` (use ASCII / punycode)")]
    InvalidChars(String),
    #[error("pattern `{0}` is too broad (public suffix)")]
    TooBroad(String),
}

/// 规范化主机名：小写、去掉末尾的点、去掉 IPv6 方括号。
pub fn normalize_host(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).map(str::to_string).unwrap_or(h)
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

/// 校验并规范化一个域名模式。
pub fn validate_pattern(pattern: &str) -> Result<String, DomainError> {
    let p = normalize_host(pattern);
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
        // 通配符的基底本身必须是"可注册域名"或其子域，不能是公共后缀。
        if psl::domain_str(base).is_none() {
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

/// 主机是否匹配模式（两者都应已规范化）。
pub fn matches(pattern: &str, host: &str) -> bool {
    let host = normalize_host(host);
    if let (Ok(a), Ok(b)) = (pattern.parse::<IpAddr>(), host.parse::<IpAddr>()) {
        return a == b;
    }
    match pattern.strip_prefix("*.") {
        Some(base) => host == base || host.ends_with(&format!(".{base}")),
        None => host == pattern,
    }
}

/// 主机是否匹配任一模式。
pub fn matches_any(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|p| matches(p, host))
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
        assert!(matches(&p, "example.com"));
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
}

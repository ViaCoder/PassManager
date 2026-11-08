//! `passmanager run --http` 的凭据策略：本机程序经服务器调用 HTTPS API 时，服务器只按这里的规则放行请求。
//!
//! - 策略由服务器上的 root 设置（`passmanager relay set`），客户端只能在它之内再收窄（单次运行的上限与请求体规则）；
//! - 允许的请求写成 `方法 路径`：路径要么精确相同，要么以 `/*` 结尾，表示这个前缀之下的任意路径（按段比较）。
//!   没有别的通配写法：吸取 OpenSSH 通配匹配的教训，规则里不能出现 `*` 的其他用法、空规则或根路径通配；
//! - 管理凭据或账号的路径（任何一段是 keys、auth、billing 等）永远不放行，策略怎么写都一样；
//! - 路径先按段做百分号解码再比较，`%2F`、`..` 之类的写法一律拒绝，不能用编码绕过规则。

use serde::{Deserialize, Serialize};

use crate::model::Entry;

/// 允许的 HTTP 方法。
pub const RELAY_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

/// 永不放行的路径段（不区分大小写）：管理凭据、登录、账号与计费的接口。
pub const FORBIDDEN_SEGMENTS: &[&str] = &[
    "keys",
    "key",
    "api-keys",
    "api_keys",
    "apikeys",
    "auth",
    "oauth",
    "oauth2",
    "token",
    "tokens",
    "credentials",
    "billing",
    "account",
    "accounts",
    "admin",
    "organization",
    "organizations",
    "users",
    "members",
    "invites",
];

/// 认证头的名称不能是这些（它们决定请求怎样送达，或会被服务器改写）。
const RESERVED_HEADERS: &[&str] =
    &["host", "content-length", "transfer-encoding", "connection", "accept-encoding", "te", "upgrade", "cookie"];

/// 请求体规则：JSON 里 `key`（可以用点写嵌套的键）的值必须是 `values` 之一。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyRule {
    pub key: String,
    pub values: Vec<String>,
}

/// 一个条目的中继策略。上限为 0 表示不限。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPolicy {
    /// 条目的引用名。
    pub entry: String,
    /// 允许的请求：`方法 路径`，例如 `POST /api/v1/chat/completions`、`GET /api/v1/models/*`。
    pub allow: Vec<String>,
    /// 凭据怎样发出：`头名: 值`，值里恰好一个占位符：`{{secret}}`（单值条目）或 `{{字段名}}`（多字段条目）。
    pub auth: String,
    /// 请求体规则（同一个键的多条合并为"之一"，不同的键都要满足）。
    pub require: Vec<BodyRule>,
    /// 额外放行给本机程序的响应头（小写）。
    pub response_headers: Vec<String>,
    pub max_requests_run: u64,
    pub max_bytes_run: u64,
    pub max_requests_day: u64,
    pub max_bytes_day: u64,
}

/// 拆开 `方法 路径`：方法必须在 [`RELAY_METHODS`] 里，路径按 [`check_rule_path`] 校验。
pub fn parse_allow(s: &str) -> Result<(String, String), String> {
    let mut it = s.split_whitespace();
    let (Some(m), Some(p), None) = (it.next(), it.next(), it.next()) else {
        return Err(format!("允许的请求写成 \"方法 路径\"，例如 \"POST /api/v1/chat/completions\"：{s}"));
    };
    let m = m.to_ascii_uppercase();
    if !RELAY_METHODS.contains(&m.as_str()) {
        return Err(format!("不支持的方法 {m}（可用：{}）", RELAY_METHODS.join(" ")));
    }
    check_rule_path(p)?;
    Ok((m, p.to_string()))
}

/// 规则里的路径：以 `/` 开头；只能在末尾写 `/*`，而且前面至少有一段；不能有查询串、`%`、`..`、空段；不能落在永不放行的路径上。
pub fn check_rule_path(p: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("路径 {p} 不可用：{why}"));
    if !p.starts_with('/') {
        return bad("要以 / 开头");
    }
    let base = p.strip_suffix("/*").unwrap_or(p);
    if base.contains('*') {
        return bad("* 只能写在末尾，形如 /前缀/*");
    }
    if base.is_empty() || base == "/" {
        return bad("不能放行根路径之下的全部请求，请写出具体的前缀");
    }
    if p.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '?' | '#' | '%' | '\\')) {
        return bad("不能含查询串、百分号编码、反斜杠或空白");
    }
    let segs: Vec<&str> = base[1..].split('/').collect();
    if segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return bad("不能有空段、. 或 ..");
    }
    if segs.iter().any(|s| is_forbidden_segment(s)) {
        return bad("管理凭据或账号的路径永远不放行");
    }
    Ok(())
}

/// 这一段是不是管理凭据或账号的路径。
pub fn is_forbidden_segment(seg: &str) -> bool {
    FORBIDDEN_SEGMENTS.iter().any(|f| seg.eq_ignore_ascii_case(f))
}

/// 把请求路径（不含查询串）拆成百分号解码后的段。编码出来的 `/`、`\`、`.`、`..`、空字节或不是 UTF-8 的一律拒绝。
pub fn decode_path(path: &str) -> Result<Vec<String>, String> {
    let bad = || Err("路径不合法（编码的 / 或 \\、. 或 ..、控制字符）".to_string());
    if !path.starts_with('/') || path.contains('\\') || path.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return bad();
    }
    let mut out = Vec::new();
    for raw in path[1..].split('/') {
        let b = raw.as_bytes();
        let mut dec = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                // 百分号后面必须是两位十六进制
                let hex = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok());
                let Some(v) = hex else { return bad() };
                dec.push(v);
                i += 3;
            } else {
                dec.push(b[i]);
                i += 1;
            }
        }
        let Ok(s) = String::from_utf8(dec) else { return bad() };
        if s.contains(['/', '\\']) || s.chars().any(char::is_control) || s == "." || s == ".." {
            return bad();
        }
        out.push(s);
    }
    Ok(out)
}

/// 请求是否在策略之内：方法与解码后的路径匹配某条规则，而且没有一段是永不放行的。
pub fn path_allowed(p: &RelayPolicy, method: &str, path: &str) -> Result<(), String> {
    let segs = decode_path(path)?;
    // 末尾的 `/`（最后一段为空）不改变匹配：/v1/models/ 与 /v1/models 相同
    let segs: Vec<&str> = match segs.split_last() {
        Some((last, rest)) if last.is_empty() => rest.iter().map(String::as_str).collect(),
        _ => segs.iter().map(String::as_str).collect(),
    };
    if segs.iter().any(|s| s.is_empty()) {
        return Err("路径不能有空段".into());
    }
    if segs.iter().any(|s| is_forbidden_segment(s)) {
        return Err("管理凭据或账号的路径永远不放行".into());
    }
    for rule in &p.allow {
        let Ok((m, rp)) = parse_allow(rule) else { continue };
        if !m.eq_ignore_ascii_case(method) {
            continue;
        }
        let (prefix, wild) = match rp.strip_suffix("/*") {
            Some(b) => (b, true),
            None => (rp.as_str(), false),
        };
        let want: Vec<&str> = prefix[1..].split('/').collect();
        // 精确规则：段数相同且逐段相等；前缀规则：前缀之下至少还有一段
        let ok = if wild { segs.len() > want.len() && segs[..want.len()] == want[..] } else { segs == want };
        if ok {
            return Ok(());
        }
    }
    Err(format!("{method} {path} 不在这个凭据的策略之内"))
}

/// 拆开认证头模板 `头名: 值`，返回（小写头名，值模板，占位符名）。
pub fn parse_auth(s: &str) -> Result<(String, String, String), String> {
    let bad = || format!("认证头写成 \"头名: 值\"，值里恰好一个占位符，例如 \"Authorization: Bearer {{{{secret}}}}\"：{s}");
    let (name, value) = s.split_once(':').ok_or_else(bad)?;
    let name = name.trim().to_ascii_lowercase();
    let value = value.trim().to_string();
    // 头名只能是 RFC 9110 的 token 字符
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)) {
        return Err(bad());
    }
    if RESERVED_HEADERS.contains(&name.as_str()) {
        return Err(format!("认证头不能用 {name}"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(bad());
    }
    let (Some(a), Some(b)) = (value.find("{{"), value.find("}}")) else { return Err(bad()) };
    if b < a || value[b + 2..].contains("{{") || value[..a].contains("}}") || value[a + 2..b].contains("{{") {
        return Err(bad());
    }
    let ph = value[a + 2..b].trim().to_string();
    if ph.is_empty() {
        return Err(bad());
    }
    Ok((name, value, ph))
}

/// 拆开请求体规则 `json:键=值`。
pub fn parse_require(s: &str) -> Result<BodyRule, String> {
    let bad = || format!("请求体规则写成 json:键=值，例如 json:model=gpt-4o-mini：{s}");
    let rest = s.trim().strip_prefix("json:").ok_or_else(bad)?;
    let (k, v) = rest.split_once('=').ok_or_else(bad)?;
    let k = k.trim();
    if k.is_empty() || k.split('.').any(|p| p.is_empty()) || k.chars().any(|c| c.is_control() || c.is_whitespace()) || v.is_empty() {
        return Err(bad());
    }
    Ok(BodyRule { key: k.to_string(), values: vec![v.to_string()] })
}

/// 同一个键的规则合并成"值之一"（顺序按第一次出现）。
pub fn merge_rules(rules: Vec<BodyRule>) -> Vec<BodyRule> {
    let mut out: Vec<BodyRule> = Vec::new();
    for r in rules {
        match out.iter_mut().find(|x| x.key == r.key) {
            Some(x) => {
                for v in r.values {
                    if !x.values.contains(&v) {
                        x.values.push(v);
                    }
                }
            }
            None => out.push(r),
        }
    }
    out
}

/// 两个上限取更严的那个（0 表示不限）。
pub fn narrow(policy: u64, run: u64) -> u64 {
    match (policy, run) {
        (0, r) => r,
        (p, 0) => p,
        (p, r) => p.min(r),
    }
}

/// 校验并规范化策略：条目必须存在、允许 HTTP，认证头的占位符必须是这个条目自己的值。
pub fn validate_relay(p: &mut RelayPolicy, e: &Entry) -> Result<(), String> {
    if p.entry != e.name {
        return Err("策略与条目不一致".into());
    }
    if !e.allows(crate::model::OP_HTTP) {
        return Err(format!("条目 {} 不允许 http 用途：先运行 passmanager update --name {} --add-op http", e.name, e.name));
    }
    if e.is_private_key() {
        return Err("SSH 私钥不能用作 HTTP 凭据".into());
    }
    if p.allow.is_empty() {
        return Err("至少写一条允许的请求（--allow '方法 路径'）".into());
    }
    let mut allow = Vec::new();
    for a in &p.allow {
        let (m, path) = parse_allow(a)?;
        let norm = format!("{m} {path}");
        if !allow.contains(&norm) {
            allow.push(norm);
        }
    }
    p.allow = allow;
    let (name, value, ph) = parse_auth(&p.auth)?;
    // 占位符：单值条目写 secret，多字段条目写字段名
    let ok = if e.fields.is_empty() { ph == crate::model::AUTO_PLACEHOLDER } else { e.field(&ph).is_some() };
    if !ok {
        return Err(if e.fields.is_empty() {
            "单值条目的认证头写 {{secret}}".to_string()
        } else {
            format!("条目 {} 没有字段 {ph}", e.name)
        });
    }
    p.auth = format!("{name}: {value}");
    for r in &p.require {
        for v in &r.values {
            parse_require(&format!("json:{}={v}", r.key))?;
        }
    }
    p.require = merge_rules(std::mem::take(&mut p.require));
    let mut hs = Vec::new();
    for h in &p.response_headers {
        let h = h.trim().to_ascii_lowercase();
        if h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(format!("响应头名称不合法：{h}"));
        }
        // 这些头可能带回请求里的凭据或会话，策略也不能放行
        if matches!(
            h.as_str(),
            "set-cookie"
                | "set-cookie2"
                | "authorization"
                | "proxy-authorization"
                | "www-authenticate"
                | "proxy-authenticate"
                | "authentication-info"
        ) {
            return Err(format!("响应头 {h} 不能放行"));
        }
        if !hs.contains(&h) {
            hs.push(h);
        }
    }
    p.response_headers = hs;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn entry(fields: &[&str], ops: &[&str]) -> Entry {
        Entry {
            name: "or".into(),
            secret: Zeroizing::new(if fields.is_empty() { "sk-test".into() } else { String::new() }),
            domains: vec!["openrouter.example.com".into()],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: fields.iter().map(|n| crate::model::Field { name: n.to_string(), value: Zeroizing::new("v".into()) }).collect(),
            host_keys: vec![],
            ops: ops.iter().map(|o| o.to_string()).collect(),
        }
    }

    fn policy(allow: &[&str]) -> RelayPolicy {
        RelayPolicy {
            entry: "or".into(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            auth: "Authorization: Bearer {{secret}}".into(),
            require: vec![],
            response_headers: vec![],
            max_requests_run: 0,
            max_bytes_run: 0,
            max_requests_day: 0,
            max_bytes_day: 0,
        }
    }

    #[test]
    fn allow_rules_are_exact_or_segment_prefix() {
        let p = policy(&["POST /api/v1/chat/completions", "GET /api/v1/models/*"]);
        assert!(path_allowed(&p, "POST", "/api/v1/chat/completions").is_ok());
        assert!(path_allowed(&p, "post", "/api/v1/chat/completions/").is_ok(), "方法不分大小写，末尾 / 不影响");
        assert!(path_allowed(&p, "GET", "/api/v1/models/gpt").is_ok());
        assert!(path_allowed(&p, "GET", "/api/v1/models/a/b").is_ok());
        // 前缀规则不包括前缀本身，也不按字符串前缀匹配
        assert!(path_allowed(&p, "GET", "/api/v1/models").is_err());
        assert!(path_allowed(&p, "GET", "/api/v1/modelsX/a").is_err());
        assert!(path_allowed(&p, "GET", "/api/v1/chat/completions").is_err(), "方法不同");
        assert!(path_allowed(&p, "POST", "/api/v1/chat/completions/x").is_err(), "精确规则不含子路径");
        // 编码绕过：%2F、%2e%2e、反斜杠、空段
        for bad in [
            "/api/v1/chat%2Fcompletions",
            "/api/v1/models/%2e%2e/keys",
            "/api/v1/models\\x",
            "/api//v1/chat/completions",
            "/api/v1/models/%zz",
        ] {
            assert!(path_allowed(&p, "GET", bad).is_err() && path_allowed(&p, "POST", bad).is_err(), "{bad}");
        }
        // 编码过的普通字符照样解码后比较
        assert!(path_allowed(&p, "POST", "/api/v1/chat/%63ompletions").is_ok());
    }

    #[test]
    fn account_paths_are_never_allowed() {
        // 即使策略写了前缀通配，keys / auth 之类的段也不放行（包括编码写法与大小写）
        let p = policy(&["GET /api/v1/models/*"]);
        for bad in
            ["/api/v1/models/keys", "/api/v1/models/KEYS/x", "/api/v1/models/%6Beys", "/api/v1/models/billing", "/api/v1/models/auth/x"]
        {
            assert!(path_allowed(&p, "GET", bad).is_err(), "{bad}");
        }
        // 写进规则本身也不行
        assert!(parse_allow("GET /api/v1/keys").is_err());
        assert!(parse_allow("POST /api/v1/auth/*").is_err());
        assert!(is_forbidden_segment("Billing") && !is_forbidden_segment("models"));
    }

    #[test]
    fn rule_syntax_has_no_other_wildcards() {
        assert!(parse_allow("GET /*").is_err(), "根路径通配");
        assert!(parse_allow("GET /").is_err());
        assert!(parse_allow("GET /a*/b").is_err());
        assert!(parse_allow("GET /a/*/b").is_err());
        assert!(parse_allow("GET /a?x=1").is_err());
        assert!(parse_allow("GET /a/%2e").is_err());
        assert!(parse_allow("GET a/b").is_err());
        assert!(parse_allow("CONNECT /a").is_err());
        assert!(parse_allow("GET").is_err() && parse_allow("GET /a extra").is_err());
        assert_eq!(parse_allow("get /v1/models").unwrap(), ("GET".to_string(), "/v1/models".to_string()));
    }

    #[test]
    fn decode_path_segments() {
        assert_eq!(decode_path("/a/b%20c").unwrap(), vec!["a", "b c"]);
        assert_eq!(decode_path("/").unwrap(), vec![""]);
        for bad in ["a/b", "/a/%2f", "/a/%5C", "/a/..", "/a/%2E", "/a/%00", "/a/%ff", "/a b", "/a/%2"] {
            assert!(decode_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn auth_template() {
        assert_eq!(
            parse_auth("Authorization: Bearer {{secret}}").unwrap(),
            ("authorization".into(), "Bearer {{secret}}".into(), "secret".into())
        );
        assert_eq!(parse_auth("x-api-key: {{token}}").unwrap().2, "token");
        for bad in [
            "Authorization Bearer {{secret}}",
            "Authorization: Bearer",
            "A: {{a}} {{b}}",
            "Host: {{secret}}",
            "A B: {{secret}}",
            "A: }}x{{",
            "A: {{}}",
        ] {
            assert!(parse_auth(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn require_rules_and_limits() {
        assert_eq!(
            parse_require("json:model=@preset/gemma31b").unwrap(),
            BodyRule { key: "model".into(), values: vec!["@preset/gemma31b".into()] }
        );
        assert_eq!(parse_require("json:a.b=x=y").unwrap().values, vec!["x=y"], "值里可以有 =");
        for bad in ["model=x", "json:=x", "json:model=", "json:a..b=x", "json:a b=x"] {
            assert!(parse_require(bad).is_err(), "{bad}");
        }
        let m = merge_rules(vec![
            parse_require("json:model=a").unwrap(),
            parse_require("json:n=1").unwrap(),
            parse_require("json:model=b").unwrap(),
        ]);
        assert_eq!(
            m,
            vec![
                BodyRule { key: "model".into(), values: vec!["a".into(), "b".into()] },
                BodyRule { key: "n".into(), values: vec!["1".into()] }
            ]
        );
        assert_eq!((narrow(0, 0), narrow(0, 5), narrow(7, 0), narrow(7, 5), narrow(3, 5)), (0, 5, 7, 5, 3));
    }

    #[test]
    fn validate_policy_against_its_entry() {
        let e = entry(&[], &["http"]);
        let mut p = policy(&["post /v1/chat/completions", "POST /v1/chat/completions"]);
        p.auth = "AUTHORIZATION:Bearer {{secret}}".into();
        p.response_headers = vec![" X-RateLimit-Remaining ".into()];
        validate_relay(&mut p, &e).unwrap();
        assert_eq!(p.allow, vec!["POST /v1/chat/completions"], "规范化并去重");
        assert_eq!(p.auth, "authorization: Bearer {{secret}}");
        assert_eq!(p.response_headers, vec!["x-ratelimit-remaining"]);
        // 不允许 http、私钥、没有规则、占位符不是自己的值、危险的响应头
        assert!(validate_relay(&mut policy(&["GET /v1/x"]), &entry(&[], &["ssh"])).is_err());
        assert!(validate_relay(&mut policy(&[]), &e).is_err());
        let mut q = policy(&["GET /v1/x"]);
        q.auth = "x-key: {{other}}".into();
        assert!(validate_relay(&mut q, &e).is_err());
        let mut q = policy(&["GET /v1/x"]);
        q.auth = "x-key: {{token}}".into();
        assert!(validate_relay(&mut q, &entry(&["token"], &["http"])).is_ok());
        assert!(validate_relay(&mut q, &entry(&["user"], &["http"])).is_err());
        let mut q = policy(&["GET /v1/x"]);
        q.response_headers = vec!["set-cookie".into()];
        assert!(validate_relay(&mut q, &e).is_err());
        let mut q = policy(&["GET /v1/x"]);
        q.entry = "other".into();
        assert!(validate_relay(&mut q, &e).is_err());
    }
}

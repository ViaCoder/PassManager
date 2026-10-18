//! Agent 的 `lookup`：按目标（URL、`user@host`、主机或条目名）返回**这一个目标**可用的凭据与现成的写法。
//!
//! - 选择规则与真正执行请求时完全相同（`http::select` / `http::ssh_credentials`），查到的就是会用到的；
//! - 只返回条目名、字段名与写法：不返回其他条目、该条目绑定的其他域名、备注或用途清单；
//! - 错误沿用执行请求时的错误码（`NO_CREDENTIAL`、`AMBIGUOUS`、`OP_NOT_ALLOWED`……），信息同样不列出域名。

use pm_proto::LookupView;
use pm_vault::{Entry, OP_GIT, OP_HTTP, Payload, domain};
use url::Url;

use crate::http::{host_string, ssh_credentials};
use crate::ssh::{parse_route, parse_target};
use crate::{ApiErr, err};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Use {
    Http,
    Ssh,
    Scp,
    Git,
}

impl Use {
    fn parse(s: &str) -> Result<Self, ApiErr> {
        match s.trim().to_ascii_lowercase().as_str() {
            "http" | "https" => Ok(Use::Http),
            "ssh" => Ok(Use::Ssh),
            "scp" | "sftp" => Ok(Use::Scp),
            "git" => Ok(Use::Git),
            other => Err(err("BAD_REQUEST", format!("unknown use \"{other}\"; use one of http, ssh, scp, git"))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Use::Http => "http",
            Use::Ssh => "ssh",
            Use::Scp => "scp",
            Use::Git => "git",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Use::Ssh | Use::Scp => 22,
            Use::Http | Use::Git => 443,
        }
    }

    fn op(self) -> &'static str {
        match self {
            Use::Http => OP_HTTP,
            Use::Git => OP_GIT,
            Use::Ssh | Use::Scp => pm_vault::OP_SSH,
        }
    }
}

/// 这台主机只在一个端口上绑定了可用于该用途的条目时（例如 git.hk.gy:8121），返回那个端口。
fn bound_port(payload: &Payload, host: &str, op: &str) -> Option<u16> {
    let mut ports: Vec<u16> = payload
        .entries
        .iter()
        .filter(|e| e.allows(op))
        .flat_map(|e| e.domains.iter())
        .filter_map(|d| match domain::pattern_parts(d) {
            (h, Some(p)) if domain::matches(&h, host) => Some(p),
            _ => None,
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    match ports.as_slice() {
        [p] => Some(*p),
        _ => None,
    }
}

/// URL 里是否显式写了端口（url 库会把与默认端口相同的端口去掉，所以看原始字符串）。
fn url_has_port(url: &str) -> bool {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    if hostport.starts_with('[') { hostport.contains("]:") } else { hostport.contains(':') }
}

/// 同 [`by_host`]；没写端口（`explicit` 为假）且按默认端口查不到时，改用该主机唯一绑定的端口。
fn by_host_guess(
    payload: &Payload,
    host: &str,
    port: u16,
    explicit: bool,
    use_: Use,
    name: Option<&str>,
    user: Option<&str>,
) -> Result<LookupView, ApiErr> {
    let r = by_host(payload, host, port, use_, name, user);
    if r.is_ok() || explicit {
        return r;
    }
    match bound_port(payload, host, use_.op()) {
        Some(p) if p != port => by_host(payload, host, p, use_, name, user).or(r),
        _ => r,
    }
}

/// 字段名中被当作"基础地址"的那个（值是秘密的 https URL，写在 URL 开头）。
const BASE_URL: &str = "base_url";

fn field_names(e: &Entry) -> Vec<String> {
    e.fields.iter().map(|f| f.name.clone()).collect()
}

/// 主机与端口的显示形式：默认端口时省略端口；IPv6 加方括号。
fn host_port(host: &str, port: u16, default: u16) -> String {
    let h = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    if port == default { h } else { format!("{h}:{port}") }
}

/// 多字段条目里适合放进 `Authorization: Bearer` 的字段（按常见的令牌字段名挑选；没有时不举请求头的例子，
/// 免得把用户名之类的字段写成令牌）。
fn token_field(e: &Entry) -> Option<&str> {
    const TOKEN_NAMES: [&str; 7] = ["api_key", "apikey", "token", "access_token", "key", "secret", "bearer"];
    TOKEN_NAMES.iter().find_map(|t| e.fields.iter().map(|f| f.name.as_str()).find(|n| n.eq_ignore_ascii_case(t)))
}

/// `named`：Agent 指定了条目名（同一主机有多个凭据时）——这时必须写 `{{名称}}`，`{{secret}}` 会再次报 AMBIGUOUS。
fn http_how(e: &Entry, url_prefix: &str, named: bool) -> String {
    if e.fields.is_empty() {
        let ph = if named { format!("{{{{{}}}}}", e.name) } else { "{{secret}}".to_string() };
        return format!(
            "http {{\"method\":\"GET\",\"url\":\"{url_prefix}/<path>\",\"headers\":{{\"Authorization\":\"Bearer {ph}\"}}}} \
             - put {ph} where this API expects its key (header, query or body)"
        );
    }
    let name = &e.name;
    let header = token_field(e).map(|f| format!(",\"headers\":{{\"Authorization\":\"Bearer {{{{{name}.{f}}}}}\"}}")).unwrap_or_default();
    format!(
        "http {{\"method\":\"GET\",\"url\":\"{url_prefix}/<path>\"{header}}} - write {{{{{name}.<field>}}}} where the API expects a field"
    )
}

fn ssh_how(target: &str, has_password: bool) -> String {
    let sudo = if has_password { "; a command starting with \"sudo \" gets the password automatically" } else { "" };
    format!(
        "ssh {{\"target\":\"{target}\",\"command\":\"<command>\"}}; scp {{\"source\":\"<local file>\",\"destination\":\"{target}:/<path>\"}}{sudo}"
    )
}

fn git_how(hp: &str) -> String {
    format!(
        "passmanager run git <clone|fetch|pull|push|ls-remote> https://{hp}/<owner>/<repo>.git - prefix every git \
         command with passmanager run; the server adds the token for that one command, nothing is installed or configured"
    )
}

/// `{{名称}}` 或 `{{名称.字段}}` 形式的目标：只在没有主机可查时使用（例如基础地址本身是秘密）。
fn by_name(payload: &Payload, token: &str, use_: Use) -> Result<LookupView, ApiErr> {
    let token = token.trim();
    let (entry, field) = match payload.entry(token) {
        Some(e) => (e, None),
        None => {
            let mut by_prefix: Vec<&Entry> =
                payload.entries.iter().filter(|e| token.len() > e.name.len() + 1 && token.starts_with(&format!("{}.", e.name))).collect();
            by_prefix.sort_by_key(|e| std::cmp::Reverse(e.name.len()));
            let e = by_prefix.first().ok_or_else(|| err("UNKNOWN_CREDENTIAL", format!("no credential \"{token}\"")))?;
            let f = &token[e.name.len() + 1..];
            if e.field(f).is_none() {
                return Err(err("UNKNOWN_FIELD", format!("\"{}\" has no field \"{f}\"", e.name)));
            }
            (*e, Some(f.to_string()))
        }
    };
    let op = match use_ {
        Use::Http => OP_HTTP,
        Use::Git => OP_GIT,
        Use::Ssh | Use::Scp => pm_vault::OP_SSH,
    };
    if !entry.allows(op) {
        return Err(err("OP_NOT_ALLOWED", format!("\"{}\" may not be used for {op} requests", entry.name)));
    }
    if entry.domains.is_empty() {
        return Err(err("DOMAIN_MISMATCH", format!("\"{}\" is not bound to any domain yet", entry.name)));
    }
    let has_base = entry.field(BASE_URL).is_some() && matches!(field.as_deref(), None | Some(BASE_URL));
    let (target, how) = if use_ == Use::Http && has_base {
        let label = format!("{{{{{}.{BASE_URL}}}}}", entry.name);
        (label.clone(), format!("{} - the base URL stays secret; do not try to find it", http_how(entry, &label, true)))
    } else {
        (format!("{{{{{}}}}}", entry.name), {
            let n = &entry.name;
            let ph = if entry.fields.is_empty() { format!("{{{{{n}}}}}") } else { format!("{{{{{n}.<field>}}}}") };
            format!(
                "write {ph} instead of {{{{secret}}}} in an http request to a host \"{n}\" is bound to, or {n}/user@host \
                     for ssh or scp. If you do not know the host, ask the user."
            )
        })
    };
    Ok(LookupView { target, use_: use_.as_str().into(), credentials: vec![entry.name.clone()], fields: field_names(entry), how })
}

fn by_host(payload: &Payload, host: &str, port: u16, use_: Use, name: Option<&str>, user: Option<&str>) -> Result<LookupView, ApiErr> {
    let hp = host_port(host, port, use_.default_port());
    match use_ {
        Use::Http | Use::Git => {
            let op = if use_ == Use::Http { OP_HTTP } else { OP_GIT };
            let e = crate::http::select(payload, name, host, port, op)?;
            let how = if use_ == Use::Http { http_how(&e, &format!("https://{hp}"), name.is_some()) } else { git_how(&hp) };
            Ok(LookupView {
                target: host_port(host, port, 0),
                use_: use_.as_str().into(),
                credentials: vec![e.name.clone()],
                fields: field_names(&e),
                how,
            })
        }
        Use::Ssh | Use::Scp => {
            let (key, pw) = ssh_credentials(payload, name, host, port)?;
            let credentials: Vec<String> = key.iter().chain(pw.iter()).map(|e| e.name.clone()).collect();
            let prefix = name.map(|n| format!("{n}/")).unwrap_or_default();
            let target = format!("{prefix}{}@{hp}", user.unwrap_or("root"));
            Ok(LookupView {
                target: host_port(host, port, 0),
                use_: use_.as_str().into(),
                credentials,
                fields: vec![],
                how: ssh_how(&target, pw.is_some()),
            })
        }
    }
}

/// `lookup` 的实现（见模块说明）。
pub fn lookup(payload: &Payload, target: &str, use_: Option<&str>) -> Result<LookupView, ApiErr> {
    let t = target.trim();
    if t.is_empty() {
        return Err(err("BAD_REQUEST", "missing target: give the URL, user@host or host you want to use"));
    }
    let given = use_.filter(|u| !u.trim().is_empty()).map(Use::parse).transpose()?;

    // {{名称}} / {{名称.字段}}
    if let Some(inner) = t.strip_prefix("{{").and_then(|r| r.strip_suffix("}}")) {
        return by_name(payload, inner, given.unwrap_or(Use::Http));
    }

    // [名称/]URL（名称用于同一主机有多个凭据时指定其中一个）
    if let Some(i) = t.find("://") {
        let (name, url) = match t[..i].split_once('/') {
            Some((n, _)) if !n.is_empty() => (Some(n), &t[n.len() + 1..]),
            _ => (None, t),
        };
        let u = Url::parse(url).map_err(|_| err("BAD_REQUEST", format!("\"{url}\" is not a valid URL")))?;
        let use_ = given.unwrap_or(Use::Http);
        if matches!(use_, Use::Ssh | Use::Scp) {
            return Err(err("BAD_REQUEST", "for ssh or scp give user@host, not a URL"));
        }
        if u.scheme() != "https" {
            return Err(err("USE_HTTPS", "only https:// URLs are supported"));
        }
        let host = host_string(&u).ok_or_else(|| err("BAD_REQUEST", format!("\"{url}\" has no host")))?;
        let port = u.port_or_known_default().unwrap_or(443);
        return by_host_guess(payload, &host, port, url_has_port(url), use_, name, None);
    }

    // 跳板路由 跳板>目标：两跳各自查 ssh 凭据，how 写完整路由
    if t.contains('>') {
        if matches!(given, Some(Use::Http | Use::Git)) {
            return Err(err("BAD_REQUEST", "a jump route jumpuser@jumphost>user@host is only for ssh or scp"));
        }
        let (jump, dest) = parse_route(t)?;
        let jump = jump.ok_or_else(|| err("BAD_REQUEST", format!("invalid target \"{t}\"")))?;
        let hop = |d: &crate::ssh::Dest| -> Result<(String, Vec<String>, bool), ApiErr> {
            let (key, pw) = ssh_credentials(payload, d.name.as_deref(), &d.host, d.port)?;
            let prefix = d.name.as_ref().map(|n| format!("{n}/")).unwrap_or_default();
            let names = key.iter().chain(pw.iter()).map(|e| e.name.clone()).collect();
            Ok((format!("{prefix}{}@{}", d.user, host_port(&d.host, d.port, 22)), names, pw.is_some()))
        };
        let (jt, mut credentials, _) = hop(&jump)?;
        let (dt, names, has_pw) = hop(&dest)?;
        credentials.extend(names.into_iter().filter(|n| !credentials.contains(n)).collect::<Vec<_>>());
        let use_ = given.unwrap_or(Use::Ssh);
        return Ok(LookupView {
            target: format!("{}>{}", host_port(&jump.host, jump.port, 0), host_port(&dest.host, dest.port, 0)),
            use_: use_.as_str().into(),
            credentials,
            fields: vec![],
            how: ssh_how(&format!("{jt}>{dt}"), has_pw),
        });
    }

    // [名称/]user@host[:port]
    if t.contains('@') || t.contains('/') {
        let use_ = given.unwrap_or(Use::Ssh);
        let d = parse_target(t)?;
        if matches!(use_, Use::Http | Use::Git) {
            // parse_target 省略端口时按 SSH 的 22 处理；http / git 没写端口时是 443。
            let hostport = t.rsplit('@').next().unwrap_or(t);
            let explicit = if hostport.starts_with('[') { hostport.contains("]:") } else { hostport.contains(':') };
            let port = if explicit { d.port } else { use_.default_port() };
            return by_host_guess(payload, &d.host, port, explicit, use_, d.name.as_deref(), None);
        }
        let hostport = t.rsplit('@').next().unwrap_or(t);
        let explicit = if hostport.starts_with('[') { hostport.contains("]:") } else { hostport.contains(':') };
        return by_host_guess(payload, &d.host, d.port, explicit, use_, d.name.as_deref(), Some(&d.user));
    }

    // 主机[:端口]（IPv6 写成 [::1] 或 [::1]:端口，也接受不带方括号的 IPv6）；
    // 没有任何条目匹配这个主机、但有同名条目时按条目名查询。
    let use_ = given.unwrap_or(Use::Http);
    let bad_port = || err("BAD_REQUEST", format!("invalid port in \"{t}\""));
    let (host, port) = if let Some(v6) = t.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| err("BAD_REQUEST", format!("invalid host \"{t}\"")))?;
        match after.strip_prefix(':') {
            Some(p) => (h, p.parse::<u16>().map_err(|_| bad_port())?),
            None if after.is_empty() => (h, use_.default_port()),
            None => return Err(err("BAD_REQUEST", format!("invalid host \"{t}\""))),
        }
    } else {
        match t.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, p.parse::<u16>().map_err(|_| bad_port())?),
            _ => (t, use_.default_port()),
        }
    };
    let host = domain::normalize_host(host);
    let explicit = if t.starts_with('[') { t.contains("]:") } else { t.rsplit_once(':').is_some_and(|(h, _)| !h.contains(':')) };
    let r = by_host_guess(payload, &host, port, explicit, use_, None, None);
    match r {
        Err(e) if e.code == "NO_CREDENTIAL" && payload.entry(t).is_some() => by_name(payload, t, use_),
        other => other,
    }
}

/// 是不是 Tang 的说明请求：目标写 `tang`、用途写 `tang`，或目标是本服务器的 `/tang` 地址（`origin` 是本服务器网页地址，
/// 非服务器模式为 None）。其他主机的 `/tang` 地址不算：那不是本服务器的 Tang。
pub fn is_tang(target: &str, use_: Option<&str>, origin: Option<&str>) -> bool {
    let t = target.trim().to_ascii_lowercase();
    let own = origin.is_some_and(|o| {
        let base = format!("{}/tang", o.to_ascii_lowercase());
        t == base || t.starts_with(&format!("{base}/"))
    });
    t == "tang" || own || use_.is_some_and(|u| u.trim().eq_ignore_ascii_case("tang"))
}

/// `lookup tang` 的结果：没有凭据，`how` 是填好本服务器地址与 Tang 签名密钥指纹的步骤。
pub fn tang_view(origin: &str, thps: &[String]) -> LookupView {
    LookupView {
        target: format!("{origin}/tang"),
        use_: "tang".into(),
        credentials: vec![],
        fields: vec![],
        how: pm_proto::agent_text::tang_how(origin, thps),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tang_targets() {
        let o = Some("https://pm.example.com:8120");
        for t in ["tang", " TANG ", "https://pm.example.com:8120/tang", "https://PM.example.com:8120/tang/adv"] {
            assert!(is_tang(t, None, o), "{t}");
        }
        assert!(is_tang("anything", Some("tang"), None), "用途写 tang");
        assert!(is_tang("tang", None, None), "非服务器模式也认出来（返回 NO_TANG）");
        // 其他主机或端口的 /tang、只是前缀相同的路径、普通目标：不是。
        for t in [
            "https://other.example.com/tang",
            "https://pm.example.com:8121/tang",
            "https://pm.example.com:8120/tangx",
            "tangd",
            "root@tang",
        ] {
            assert!(!is_tang(t, None, o), "{t}");
        }
        assert!(!is_tang("https://pm.example.com:8120/tang", Some("http"), None), "非服务器模式不认 URL");
    }

    #[test]
    fn tang_view_has_no_credentials() {
        let v = tang_view("https://pm.example.com:8120", &["thpA".into()]);
        assert_eq!((v.target.as_str(), v.use_.as_str()), ("https://pm.example.com:8120/tang", "tang"));
        assert!(v.credentials.is_empty() && v.fields.is_empty());
        assert!(v.how.contains(r#""thp":"thpA""#));
    }
    use pm_vault::Field;
    use zeroize::Zeroizing;

    fn entry(name: &str, secret: &str, domains: &[&str], ops: &[&str]) -> Entry {
        Entry {
            name: name.into(),
            secret: Zeroizing::new(secret.into()),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            note: "NOTE-SHOULD-NOT-LEAK /root/secret-path".into(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: vec![],
            host_keys: vec![],
            ops: ops.iter().map(|o| o.to_string()).collect(),
        }
    }

    fn fld(n: &str, v: &str) -> Field {
        Field { name: n.into(), value: Zeroizing::new(v.into()) }
    }

    fn payload() -> Payload {
        let mut p = Payload::default();
        p.entries.push(entry("github", "ghp_SECRET1", &["github.com", "api.github.com", "other-private.example.net"], &["http", "git"]));
        p.entries.push(entry("cf", "CF_SECRET", &["api.cloudflare.com"], &["http"]));
        p.entries.push(entry("init", "INITPASS", &["198.51.100.0/24"], &["ssh"]));
        let mut ai = entry("ai", "", &["gateway.example.com"], &["http"]);
        ai.fields = vec![fld("base_url", "https://gateway.example.com/v1/acct-7f3e"), fld("api_key", "sk-SECRET")];
        p.entries.push(ai);
        p.entries.push(entry("dup1", "D1", &["dup.example.com"], &[]));
        p.entries.push(entry("dup2", "D2", &["dup.example.com"], &[]));
        p
    }

    fn json(v: &LookupView) -> String {
        serde_json::to_string(v).unwrap()
    }

    /// 只返回这一个目标的信息：没有其他条目、其他域名、备注、用途清单或秘密。
    #[test]
    fn need_to_know_only() {
        let p = payload();
        let v = lookup(&p, "https://api.github.com/user", None).unwrap();
        assert_eq!(v.credentials, vec!["github"]);
        assert_eq!(v.use_, "http");
        assert!(v.how.contains("{{secret}}") && v.how.contains("https://api.github.com/<path>"), "{}", v.how);
        let s = json(&v);
        for leak in ["other-private", "github.com\"", "NOTE", "secret-path", "ghp_", "cf", "init", "\"git\"", "ops"] {
            assert!(!s.contains(leak), "leaked {leak}: {s}");
        }
    }

    #[test]
    fn ssh_targets_and_use_inference() {
        let p = payload();
        let v = lookup(&p, "root@198.51.100.254", None).unwrap();
        assert_eq!((v.use_.as_str(), v.credentials.clone()), ("ssh", vec!["init".to_string()]));
        assert!(v.how.contains("\"target\":\"root@198.51.100.254\"") && v.how.contains("sudo"), "{}", v.how);
        assert!(!json(&v).contains("198.51.100.0/24"));
        let v = lookup(&p, "deploy@198.51.100.9:2222", Some("scp")).unwrap();
        assert_eq!(v.use_, "scp");
        assert!(v.how.contains("deploy@198.51.100.9:2222:/<path>"), "{}", v.how);
        // 只能用于 ssh 的条目不能用于 http。
        assert_eq!(lookup(&p, "https://198.51.100.5/", None).unwrap_err().code, "OP_NOT_ALLOWED");
    }

    #[test]
    fn url_port_detection() {
        assert!(!url_has_port("https://git.example.com/o/r.git"));
        assert!(url_has_port("https://git.example.com:443/o/r.git"));
        assert!(url_has_port("https://git.example.com:8121"));
        assert!(!url_has_port("https://user@git.example.com/o"));
        assert!(url_has_port("https://user:pw@git.example.com:8121/o"));
        assert!(!url_has_port("https://[2001:db8::1]/x"));
        assert!(url_has_port("https://[2001:db8::1]:8443/x"));
        assert!(!url_has_port("https://a.example.com/path:with:colons"));
    }

    /// 没写端口时：主机只在一个端口上绑定了可用条目，就用那个端口（例如 MegaGit 只开 8121）。
    #[test]
    fn implicit_port_from_binding() {
        let mut p = payload();
        p.entries.push(entry("forge", "PAT_SECRET", &["git.example.com:8121"], &["git"]));
        p.entries.push(entry("alt", "ALTPW", &["203.0.113.5:2222"], &["ssh"]));
        for t in ["git.example.com", "https://git.example.com/owner/repo.git"] {
            let v = lookup(&p, t, Some("git")).unwrap();
            assert_eq!((v.target.as_str(), v.credentials.clone()), ("git.example.com:8121", vec!["forge".to_string()]), "{t}");
            assert!(v.how.contains("https://git.example.com:8121/<owner>/<repo>.git"), "{}", v.how);
        }
        // 显式写了别的端口：不改端口。
        assert!(lookup(&p, "git.example.com:443", Some("git")).is_err());
        assert!(lookup(&p, "https://git.example.com:443/o/r.git", Some("git")).is_err());
        // ssh 同理。
        let v = lookup(&p, "root@203.0.113.5", None).unwrap();
        assert!(v.how.contains("root@203.0.113.5:2222"), "{}", v.how);
        // 默认端口本来就能查到：结果不变。
        assert_eq!(lookup(&p, "root@198.51.100.254", None).unwrap().credentials, vec!["init".to_string()]);
        // 同一主机绑定了两个端口：有歧义，不猜。
        p.entries.push(entry("forge2", "PAT2", &["git.example.com:8122"], &["git"]));
        assert!(lookup(&p, "git.example.com", Some("git")).is_err());
        assert!(!json(&lookup(&p, "git.example.com:8121", Some("git")).unwrap()).contains("8122"), "不泄露同主机的其他绑定");
    }

    /// 跳板路由：两跳各自查凭据，how 写完整路由；任何一跳没有凭据就报那一跳的错误。
    #[test]
    fn jump_route() {
        let p = payload();
        let v = lookup(&p, "root@198.51.100.254>deploy@198.51.100.9:2222", None).unwrap();
        assert_eq!((v.use_.as_str(), v.credentials.clone()), ("ssh", vec!["init".to_string()]), "两跳同一条目只列一次");
        assert_eq!(v.target, "198.51.100.254:22>198.51.100.9:2222", "与单跳一样，target 总带端口");
        assert!(v.how.contains("\"target\":\"root@198.51.100.254>deploy@198.51.100.9:2222\""), "{}", v.how);
        assert!(v.how.contains("root@198.51.100.254>deploy@198.51.100.9:2222:/<path>") && v.how.contains("sudo"), "{}", v.how);
        assert!(!json(&v).contains("198.51.100.0/24"));
        assert_eq!(lookup(&p, "root@198.51.100.254>root@db.example.com", None).unwrap_err().code, "NO_CREDENTIAL");
        assert_eq!(lookup(&p, "root@db.example.com>root@198.51.100.9", None).unwrap_err().code, "NO_CREDENTIAL");
        assert_eq!(lookup(&p, "root@198.51.100.254>root@198.51.100.9", Some("http")).unwrap_err().code, "BAD_REQUEST");
        assert_eq!(lookup(&p, "root@198.51.100.1>root@198.51.100.2>root@198.51.100.3", None).unwrap_err().code, "BAD_REQUEST");
    }

    /// user@host 用于 http / git 时，没写端口按 443（而不是 SSH 的 22）；IPv6 主机的各种写法。
    #[test]
    fn ports_and_ipv6() {
        let mut p = payload();
        p.entries.push(entry("tls-only", "T", &["svc.example.com:443"], &["http"]));
        p.entries.push(entry("v6", "V", &["2001:db8::7"], &[]));
        assert_eq!(lookup(&p, "tls-only/u@svc.example.com", Some("http")).unwrap().target, "svc.example.com:443");
        assert_eq!(lookup(&p, "u@svc.example.com:8443", Some("http")).unwrap_err().code, "NO_CREDENTIAL");
        for t in ["2001:db8::7", "[2001:db8::7]", "[2001:db8::7]:443", "https://[2001:db8::7]/x"] {
            let v = lookup(&p, t, None).unwrap_or_else(|e| panic!("{t}: {} {}", e.code, e.message));
            assert_eq!((v.credentials[0].as_str(), v.target.as_str()), ("v6", "[2001:db8::7]:443"), "{t}");
            assert!(v.how.contains("https://[2001:db8::7]/<path>"), "{}", v.how);
        }
        assert_eq!(lookup(&p, "[2001:db8::7", None).unwrap_err().code, "BAD_REQUEST");
        assert_eq!(lookup(&p, "svc.example.com:99999", None).unwrap_err().code, "BAD_REQUEST");
    }

    /// 多字段条目：只有令牌类字段才举 Bearer 的例子；用户名口令类不举，免得写错。
    #[test]
    fn header_example_only_for_token_fields() {
        let mut p = payload();
        let mut c = entry("creds", "", &["login.example.com"], &[]);
        c.fields = vec![fld("username", "u"), fld("password", "pw")];
        p.entries.push(c);
        let v = lookup(&p, "https://login.example.com/", None).unwrap();
        assert!(!v.how.contains("Bearer") && v.how.contains("{{creds.<field>}}"), "{}", v.how);
        assert_eq!(v.fields, vec!["username", "password"]);
        // 按名称查询普通条目：直接给出 {{名称}} 的写法，不再让 Agent 回头查询（避免循环）。
        let v = lookup(&p, "{{creds}}", None).unwrap();
        assert!(
            v.how.contains("{{creds.<field>}}") && v.how.contains("instead of {{secret}}") && !v.how.contains("call lookup"),
            "{}",
            v.how
        );
    }

    #[test]
    fn git_and_errors() {
        let p = payload();
        let v = lookup(&p, "github.com", Some("git")).unwrap();
        // git 的写法与规则块 v5 一致：用 passmanager run，不再叫 Agent 安装 git-proxy。
        assert!(v.how.starts_with("passmanager run git ") && v.how.contains("https://github.com/<owner>"), "{}", v.how);
        assert!(!v.how.contains("git-proxy"), "{}", v.how);
        assert_eq!(lookup(&p, "api.cloudflare.com", Some("git")).unwrap_err().code, "OP_NOT_ALLOWED");
        assert_eq!(lookup(&p, "nothing.example.org", None).unwrap_err().code, "NO_CREDENTIAL");
        let e = lookup(&p, "https://dup.example.com/x", None).unwrap_err();
        assert_eq!(e.code, "AMBIGUOUS");
        assert!(e.message.contains("dup1") && e.message.contains("dup2") && !e.message.contains("NOTE"), "{}", e.message);
        // 指定名称即可消除歧义（user@host 或 URL 前加 名称/）。
        assert_eq!(lookup(&p, "dup2/u@dup.example.com", Some("http")).unwrap().credentials, vec!["dup2"]);
        let v = lookup(&p, "dup1/https://dup.example.com/x", None).unwrap();
        assert_eq!((v.credentials.clone(), v.target.as_str()), (vec!["dup1".to_string()], "dup.example.com:443"));
        // 指定了名称时写法用 {{dup1}}：{{secret}} 在这台主机上会再次报 AMBIGUOUS。
        assert!(v.how.contains("Bearer {{dup1}}") && !v.how.contains("{{secret}}"), "{}", v.how);
        assert_eq!(lookup(&p, "nope/https://dup.example.com/x", None).unwrap_err().code, "UNKNOWN_CREDENTIAL");
        // 名称与主机不符：不列出该条目绑定的域名。
        let e = lookup(&p, "cf/u@api.github.com", Some("http")).unwrap_err();
        assert_eq!(e.code, "DOMAIN_MISMATCH");
        assert!(!e.message.contains("cloudflare"), "{}", e.message);
        assert_eq!(lookup(&p, "x", Some("ftp")).unwrap_err().code, "BAD_REQUEST");
        assert_eq!(lookup(&p, "  ", None).unwrap_err().code, "BAD_REQUEST");
        assert_eq!(lookup(&p, "http://github.com/", None).unwrap_err().code, "USE_HTTPS");
    }

    /// 基础地址本身是秘密：按条目名查询，给出 {{ai.base_url}} 写法，不泄露地址或主机。
    #[test]
    fn base_url_by_name() {
        let p = payload();
        for t in ["{{ai.base_url}}", "{{ai}}", "ai"] {
            let v = lookup(&p, t, None).unwrap();
            assert_eq!(v.target, "{{ai.base_url}}", "{t}");
            assert!(v.how.contains("\"url\":\"{{ai.base_url}}/<path>\"") && v.how.contains("Bearer {{ai.api_key}}"), "{}", v.how);
            assert_eq!(v.fields, vec!["base_url", "api_key"]);
            let s = json(&v);
            assert!(!s.contains("acct-7f3e") && !s.contains("gateway.example.com") && !s.contains("sk-"), "{s}");
        }
        // 普通条目按名称查询：不给域名，只告诉 Agent 用目标再查。
        let v = lookup(&p, "{{cf}}", None).unwrap();
        assert!(v.how.contains("{{cf}}") && !json(&v).contains("cloudflare.com"), "{}", v.how);
        assert_eq!(lookup(&p, "{{nope}}", None).unwrap_err().code, "UNKNOWN_CREDENTIAL");
    }
}

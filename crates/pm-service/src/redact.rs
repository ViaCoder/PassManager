//! 输出脱敏。
//!
//! 对每个密钥生成多种编码变体：原文、Base64（标准 / URL 安全，各 3 种字节对齐偏移）、
//! hex（大小写）、URL 百分号编码、JSON 转义、HTML 转义；多行密钥（如 PEM 私钥）的每一行。
//! 用 Aho-Corasick 一次扫描全部变体，替换为 `[REDACTED:name]`。

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

const MIN_LEN: usize = 4;

pub struct Redactor {
    ac: Option<AhoCorasick>,
    replacements: Vec<String>,
    /// 别名的真实地址与主机（不区分大小写：主机名大小写不敏感，服务器常把它原样或改写后回显）。
    alias_ac: Option<AhoCorasick>,
    alias_replacements: Vec<String>,
    /// 流式脱敏用：全部模式（排序后）及其首字节，用来判断数据末尾是否可能是某个模式的开头。
    prefixes: Prefixes,
    alias_prefixes: Prefixes,
}

/// 排好序的模式，回答"这段字节是不是某个模式的开头"。
#[derive(Default)]
struct Prefixes {
    sorted: Vec<Vec<u8>>,
    first: Vec<bool>,
    max: usize,
    /// 不区分大小写（别名）：模式与被查的字节都转成小写。
    ci: bool,
}

impl Prefixes {
    fn new(patterns: &[Vec<u8>], ci: bool) -> Self {
        let mut sorted: Vec<Vec<u8>> = patterns.iter().map(|p| if ci { p.to_ascii_lowercase() } else { p.clone() }).collect();
        sorted.sort();
        sorted.dedup();
        let mut first = vec![false; 256];
        for p in &sorted {
            first[p[0] as usize] = true;
        }
        let max = sorted.iter().map(Vec::len).max().unwrap_or(0);
        Self { sorted, first, max, ci }
    }

    /// `buf` 末尾最长的、恰好是某个模式开头的那一段有多长（最多比最长的模式短一个字节）。
    /// 这一段之前的字节不可能再属于一个还没出现完整的匹配，可以放心送出。
    fn hold(&self, buf: &[u8]) -> usize {
        let lim = self.max.saturating_sub(1).min(buf.len());
        if lim == 0 {
            return 0;
        }
        let tail = &buf[buf.len() - lim..];
        let tail = if self.ci { tail.to_ascii_lowercase() } else { tail.to_vec() };
        for k in (1..=lim).rev() {
            let s = &tail[lim - k..];
            if !self.first[s[0] as usize] {
                continue;
            }
            // 排序后第一个不小于 s 的模式：如果有以 s 开头的模式，它就是其中之一
            let i = self.sorted.partition_point(|p| p.as_slice() < s);
            if self.sorted.get(i).is_some_and(|p| p.starts_with(s)) {
                return k;
            }
        }
        0
    }
}

fn push(out: &mut Vec<Vec<u8>>, v: Vec<u8>) {
    if v.len() >= MIN_LEN && !out.contains(&v) {
        out.push(v);
    }
}

/// Base64 中"完全由密钥字节决定"的那一段字符（对任意前后文都成立）。
fn base64_core(secret: &[u8], offset: usize, url_safe: bool) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; offset];
    buf.extend_from_slice(secret);
    let enc = if url_safe { URL_SAFE_NO_PAD.encode(&buf) } else { STANDARD_NO_PAD.encode(&buf) };
    let start = (8 * offset).div_ceil(6);
    let end = (8 * (offset + secret.len())) / 6;
    if end <= start {
        return None;
    }
    Some(enc.as_bytes()[start..end].to_vec())
}

pub fn variants(secret: &str) -> Vec<Vec<u8>> {
    let s = secret.as_bytes();
    let mut out = Vec::new();
    push(&mut out, s.to_vec());
    let trimmed = secret.trim();
    if trimmed != secret {
        push(&mut out, trimmed.as_bytes().to_vec());
    }
    for off in 0..3 {
        for url in [false, true] {
            if let Some(v) = base64_core(s, off, url) {
                push(&mut out, v);
            }
        }
    }
    push(&mut out, hex::encode(s).into_bytes());
    push(&mut out, hex::encode_upper(s).into_bytes());
    // 百分号编码：全部编码 / 保留 RFC 3986 unreserved（-._~）/ 表单编码（空格为 +），各含大小写十六进制。
    const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');
    const FORM: &percent_encoding::AsciiSet = &UNRESERVED.remove(b' ').remove(b'*');
    for set in [percent_encoding::NON_ALPHANUMERIC, UNRESERVED] {
        let pct = percent_encoding::utf8_percent_encode(secret, set).to_string();
        push(&mut out, lower_hex_escapes(&pct).into_bytes());
        push(&mut out, pct.into_bytes());
    }
    let form = percent_encoding::utf8_percent_encode(secret, FORM).to_string().replace(' ', "+");
    push(&mut out, lower_hex_escapes(&form).into_bytes());
    push(&mut out, form.into_bytes());
    if let Ok(j) = serde_json::to_string(secret) {
        push(&mut out, j.as_bytes()[1..j.len() - 1].to_vec());
    }
    let html = secret.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;");
    push(&mut out, html.into_bytes());
    // 值是 URL（例如保存在 base_url 字段里的网关地址，路径里有账号标识）：路径（含查询）也单独脱敏——
    // 上游常在错误信息或请求回显里只给出路径。
    if let Ok(u) = url::Url::parse(trimmed)
        && matches!(u.scheme(), "https" | "http")
    {
        let mut path = u.path().to_string();
        if let Some(q) = u.query() {
            path.push('?');
            path.push_str(q);
        }
        let path = path.trim_end_matches('/');
        if path.len() >= 8 && path != trimmed {
            for v in variants(path) {
                if !out.contains(&v) {
                    out.push(v);
                }
            }
        }
    }
    // 多行的值（PEM 私钥、多行口令）：每一行（≥ 8 个字符）也按全部编码单独脱敏。
    if secret.contains('\n') {
        for line in secret.lines() {
            let l = line.trim();
            if l.len() >= 8 && l != secret {
                for v in variants(l) {
                    if !out.contains(&v) {
                        out.push(v);
                    }
                }
            }
        }
    }
    out
}

/// 把 `%2B` 形式的转义改成小写 `%2b`（其余字符不变）。
fn lower_hex_escapes(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push('%');
            out.push((b[i + 1] as char).to_ascii_lowercase());
            out.push((b[i + 2] as char).to_ascii_lowercase());
            i += 3;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

impl Redactor {
    pub fn empty() -> Self {
        Self {
            ac: None,
            replacements: vec![],
            alias_ac: None,
            alias_replacements: vec![],
            prefixes: Prefixes::default(),
            alias_prefixes: Prefixes::default(),
        }
    }

    pub fn build<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut patterns = Vec::new();
        let mut replacements = Vec::new();
        for (name, secret) in secrets {
            for v in variants(secret) {
                patterns.push(v);
                replacements.push(format!("[REDACTED:{name}]"));
            }
        }
        if patterns.is_empty() {
            return Self::empty();
        }
        // 模式总长度大时（例如 64 KiB 的导入内容及其各种编码）不能让库自动选 DFA：DFA 的状态表随模式长度
        // 成倍增长，构建会耗尽 CPU 与内存。大于 16 KiB 时固定用 contiguous NFA（构建是线性的）。
        let total: usize = patterns.iter().map(|p| p.len()).sum();
        let mut b = AhoCorasickBuilder::new();
        b.match_kind(MatchKind::LeftmostLongest);
        if total > 16 * 1024 {
            b.kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA));
        }
        let ac = b.build(&patterns).ok();
        Self { ac, replacements, prefixes: Prefixes::new(&patterns, false), ..Self::empty() }
    }

    /// 加上别名：结果里的真实地址（URL、`主机:端口`、`主机/路径`、主机，以及它们的编码形式）都换成 `alias://名称`。
    pub fn with_aliases(mut self, aliases: &[pm_vault::Alias]) -> Self {
        let mut patterns = Vec::new();
        let mut replacements = Vec::new();
        for a in aliases {
            let Some((host, port, path)) = pm_vault::alias_parts(&a.url) else { continue };
            let authority = a.url.trim_start_matches("https://").split('/').next().unwrap_or_default().to_string();
            let scheme_less = format!("{authority}{path}");
            let mut forms = vec![a.url.clone(), scheme_less, authority, format!("{host}:{port}"), host];
            forms.sort();
            forms.dedup();
            for f in forms {
                for v in variants(&f) {
                    patterns.push(v);
                    replacements.push(format!("alias://{}", a.name));
                }
            }
        }
        if !patterns.is_empty() {
            let mut b = AhoCorasickBuilder::new();
            b.match_kind(MatchKind::LeftmostLongest).ascii_case_insensitive(true);
            self.alias_ac = b.build(&patterns).ok();
            self.alias_replacements = replacements;
            self.alias_prefixes = Prefixes::new(&patterns, true);
        }
        self
    }

    /// 是否有别名要脱敏。
    pub fn has_aliases(&self) -> bool {
        self.alias_ac.is_some()
    }

    /// 返回 (脱敏后的数据, 命中次数)。
    pub fn redact(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let (out, n) = Self::pass(&self.ac, &self.replacements, data.to_vec());
        let (out, m) = Self::pass(&self.alias_ac, &self.alias_replacements, out);
        (out, n + m)
    }

    fn pass(ac: &Option<AhoCorasick>, replacements: &[String], data: Vec<u8>) -> (Vec<u8>, usize) {
        let Some(ac) = ac else { return (data, 0) };
        let count = ac.find_iter(&data).count();
        if count == 0 {
            return (data, 0);
        }
        let reps: Vec<&[u8]> = replacements.iter().map(|s| s.as_bytes()).collect();
        (ac.replace_all_bytes(&data, &reps), count)
    }

    pub fn redact_str(&self, s: &str) -> String {
        String::from_utf8_lossy(&self.redact(s.as_bytes()).0).into_owned()
    }
}

/// 流式脱敏：数据一块一块地进来，结果与对整段数据调用 [`Redactor::redact`] 完全相同；
/// 每一轮只扣住末尾"可能是某个模式开头"的几个字节，所以 SSE 事件（以空行结尾）会立刻送出，不等下一块。
pub struct StreamRedact {
    r: std::sync::Arc<Redactor>,
    /// 两轮（密钥、别名）各自扣住的尾巴。
    tails: [Vec<u8>; 2],
    /// 已替换的次数。
    pub count: usize,
}

impl StreamRedact {
    pub fn new(r: std::sync::Arc<Redactor>) -> Self {
        Self { r, tails: [Vec::new(), Vec::new()], count: 0 }
    }

    /// 送入一块数据，返回现在就可以发出的脱敏结果。
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.run(chunk, false)
    }

    /// 数据结束：把扣住的尾巴也处理完。
    pub fn finish(&mut self) -> Vec<u8> {
        self.run(&[], true)
    }

    fn run(&mut self, chunk: &[u8], last: bool) -> Vec<u8> {
        let r = self.r.clone();
        let [t0, t1] = &mut self.tails;
        let a = step(&r.ac, &r.replacements, &r.prefixes, t0, chunk, last, &mut self.count);
        step(&r.alias_ac, &r.alias_replacements, &r.alias_prefixes, t1, &a, last, &mut self.count)
    }
}

/// 一轮流式替换：`tail` 是上次扣住的字节。返回可以发出的部分，新的尾巴留在 `tail` 里。
fn step(
    ac: &Option<AhoCorasick>,
    reps: &[String],
    pre: &Prefixes,
    tail: &mut Vec<u8>,
    chunk: &[u8],
    last: bool,
    count: &mut usize,
) -> Vec<u8> {
    let Some(ac) = ac else { return chunk.to_vec() };
    let mut buf = std::mem::take(tail);
    buf.extend_from_slice(chunk);
    // cut 之前开始的匹配都已经确定（不会因为后面的数据变长），cut 之后的留到下一块
    let cut = if last { buf.len() } else { buf.len() - pre.hold(&buf) };
    let mut out = Vec::with_capacity(buf.len());
    let mut pos = 0;
    for m in ac.find_iter(&buf) {
        if m.start() >= cut {
            break;
        }
        out.extend_from_slice(&buf[pos..m.start()]);
        out.extend_from_slice(reps[m.pattern().as_usize()].as_bytes());
        pos = m.end();
        *count += 1;
    }
    let keep = pos.max(cut);
    out.extend_from_slice(&buf[pos..keep]);
    *tail = buf[keep..].to_vec();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_hide_every_form_of_the_address() {
        let a = pm_vault::Alias { name: "billing".into(), url: "https://api.example.com:8443/v1".into(), note: String::new() };
        let r = Redactor::build([("k", "s3cret-value")]).with_aliases(std::slice::from_ref(&a));
        assert!(r.has_aliases() && !Redactor::build([("k", "s3cret-value")]).has_aliases());
        for (text, want) in [
            ("see https://api.example.com:8443/v1/x", "see alias://billing/x"),
            ("HTTPS://API.EXAMPLE.COM:8443/V1/x", "alias://billing/x"),
            ("Location: https://Api.Example.Com:8443/v1", "Location: alias://billing"),
            ("host api.example.com only", "host alias://billing only"),
            ("api.example.com:8443 down", "alias://billing down"),
            ("api.example.com:8443/v1/y", "alias://billing/y"),
            ("key s3cret-value", "key [REDACTED:k]"),
        ] {
            assert_eq!(r.redact_str(text), want, "{text}");
        }
        // 编码形式：百分号、base64、hex。
        let enc = percent_encoding::utf8_percent_encode("https://api.example.com:8443/v1", percent_encoding::NON_ALPHANUMERIC).to_string();
        assert_eq!(r.redact_str(&enc), "alias://billing");
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode("api.example.com");
        assert!(!r.redact_str(&b64).contains(b64.trim_end_matches('=')), "{b64}");
        assert!(!r.redact_str(&hex::encode("api.example.com")).contains(&hex::encode("api.example.com")));
        assert_eq!(r.redact(b"nothing here").1, 0);
    }

    /// 很长的密钥（导入上限 64 KiB）：构建与扫描都必须很快（曾因自动选择 DFA 而卡住）。
    #[test]
    fn large_secrets_build_quickly() {
        let big = "y".repeat(64 * 1024);
        let multi = (0..2000).map(|i| format!("line-{i:05}-abcdefgh")).collect::<Vec<_>>().join("\n");
        let t0 = std::time::Instant::now();
        let r = Redactor::build([("big", big.as_str()), ("multi", multi.as_str())]);
        let (out, n) = r.redact(format!("x{big}x {}", "line-01234-abcdefgh").as_bytes());
        assert!(n >= 2);
        assert!(!String::from_utf8_lossy(&out).contains("line-01234-abcdefgh"));
        assert!(t0.elapsed() < std::time::Duration::from_secs(20), "{:?}", t0.elapsed());
    }
    use base64::engine::general_purpose::STANDARD;

    const T_UNRESERVED: &percent_encoding::AsciiSet =
        &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');
    const T_UNDERSCORE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'_');

    #[test]
    fn catches_encodings() {
        let secret = "ghp_S3cr3tT0k3n+/=&<x>";
        let r = Redactor::build([("github", secret)]);
        let cases = vec![
            format!("token={secret}!"),
            format!("Authorization: Basic {}", STANDARD.encode(format!("user:{secret}"))),
            format!("Authorization: Basic {}", STANDARD.encode(format!("u:{secret}"))),
            format!("Authorization: Basic {}", STANDARD.encode(format!("us:{secret}"))),
            format!("{{\"b64url\":\"{}\"}}", URL_SAFE_NO_PAD.encode(secret)),
            format!("hex {}", hex::encode(secret)),
            format!("HEX {}", hex::encode_upper(secret)),
            format!("url {}", percent_encoding::utf8_percent_encode(secret, percent_encoding::NON_ALPHANUMERIC)),
            format!("GET /x?key={} HTTP/1.1", percent_encoding::utf8_percent_encode(secret, T_UNRESERVED)),
            format!("q={}", lower_hex_escapes(&percent_encoding::utf8_percent_encode(secret, T_UNDERSCORE).to_string())),
            format!("json {}", serde_json::to_string(secret).unwrap()),
        ];
        for c in cases {
            let (out, n) = r.redact(c.as_bytes());
            let out = String::from_utf8(out).unwrap();
            assert!(n > 0, "not redacted: {c}");
            assert!(out.contains("[REDACTED:github]"), "{out}");
            assert!(!out.contains(secret));
        }
        let (out, n) = r.redact(b"nothing here");
        assert_eq!(n, 0);
        assert_eq!(out, b"nothing here");
    }

    /// 把 `data` 在每个字节位置切成两块（以及逐字节）送入流式脱敏，结果都必须与整段脱敏相同。
    fn stream_equals_batch(r: &std::sync::Arc<Redactor>, data: &[u8]) {
        let (want, n) = r.redact(data);
        for cut in 0..=data.len() {
            let mut s = StreamRedact::new(r.clone());
            let mut got = s.feed(&data[..cut]);
            got.extend(s.feed(&data[cut..]));
            got.extend(s.finish());
            assert_eq!((String::from_utf8_lossy(&got), s.count), (String::from_utf8_lossy(&want), n), "cut at {cut}");
        }
        let mut s = StreamRedact::new(r.clone());
        let mut got = Vec::new();
        for b in data {
            got.extend(s.feed(std::slice::from_ref(b)));
        }
        got.extend(s.finish());
        assert_eq!(got, want, "byte by byte");
    }

    #[test]
    fn streaming_matches_batch_at_every_split() {
        let secret = "sk-or-v1-0123456789abcdef";
        let alias = pm_vault::Alias { name: "llm".into(), url: "https://api.example.com/v1".into(), note: String::new() };
        let r = std::sync::Arc::new(Redactor::build([("or", secret)]).with_aliases(&[alias]));
        let b64 = STANDARD.encode(format!("Bearer {secret}"));
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        let pct = percent_encoding::utf8_percent_encode(secret, percent_encoding::NON_ALPHANUMERIC).to_string();
        let json = serde_json::to_string(&format!("a\"{secret}")).unwrap();
        let data = format!("data: {{\"auth\":\"Bearer {secret}\"}}\n\ndata: {b64} {url} {pct} {json} API.Example.com/v1/x\n\n");
        stream_equals_batch(&r, data.as_bytes());
        // 没有任何密钥与别名：原样通过，也不扣字节
        let empty = std::sync::Arc::new(Redactor::empty());
        let mut s = StreamRedact::new(empty);
        assert_eq!(s.feed(b"abc"), b"abc");
    }

    #[test]
    fn streaming_holds_back_only_possible_prefixes() {
        let r = std::sync::Arc::new(Redactor::build([("or", "sk-or-v1-0123456789abcdef")]));
        let mut s = StreamRedact::new(r);
        // 一个完整的 SSE 事件：末尾的空行不可能是密钥的开头，立刻全部送出
        assert_eq!(s.feed(b"data: {\"x\":1}\n\n"), b"data: {\"x\":1}\n\n");
        // 末尾像密钥的开头：只扣住这几个字节
        assert_eq!(s.feed(b"data: sk-or"), b"data: ");
        assert_eq!(s.feed(b"-v2\n\n"), b"sk-or-v2\n\n", "不是密钥：补齐后送出");
        assert_eq!(s.feed(b"x sk-or-v1-0123456789abcdef y"), b"x [REDACTED:or] y");
        assert_eq!(s.count, 1);
        assert!(s.finish().is_empty());
    }

    #[test]
    fn pem_lines() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\nAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD0aQ\n-----END OPENSSH PRIVATE KEY-----\n";
        let r = Redactor::build([("srv", pem)]);
        let s = r.redact_str("leak: AAAAMwAAAAtzc2gtZWQyNTUxOQAAACD0aQ end");
        assert!(s.contains("[REDACTED:srv]"));
    }

    #[test]
    fn url_values_also_redact_their_path() {
        let gw = "https://gateway.example.com/v1/acct-7f3e/gw-x/compat/chat/completions";
        let r = Redactor::build([("ai.base_url", gw)]);
        let echo = "GET /v1/acct-7f3e/gw-x/compat/chat/completions/models HTTP/1.1";
        let out = r.redact_str(echo);
        assert!(!out.contains("acct-7f3e"), "{out}");
        assert!(r.redact_str(&format!("see {gw}")).contains("[REDACTED:ai.base_url]"));
        // 只有主机（没有路径）的值：不会把常见的短路径当作秘密。
        let r2 = Redactor::build([("x", "https://gateway.example.com")]);
        assert_eq!(r2.redact_str("GET / HTTP/1.1"), "GET / HTTP/1.1");
    }
}

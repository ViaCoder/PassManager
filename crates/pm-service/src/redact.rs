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
    if secret.contains('\n') {
        for line in secret.lines() {
            let l = line.trim();
            if l.len() >= 16 {
                push(&mut out, l.as_bytes().to_vec());
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
        Self { ac: None, replacements: vec![] }
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
        let ac = AhoCorasickBuilder::new().match_kind(MatchKind::LeftmostLongest).build(&patterns).ok();
        Self { ac, replacements }
    }

    /// 返回 (脱敏后的数据, 命中次数)。
    pub fn redact(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let Some(ac) = &self.ac else { return (data.to_vec(), 0) };
        let count = ac.find_iter(data).count();
        if count == 0 {
            return (data.to_vec(), 0);
        }
        let reps: Vec<&[u8]> = self.replacements.iter().map(|s| s.as_bytes()).collect();
        (ac.replace_all_bytes(data, &reps), count)
    }

    pub fn redact_str(&self, s: &str) -> String {
        String::from_utf8_lossy(&self.redact(s.as_bytes()).0).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn pem_lines() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\nAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD0aQ\n-----END OPENSSH PRIVATE KEY-----\n";
        let r = Redactor::build([("srv", pem)]);
        let s = r.redact_str("leak: AAAAMwAAAAtzc2gtZWQyNTUxOQAAACD0aQ end");
        assert!(s.contains("[REDACTED:srv]"));
    }
}

//! `passmanager import`：从标准输入导入密钥（服务器上的 root 命令）。
//!
//! - 内容原样保存（可以多行，例如 PEM 私钥）；只去掉末尾的**一个**换行（`\n` 或 `\r\n`）；
//! - `--fields a,b,…`：第 1..n 行依次是各字段的值（行数必须正好等于字段数；每行去掉一个换行，含 `\r\n`；值不能为空）；
//! - 上限 64 KiB，空输入拒绝，必须是 UTF-8；标准输入是终端时拒绝（除非 `--interactive`，以不回显的方式逐项输入）；
//! - 任何输出、错误信息里都不包含密钥内容；只打印 `已导入 <名称>（<n> 字节，<k> 个域名）`（私钥另打印公钥指纹）。

use std::io::Read;

use pm_proto::{EntryInput, FieldInput, KIND_SSH_KEY};
use zeroize::Zeroizing;

/// 导入内容的大小上限。
pub const MAX_IMPORT: usize = 64 * 1024;

#[derive(Clone, Debug, Default)]
pub struct ImportOpts {
    pub name: String,
    pub domains: Vec<String>,
    /// 允许的用途（http / ssh / git；空表示不限）。
    pub ops: Vec<String>,
    pub note: String,
    pub self_signed: bool,
    pub replace: bool,
    pub kind: Option<String>,
    pub fields: Option<Vec<String>>,
    pub interactive: bool,
    /// SSH 私钥：允许 ssh-agent 桥签名的主机密钥（指纹或公钥行）。
    pub host_keys: Vec<String>,
}

/// 读取标准输入（最多 MAX_IMPORT + 1 字节，用来判断是否超限）。
pub fn read_limited(mut r: impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buf = Zeroizing::new(Vec::with_capacity(4096));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = r.read(chunk.as_mut()).map_err(|e| format!("读取标准输入失败：{}", e.kind()))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_IMPORT {
            return Err(format!("输入超过上限（{} KiB）", MAX_IMPORT / 1024));
        }
    }
    Ok(buf)
}

fn strip_one_newline(s: &str) -> &str {
    s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s)
}

/// 由原始输入构造条目（纯函数，便于测试）。返回（条目，密钥字节数）。
pub fn build_entry(o: &ImportOpts, data: &[u8]) -> Result<(EntryInput, usize), String> {
    if data.is_empty() {
        return Err("输入为空".into());
    }
    if data.len() > MAX_IMPORT {
        return Err(format!("输入超过上限（{} KiB）", MAX_IMPORT / 1024));
    }
    let text = std::str::from_utf8(data).map_err(|_| "输入必须是 UTF-8 文本".to_string())?;
    let mut input = EntryInput {
        name: o.name.trim().to_string(),
        domains: o.domains.clone(),
        note: o.note.clone(),
        self_signed: o.self_signed,
        kind: o.kind.clone(),
        // --replace 时整体替换（与域名一样）：没有 --ops 表示不限。
        ops: Some(o.ops.iter().map(|x| x.trim().to_ascii_lowercase()).collect()),
        ..Default::default()
    };
    if let Some(bad) = o.ops.iter().map(|x| x.trim().to_ascii_lowercase()).find(|x| !pm_vault::OPS.contains(&x.as_str())) {
        return Err(format!("未知的用途 {bad}（可用：{}）", pm_vault::OPS.join("、")));
    }
    if input.name.is_empty() {
        return Err("必须指定 --name".into());
    }
    if !o.host_keys.is_empty() {
        if o.kind.as_deref() != Some(KIND_SSH_KEY) {
            return Err("--host-key 只用于 --kind ssh-key".into());
        }
        input.host_keys = Some(o.host_keys.iter().map(|h| pm_service::agent::host_key_fingerprint(h)).collect::<Result<_, _>>()?);
    }
    let bytes;
    match &o.fields {
        Some(names) => {
            if o.kind.as_deref() == Some(KIND_SSH_KEY) {
                return Err("--kind ssh-key 是整个私钥，不能与 --fields 同时使用".into());
            }
            if names.is_empty() || names.iter().any(|n| n.trim().is_empty()) {
                return Err("--fields 需要以逗号分隔的字段名".into());
            }
            let body = strip_one_newline(text);
            let lines: Vec<&str> = body.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
            if lines.len() != names.len() {
                return Err(format!("输入的行数与字段数不符（需要正好 {} 行，每行一个值）", names.len()));
            }
            if lines.iter().any(|l| l.is_empty()) {
                return Err("字段的值不能为空".into());
            }
            bytes = lines.iter().map(|l| l.len()).sum();
            input.fields =
                Some(names.iter().zip(lines).map(|(n, v)| FieldInput { name: n.trim().to_string(), value: Some(v.to_string()) }).collect());
        }
        None => {
            let body = strip_one_newline(text);
            if body.is_empty() {
                return Err("输入为空".into());
            }
            bytes = body.len();
            input.secret = Some(body.to_string());
        }
    }
    Ok((input, bytes))
}

/// `--interactive`：在终端上不回显地逐项输入。
pub fn prompt_interactive(o: &ImportOpts) -> Result<Zeroizing<Vec<u8>>, String> {
    let names = o.fields.clone().unwrap_or_else(|| vec!["密钥".into()]);
    let mut out = Zeroizing::new(Vec::new());
    for (i, n) in names.iter().enumerate() {
        let v = Zeroizing::new(rpassword::prompt_password(format!("{n}（不回显）：")).map_err(|e| format!("读取输入失败：{}", e.kind()))?);
        if i > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(v.as_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ImportOpts {
        ImportOpts { name: "blob".into(), ..Default::default() }
    }

    #[test]
    fn whole_blob_is_verbatim_minus_one_newline() {
        let (e, n) = build_entry(&opts(), b"line1\nline2\n\n").unwrap();
        assert_eq!(e.secret.as_deref(), Some("line1\nline2\n"), "只去掉一个换行");
        assert_eq!(n, 12);
        assert_eq!(build_entry(&opts(), b"tok\r\n").unwrap().0.secret.as_deref(), Some("tok"));
        assert_eq!(build_entry(&opts(), b"  spaced  ").unwrap().0.secret.as_deref(), Some("  spaced  "), "不去掉空白");
        assert!(e.fields.is_none());
        let mut k = opts();
        k.host_keys = vec!["SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".into()];
        assert!(build_entry(&k, b"x").is_err(), "--host-key 需要 --kind ssh-key");
        k.kind = Some("ssh-key".into());
        assert_eq!(build_entry(&k, b"x").unwrap().0.host_keys.unwrap().len(), 1);
        k.host_keys = vec!["not a key".into()];
        assert!(build_entry(&k, b"x").is_err());
    }

    #[test]
    fn ops_option() {
        assert_eq!(build_entry(&opts(), b"x").unwrap().0.ops, Some(vec![]), "默认不限；--replace 时也整体替换");
        let mut o = opts();
        o.ops = vec!["SSH".into(), " git".into()];
        assert_eq!(build_entry(&o, b"x").unwrap().0.ops, Some(vec!["ssh".to_string(), "git".to_string()]));
        o.ops = vec!["ftp".into()];
        let e = build_entry(&o, b"top-secret").unwrap_err();
        assert!(e.contains("ftp") && !e.contains("top-secret"));
    }

    #[test]
    fn limits_and_errors_never_echo_content() {
        let secret = b"top-secret-value";
        assert_eq!(build_entry(&opts(), b"").unwrap_err(), "输入为空");
        assert_eq!(build_entry(&opts(), b"\n").unwrap_err(), "输入为空");
        let max = vec![b'a'; MAX_IMPORT];
        assert!(build_entry(&opts(), &max).is_ok());
        let over = vec![b'a'; MAX_IMPORT + 1];
        assert!(build_entry(&opts(), &over).unwrap_err().contains("64 KiB"));
        assert!(read_limited(&over[..]).unwrap_err().contains("64 KiB"));
        assert_eq!(read_limited(&max[..]).unwrap().len(), MAX_IMPORT);
        assert!(build_entry(&opts(), &[0xff, 0xfe]).unwrap_err().contains("UTF-8"));
        let mut f = opts();
        f.fields = Some(vec!["username".into(), "password".into()]);
        for bad in [&b"only-one-line"[..], b"a\nb\nc", b"a\n\n", b"\nb"] {
            let e = build_entry(&f, &[bad, secret].concat()).unwrap_err();
            assert!(!e.contains("top-secret") && !e.contains("only-one"), "{e}");
        }
        assert!(build_entry(&ImportOpts { name: " ".into(), ..Default::default() }, b"x").is_err());
        let mut k = f.clone();
        k.kind = Some("ssh-key".into());
        assert!(build_entry(&k, b"a\nb").is_err());
    }

    #[test]
    fn fields_map_lines_including_crlf() {
        let mut f = opts();
        f.fields = Some(vec!["username".into(), "password".into()]);
        let (e, n) = build_entry(&f, b"me@example.com\r\np@ss word\r\n").unwrap();
        let fs = e.fields.unwrap();
        assert_eq!((fs[0].name.as_str(), fs[0].value.as_deref()), ("username", Some("me@example.com")));
        assert_eq!((fs[1].name.as_str(), fs[1].value.as_deref()), ("password", Some("p@ss word")));
        assert_eq!(n, 23);
        assert!(e.secret.is_none());
        // 没有末尾换行也可以。
        assert!(build_entry(&f, b"u\np").is_ok());
    }
}

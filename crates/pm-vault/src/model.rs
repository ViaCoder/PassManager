//! 库内数据模型（整体加密保存）。

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::domain;

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 条目：名称 + 密钥 + 域名（+ 可选说明与高级选项）。
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub secret: Zeroizing<String>,
    pub domains: Vec<String>,
    #[serde(default)]
    pub note: String,
    /// 自签证书：不走公共 CA，改用首次连接时记录的证书公钥指纹。
    #[serde(default)]
    pub self_signed: bool,
    /// 私钥条目：主机密钥变更时自动接受。
    #[serde(default)]
    pub auto_accept_host_key: bool,
    pub created: u64,
    pub updated: u64,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry").field("name", &self.name).field("secret", &"<redacted>").field("domains", &self.domains).finish()
    }
}

impl Entry {
    /// 密钥内容看起来是 SSH/PEM 私钥。
    pub fn is_private_key(&self) -> bool {
        let s = self.secret.trim_start();
        s.starts_with("-----BEGIN") && s.contains("PRIVATE KEY-----")
    }
}

/// 自动选择凭据的占位符：`{{secret}}` 表示"与目标主机匹配的那个凭据"。
pub const AUTO_PLACEHOLDER: &str = "secret";

/// 引用名（内部标识）：1~64 个字符，只允许字母、数字、`_`、`-`、`.`。
/// 用户不需要填写：留空时按第一个域名自动生成（见 [`auto_name`]）。
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("名称长度必须为 1~64 个字符".into());
    }
    if name == AUTO_PLACEHOLDER {
        return Err(format!("\"{AUTO_PLACEHOLDER}\" 是保留字（{{{{{AUTO_PLACEHOLDER}}}}} 表示按主机自动选择凭据）"));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') {
        return Err("名称只能包含字母、数字、_、-、.".into());
    }
    Ok(())
}

/// 按第一个域名生成引用名（如 `*.github.com` → `github.com`），与已有名称冲突时追加 `-2`、`-3`……
pub fn auto_name(domains: &[String], taken: &[&str]) -> String {
    let base: String = domains
        .first()
        .map(|d| {
            d.trim_start_matches("*.").chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' }).collect()
        })
        .filter(|s: &String| !s.is_empty())
        .unwrap_or_else(|| "credential".into());
    let base: String = base.chars().take(56).collect();
    let base = if base == AUTO_PLACEHOLDER { format!("{base}-1") } else { base };
    if !taken.contains(&base.as_str()) {
        return base;
    }
    (2..).map(|i| format!("{base}-{i}")).find(|n| !taken.contains(&n.as_str())).unwrap()
}

/// 校验并规范化条目（名称、域名）。
pub fn validate_entry(e: &mut Entry) -> Result<(), String> {
    validate_name(&e.name)?;
    if e.secret.is_empty() {
        return Err("密钥不能为空".into());
    }
    if e.domains.is_empty() {
        return Err("至少需要一个域名".into());
    }
    let mut out = Vec::new();
    for d in &e.domains {
        let v = domain::validate_pattern(d).map_err(|err| err.to_string())?;
        if !out.contains(&v) {
            out.push(v);
        }
    }
    e.domains = out;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinKind {
    Ssh,
    Https,
}

/// 首次连接时记录的主机指纹（SSH 主机密钥或自签证书公钥）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pin {
    pub kind: PinKind,
    /// `host:port`
    pub host_port: String,
    pub algo: String,
    /// `SHA256:<base64>` 格式。
    pub fingerprint: String,
    pub first_seen: u64,
}

/// Agent 访问令牌（只保存 SHA-256）。令牌保存在库外的 `tokens.json` 中，
/// 这样库处于锁定状态时也能识别合法令牌，并给出"请解锁"的提示（令牌本身有 256 bit 熵，哈希不可逆）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub label: String,
    pub hash: [u8; 32],
    pub created: u64,
    pub last_used: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    /// 空闲多少小时后自动锁定；0 表示不自动锁定。
    pub auto_lock_hours: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto_lock_hours: 12 }
    }
}

/// 加密载荷。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Payload {
    pub entries: Vec<Entry>,
    pub pins: Vec<Pin>,
    pub settings: Settings,
}

impl Payload {
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    pub fn pin(&self, kind: PinKind, host_port: &str) -> Option<&Pin> {
        self.pins.iter().find(|p| p.kind == kind && p.host_port == host_port)
    }
}

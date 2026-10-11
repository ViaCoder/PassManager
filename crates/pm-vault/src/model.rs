//! 库内数据模型（整体加密保存）。

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::domain;

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 多字段条目中的一个字段（例如 `username`、`password`）。值只写不读。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: Zeroizing<String>,
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Field").field("name", &self.name).field("value", &"<redacted>").finish()
    }
}

/// 条目：名称 + 密钥（单个值，或有序的命名字段）+ 域名（+ 可选说明与高级选项）。
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
    /// 多字段条目（非空时 `secret` 为空）。库文件 v2 载荷新增，旧库读入时为空。
    pub fields: Vec<Field>,
    /// SSH 私钥条目：允许 ssh-agent 桥代为签名的主机密钥指纹（`SHA256:…`）。v2 新增。
    pub host_keys: Vec<String>,
    /// 允许的用途（[`OPS`]：`http`、`ssh`、`git`）；为空表示不限。v2 新增。
    /// 例如只用于 SSH 登录的初始口令设为 `ssh`，就不会被代入 HTTP 请求。`ssh` 包括 scp / sftp 与 ssh-agent 桥。
    pub ops: Vec<String>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .field("fields", &self.fields.iter().map(|x| x.name.as_str()).collect::<Vec<_>>())
            .field("domains", &self.domains)
            .finish()
    }
}

/// 0.1.0 的条目结构（库文件 v1 载荷），只用于读取旧库。
#[derive(Clone, Serialize, Deserialize)]
pub struct EntryV1 {
    pub name: String,
    pub secret: Zeroizing<String>,
    pub domains: Vec<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub self_signed: bool,
    #[serde(default)]
    pub auto_accept_host_key: bool,
    pub created: u64,
    pub updated: u64,
}

impl From<EntryV1> for Entry {
    fn from(e: EntryV1) -> Self {
        Self {
            name: e.name,
            secret: e.secret,
            domains: e.domains,
            note: e.note,
            self_signed: e.self_signed,
            auto_accept_host_key: e.auto_accept_host_key,
            created: e.created,
            updated: e.updated,
            fields: Vec::new(),
            host_keys: Vec::new(),
            ops: Vec::new(),
        }
    }
}

/// 条目可限定的用途。
pub const OPS: [&str; 3] = ["http", "ssh", "git"];
pub const OP_HTTP: &str = "http";
pub const OP_SSH: &str = "ssh";
pub const OP_GIT: &str = "git";

/// 主机密钥指纹：`SHA256:` + 43 个 base64 字符（OpenSSH 格式）。
pub fn validate_host_key_fp(fp: &str) -> Result<(), String> {
    let ok =
        fp.strip_prefix("SHA256:").is_some_and(|b| b.len() == 43 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/'));
    if ok { Ok(()) } else { Err("主机密钥指纹格式无效（应为 SHA256:… ，可用 ssh-keygen -lf 查看）".into()) }
}

/// 字段名：1~64 个字符，字母、数字、`_`、`-`（不含 `.`，因为 `{{条目.字段}}` 用点分隔）。
pub fn validate_field_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("字段名长度必须为 1~64 个字符".into());
    }
    if name == AUTO_PLACEHOLDER {
        return Err(format!("\"{AUTO_PLACEHOLDER}\" 不能用作字段名"));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err("字段名只能包含字母、数字、_、-".into());
    }
    Ok(())
}

impl Entry {
    /// 条目是否允许用于该用途（`ops` 为空表示不限）。
    pub fn allows(&self, op: &str) -> bool {
        self.ops.is_empty() || self.ops.iter().any(|o| o == op)
    }

    /// 密钥内容看起来是 SSH/PEM 私钥。
    pub fn is_private_key(&self) -> bool {
        let s = self.secret.trim_start();
        self.fields.is_empty() && s.starts_with("-----BEGIN") && s.contains("PRIVATE KEY-----")
    }

    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// 用于登录（SSH 口令、sudo）的口令：单值条目是整个密钥；多字段条目是名为 `password` 的字段。
    pub fn password(&self) -> Option<&str> {
        if self.fields.is_empty() { Some(self.secret.as_str()) } else { self.field("password").map(|f| f.value.as_str()) }
    }

    /// 所有需要脱敏的值：(标签, 值)。单值条目标签为引用名，字段为 `引用名.字段`。
    pub fn secret_values(&self) -> Vec<(String, &str)> {
        if self.fields.is_empty() {
            vec![(self.name.clone(), self.secret.as_str())]
        } else {
            self.fields.iter().map(|f| (format!("{}.{}", self.name, f.name), f.value.as_str())).collect()
        }
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

/// 校验并规范化条目（名称、密钥或字段、域名）。
/// 没有域名的条目是允许的：会保存，但在添加域名之前 Agent 无法使用（列表中显示"未绑定域名"）。
pub fn validate_entry(e: &mut Entry) -> Result<(), String> {
    validate_name(&e.name)?;
    if e.fields.is_empty() {
        if e.secret.is_empty() {
            return Err("密钥不能为空".into());
        }
    } else {
        if !e.secret.is_empty() {
            return Err("多字段条目不能同时有单独的密钥".into());
        }
        let mut seen: Vec<&str> = Vec::new();
        for f in &e.fields {
            validate_field_name(&f.name)?;
            if f.value.is_empty() {
                return Err(format!("字段 {} 的值不能为空", f.name));
            }
            if seen.contains(&f.name.as_str()) {
                return Err(format!("字段 {} 重复", f.name));
            }
            seen.push(&f.name);
        }
    }
    for h in &e.host_keys {
        validate_host_key_fp(h)?;
    }
    let mut ops: Vec<String> = Vec::new();
    for o in &e.ops {
        let o = o.trim().to_ascii_lowercase();
        if !OPS.contains(&o.as_str()) {
            return Err(format!("未知的用途 {o}（可用：{}）", OPS.join("、")));
        }
        if !ops.contains(&o) {
            ops.push(o);
        }
    }
    ops.sort_by_key(|o| OPS.iter().position(|x| x == o));
    e.ops = ops;
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

/// 0.1.0 的载荷结构（v1），只用于读取旧库。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PayloadV1 {
    pub entries: Vec<EntryV1>,
    pub pins: Vec<Pin>,
    pub settings: Settings,
}

impl std::fmt::Debug for EntryV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryV1").field("name", &self.name).finish()
    }
}

impl From<PayloadV1> for Payload {
    fn from(p: PayloadV1) -> Self {
        Self { entries: p.entries.into_iter().map(Entry::from).collect(), pins: p.pins, settings: p.settings }
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

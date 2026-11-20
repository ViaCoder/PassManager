//! PassManager 两步验证：算验证码（TOTP、Steam），解析导入格式（otpauth 链接、Google 身份验证器的迁移码、
//! 2FAS 备份），从图片里找二维码。
//!
//! 除了 [`qr`] 里子进程的两端，这里都是纯函数：不读写文件，不联网，不记日志。种子一律放在 `Zeroizing` 里，
//! `Debug` 输出把种子遮住。

pub mod code;
pub mod migration;
pub mod qr;
pub mod twofas;
pub mod uri;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// 验证码的 HMAC 哈希算法。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Alg {
    /// 解析算法名：`SHA1`、`sha256`、`SHA-512` 都认；不认识的返回 None。
    pub fn parse(s: &str) -> Option<Alg> {
        // 去掉空白与连字符，统一成大写再比较
        let n: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_ascii_uppercase();
        match n.as_str() {
            "SHA1" => Some(Alg::Sha1),
            "SHA224" => Some(Alg::Sha224),
            "SHA256" => Some(Alg::Sha256),
            "SHA384" => Some(Alg::Sha384),
            "SHA512" => Some(Alg::Sha512),
            _ => None,
        }
    }

    /// 网页上显示的名称。
    pub fn name(self) -> &'static str {
        match self {
            Alg::Sha1 => "SHA1",
            Alg::Sha224 => "SHA224",
            Alg::Sha256 => "SHA256",
            Alg::Sha384 => "SHA384",
            Alg::Sha512 => "SHA512",
        }
    }

    /// 对应的 pm-crypto 算法。
    fn hmac(self) -> pm_crypto::HmacAlg {
        match self {
            Alg::Sha1 => pm_crypto::HmacAlg::Sha1,
            Alg::Sha224 => pm_crypto::HmacAlg::Sha224,
            Alg::Sha256 => pm_crypto::HmacAlg::Sha256,
            Alg::Sha384 => pm_crypto::HmacAlg::Sha384,
            Alg::Sha512 => pm_crypto::HmacAlg::Sha512,
        }
    }
}

/// 验证码的种类。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// RFC 6238 的时间型验证码（Google 身份验证器那种数字码）。
    Totp,
    /// Steam 令牌：同样按时间计算，但输出 5 个字母数字。
    Steam,
}

/// 算码参数。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    pub kind: Kind,
    pub alg: Alg,
    /// 位数（Steam 固定为 5）。
    pub digits: u8,
    /// 周期（秒）。
    pub period: u32,
}

impl Default for Params {
    /// Google 身份验证器的默认值：SHA1、6 位、30 秒。
    fn default() -> Self {
        Params { kind: Kind::Totp, alg: Alg::Sha1, digits: 6, period: 30 }
    }
}

/// 一个解析出来、还没存进库的 2FA 账户。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    /// 发行方（网站名），可能为空。
    pub issuer: String,
    /// 账户名（通常是邮箱或用户名），可能为空。
    pub account: String,
    /// 种子（原始字节，不是 Base32）。
    pub secret: Zeroizing<Vec<u8>>,
    pub params: Params,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 种子从不出现在 Debug 输出里
        f.debug_struct("Account")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .field("params", &self.params)
            .finish()
    }
}

impl Account {
    /// 显示用的名称：`发行方:账户`；缺一项时只用另一项；都没有时是"未命名"。
    pub fn label(&self) -> String {
        label_of(&self.issuer, &self.account)
    }
}

/// `发行方:账户` 形式的名称（导入失败的条目也用它，在结果页里说明是哪一个）。
pub fn label_of(issuer: &str, account: &str) -> String {
    match (issuer.is_empty(), account.is_empty()) {
        (false, false) => format!("{issuer}:{account}"),
        (false, true) => issuer.to_string(),
        (true, false) => account.to_string(),
        (true, true) => "未命名".to_string(),
    }
}

/// 不能导入的一项：名称与原因。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub label: String,
    pub reason: String,
}

impl Skipped {
    pub fn new(label: impl Into<String>, reason: impl Into<String>) -> Self {
        Skipped { label: label.into(), reason: reason.into() }
    }
}

/// 一次解析的结果：能导入的账户和不能导入的项。
#[derive(Debug, Default)]
pub struct Parsed {
    pub accounts: Vec<Account>,
    pub skipped: Vec<Skipped>,
}

impl Parsed {
    /// 把另一次解析的结果并进来。
    pub fn extend(&mut self, other: Parsed) {
        self.accounts.extend(other.accounts);
        self.skipped.extend(other.skipped);
    }

    /// 收下一个账户：先过 [`check`]，不合格的记进 skipped。
    pub fn push(&mut self, a: Account) {
        match check(a) {
            Ok(a) => self.accounts.push(a),
            Err(s) => self.skipped.push(s),
        }
    }
}

/// 种子最少 5 字节（8 个 Base32 字符）；更短的多半是抄错了。
pub const MIN_SECRET: usize = 5;
/// 种子最多 128 字节；没有正常的服务会给更长的。
pub const MAX_SECRET: usize = 128;
/// 发行方与账户名各最多 256 个字符。
pub const MAX_TEXT: usize = 256;

/// 导入前的检查：整理名称（去掉控制字符和首尾空白、限长），检查种子长度、位数和周期。
pub fn check(mut a: Account) -> Result<Account, Skipped> {
    // 名称里不留控制字符（换行等），首尾空白去掉，过长的截断
    a.issuer = clean(&a.issuer);
    a.account = clean(&a.account);
    let label = a.label();
    // 种子长度
    if a.secret.len() < MIN_SECRET {
        return Err(Skipped::new(label, "种子太短"));
    }
    if a.secret.len() > MAX_SECRET {
        return Err(Skipped::new(label, "种子太长"));
    }
    // Steam 固定 5 位；TOTP 允许 5～9 位（10 的 9 次方仍小于 2 的 31 次方，截断后的值不会不够用）
    match a.params.kind {
        Kind::Steam => a.params.digits = 5,
        Kind::Totp if !(5..=9).contains(&a.params.digits) => return Err(Skipped::new(label, "验证码位数不支持（只支持 5～9 位）")),
        Kind::Totp => {}
    }
    // 周期 5 秒到 5 分钟
    if !(5..=300).contains(&a.params.period) {
        return Err(Skipped::new(label, "周期不支持（只支持 5～300 秒）"));
    }
    Ok(a)
}

/// 去掉控制字符和首尾空白，最多保留 [`MAX_TEXT`] 个字符。
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>().trim().chars().take(MAX_TEXT).collect::<String>().trim().to_string()
}

/// 解码 Base32 种子：不分大小写，忽略空格、连字符和末尾的 `=`，不要求结尾比特为 0（与 Google 身份验证器一样宽松）。
pub fn base32_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    use std::sync::OnceLock;
    // 宽松的 Base32 规格只建一次
    static ENC: OnceLock<data_encoding::Encoding> = OnceLock::new();
    let enc = ENC.get_or_init(|| {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        spec.check_trailing_bits = false;
        // 规格是固定的常量，不会出错
        spec.encoding().unwrap_or_else(|_| data_encoding::BASE32_NOPAD.clone())
    });
    // 整理后的文本也是种子，放进 Zeroizing
    let mut t: Zeroizing<String> = Zeroizing::new(s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect());
    t.make_ascii_uppercase();
    let body = t.trim_end_matches('=');
    if body.is_empty() {
        return None;
    }
    enc.decode(body.as_bytes()).ok().map(Zeroizing::new)
}

/// 解析粘贴的文本：每行一个 `otpauth://` 或 `otpauth-migration://` 链接，空行忽略。
pub fn parse_text(text: &str) -> Parsed {
    let mut out = Parsed::default();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        // 按链接开头分派（不分大小写）
        let lower = line.get(..21).unwrap_or(line).to_ascii_lowercase();
        if lower.starts_with("otpauth-migration://") {
            out.extend(migration::parse(line));
        } else if lower.starts_with("otpauth://") {
            match uri::parse(line) {
                Ok(a) => out.push(a),
                Err(s) => out.skipped.push(s),
            }
        } else {
            // 不是链接的行不回显内容（可能是误粘的种子），只说明行号之外的原因
            out.skipped.push(Skipped::new("（一行文本）", "不是 otpauth:// 或 otpauth-migration:// 链接"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(secret: &[u8], params: Params) -> Account {
        Account { issuer: "Example".into(), account: "alice@example.com".into(), secret: Zeroizing::new(secret.to_vec()), params }
    }

    #[test]
    fn alg_parse_accepts_common_spellings() {
        assert_eq!(Alg::parse("SHA1"), Some(Alg::Sha1));
        assert_eq!(Alg::parse("sha256"), Some(Alg::Sha256));
        assert_eq!(Alg::parse("SHA-512"), Some(Alg::Sha512));
        assert_eq!(Alg::parse(" sha224 "), Some(Alg::Sha224));
        assert_eq!(Alg::parse("SHA384"), Some(Alg::Sha384));
        assert_eq!(Alg::parse("MD5"), None);
        assert_eq!(Alg::parse(""), None);
        // name 与 parse 互逆
        for a in [Alg::Sha1, Alg::Sha224, Alg::Sha256, Alg::Sha384, Alg::Sha512] {
            assert_eq!(Alg::parse(a.name()), Some(a));
        }
    }

    #[test]
    fn label_of_covers_missing_parts() {
        assert_eq!(label_of("GitHub", "alice"), "GitHub:alice");
        assert_eq!(label_of("GitHub", ""), "GitHub");
        assert_eq!(label_of("", "alice"), "alice");
        assert_eq!(label_of("", ""), "未命名");
    }

    #[test]
    fn debug_never_shows_secret() {
        let a = acct(b"12345678901234567890", Params::default());
        let d = format!("{a:?}");
        assert!(d.contains("<redacted>") && !d.contains("49, 50, 51") && !d.contains("1234"), "{d}");
    }

    #[test]
    fn check_limits_secret_digits_period_and_cleans_names() {
        // 正常账户通过，名称里的控制字符与首尾空白被去掉
        let mut a = acct(b"12345678901234567890", Params::default());
        a.issuer = " Exa\nmple ".into();
        let ok = check(a).unwrap();
        assert_eq!(ok.issuer, "Example");
        // 种子太短、太长
        assert_eq!(check(acct(b"1234", Params::default())).unwrap_err().reason, "种子太短");
        assert_eq!(check(acct(&[7u8; 129], Params::default())).unwrap_err().reason, "种子太长");
        // 位数
        let p4 = Params { digits: 4, ..Params::default() };
        assert!(check(acct(b"12345678901234567890", p4)).unwrap_err().reason.contains("位数"));
        let p10 = Params { digits: 10, ..Params::default() };
        assert!(check(acct(b"12345678901234567890", p10)).is_err());
        let p8 = Params { digits: 8, ..Params::default() };
        assert!(check(acct(b"12345678901234567890", p8)).is_ok());
        // Steam 的位数一律改成 5
        let ps = Params { kind: Kind::Steam, digits: 6, ..Params::default() };
        assert_eq!(check(acct(b"12345678901234567890", ps)).unwrap().params.digits, 5);
        // 周期
        let p0 = Params { period: 0, ..Params::default() };
        assert!(check(acct(b"12345678901234567890", p0)).unwrap_err().reason.contains("周期"));
        let p301 = Params { period: 301, ..Params::default() };
        assert!(check(acct(b"12345678901234567890", p301)).is_err());
        // 过长的名称被截断到 MAX_TEXT
        let mut long = acct(b"12345678901234567890", Params::default());
        long.account = "a".repeat(1000);
        assert_eq!(check(long).unwrap().account.chars().count(), MAX_TEXT);
    }

    #[test]
    fn base32_decode_is_lenient_but_rejects_garbage() {
        // RFC 4226 的测试种子 "12345678901234567890"
        let want = b"12345678901234567890".to_vec();
        assert_eq!(*base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(), want);
        // 小写、空格、连字符、末尾的 =
        assert_eq!(*base32_decode("gezd gnbv gy3t qojq-gezd gnbv gy3t qojq").unwrap(), want);
        assert_eq!(*base32_decode("JBSWY3DPEE======").unwrap(), b"Hello!".to_vec());
        // 结尾比特不为 0 也接受（"JBSWY3DPEF" 与 "JBSWY3DPEE" 只差结尾比特）
        assert_eq!(*base32_decode("JBSWY3DPEF").unwrap(), b"Hello!".to_vec());
        // 非法字符、空串
        assert!(base32_decode("GEZDGNBV1").is_none());
        assert!(base32_decode("").is_none());
        assert!(base32_decode("====").is_none());
    }

    #[test]
    fn parse_text_dispatches_by_scheme() {
        let text = "\n otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example \nnot a link\n\n";
        let p = parse_text(text);
        assert_eq!(p.accounts.len(), 1);
        assert_eq!(p.accounts[0].label(), "Example:alice");
        assert_eq!(p.skipped.len(), 1);
        // 不是链接的行不回显内容
        assert!(!p.skipped[0].label.contains("not a link"));
        // 大写的协议名也认
        assert_eq!(parse_text("OTPAUTH://totp/x?secret=GEZDGNBVGY3TQOJQ").accounts.len(), 1);
    }
}

//! 2FAS Auth 的备份文件（`.2fas`，JSON）。格式取自 2FAS 安卓版源码（twofas/2fas-android）：
//!
//! - `BackupContent`：`services`、`schemaVersion`（当前为 4）、`servicesEncrypted`、`reference` 等；
//!   `reference` 不为空表示加密备份，这时 `services` 为空，账户在 `servicesEncrypted` 里。
//! - `BackupService`：`name`、`secret`（Base32）、`otp { account, issuer, digits, period, algorithm, tokenType, … }`，
//!   `otp` 里的字段都可能缺省（缺省值：6 位、30 秒、SHA1、TOTP）。
//! - 加密（`BackupCipherImpl`、`BackupKeyGeneratorPbkdf`、`CipherAes`）：`servicesEncrypted` 与 `reference` 都是
//!   `base64(密文‖16 字节标签):base64(盐):base64(IV)`；密钥 = PBKDF2-HMAC-SHA256(口令, 盐, 10000 次, 32 字节)，
//!   AES-256-GCM（IV 由 Java 默认生成，为 12 字节）。`reference` 解开是一个固定字符串，用来判断口令对不对。

use base64::Engine;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{Account, Alg, Kind, Params, Parsed, Skipped, base32_decode, label_of};

/// 读得懂的最高格式版本。
pub const MAX_SCHEMA: u64 = 4;
/// PBKDF2 迭代次数（2FAS 固定用 10000）。
const ITERATIONS: u32 = 10_000;
/// 盐最长 1 KiB（2FAS 用 256 字节）。
const MAX_SALT: usize = 1024;

/// 备份文件的顶层（只取用到的字段；其余字段忽略）。
#[derive(Deserialize)]
struct Backup {
    #[serde(default)]
    services: Vec<Service>,
    #[serde(rename = "schemaVersion", default)]
    schema: Option<u64>,
    #[serde(rename = "servicesEncrypted", default)]
    services_encrypted: Option<String>,
    #[serde(default)]
    reference: Option<String>,
}

/// 一个服务（账户）。
#[derive(Deserialize)]
struct Service {
    #[serde(default)]
    name: String,
    /// Base32 种子：反序列化直接进 Zeroizing。
    #[serde(default)]
    secret: Zeroizing<String>,
    #[serde(default)]
    otp: Otp,
}

/// `otp` 对象（字段都可以缺省或为 null）。
#[derive(Deserialize, Default)]
#[serde(default)]
struct Otp {
    account: Option<String>,
    issuer: Option<String>,
    label: Option<String>,
    digits: Option<i64>,
    period: Option<i64>,
    algorithm: Option<String>,
    #[serde(rename = "tokenType")]
    token_type: Option<String>,
}

/// 读一个 2FAS 备份。`password` 只在加密备份时需要。整份文件读不了时返回错误原因。
pub fn parse(json: &[u8], password: Option<&str>) -> Result<Parsed, String> {
    let b: Backup = serde_json::from_slice(json).map_err(|_| "不是 2FAS 备份文件（JSON 格式不对）".to_string())?;
    // 格式版本太新的不猜
    if let Some(v) = b.schema
        && v > MAX_SCHEMA
    {
        return Err(format!("备份格式版本 {v} 太新，只支持到 {MAX_SCHEMA}"));
    }
    // 加密备份：先用 reference 检查口令，再解开 services
    let encrypted = b.reference.as_deref().is_some_and(|r| !r.trim().is_empty());
    let services: Vec<Service> = if encrypted {
        let pw = password.filter(|p| !p.is_empty()).ok_or("这是加密的备份，请填写备份口令")?;
        let reference = b.reference.as_deref().unwrap_or_default();
        decrypt(reference, pw).map_err(|e| if e == WRONG { "备份口令不对".to_string() } else { e.to_string() })?;
        let data = b.services_encrypted.as_deref().ok_or("加密的备份里没有 servicesEncrypted")?;
        let plain = decrypt(data, pw).map_err(|e| if e == WRONG { "备份口令不对".to_string() } else { e.to_string() })?;
        serde_json::from_slice(&plain).map_err(|_| "解开的账户数据格式不对".to_string())?
    } else {
        b.services
    };
    // 逐个转换
    let mut out = Parsed::default();
    for s in services {
        match account(s) {
            Ok(a) => out.push(a),
            Err(sk) => out.skipped.push(sk),
        }
    }
    Ok(out)
}

/// 口令错误（GCM 标签校验失败）。
const WRONG: &str = "wrong password";

/// 解开 `base64(密文‖标签):base64(盐):base64(IV)`。
fn decrypt(field: &str, password: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    // 必须正好三段
    let parts: Vec<&str> = field.trim().split(':').collect();
    let [data, salt, iv] = parts.as_slice() else { return Err("加密数据的格式不对（应为三段）") };
    // 标准 base64；带不带 = 都接受，空白去掉
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let dec =
        |s: &str| engine.decode(s.chars().filter(|c| !c.is_whitespace()).collect::<String>()).map_err(|_| "加密数据不是合法的 base64");
    let (data, salt, iv) = (dec(data)?, dec(salt)?, dec(iv)?);
    // 盐不能为空或过长；IV 必须是 12 字节（AES-GCM 的标准长度）
    if salt.is_empty() || salt.len() > MAX_SALT {
        return Err("加密数据的盐长度不对");
    }
    let iv: [u8; 12] = iv.as_slice().try_into().map_err(|_| "加密数据的 IV 不是 12 字节，不支持")?;
    // 密文至少要有 16 字节标签
    if data.len() < 16 {
        return Err("加密数据太短");
    }
    // 口令按 UTF-8 编码（与 Java 的 PBEKeySpec 一致）派生密钥
    let key = pm_crypto::pbkdf2_hmac_sha256(password.as_bytes(), &salt, ITERATIONS);
    pm_crypto::aead::open_with_nonce(pm_crypto::aead::Cipher::Aes256Gcm, &key, iv, b"", &data).map_err(|_| WRONG)
}

/// 一个服务转成账户。
fn account(s: Service) -> Result<Account, Skipped> {
    let o = s.otp;
    // 发行方：otp.issuer，没有时用服务名；账户：otp.account，没有时用 otp.label
    let issuer = o.issuer.filter(|x| !x.trim().is_empty()).unwrap_or(s.name);
    let account = o.account.or(o.label).unwrap_or_default();
    let label = label_of(issuer.trim(), account.trim());
    // 类型：缺省为 TOTP
    let kind = match o.token_type.as_deref().map(str::to_ascii_uppercase).as_deref() {
        None | Some("TOTP") => Kind::Totp,
        Some("STEAM") => Kind::Steam,
        Some("HOTP") => return Err(Skipped::new(label, "HOTP（计数器型）验证码不支持")),
        Some(_) => return Err(Skipped::new(label, "验证码类型不支持")),
    };
    // 算法：缺省 SHA1
    let alg = match o.algorithm.as_deref() {
        None => Alg::Sha1,
        Some(a) => Alg::parse(a).ok_or_else(|| Skipped::new(label.clone(), "算法不支持"))?,
    };
    // 位数与周期：缺省 6 位、30 秒；负数或超出范围的交给 check 报错
    let digits = u8::try_from(o.digits.unwrap_or(6)).unwrap_or(0);
    let period = u32::try_from(o.period.unwrap_or(30)).unwrap_or(0);
    // 种子
    let secret = base32_decode(&s.secret).ok_or_else(|| Skipped::new(label.clone(), "secret 不是合法的 Base32"))?;
    Ok(Account { issuer, account, secret, params: Params { kind, alg, digits, period } })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 不加密的备份样本（结构照 2FAS 安卓版的 BackupContent / BackupService）。
    pub const PLAIN: &str = r#"{
      "services": [
        {"name": "GitHub", "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "updatedAt": 1700000000000, "serviceTypeID": null,
         "otp": {"link": null, "label": "alice", "account": "alice@example.com", "issuer": "GitHub", "digits": 6, "period": 30,
                 "algorithm": "SHA1", "counter": 0, "tokenType": "TOTP", "source": "Link"},
         "order": {"position": 0}, "badge": null, "icon": null, "groupId": null},
        {"name": "Steam", "secret": "jbswy3dpehpk3pxp", "updatedAt": 0, "serviceTypeID": null,
         "otp": {"account": "bob", "issuer": null, "digits": 5, "period": 30, "algorithm": "SHA1", "tokenType": "STEAM"},
         "order": {"position": 1}, "badge": null, "icon": null, "groupId": null},
        {"name": "Bank", "secret": "JBSWY3DPEHPK3PXP", "updatedAt": 0, "serviceTypeID": null,
         "otp": {"account": "carol", "tokenType": "HOTP", "counter": 3}, "order": {"position": 2}, "badge": null, "icon": null, "groupId": null},
        {"name": "Minimal", "secret": "JBSWY3DPEHPK3PXP", "updatedAt": 0, "serviceTypeID": null, "otp": {},
         "order": {"position": 3}, "badge": null, "icon": null, "groupId": null},
        {"name": "Sha512", "secret": "JBSWY3DPEHPK3PXP", "updatedAt": 0, "serviceTypeID": null,
         "otp": {"account": "dave", "digits": 8, "period": 60, "algorithm": "SHA512"}, "order": {"position": 4}, "badge": null, "icon": null, "groupId": null},
        {"name": "Broken", "secret": "not base32!", "updatedAt": 0, "serviceTypeID": null, "otp": {"account": "erin"},
         "order": {"position": 5}, "badge": null, "icon": null, "groupId": null}
      ],
      "groups": [], "updatedAt": 1700000000000, "schemaVersion": 4, "appVersionCode": 5000000, "appVersionName": "5.0.0", "appOrigin": "android"
    }"#;

    #[test]
    fn reads_plain_backup() {
        let p = parse(PLAIN.as_bytes(), None).unwrap();
        let labels: Vec<String> = p.accounts.iter().map(|a| a.label()).collect();
        assert_eq!(labels, ["GitHub:alice@example.com", "Steam:bob", "Minimal", "Sha512:dave"]);
        assert_eq!(*p.accounts[0].secret, b"12345678901234567890".to_vec());
        assert_eq!(p.accounts[1].params.kind, Kind::Steam);
        assert_eq!(p.accounts[1].params.digits, 5);
        // 缺省值
        assert_eq!(p.accounts[2].params, Params::default());
        assert_eq!(p.accounts[3].params, Params { kind: Kind::Totp, alg: Alg::Sha512, digits: 8, period: 60 });
        let reasons: Vec<(&str, &str)> = p.skipped.iter().map(|s| (s.label.as_str(), s.reason.as_str())).collect();
        assert_eq!(reasons, [("Bank:carol", "HOTP（计数器型）验证码不支持"), ("Broken:erin", "secret 不是合法的 Base32")]);
    }

    #[test]
    fn rejects_bad_files() {
        assert!(parse(b"not json", None).unwrap_err().contains("JSON"));
        assert!(parse(br#"{"services": [], "schemaVersion": 5}"#, None).unwrap_err().contains("太新"));
        // 没有版本号也照常读
        assert!(parse(br#"{"services": []}"#, None).unwrap().accounts.is_empty());
        // 加密备份没给口令
        assert!(parse(br#"{"services": [], "reference": "a:b:c", "servicesEncrypted": "a:b:c"}"#, None).unwrap_err().contains("口令"));
        // 加密数据不是三段、不是 base64、IV 不是 12 字节、太短
        let r = |reference: &str| {
            parse(format!(r#"{{"reference": "{reference}", "servicesEncrypted": "x"}}"#).as_bytes(), Some("pw")).unwrap_err()
        };
        assert!(r("a:b").contains("三段"));
        assert!(r("@@:AAAA:AAAA").contains("base64"));
        assert!(r("AAAAAAAAAAAAAAAAAAAAAA==:AAAA:AAAA").contains("IV"));
        assert!(r("AAAA:AAAA:AAAAAAAAAAAAAAAA").contains("太短"));
        assert!(r("AAAAAAAAAAAAAAAAAAAAAA==::AAAAAAAAAAAAAAAA").contains("盐"));
    }

    /// 用 pm-crypto 做一份加密备份（只为测试口令错误、篡改等分支；与独立实现的交叉测试见 tests/twofas_vector.rs）。
    fn encrypt(plain: &[u8], password: &str, salt: &[u8], iv: [u8; 12]) -> String {
        let key = pm_crypto::pbkdf2_hmac_sha256(password.as_bytes(), salt, ITERATIONS);
        let ct = pm_crypto::aead::seal_with_nonce(pm_crypto::aead::Cipher::Aes256Gcm, &key, iv, b"", plain).unwrap();
        let e = base64::engine::general_purpose::STANDARD;
        format!("{}:{}:{}", e.encode(ct), e.encode(salt), e.encode(iv))
    }

    #[test]
    fn encrypted_backup_password_and_tamper_checks() {
        let services = r#"[{"name": "GitHub", "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "otp": {"account": "alice"}}]"#;
        let salt = [7u8; 256];
        let reference = encrypt(b"fixed reference text", "correct horse", &salt, [1; 12]);
        let data = encrypt(services.as_bytes(), "correct horse", &salt, [2; 12]);
        let file = format!(r#"{{"services": [], "schemaVersion": 4, "reference": "{reference}", "servicesEncrypted": "{data}"}}"#);
        // 口令对：读出账户
        let p = parse(file.as_bytes(), Some("correct horse")).unwrap();
        assert_eq!(p.accounts.len(), 1);
        assert_eq!(p.accounts[0].label(), "GitHub:alice");
        // 口令错、口令为空
        assert_eq!(parse(file.as_bytes(), Some("wrong")).unwrap_err(), "备份口令不对");
        assert!(parse(file.as_bytes(), Some("")).unwrap_err().contains("请填写"));
        // 篡改密文：标签校验失败（报口令不对，不会读出被改过的数据）
        let mut bad = data.clone();
        bad.replace_range(0..4, if &bad[0..4] == "AAAA" { "BBBB" } else { "AAAA" });
        let file2 = format!(r#"{{"reference": "{reference}", "servicesEncrypted": "{bad}"}}"#);
        assert_eq!(parse(file2.as_bytes(), Some("correct horse")).unwrap_err(), "备份口令不对");
        // reference 对、services 缺失
        let file3 = format!(r#"{{"reference": "{reference}"}}"#);
        assert!(parse(file3.as_bytes(), Some("correct horse")).unwrap_err().contains("servicesEncrypted"));
    }
}

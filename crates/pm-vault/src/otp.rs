//! 库里保存的两步验证账户（加密载荷 v6 起）。
//!
//! 种子和密码条目一起放在同一个加密载荷里。平时只返回算出来的验证码；只有网页会话在账户页点"显示密钥"时才返回种子，
//! 服务端每次都记日志。

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// 一个两步验证账户。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpAccount {
    /// 库内唯一的名称（默认是"发行方:账户"，重名时加序号）。
    pub name: String,
    pub issuer: String,
    pub account: String,
    /// 种子（原始字节）。
    pub secret: Zeroizing<Vec<u8>>,
    pub params: pm_otp::Params,
    pub created: u64,
}

impl std::fmt::Debug for OtpAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 种子从不出现在 Debug 输出里
        f.debug_struct("OtpAccount").field("name", &self.name).field("secret", &"<redacted>").field("params", &self.params).finish()
    }
}

/// 名称最长 300 个字符（发行方与账户各 256 个字符时，"发行方:账户"可能更长，截断到这里）。
pub const MAX_NAME: usize = 300;
/// 一个库最多 2000 个两步验证账户。
pub const MAX_ACCOUNTS: usize = 2000;

/// 加入一个账户的结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Added {
    /// 已加入，名称是这个。
    New(String),
    /// 库里已经有同一个种子与参数的账户（名称是已有的那个），没有重复加入。
    Duplicate(String),
    /// 账户数已到上限。
    Full,
}

/// 把解析好的账户加进列表：同一个种子与参数的不重复加入；名称重复时依次改成"名称 (2)"、"名称 (3)"……
pub fn add(list: &mut Vec<OtpAccount>, a: pm_otp::Account, now: u64) -> Added {
    // 同一个种子（常数时间比较）且参数相同：已经有了
    if let Some(x) = list.iter().find(|x| x.params == a.params && pm_crypto::ct_eq(&x.secret, &a.secret)) {
        return Added::Duplicate(x.name.clone());
    }
    if list.len() >= MAX_ACCOUNTS {
        return Added::Full;
    }
    // 名称：截断后找一个没用过的
    let base: String = a.label().chars().take(MAX_NAME).collect();
    let mut name = base.clone();
    let mut n = 2;
    while list.iter().any(|x| x.name == name) {
        name = format!("{base} ({n})");
        n += 1;
    }
    list.push(OtpAccount { name: name.clone(), issuer: a.issuer, account: a.account, secret: a.secret, params: a.params, created: now });
    Added::New(name)
}

/// 改名：新名称去掉首尾空白，不能为空、不能过长、不能与别的账户重名。
pub fn rename(list: &mut [OtpAccount], name: &str, new_name: &str) -> Result<(), String> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err("名称不能为空".into());
    }
    if new_name.chars().count() > MAX_NAME || new_name.chars().any(char::is_control) {
        return Err("名称太长或含有控制字符".into());
    }
    if new_name != name && list.iter().any(|x| x.name == new_name) {
        return Err(format!("已经有名为 {new_name} 的账户"));
    }
    let a = list.iter_mut().find(|x| x.name == name).ok_or("账户不存在")?;
    a.name = new_name.to_string();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(issuer: &str, account: &str, secret: &[u8]) -> pm_otp::Account {
        pm_otp::Account {
            issuer: issuer.into(),
            account: account.into(),
            secret: Zeroizing::new(secret.to_vec()),
            params: pm_otp::Params::default(),
        }
    }

    #[test]
    fn add_dedupes_by_secret_and_numbers_names() {
        let mut l = Vec::new();
        assert_eq!(add(&mut l, parsed("GitHub", "alice", b"secret-one-1234"), 1), Added::New("GitHub:alice".into()));
        // 同一个种子：不重复加入，名称不同也一样
        assert_eq!(add(&mut l, parsed("Other", "x", b"secret-one-1234"), 2), Added::Duplicate("GitHub:alice".into()));
        // 同名、不同种子：依次加序号
        assert_eq!(add(&mut l, parsed("GitHub", "alice", b"secret-two-1234"), 3), Added::New("GitHub:alice (2)".into()));
        assert_eq!(add(&mut l, parsed("GitHub", "alice", b"secret-three-12"), 4), Added::New("GitHub:alice (3)".into()));
        // 同一个种子但参数不同（例如 8 位）算不同的账户
        let mut p8 = parsed("GitHub", "alice", b"secret-one-1234");
        p8.params.digits = 8;
        assert_eq!(add(&mut l, p8, 5), Added::New("GitHub:alice (4)".into()));
        assert_eq!(l.len(), 4);
        assert_eq!(l[0].created, 1);
    }

    #[test]
    fn add_stops_at_limit_and_truncates_names() {
        let mut l = Vec::new();
        for i in 0..MAX_ACCOUNTS {
            assert!(matches!(add(&mut l, parsed("E", &i.to_string(), format!("seed-{i:08}").as_bytes()), 0), Added::New(_)));
        }
        assert_eq!(add(&mut l, parsed("E", "new", b"seed-new-12345"), 0), Added::Full);
        // 名称截断到 MAX_NAME
        let mut l2 = Vec::new();
        let Added::New(n) = add(&mut l2, parsed(&"i".repeat(256), &"a".repeat(256), b"seed-long-1234"), 0) else { panic!() };
        assert_eq!(n.chars().count(), MAX_NAME);
    }

    #[test]
    fn rename_checks_names() {
        let mut l = Vec::new();
        add(&mut l, parsed("A", "a", b"seed-a-1234567"), 0);
        add(&mut l, parsed("B", "b", b"seed-b-1234567"), 0);
        assert!(rename(&mut l, "A:a", "  ").unwrap_err().contains("不能为空"));
        assert!(rename(&mut l, "A:a", "B:b").unwrap_err().contains("已经有"));
        assert!(rename(&mut l, "A:a", "x\ny").is_err());
        assert!(rename(&mut l, "A:a", &"z".repeat(MAX_NAME + 1)).is_err());
        assert!(rename(&mut l, "nope", "C").unwrap_err().contains("不存在"));
        // 改成自己原来的名字也行
        rename(&mut l, "A:a", "A:a").unwrap();
        rename(&mut l, "A:a", " 工作邮箱 ").unwrap();
        assert_eq!(l[0].name, "工作邮箱");
    }

    #[test]
    fn debug_hides_secret() {
        let mut l = Vec::new();
        add(&mut l, parsed("A", "a", b"seed-visible-x"), 0);
        let d = format!("{:?}", l[0]);
        assert!(d.contains("<redacted>") && !d.contains("115, 101, 101, 100"), "{d}");
    }
}

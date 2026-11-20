//! 算验证码：RFC 4226（HOTP 的动态截取）、RFC 6238（TOTP）与 Steam 令牌。

use zeroize::Zeroizing;

use crate::{Alg, Kind, Params};

/// Steam 令牌用的 26 个字符（去掉了容易看混的字母与数字）。
const STEAM_CHARS: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// HOTP 的 31 位截断值（RFC 4226 第 5.3 节）：HMAC(种子, 8 字节大端计数器) 后做动态截取。
pub fn truncated(secret: &[u8], alg: Alg, counter: u64) -> u32 {
    // HMAC 的输入是大端的 8 字节计数器
    let mac = Zeroizing::new(pm_crypto::hmac_sha(alg.hmac(), secret, &counter.to_be_bytes()));
    // 最后一个字节的低 4 位是偏移量；HMAC 输出至少 20 字节，偏移 + 4 不会越界
    let off = (mac[mac.len() - 1] & 0x0f) as usize;
    // 从偏移处取 4 字节，去掉最高位，得到 31 位整数
    u32::from_be_bytes([mac[off], mac[off + 1], mac[off + 2], mac[off + 3]]) & 0x7fff_ffff
}

/// HOTP 数字码：截断值对 10^位数 取模，前面补 0。
pub fn hotp(secret: &[u8], alg: Alg, counter: u64, digits: u8) -> Zeroizing<String> {
    // 位数已由 crate::check 限制在 5～9；这里再夹一次，保证 10 的幂不溢出
    let d = u32::from(digits.clamp(1, 9));
    let v = truncated(secret, alg, counter) % 10u32.pow(d);
    Zeroizing::new(format!("{v:0width$}", width = d as usize))
}

/// Steam 码：截断值按 26 进制、从低位开始取 5 个字符。
pub fn steam(secret: &[u8], alg: Alg, counter: u64) -> Zeroizing<String> {
    let mut v = truncated(secret, alg, counter);
    let mut s = Zeroizing::new(String::with_capacity(5));
    for _ in 0..5 {
        s.push(STEAM_CHARS[(v % 26) as usize] as char);
        v /= 26;
    }
    s
}

/// 时间计数器：Unix 秒数除以周期（周期为 0 时按 30 秒，避免除零）。
pub fn counter(p: &Params, unix: u64) -> u64 {
    unix / u64::from(p.period.max(1))
}

/// 当前验证码的剩余秒数（1～周期）。
pub fn remaining(p: &Params, unix: u64) -> u32 {
    let period = u64::from(p.period.max(1));
    (period - unix % period) as u32
}

/// 某一时刻的验证码。
pub fn at(secret: &[u8], p: &Params, unix: u64) -> Zeroizing<String> {
    let c = counter(p, unix);
    match p.kind {
        Kind::Totp => hotp(secret, p.alg, c, p.digits),
        Kind::Steam => steam(secret, p.alg, c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 附录 B 的种子：SHA1 用 20 字节，SHA256 用 32 字节，SHA512 用 64 字节（"1234567890" 重复）。
    fn seed(n: usize) -> Vec<u8> {
        b"1234567890".iter().cycle().take(n).copied().collect()
    }

    #[test]
    fn hotp_matches_rfc4226_appendix_d() {
        // RFC 4226 附录 D：种子 "12345678901234567890"，计数器 0～9 的 6 位码
        let want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
        for (c, w) in want.iter().enumerate() {
            assert_eq!(hotp(&seed(20), Alg::Sha1, c as u64, 6).as_str(), *w, "counter {c}");
        }
        // 附录 D 也给出了截断值（十进制）
        assert_eq!(truncated(&seed(20), Alg::Sha1, 0), 1284755224);
        assert_eq!(truncated(&seed(20), Alg::Sha1, 9), 645520489);
    }

    #[test]
    fn totp_matches_rfc6238_appendix_b() {
        // RFC 6238 附录 B：8 位码，周期 30 秒
        let rows: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, s1, s256, s512) in rows {
            for (alg, n, w) in [(Alg::Sha1, 20, s1), (Alg::Sha256, 32, s256), (Alg::Sha512, 64, s512)] {
                let p = Params { kind: Kind::Totp, alg, digits: 8, period: 30 };
                assert_eq!(at(&seed(n), &p, t).as_str(), w, "{alg:?} at {t}");
            }
        }
    }

    #[test]
    fn steam_code_uses_26_letter_alphabet() {
        // 期望值由 Python 按 2FAS 源码（ServiceCodeGenerator.generateSteamCode）独立重写的实现算出：
        // 计数器 0 的截断值 1284755224 按 26 进制从低位取 5 个字符
        assert_eq!(steam(&seed(20), Alg::Sha1, 0).as_str(), "GG5F5");
        // Steam 码总是 5 个字符，且只用那 26 个字符
        for c in 0..50 {
            let s = steam(&seed(20), Alg::Sha1, c);
            assert_eq!(s.len(), 5);
            assert!(s.bytes().all(|b| STEAM_CHARS.contains(&b)));
        }
        // at() 按种类分派
        let p = Params { kind: Kind::Steam, alg: Alg::Sha1, digits: 5, period: 30 };
        assert_eq!(at(&seed(20), &p, 29).as_str(), "GG5F5");
    }

    #[test]
    fn counter_and_remaining_follow_period() {
        let p = Params::default();
        assert_eq!(counter(&p, 0), 0);
        assert_eq!(counter(&p, 59), 1);
        // 剩余秒数在 1～30 之间：整 30 秒时是完整的 30 秒
        assert_eq!(remaining(&p, 60), 30);
        assert_eq!(remaining(&p, 89), 1);
        assert_eq!(remaining(&p, 75), 15);
        // 周期为 0 不会除零
        let z = Params { period: 0, ..Params::default() };
        assert_eq!(counter(&z, 5), 5);
        assert_eq!(remaining(&z, 5), 1);
        // 自定义周期
        let p60 = Params { period: 60, ..Params::default() };
        assert_eq!(counter(&p60, 59), 0);
        assert_eq!(remaining(&p60, 0), 60);
    }

    #[test]
    fn hotp_pads_with_leading_zeros() {
        // 计数器 1111111109 / 30 = 37037036，SHA1 8 位码 "07081804" 以 0 开头（RFC 6238 附录 B）
        let p = Params { digits: 8, ..Params::default() };
        let c = at(&seed(20), &p, 1111111109);
        assert!(c.starts_with('0') && c.len() == 8);
    }
}

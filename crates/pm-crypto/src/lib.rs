//! PassManager 密码学核心。
//!
//! - 随机数：操作系统 CSPRNG（getrandom）+ AWS-LC DRBG，两路经 HKDF-SHA512 组合，带健康检测。
//! - 口令 KDF：Argon2id。
//! - 抗量子 KEM：ML-KEM-1024（aws-lc-rs）+ Classic-McEliece-6688128（liboqs）。
//! - 对称：AES-256-GCM（外层）+ ChaCha20-Poly1305（内层），HKDF-SHA512。
//! - 可选的第三个随机源：TPM 2.0 `TPM2_GetRandom`（不可用时自动跳过）。

pub mod aead;
pub mod devseal;
pub mod envelope;
pub mod error;
pub mod hkdf;
pub mod kdf;
pub mod kem;
pub mod rng;
pub mod selftest;
pub mod tpm;

pub use error::CryptoError;

/// 常数时间比较。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// SHA-256 摘要。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// SHA-384 摘要（服务端内层公钥指纹）。
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data);
    let mut out = [0u8; 48];
    out.copy_from_slice(d.as_ref());
    out
}

/// HMAC-SHA-384。
pub fn hmac_sha384(key: &[u8], parts: &[&[u8]]) -> [u8; 48] {
    let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA384, key);
    let mut ctx = aws_lc_rs::hmac::Context::with_key(&k);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// SHA-512 摘要。
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, data);
    let mut out = [0u8; 64];
    out.copy_from_slice(d.as_ref());
    out
}

/// 一次性验证码（HOTP/TOTP）用的 HMAC 哈希算法。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacAlg {
    /// SHA-1：RFC 4226/6238 的默认算法，绝大多数网站用它（只用于 HMAC，不用于签名）。
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// HMAC：`key` 是验证码种子，`msg` 是 8 字节计数器；返回完整的 MAC（长度随算法）。
pub fn hmac_sha(alg: HmacAlg, key: &[u8], msg: &[u8]) -> Vec<u8> {
    use aws_lc_rs::hmac;
    // 把我们的枚举换成 aws-lc-rs 的算法常量
    let a = match alg {
        HmacAlg::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HmacAlg::Sha224 => hmac::HMAC_SHA224,
        HmacAlg::Sha256 => hmac::HMAC_SHA256,
        HmacAlg::Sha384 => hmac::HMAC_SHA384,
        HmacAlg::Sha512 => hmac::HMAC_SHA512,
    };
    // 计算 HMAC 并复制出来
    hmac::sign(&hmac::Key::new(a, key), msg).as_ref().to_vec()
}

/// PBKDF2-HMAC-SHA256，输出 32 字节（读 2FAS 加密备份用）。`iterations` 为 0 时按 1 处理。
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> zeroize::Zeroizing<[u8; 32]> {
    // 迭代次数至少 1（PBKDF2 不允许 0）
    let n = std::num::NonZeroU32::new(iterations.max(1)).unwrap_or(std::num::NonZeroU32::MIN);
    // 派生出的密钥放进 Zeroizing，用完清零
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    // 输出固定 32 字节，远小于上限，derive 不会 panic
    aws_lc_rs::pbkdf2::derive(aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256, n, salt, password, out.as_mut());
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn sha384_and_hmac_known_answers() {
        // FIPS 180-2 附录 D.1："abc"。
        assert_eq!(
            hex::encode(super::sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        // RFC 4231 测试用例 2（分两段输入）。
        assert_eq!(
            hex::encode(super::hmac_sha384(b"Jefe", &[b"what do ya want ", b"for nothing?"])),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        );
    }

    #[test]
    fn hmac_sha_known_answers() {
        use super::{HmacAlg, hmac_sha};
        // RFC 2202（SHA-1）与 RFC 4231（SHA-2）的测试用例 2："Jefe" / "what do ya want for nothing?"
        let m = b"what do ya want for nothing?";
        let want = [
            (HmacAlg::Sha1, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
            (HmacAlg::Sha224, "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"),
            (HmacAlg::Sha256, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (HmacAlg::Sha384, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"),
            (
                HmacAlg::Sha512,
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            ),
        ];
        for (alg, hex_want) in want {
            assert_eq!(hex::encode(hmac_sha(alg, b"Jefe", m)), hex_want, "{alg:?}");
        }
    }

    #[test]
    fn pbkdf2_sha256_known_answers() {
        // RFC 7914 第 11 节的 PBKDF2-HMAC-SHA256 向量（取前 32 字节；PBKDF2 的输出前缀与输出长度无关）
        let a = super::pbkdf2_hmac_sha256(b"passwd", b"salt", 1);
        assert_eq!(hex::encode(*a), "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
        let b = super::pbkdf2_hmac_sha256(b"Password", b"NaCl", 80000);
        assert_eq!(hex::encode(*b), "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56");
        // 迭代次数 0 按 1 处理，不 panic
        assert_eq!(*super::pbkdf2_hmac_sha256(b"passwd", b"salt", 0), *a);
    }
}

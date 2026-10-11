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
}

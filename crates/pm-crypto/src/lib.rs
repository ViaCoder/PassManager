//! PassManager 密码学核心。
//!
//! - 随机数：操作系统 CSPRNG（getrandom）+ AWS-LC DRBG，两路经 HKDF-SHA512 组合，带健康检测。
//! - 口令 KDF：Argon2id。
//! - 抗量子 KEM：ML-KEM-1024（aws-lc-rs）+ Classic-McEliece-6688128（liboqs）。
//! - 对称：AES-256-GCM（外层）+ ChaCha20-Poly1305（内层），HKDF-SHA512。

pub mod aead;
pub mod envelope;
pub mod error;
pub mod hkdf;
pub mod kdf;
pub mod kem;
pub mod rng;
pub mod selftest;

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

/// SHA-512 摘要。
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, data);
    let mut out = [0u8; 64];
    out.copy_from_slice(d.as_ref());
    out
}

//! 用设备密钥封存小块机密（服务器模式：内层通道私钥、TLS 私钥、ACME 账号、Cloudflare token）。
//!
//! ```text
//! K    = HKDF-SHA512(salt = "pm/devseal/v1", ikm = device_key, info = label)
//! file = "PMSEAL1\0" ‖ nonce(12) ‖ AES-256-GCM(K, nonce, data, aad = "PMSEAL1\0" ‖ label)
//! ```
//! label 区分用途，一个文件不能被当成另一种机密解开。

use zeroize::Zeroizing;

use crate::CryptoError;
use crate::aead::{self, Cipher};
use crate::hkdf::derive32;

pub const MAGIC: &[u8; 8] = b"PMSEAL1\0";

fn key(device_key: &[u8; 32], label: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    derive32(b"pm/devseal/v1", device_key, &[label.as_bytes()])
}

fn aad(label: &str) -> Vec<u8> {
    let mut a = MAGIC.to_vec();
    a.extend_from_slice(label.as_bytes());
    a
}

pub fn seal(device_key: &[u8; 32], label: &str, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let k = key(device_key, label)?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&aead::seal(Cipher::Aes256Gcm, &k, &aad(label), data)?);
    Ok(out)
}

pub fn open(device_key: &[u8; 32], label: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let body = blob.strip_prefix(MAGIC.as_slice()).ok_or(CryptoError::Invalid("not a sealed blob"))?;
    let k = key(device_key, label)?;
    aead::open(Cipher::Aes256Gcm, &k, &aad(label), body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_every_failure_mode() {
        let dk = [1u8; 32];
        let b = seal(&dk, "tls-key", b"-----BEGIN PRIVATE KEY-----").unwrap();
        assert!(!b.windows(5).any(|w| w == b"BEGIN"));
        assert_eq!(open(&dk, "tls-key", &b).unwrap().as_slice(), b"-----BEGIN PRIVATE KEY-----");
        assert_ne!(seal(&dk, "tls-key", b"x").unwrap(), seal(&dk, "tls-key", b"x").unwrap(), "随机 nonce");
        assert!(open(&[2u8; 32], "tls-key", &b).is_err(), "错误设备密钥");
        assert!(open(&dk, "cf-token", &b).is_err(), "用途标签不同");
        for i in [0, 8, 20, b.len() - 1] {
            let mut t = b.clone();
            t[i] ^= 1;
            assert!(open(&dk, "tls-key", &t).is_err(), "篡改 {i}");
        }
        assert!(open(&dk, "tls-key", &b[..b.len() - 1]).is_err());
        assert!(open(&dk, "tls-key", b"").is_err());
        assert!(open(&dk, "tls-key", MAGIC).is_err());
    }
}

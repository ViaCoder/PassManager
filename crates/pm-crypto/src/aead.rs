//! AEAD 封装：AES-256-GCM 与 ChaCha20-Poly1305（均来自 aws-lc-rs）。
//!
//! 输出格式统一为 `nonce(12) ‖ ciphertext ‖ tag(16)`。

use aws_lc_rs::aead::{AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::{CryptoError, rng};

#[derive(Clone, Copy, Debug)]
pub enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

fn key(cipher: Cipher, k: &[u8; 32]) -> Result<LessSafeKey, CryptoError> {
    let alg = match cipher {
        Cipher::Aes256Gcm => &AES_256_GCM,
        Cipher::ChaCha20Poly1305 => &CHACHA20_POLY1305,
    };
    Ok(LessSafeKey::new(UnboundKey::new(alg, k)?))
}

/// 用显式 nonce 加密（调用方保证 nonce 唯一）。
pub fn seal_with_nonce(cipher: Cipher, k: &[u8; 32], nonce: [u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = key(cipher, k)?;
    let mut buf = Vec::with_capacity(plaintext.len() + 16);
    buf.extend_from_slice(plaintext);
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)?;
    Ok(buf)
}

/// 用显式 nonce 解密。
pub fn open_with_nonce(
    cipher: Cipher,
    k: &[u8; 32],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key = key(cipher, k)?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let len = key
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), buf.as_mut_slice())
        .map_err(|_| CryptoError::AuthFailed)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

/// 随机 nonce 加密，输出 `nonce ‖ ct ‖ tag`。
pub fn seal(cipher: Cipher, k: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    rng::fill(&mut nonce)?;
    let ct = seal_with_nonce(cipher, k, nonce, aad, plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密 `nonce ‖ ct ‖ tag`。
pub fn open(cipher: Cipher, k: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if data.len() < NONCE_LEN + 16 {
        return Err(CryptoError::AuthFailed);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[..NONCE_LEN]);
    open_with_nonce(cipher, k, nonce, aad, &data[NONCE_LEN..])
}

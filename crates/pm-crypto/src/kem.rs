//! 两种不同家族的抗量子 KEM，分别来自两个独立的库：
//! - ML-KEM-1024（格密码，FIPS 203）—— aws-lc-rs
//! - Classic-McEliece-6688128（编码密码，NIST 5 级）—— liboqs
//!
//! liboqs 的随机数通过 `OQS_randombytes_custom_algorithm` 接入本 crate 的双源 RNG。

use std::sync::Once;

use aws_lc_rs::kem::{Ciphertext as AwsCiphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use zeroize::Zeroizing;

use crate::{CryptoError, ct_eq, rng};

static OQS_INIT: Once = Once::new();

unsafe extern "C" fn oqs_randombytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: liboqs 保证 ptr 指向至少 len 字节的可写内存。
    let buf = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    if rng::fill(buf).is_err() {
        // 随机数失败时绝不能继续生成密钥：fail-closed。
        std::process::abort();
    }
}

/// 初始化 liboqs，并把它的随机数源切换为组合 RNG。
pub fn init() {
    OQS_INIT.call_once(|| {
        oqs::init();
        // SAFETY: 传入的回调是 'static 函数，签名与 liboqs 要求一致。
        unsafe { oqs_sys::rand::OQS_randombytes_custom_algorithm(Some(oqs_randombytes)) };
    });
}

/// ML-KEM-1024 密钥对。
pub struct MlKemKeys {
    pub dk: Zeroizing<Vec<u8>>,
    pub ek: Vec<u8>,
}

pub fn mlkem_generate() -> Result<MlKemKeys, CryptoError> {
    let dk = DecapsulationKey::generate(&ML_KEM_1024)?;
    let ek = dk.encapsulation_key()?.key_bytes()?.as_ref().to_vec();
    let dk_bytes = Zeroizing::new(dk.key_bytes()?.as_ref().to_vec());
    let keys = MlKemKeys { dk: dk_bytes, ek };
    // 成对一致性测试。
    let (ct, ss) = mlkem_encaps(&keys.ek)?;
    let ss2 = mlkem_decaps(&keys.dk, &ct)?;
    if !ct_eq(&ss, &ss2) {
        return Err(CryptoError::SelfTest("ML-KEM pairwise consistency"));
    }
    Ok(keys)
}

pub fn mlkem_encaps(ek: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let ek = EncapsulationKey::new(&ML_KEM_1024, ek).map_err(|_| CryptoError::Invalid("ML-KEM public key"))?;
    let (ct, ss) = ek.encapsulate()?;
    Ok((ct.as_ref().to_vec(), Zeroizing::new(ss.as_ref().to_vec())))
}

pub fn mlkem_decaps(dk: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let dk = DecapsulationKey::new(&ML_KEM_1024, dk).map_err(|_| CryptoError::Invalid("ML-KEM secret key"))?;
    let ss = dk.decapsulate(AwsCiphertext::from(ct)).map_err(|_| CryptoError::AuthFailed)?;
    Ok(Zeroizing::new(ss.as_ref().to_vec()))
}

fn mce() -> Result<oqs::kem::Kem, CryptoError> {
    init();
    oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6688128).map_err(|_| CryptoError::Internal("liboqs McEliece unavailable"))
}

/// Classic McEliece 密钥对。
pub struct McElieceKeys {
    pub sk: Zeroizing<Vec<u8>>,
    pub pk: Vec<u8>,
}

pub fn mceliece_generate() -> Result<McElieceKeys, CryptoError> {
    let kem = mce()?;
    let (pk, sk) = kem.keypair().map_err(|_| CryptoError::Internal("McEliece keygen"))?;
    let keys = McElieceKeys { sk: Zeroizing::new(sk.into_vec()), pk: pk.into_vec() };
    let (ct, ss) = mceliece_encaps(&keys.pk)?;
    let ss2 = mceliece_decaps(&keys.sk, &ct)?;
    if !ct_eq(&ss, &ss2) {
        return Err(CryptoError::SelfTest("McEliece pairwise consistency"));
    }
    Ok(keys)
}

pub fn mceliece_encaps(pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let kem = mce()?;
    let pk = kem.public_key_from_bytes(pk).ok_or(CryptoError::Invalid("McEliece public key"))?;
    let (ct, ss) = kem.encapsulate(pk).map_err(|_| CryptoError::Internal("McEliece encaps"))?;
    Ok((ct.into_vec(), Zeroizing::new(ss.into_vec())))
}

pub fn mceliece_decaps(sk: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let kem = mce()?;
    let sk = kem.secret_key_from_bytes(sk).ok_or(CryptoError::Invalid("McEliece secret key"))?;
    let ct = kem.ciphertext_from_bytes(ct).ok_or(CryptoError::AuthFailed)?;
    let ss = kem.decapsulate(sk, ct).map_err(|_| CryptoError::AuthFailed)?;
    Ok(Zeroizing::new(ss.into_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_roundtrip_and_tamper() {
        let k = mlkem_generate().unwrap();
        let (mut ct, ss) = mlkem_encaps(&k.ek).unwrap();
        assert_eq!(ss.len(), 32);
        ct[0] ^= 1;
        // ML-KEM 隐式拒绝：被篡改的密文得到不同的共享密钥。
        let ss2 = mlkem_decaps(&k.dk, &ct).unwrap();
        assert!(!ct_eq(&ss, &ss2));
    }

    #[test]
    fn mceliece_roundtrip_and_tamper() {
        let k = mceliece_generate().unwrap();
        assert_eq!(k.pk.len(), 1_044_992);
        let (mut ct, ss) = mceliece_encaps(&k.pk).unwrap();
        ct[5] ^= 1;
        let ss2 = mceliece_decaps(&k.sk, &ct).unwrap();
        assert!(!ct_eq(&ss, &ss2));
    }
}

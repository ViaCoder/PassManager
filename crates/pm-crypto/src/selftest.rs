//! 启动自检：RNG 健康检测 + 各原语的已知答案测试（KAT）+ KEM 往返测试。任何一项失败都拒绝运行。

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

use crate::aead::{self, Cipher};
use crate::hkdf::hkdf_sha256;
use crate::{CryptoError, ct_eq, kem, rng, sha512};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.replace([' ', '\n'], "")).expect("valid test vector hex")
}

fn check(cond: bool, what: &'static str) -> Result<(), CryptoError> {
    if cond { Ok(()) } else { Err(CryptoError::SelfTest(what)) }
}

/// SHA-512("abc")，FIPS 180-2。
fn kat_sha512() -> Result<(), CryptoError> {
    let expect = unhex(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
    check(sha512(b"abc").as_slice() == expect.as_slice(), "SHA-512 KAT")
}

/// RFC 5869 测试用例 1。
fn kat_hkdf() -> Result<(), CryptoError> {
    let ikm = [0x0bu8; 22];
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let expect = unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    let mut okm = [0u8; 42];
    hkdf_sha256(&salt, &ikm, &[&info], &mut okm)?;
    check(okm.as_slice() == expect.as_slice(), "HKDF KAT")
}

/// AES-256-GCM，GCM 规范测试用例 14（全零密钥、全零 nonce、16 字节全零明文）。
fn kat_aes_gcm() -> Result<(), CryptoError> {
    let ct = aead::seal_with_nonce(Cipher::Aes256Gcm, &[0u8; 32], [0u8; 12], &[], &[0u8; 16])?;
    let expect = unhex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    check(ct == expect, "AES-256-GCM KAT")?;
    let pt = aead::open_with_nonce(Cipher::Aes256Gcm, &[0u8; 32], [0u8; 12], &[], &ct)?;
    check(pt.as_slice() == [0u8; 16], "AES-256-GCM decrypt KAT")
}

/// ChaCha20-Poly1305，RFC 8439 §2.8.2。
fn kat_chacha() -> Result<(), CryptoError> {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = 0x80 + i as u8;
    }
    let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expect = unhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
         3ff4def08e4b7a9de576d26586cec64b6116
         1ae10b594f09e26a7e902ecbd0600691",
    );
    let ct = aead::seal_with_nonce(Cipher::ChaCha20Poly1305, &key, nonce, &aad, pt)?;
    check(ct == expect, "ChaCha20-Poly1305 KAT")
}

/// Argon2id，RFC 9106 §5.3。
fn kat_argon2id() -> Result<(), CryptoError> {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[4u8; 12]).map_err(|_| CryptoError::SelfTest("argon2 ad"))?)
        .build()
        .map_err(|_| CryptoError::SelfTest("argon2 params"))?;
    let argon = Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|_| CryptoError::SelfTest("argon2 secret"))?;
    let mut out = [0u8; 32];
    argon.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out).map_err(|_| CryptoError::SelfTest("argon2 hash"))?;
    let expect = unhex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    check(out.as_slice() == expect.as_slice(), "Argon2id KAT")
}

fn kem_roundtrips() -> Result<(), CryptoError> {
    let k = kem::mlkem_generate()?;
    let (ct, ss) = kem::mlkem_encaps(&k.ek)?;
    check(ct_eq(&ss, &kem::mlkem_decaps(&k.dk, &ct)?), "ML-KEM round trip")?;
    // McEliece 密钥生成较慢，启动时只验证库可用；完整往返在解锁时用库自身的密钥做成对一致性测试。
    kem::init();
    oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6688128).map_err(|_| CryptoError::SelfTest("liboqs McEliece unavailable"))?;
    Ok(())
}

/// 运行全部启动自检。
pub fn run_all() -> Result<(), CryptoError> {
    rng::startup_health_test()?;
    kat_sha512()?;
    kat_hkdf()?;
    kat_aes_gcm()?;
    kat_chacha()?;
    kat_argon2id()?;
    kem_roundtrips()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn all_self_tests_pass() {
        super::run_all().unwrap();
    }
}

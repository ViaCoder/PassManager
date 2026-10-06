//! 密钥层级与双层加密。
//!
//! ```text
//! IKM   = Argon2id(NFKC(password), salt) ‖ device_key
//! KEK_A = HKDF(salt=vault_id, IKM, "pm/v1/kek/A");  KEK_B = HKDF(..., "pm/v1/kek/B")
//! wrap_A = AES-256-GCM(KEK_A, VK_A ‖ dk_mlkem)
//! wrap_B = ChaCha20-Poly1305(KEK_B, VK_B ‖ sk_mceliece)
//!
//! 每次保存（DEK 与 nonce 全新）：
//!   内层：DEK_B = HKDF(VK_B ‖ ss_McEliece, "pm/v1/dek/B" ‖ H ‖ ct_M)；C1 = ChaCha20-Poly1305(DEK_B, P, aad=H)
//!   外层：DEK_A = HKDF(VK_A ‖ ss_MLKEM,   "pm/v1/dek/A" ‖ H ‖ ct_K)；C2 = AES-256-GCM(DEK_A, C1, aad=H ‖ ct_M)
//! ```

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aead::{self, Cipher};
use crate::hkdf::derive32;
use crate::kdf::{self, KdfParams};
use crate::kem::{self, McElieceKeys, MlKemKeys};
use crate::{CryptoError, ct_eq, rng};

pub const VK_LEN: usize = 32;

/// 由口令和设备密钥派生出的两把 KEK。
pub struct Keks {
    a: Zeroizing<[u8; 32]>,
    b: Zeroizing<[u8; 32]>,
}

pub fn derive_keks(
    password: &str,
    salt: &[u8],
    params: KdfParams,
    device_key: &[u8; 32],
    vault_id: &[u8; 16],
) -> Result<Keks, CryptoError> {
    let pw_key = kdf::derive(password, salt, params)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(pw_key.as_ref());
    ikm[32..].copy_from_slice(device_key);
    Ok(Keks { a: derive32(vault_id, ikm.as_ref(), &[b"pm/v1/kek/A"])?, b: derive32(vault_id, ikm.as_ref(), &[b"pm/v1/kek/B"])? })
}

/// 设备密钥校验值：HKDF(device_key, "pm/v1/kcv")[..16]。设备密钥有 256 bit 熵，不构成预言机。
pub fn key_check_value(device_key: &[u8; 32], vault_id: &[u8; 16]) -> Result<[u8; 16], CryptoError> {
    let full = derive32(vault_id, device_key, &[b"pm/v1/kcv"])?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    Ok(out)
}

/// 每次保存产生的密文。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedPayload {
    pub ct_mlkem: Vec<u8>,
    pub ct_mce: Vec<u8>,
    pub nonce_a: [u8; 12],
    pub nonce_b: [u8; 12],
    pub c2: Vec<u8>,
}

/// 库的全部长期密钥（解锁后保存在内存中）。
pub struct VaultKeys {
    vk_a: Zeroizing<[u8; VK_LEN]>,
    vk_b: Zeroizing<[u8; VK_LEN]>,
    mlkem: MlKemKeys,
    mce: McElieceKeys,
}

fn wrap_aad(vault_id: &[u8; 16], label: &[u8]) -> Vec<u8> {
    let mut v = vault_id.to_vec();
    v.extend_from_slice(label);
    v
}

impl VaultKeys {
    /// 生成全新的库密钥（McEliece 密钥生成较慢，约数百毫秒）。
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            vk_a: Zeroizing::new(rng::random_array()?),
            vk_b: Zeroizing::new(rng::random_array()?),
            mlkem: kem::mlkem_generate()?,
            mce: kem::mceliece_generate()?,
        })
    }

    pub fn mlkem_public(&self) -> &[u8] {
        &self.mlkem.ek
    }

    pub fn mceliece_public(&self) -> &[u8] {
        &self.mce.pk
    }

    /// 用 KEK 包裹长期密钥。
    pub fn wrap(&self, keks: &Keks, vault_id: &[u8; 16]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut pa = Zeroizing::new(Vec::with_capacity(VK_LEN + self.mlkem.dk.len()));
        pa.extend_from_slice(self.vk_a.as_ref());
        pa.extend_from_slice(&self.mlkem.dk);
        let mut pb = Zeroizing::new(Vec::with_capacity(VK_LEN + self.mce.sk.len()));
        pb.extend_from_slice(self.vk_b.as_ref());
        pb.extend_from_slice(&self.mce.sk);
        let wa = aead::seal(Cipher::Aes256Gcm, &keks.a, &wrap_aad(vault_id, b"pm/v1/wrap/A"), &pa)?;
        let wb = aead::seal(Cipher::ChaCha20Poly1305, &keks.b, &wrap_aad(vault_id, b"pm/v1/wrap/B"), &pb)?;
        Ok((wa, wb))
    }

    /// 解开包裹，并用成对一致性测试确认私钥与文件头中的公钥匹配。
    pub fn unwrap(
        keks: &Keks,
        vault_id: &[u8; 16],
        wrap_a: &[u8],
        wrap_b: &[u8],
        ek_mlkem: &[u8],
        pk_mce: &[u8],
    ) -> Result<Self, CryptoError> {
        let pa = aead::open(Cipher::Aes256Gcm, &keks.a, &wrap_aad(vault_id, b"pm/v1/wrap/A"), wrap_a)?;
        let pb = aead::open(Cipher::ChaCha20Poly1305, &keks.b, &wrap_aad(vault_id, b"pm/v1/wrap/B"), wrap_b)?;
        if pa.len() <= VK_LEN || pb.len() <= VK_LEN {
            return Err(CryptoError::AuthFailed);
        }
        let mut vk_a = Zeroizing::new([0u8; VK_LEN]);
        vk_a.copy_from_slice(&pa[..VK_LEN]);
        let mut vk_b = Zeroizing::new([0u8; VK_LEN]);
        vk_b.copy_from_slice(&pb[..VK_LEN]);
        let keys = Self {
            vk_a,
            vk_b,
            mlkem: MlKemKeys { dk: Zeroizing::new(pa[VK_LEN..].to_vec()), ek: ek_mlkem.to_vec() },
            mce: McElieceKeys { sk: Zeroizing::new(pb[VK_LEN..].to_vec()), pk: pk_mce.to_vec() },
        };
        let (ct, ss) = kem::mlkem_encaps(&keys.mlkem.ek)?;
        if !ct_eq(&ss, &kem::mlkem_decaps(&keys.mlkem.dk, &ct)?) {
            return Err(CryptoError::AuthFailed);
        }
        let (ct, ss) = kem::mceliece_encaps(&keys.mce.pk)?;
        if !ct_eq(&ss, &kem::mceliece_decaps(&keys.mce.sk, &ct)?) {
            return Err(CryptoError::AuthFailed);
        }
        Ok(keys)
    }

    fn dek_a(&self, ss: &[u8], header_hash: &[u8], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let mut ikm = Zeroizing::new(self.vk_a.to_vec());
        ikm.extend_from_slice(ss);
        derive32(b"pm/v1/dek", &ikm, &[b"pm/v1/dek/A", header_hash, ct])
    }

    fn dek_b(&self, ss: &[u8], header_hash: &[u8], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let mut ikm = Zeroizing::new(self.vk_b.to_vec());
        ikm.extend_from_slice(ss);
        derive32(b"pm/v1/dek", &ikm, &[b"pm/v1/dek/B", header_hash, ct])
    }

    /// 双层加密载荷。`header_hash` 为文件头静态部分的 SHA-512。
    pub fn seal_payload(&self, header_hash: &[u8; 64], plaintext: &[u8]) -> Result<SealedPayload, CryptoError> {
        let (ct_mce, ss_m) = kem::mceliece_encaps(&self.mce.pk)?;
        let dek_b = self.dek_b(&ss_m, header_hash, &ct_mce)?;
        let nonce_b = rng::random_array()?;
        let c1 = aead::seal_with_nonce(Cipher::ChaCha20Poly1305, &dek_b, nonce_b, header_hash, plaintext)?;

        let (ct_mlkem, ss_k) = kem::mlkem_encaps(&self.mlkem.ek)?;
        let dek_a = self.dek_a(&ss_k, header_hash, &ct_mlkem)?;
        let nonce_a = rng::random_array()?;
        let mut aad = header_hash.to_vec();
        aad.extend_from_slice(&ct_mce);
        let c2 = aead::seal_with_nonce(Cipher::Aes256Gcm, &dek_a, nonce_a, &aad, &c1)?;
        Ok(SealedPayload { ct_mlkem, ct_mce, nonce_a, nonce_b, c2 })
    }

    pub fn open_payload(&self, header_hash: &[u8; 64], sealed: &SealedPayload) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let ss_k = kem::mlkem_decaps(&self.mlkem.dk, &sealed.ct_mlkem)?;
        let dek_a = self.dek_a(&ss_k, header_hash, &sealed.ct_mlkem)?;
        let mut aad = header_hash.to_vec();
        aad.extend_from_slice(&sealed.ct_mce);
        let c1 = aead::open_with_nonce(Cipher::Aes256Gcm, &dek_a, sealed.nonce_a, &aad, &sealed.c2)?;

        let ss_m = kem::mceliece_decaps(&self.mce.sk, &sealed.ct_mce)?;
        let dek_b = self.dek_b(&ss_m, header_hash, &sealed.ct_mce)?;
        aead::open_with_nonce(Cipher::ChaCha20Poly1305, &dek_b, sealed.nonce_b, header_hash, &c1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::TEST_PARAMS;

    fn setup() -> (VaultKeys, Keks, [u8; 16], [u8; 32]) {
        // SAFETY: 测试进程内设置环境变量。
        unsafe { std::env::set_var("PASSMANAGER_INSECURE_TEST_KDF", "1") };
        let vault_id = [7u8; 16];
        let device_key = [9u8; 32];
        let keks = derive_keks("correct horse", b"saltsaltsaltsalt", TEST_PARAMS, &device_key, &vault_id).unwrap();
        (VaultKeys::generate().unwrap(), keks, vault_id, device_key)
    }

    #[test]
    fn full_roundtrip_and_failures() {
        let (keys, keks, vault_id, device_key) = setup();
        let (wa, wb) = keys.wrap(&keks, &vault_id).unwrap();
        let reopened = VaultKeys::unwrap(&keks, &vault_id, &wa, &wb, keys.mlkem_public(), keys.mceliece_public()).unwrap();
        let h = [3u8; 64];
        let s1 = keys.seal_payload(&h, b"hello vault").unwrap();
        let s2 = keys.seal_payload(&h, b"hello vault").unwrap();
        assert_ne!(s1.nonce_a, s2.nonce_a);
        assert_ne!(s1.ct_mlkem, s2.ct_mlkem);
        assert_eq!(reopened.open_payload(&h, &s1).unwrap().as_slice(), b"hello vault");

        // 篡改任何部分都必须失败。
        let mut bad = s1.clone();
        bad.c2[3] ^= 1;
        assert!(reopened.open_payload(&h, &bad).is_err());
        let mut bad = s1.clone();
        bad.ct_mce[0] ^= 1;
        assert!(reopened.open_payload(&h, &bad).is_err());
        let mut bad = s1.clone();
        bad.ct_mlkem[0] ^= 1;
        assert!(reopened.open_payload(&h, &bad).is_err());
        assert!(reopened.open_payload(&[4u8; 64], &s1).is_err());

        // 错误口令 / 错误设备密钥。
        let wrong_pw = derive_keks("wrong", b"saltsaltsaltsalt", TEST_PARAMS, &device_key, &vault_id).unwrap();
        assert!(VaultKeys::unwrap(&wrong_pw, &vault_id, &wa, &wb, keys.mlkem_public(), keys.mceliece_public()).is_err());
        let wrong_dev = derive_keks("correct horse", b"saltsaltsaltsalt", TEST_PARAMS, &[1u8; 32], &vault_id).unwrap();
        assert!(VaultKeys::unwrap(&wrong_dev, &vault_id, &wa, &wb, keys.mlkem_public(), keys.mceliece_public()).is_err());
        assert_ne!(key_check_value(&device_key, &vault_id).unwrap(), key_check_value(&[1u8; 32], &vault_id).unwrap());
    }
}

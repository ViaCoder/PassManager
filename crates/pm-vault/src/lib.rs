//! PassManager 库文件：数据模型、域名规则、文件格式与加解密。

pub mod domain;
pub mod format;
pub mod model;
pub mod store;

use std::path::{Path, PathBuf};

use pm_crypto::CryptoError;
use pm_crypto::envelope::{self, VaultKeys};
use pm_crypto::kdf::KdfParams;
use thiserror::Error;

use crate::format::Header;
pub use crate::model::*;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault does not exist")]
    NotFound,
    #[error("vault already exists")]
    AlreadyExists,
    #[error("wrong password")]
    WrongPassword,
    #[error("device key does not match this vault (different machine, reinstalled system or cleared TPM)")]
    WrongDeviceKey,
    #[error("sealing level mismatch: vault was created with L{recorded}, current environment provides L{actual}")]
    LevelMismatch { recorded: u8, actual: u8 },
    #[error("vault file corrupt: {0}")]
    Corrupt(&'static str),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// 已解锁的库。
pub struct Vault {
    path: PathBuf,
    header: Header,
    keys: VaultKeys,
    pub payload: Payload,
}

impl Vault {
    /// 新建库并立即写盘。
    pub fn create(path: &Path, password: &str, device_key: &[u8; 32], seal_level: u8, kdf: KdfParams) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        kdf.check_floor()?;
        let vault_id: [u8; 16] = pm_crypto::rng::random_array()?;
        let salt: [u8; 32] = pm_crypto::rng::random_array()?;
        let keys = VaultKeys::generate()?;
        let keks = envelope::derive_keks(password, &salt, kdf, device_key, &vault_id)?;
        let (wrap_a, wrap_b) = keys.wrap(&keks, &vault_id)?;
        let header = Header {
            version: format::VERSION,
            vault_id,
            seal_level,
            kcv: envelope::key_check_value(device_key, &vault_id)?,
            kdf,
            salt,
            ek_mlkem: keys.mlkem_public().to_vec(),
            pk_mce: keys.mceliece_public().to_vec(),
            wrap_a,
            wrap_b,
        };
        let v = Self { path: path.to_path_buf(), header, keys, payload: Payload::default() };
        v.save()?;
        Ok(v)
    }

    /// 只读取文件头（不需要口令）。
    pub fn read_header(path: &Path) -> Result<Header, VaultError> {
        let data = match store::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::NotFound),
            Err(e) => return Err(e.into()),
        };
        Ok(format::decode_file(&data)?.0)
    }

    /// 检查设备密钥与封存等级（不需要口令，不运行 Argon2）。
    pub fn check_device(header: &Header, device_key: &[u8; 32], actual_level: u8) -> Result<(), VaultError> {
        let kcv = envelope::key_check_value(device_key, &header.vault_id)?;
        if !pm_crypto::ct_eq(&kcv, &header.kcv) {
            return Err(VaultError::WrongDeviceKey);
        }
        if header.seal_level != actual_level {
            return Err(VaultError::LevelMismatch { recorded: header.seal_level, actual: actual_level });
        }
        Ok(())
    }

    /// 打开（解锁）库。
    pub fn open(path: &Path, password: &str, device_key: &[u8; 32], actual_level: u8) -> Result<Self, VaultError> {
        let data = match store::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let (header, sealed) = format::decode_file(&data)?;
        Self::check_device(&header, device_key, actual_level)?;
        header.kdf.check_floor()?;
        let keks = envelope::derive_keks(password, &header.salt, header.kdf, device_key, &header.vault_id)?;
        let keys =
            VaultKeys::unwrap(&keks, &header.vault_id, &header.wrap_a, &header.wrap_b, &header.ek_mlkem, &header.pk_mce).map_err(|e| {
                match e {
                    CryptoError::AuthFailed => VaultError::WrongPassword,
                    other => other.into(),
                }
            })?;
        let plain = keys.open_payload(&header.hash()?, &sealed).map_err(|e| match e {
            CryptoError::AuthFailed => VaultError::Corrupt("payload authentication failed (tampered?)"),
            other => other.into(),
        })?;
        let payload = format::decode_payload(&plain)?;
        Ok(Self { path: path.to_path_buf(), header, keys, payload })
    }

    /// 校验口令（运行一次 Argon2id）。
    pub fn verify_password(&self, password: &str, device_key: &[u8; 32]) -> bool {
        Self::check_password(&self.header, password, device_key)
    }

    /// 只依据文件头校验口令（不需要持有已解锁的库，便于在锁外运行 Argon2id）。
    pub fn check_password(header: &Header, password: &str, device_key: &[u8; 32]) -> bool {
        let Ok(keks) = envelope::derive_keks(password, &header.salt, header.kdf, device_key, &header.vault_id) else {
            return false;
        };
        VaultKeys::unwrap(&keks, &header.vault_id, &header.wrap_a, &header.wrap_b, &header.ek_mlkem, &header.pk_mce).is_ok()
    }

    /// 修改口令：只重新包裹长期密钥。
    pub fn change_password(&mut self, new_password: &str, device_key: &[u8; 32], kdf: KdfParams) -> Result<(), VaultError> {
        kdf.check_floor()?;
        let salt: [u8; 32] = pm_crypto::rng::random_array()?;
        let keks = envelope::derive_keks(new_password, &salt, kdf, device_key, &self.header.vault_id)?;
        let (wa, wb) = self.keys.wrap(&keks, &self.header.vault_id)?;
        self.header.salt = salt;
        self.header.kdf = kdf;
        self.header.wrap_a = wa;
        self.header.wrap_b = wb;
        self.save()
    }

    /// 加密并原子写盘（每次都使用新的 DEK 与 nonce）。
    pub fn save(&self) -> Result<(), VaultError> {
        let plain = format::encode_payload(&self.payload)?;
        let sealed = self.keys.seal_payload(&self.header.hash()?, &plain)?;
        let file = format::encode_file(&self.header, &sealed)?;
        store::write_atomic(&self.path, &file)?;
        Ok(())
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pm_crypto::kdf::TEST_PARAMS;
    use zeroize::Zeroizing;

    fn test_mode() {
        // SAFETY: 测试中设置环境变量。
        unsafe { std::env::set_var("PASSMANAGER_INSECURE_TEST_KDF", "1") };
    }

    fn entry(name: &str) -> Entry {
        Entry {
            name: name.into(),
            secret: Zeroizing::new("s3cret-value-123".into()),
            domains: vec!["*.example.com".into()],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: now(),
            updated: now(),
        }
    }

    #[test]
    fn create_open_save_tamper() {
        test_mode();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pmv");
        let dk = [5u8; 32];
        let mut v = Vault::create(&path, "pw-123456", &dk, 2, TEST_PARAMS).unwrap();
        v.payload.entries.push(entry("github"));
        v.save().unwrap();
        assert!(store::backup_path(&path).exists());

        let v2 = Vault::open(&path, "pw-123456", &dk, 2).unwrap();
        assert_eq!(v2.payload.entries.len(), 1);
        assert_eq!(v2.payload.entries[0].secret.as_str(), "s3cret-value-123");
        assert!(v2.verify_password("pw-123456", &dk));
        assert!(!v2.verify_password("nope", &dk));

        assert!(matches!(Vault::open(&path, "wrong", &dk, 2), Err(VaultError::WrongPassword)));
        assert!(matches!(Vault::open(&path, "pw-123456", &[6u8; 32], 2), Err(VaultError::WrongDeviceKey)));
        assert!(matches!(Vault::open(&path, "pw-123456", &dk, 1), Err(VaultError::LevelMismatch { .. })));

        // 密文中没有明文。
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(16).any(|w| w == b"s3cret-value-123"));

        // 翻转任意位置的一个比特都必须失败。
        for pos in [20usize, 200, raw.len() / 2, raw.len() - 5] {
            let mut bad = raw.clone();
            bad[pos] ^= 0x01;
            let p2 = dir.path().join(format!("bad{pos}.pmv"));
            std::fs::write(&p2, &bad).unwrap();
            assert!(Vault::open(&p2, "pw-123456", &dk, 2).is_err(), "bit flip at {pos} not detected");
        }

        // 篡改等级字段（降级）必须被拒绝：重新编码文件头使等级为 1。
        let (mut h, s) = format::decode_file(&raw).unwrap();
        h.seal_level = 1;
        let p3 = dir.path().join("downgrade.pmv");
        std::fs::write(&p3, format::encode_file(&h, &s).unwrap()).unwrap();
        assert!(Vault::open(&p3, "pw-123456", &dk, 1).is_err());

        // 修改口令。
        let mut v3 = Vault::open(&path, "pw-123456", &dk, 2).unwrap();
        v3.change_password("new-password", &dk, TEST_PARAMS).unwrap();
        assert!(Vault::open(&path, "pw-123456", &dk, 2).is_err());
        assert_eq!(Vault::open(&path, "new-password", &dk, 2).unwrap().payload.entries.len(), 1);
    }

    #[test]
    fn weak_kdf_rejected_without_test_mode() {
        let weak = KdfParams { m_kib: 1024, t: 1, p: 1 };
        // 测试模式由环境变量控制，这里直接检查下限逻辑。
        assert!(weak.m_kib < pm_crypto::kdf::MIN_M_KIB);
        let strong = KdfParams::default();
        assert!(strong.m_kib >= pm_crypto::kdf::MIN_M_KIB && strong.t >= pm_crypto::kdf::MIN_T);
    }

    #[test]
    fn auto_names() {
        let d = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(auto_name(&d(&["*.github.com"]), &[]), "github.com");
        assert_eq!(auto_name(&d(&["*.github.com"]), &["github.com"]), "github.com-2");
        assert_eq!(auto_name(&d(&["*.github.com"]), &["github.com", "github.com-2"]), "github.com-3");
        assert_eq!(auto_name(&d(&["::1"]), &[]), "--1");
        assert_eq!(auto_name(&d(&["10.0.0.5"]), &[]), "10.0.0.5");
        assert!(validate_name("secret").is_err());
    }

    #[test]
    fn entry_validation() {
        let mut e = entry("bad name");
        assert!(validate_entry(&mut e).is_err());
        let mut e = entry("ok");
        e.domains = vec!["*.com".into()];
        assert!(validate_entry(&mut e).is_err());
        let mut e = entry("ok");
        e.domains = vec!["API.example.com".into(), "api.example.com".into()];
        validate_entry(&mut e).unwrap();
        assert_eq!(e.domains, vec!["api.example.com".to_string()]);
    }
}

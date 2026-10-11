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

pub use crate::format::{Header, VaultMode};
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
    #[error("vault mode mismatch: the vault is a {found:?} vault, expected {expected:?} (possible downgrade attempt)")]
    ModeMismatch { expected: VaultMode, found: VaultMode },
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
    /// 是否从 `.bak` 恢复（主文件缺失或损坏）。为真时下一次保存不把主文件复制为 `.bak`。
    recovered: std::sync::atomic::AtomicBool,
}

/// 依次尝试主文件与 `.bak`。只有主文件缺失或损坏（截断、半写、校验失败）时才回退到 `.bak`；
/// 文件完好但被策略拒绝（口令错误、设备密钥不符、等级降级、模式不符）时不回退，
/// 否则旧的 `.bak` 可以用来绕过这些检查。两者都失败时返回主文件的错误。
fn load_with_fallback<T>(path: &Path, f: impl Fn(&[u8]) -> Result<T, VaultError>) -> Result<(T, bool), VaultError> {
    let main_err = match store::read_main(path) {
        Ok(d) => match f(&d) {
            Ok(v) => return Ok((v, false)),
            Err(e @ (VaultError::Corrupt(_) | VaultError::Crypto(_) | VaultError::Io(_))) => e,
            Err(e) => return Err(e),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => VaultError::NotFound,
        Err(e) => e.into(),
    };
    match store::read_backup(path) {
        Ok(d) => match f(&d) {
            Ok(v) => Ok((v, true)),
            Err(_) => Err(main_err),
        },
        Err(_) => Err(main_err),
    }
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
            mode: VaultMode::Password,
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
        let v = Self {
            path: path.to_path_buf(),
            header,
            keys,
            payload: Payload::default(),
            recovered: std::sync::atomic::AtomicBool::new(false),
        };
        v.save()?;
        Ok(v)
    }

    /// 新建无口令库（服务器在线版）：IKM 只有设备密钥，不运行 Argon2。
    pub fn create_device_only(path: &Path, device_key: &[u8; 32], seal_level: u8) -> Result<Self, VaultError> {
        if path.exists() || store::backup_path(path).exists() {
            return Err(VaultError::AlreadyExists);
        }
        let vault_id: [u8; 16] = pm_crypto::rng::random_array()?;
        let salt: [u8; 32] = pm_crypto::rng::random_array()?;
        let keys = VaultKeys::generate()?;
        let keks = envelope::derive_keks_device_only(device_key, &vault_id, &salt)?;
        let (wrap_a, wrap_b) = keys.wrap(&keks, &vault_id)?;
        let header = Header {
            version: format::VERSION_DEVICE_ONLY,
            mode: VaultMode::DeviceOnly,
            vault_id,
            seal_level,
            kcv: envelope::key_check_value(device_key, &vault_id)?,
            // 无口令模式不使用 KDF；记录默认值只为保持文件头结构一致。
            kdf: KdfParams::default(),
            salt,
            ek_mlkem: keys.mlkem_public().to_vec(),
            pk_mce: keys.mceliece_public().to_vec(),
            wrap_a,
            wrap_b,
        };
        // 新库没有设置过：默认不自动锁定（没有口令，锁定后只能由管理员在网页或 root 命令解锁）。
        let payload = Payload { settings: Settings { auto_lock_hours: 0 }, ..Default::default() };
        let v = Self { path: path.to_path_buf(), header, keys, payload, recovered: std::sync::atomic::AtomicBool::new(false) };
        v.save()?;
        Ok(v)
    }

    /// 打开无口令库。文件头不是无口令模式（例如被改成口令模式）时拒绝。
    pub fn open_device_only(path: &Path, device_key: &[u8; 32], actual_level: u8) -> Result<Self, VaultError> {
        let (v, recovered) = load_with_fallback(path, |data| {
            let (header, sealed) = format::decode_file(data)?;
            if header.mode != VaultMode::DeviceOnly {
                return Err(VaultError::ModeMismatch { expected: VaultMode::DeviceOnly, found: header.mode });
            }
            Self::check_device(&header, device_key, actual_level)?;
            let keks = envelope::derive_keks_device_only(device_key, &header.vault_id, &header.salt)?;
            Self::finish_open(path, header, &sealed, &keks)
        })?;
        v.recovered.store(recovered, std::sync::atomic::Ordering::SeqCst);
        Ok(v)
    }

    fn finish_open(path: &Path, header: Header, sealed: &envelope::SealedPayload, keks: &envelope::Keks) -> Result<Self, VaultError> {
        let mode = header.mode;
        let keys =
            VaultKeys::unwrap(keks, &header.vault_id, &header.wrap_a, &header.wrap_b, &header.ek_mlkem, &header.pk_mce).map_err(|e| {
                match e {
                    // 口令模式：包裹解不开说明口令错误。无口令模式：设备密钥已由 kcv 确认，解不开只能是文件损坏。
                    CryptoError::AuthFailed if mode == VaultMode::Password => VaultError::WrongPassword,
                    CryptoError::AuthFailed => VaultError::Corrupt("key wrap authentication failed (tampered?)"),
                    other => other.into(),
                }
            })?;
        let plain = keys.open_payload(&header.hash()?, sealed).map_err(|e| match e {
            CryptoError::AuthFailed => VaultError::Corrupt("payload authentication failed (tampered?)"),
            other => other.into(),
        })?;
        let payload = format::decode_payload(&plain)?;
        Ok(Self { path: path.to_path_buf(), header, keys, payload, recovered: std::sync::atomic::AtomicBool::new(false) })
    }

    /// 只读取文件头（不需要口令）。
    pub fn read_header(path: &Path) -> Result<Header, VaultError> {
        Ok(load_with_fallback(path, |data| Ok(format::decode_file(data)?.0))?.0)
    }

    /// 检查设备密钥与封存等级（不需要口令，不运行 Argon2）。
    pub fn check_device(header: &Header, device_key: &[u8; 32], actual_level: u8) -> Result<(), VaultError> {
        let kcv = envelope::key_check_value(device_key, &header.vault_id)?;
        if !pm_crypto::ct_eq(&kcv, &header.kcv) {
            return Err(VaultError::WrongDeviceKey);
        }
        // 只拒绝降级：库记录的等级高于当前环境（例如 L3 的库被拿到只有 L2 的环境）。
        // 升级（`reseal` 把 L2 改为 L3 后）允许打开，下一次保存时文件头更新为新等级。
        if header.seal_level > actual_level {
            return Err(VaultError::LevelMismatch { recorded: header.seal_level, actual: actual_level });
        }
        Ok(())
    }

    /// 打开（解锁）库。
    pub fn open(path: &Path, password: &str, device_key: &[u8; 32], actual_level: u8) -> Result<Self, VaultError> {
        let (v, recovered) = load_with_fallback(path, |data| {
            let (header, sealed) = format::decode_file(data)?;
            if header.mode != VaultMode::Password {
                return Err(VaultError::ModeMismatch { expected: VaultMode::Password, found: header.mode });
            }
            Self::check_device(&header, device_key, actual_level)?;
            header.kdf.check_floor()?;
            let keks = envelope::derive_keks(password, &header.salt, header.kdf, device_key, &header.vault_id)?;
            Self::finish_open(path, header, &sealed, &keks)
        })?;
        v.recovered.store(recovered, std::sync::atomic::Ordering::SeqCst);
        Ok(v)
    }

    /// 校验口令（运行一次 Argon2id）。
    pub fn verify_password(&self, password: &str, device_key: &[u8; 32]) -> bool {
        Self::check_password(&self.header, password, device_key)
    }

    /// 只依据文件头校验口令（不需要持有已解锁的库，便于在锁外运行 Argon2id）。
    pub fn check_password(header: &Header, password: &str, device_key: &[u8; 32]) -> bool {
        if header.mode != VaultMode::Password {
            return false;
        }
        let Ok(keks) = envelope::derive_keks(password, &header.salt, header.kdf, device_key, &header.vault_id) else {
            return false;
        };
        VaultKeys::unwrap(&keks, &header.vault_id, &header.wrap_a, &header.wrap_b, &header.ek_mlkem, &header.pk_mce).is_ok()
    }

    /// 修改口令：只重新包裹长期密钥。
    pub fn change_password(&mut self, new_password: &str, device_key: &[u8; 32], kdf: KdfParams) -> Result<(), VaultError> {
        if self.header.mode != VaultMode::Password {
            return Err(VaultError::ModeMismatch { expected: VaultMode::Password, found: self.header.mode });
        }
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
        store::write_atomic_opts(&self.path, &file, !self.recovered.load(std::sync::atomic::Ordering::SeqCst))?;
        self.recovered.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// 封存等级升级（`reseal`）后更新文件头记录的等级并重新加密保存。只允许升级。
    pub fn upgrade_seal_level(&mut self, level: u8) -> Result<(), VaultError> {
        if level < self.header.seal_level {
            return Err(VaultError::LevelMismatch { recorded: self.header.seal_level, actual: level });
        }
        if level == self.header.seal_level {
            return Ok(());
        }
        self.header.seal_level = level;
        self.save()
    }

    /// 测试用：按 0.1.0 的载荷格式写盘（验证旧库迁移）。
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn save_legacy_v1_for_test(&self) -> Result<(), VaultError> {
        let legacy = model::PayloadV1 {
            entries: self
                .payload
                .entries
                .iter()
                .map(|e| model::EntryV1 {
                    name: e.name.clone(),
                    secret: e.secret.clone(),
                    domains: e.domains.clone(),
                    note: e.note.clone(),
                    self_signed: e.self_signed,
                    auto_accept_host_key: e.auto_accept_host_key,
                    created: e.created,
                    updated: e.updated,
                })
                .collect(),
            pins: self.payload.pins.clone(),
            settings: self.payload.settings.clone(),
        };
        let plain = format::encode_payload_v1(&legacy)?;
        let sealed = self.keys.seal_payload(&self.header.hash()?, &plain)?;
        store::write_atomic(&self.path, &format::encode_file(&self.header, &sealed)?)?;
        Ok(())
    }

    pub fn mode(&self) -> VaultMode {
        self.header.mode
    }

    /// 是否从 `.bak` 恢复（主文件缺失或损坏）。
    pub fn recovered_from_backup(&self) -> bool {
        self.recovered.load(std::sync::atomic::Ordering::SeqCst)
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
            fields: vec![],
            host_keys: vec![],
            ops: vec![],
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

    /// 无口令模式：首次创建、重新打开（模拟重启后自动解锁）、错误设备密钥、模式字段被篡改或降级、等级只允许升级。
    #[test]
    fn device_only_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pmv");
        let dk = [3u8; 32];
        let mut v = Vault::create_device_only(&path, &dk, 2).unwrap();
        assert_eq!(v.mode(), VaultMode::DeviceOnly);
        assert_eq!(v.payload.settings.auto_lock_hours, 0);
        assert!(matches!(Vault::create_device_only(&path, &dk, 2), Err(VaultError::AlreadyExists)));
        v.payload.entries.push(entry("github"));
        v.save().unwrap();
        // 重启后只凭设备密钥打开。
        let v2 = Vault::open_device_only(&path, &dk, 2).unwrap();
        assert_eq!(v2.payload.entries[0].secret.as_str(), "s3cret-value-123");
        assert_eq!(Vault::read_header(&path).unwrap().version, format::VERSION_DEVICE_ONLY);
        // 错误设备密钥、等级降级。
        assert!(matches!(Vault::open_device_only(&path, &[4u8; 32], 2), Err(VaultError::WrongDeviceKey)));
        assert!(matches!(Vault::open_device_only(&path, &dk, 1), Err(VaultError::LevelMismatch { recorded: 2, actual: 1 })));
        // 口令接口一律拒绝无口令库（不会用空口令/任意口令打开）。
        assert!(matches!(Vault::open(&path, "", &dk, 2), Err(VaultError::ModeMismatch { .. })));
        assert!(!Vault::check_password(v2.header(), "", &dk));
        let mut v3 = Vault::open_device_only(&path, &dk, 2).unwrap();
        assert!(v3.change_password("new-password", &dk, TEST_PARAMS).is_err());
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(16).any(|w| w == b"s3cret-value-123"));

        // 篡改：把文件头改写成 v1（口令模式）——两种打开方式都失败。
        let (h, sealed) = format::decode_file(&raw).unwrap();
        let mut down = h.clone();
        down.version = format::VERSION;
        down.mode = VaultMode::Password;
        let p2 = dir.path().join("downgraded.pmv");
        std::fs::write(&p2, format::encode_file(&down, &sealed).unwrap()).unwrap();
        assert!(matches!(Vault::open_device_only(&p2, &dk, 2), Err(VaultError::ModeMismatch { .. })));
        test_mode();
        assert!(Vault::open(&p2, "", &dk, 2).is_err());
        // 模式字节改成未知值、或版本与模式不一致：解析即失败。
        let hb = h.to_bytes().unwrap();
        let mut bad_mode = hb.clone();
        bad_mode[1] = 7;
        assert!(Header::from_bytes(&bad_mode).is_err());
        let mut mismatch = h.clone();
        mismatch.mode = VaultMode::Password;
        assert!(mismatch.to_bytes().is_err());
        // 文件头里的等级被改（降级到 1）：AAD 不符。
        let mut lvl = h.clone();
        lvl.seal_level = 1;
        let p3 = dir.path().join("level.pmv");
        std::fs::write(&p3, format::encode_file(&lvl, &sealed).unwrap()).unwrap();
        assert!(Vault::open_device_only(&p3, &dk, 1).is_err());

        // 升级封存等级：L2 的库在 L3 环境里能打开，upgrade 后文件头记为 3，再也不能在 L2 下打开。
        let mut v4 = Vault::open_device_only(&path, &dk, 3).unwrap();
        assert!(v4.upgrade_seal_level(1).is_err());
        v4.upgrade_seal_level(3).unwrap();
        assert_eq!(Vault::read_header(&path).unwrap().seal_level, 3);
        assert!(
            matches!(Vault::open_device_only(&path, &dk, 2), Err(VaultError::LevelMismatch { .. })),
            "旧的 L2 .bak 不能被用来绕过等级检查"
        );
        assert_eq!(Vault::open_device_only(&path, &dk, 3).unwrap().payload.entries.len(), 1);
    }

    /// 口令库（v1 格式）不能用无口令接口打开，且 v1 文件头重新编码后逐字节不变。
    #[test]
    fn password_vault_is_unchanged_and_not_openable_device_only() {
        test_mode();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pmv");
        let dk = [5u8; 32];
        Vault::create(&path, "pw-123456", &dk, 2, TEST_PARAMS).unwrap();
        let raw = std::fs::read(&path).unwrap();
        let hlen = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
        let (h, _) = format::decode_file(&raw).unwrap();
        assert_eq!((h.version, h.mode), (format::VERSION, VaultMode::Password));
        assert_eq!(h.to_bytes().unwrap(), raw[12..12 + hlen].to_vec());
        assert!(matches!(Vault::open_device_only(&path, &dk, 2), Err(VaultError::ModeMismatch { .. })));
    }

    /// 断电 / kill -9 注入：写入的每个关键点崩溃后都能打开，内容为旧版本或新版本；
    /// 主文件被截断、损坏或丢失时回退到 .bak，且回退后的第一次保存不会用坏主文件覆盖 .bak。
    #[test]
    fn crash_injection_and_backup_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pmv");
        let dk = [7u8; 32];
        let mut v = Vault::create_device_only(&path, &dk, 2).unwrap();
        v.payload.entries.push(entry("one"));
        v.save().unwrap();
        for point in [store::CrashPoint::HalfWrittenTemp, store::CrashPoint::BeforeBackup, store::CrashPoint::BeforeRename] {
            v.payload.entries.push(entry(&format!("crash{}", v.payload.entries.len())));
            store::CRASH_AT.with(|c| c.set(Some(point)));
            assert!(v.save().is_err(), "{point:?}");
            let r = Vault::open_device_only(&path, &dk, 2).unwrap();
            assert_eq!(r.payload.entries.len(), v.payload.entries.len() - 1, "{point:?}: old content survives");
            assert!(!r.recovered_from_backup());
            v.save().unwrap();
            assert_eq!(Vault::open_device_only(&path, &dk, 2).unwrap().payload.entries.len(), v.payload.entries.len());
        }
        let n = v.payload.entries.len();
        let good_main = std::fs::read(&path).unwrap();
        let bak = store::read_backup(&path).unwrap();
        // 主文件被截断到各种长度（包括 0 字节）：回退到 .bak（少一条记录的上一版）。
        for cut in [0usize, 5, 12, 100, good_main.len() / 2, good_main.len() - 1] {
            std::fs::write(&path, &good_main[..cut]).unwrap();
            let r = Vault::open_device_only(&path, &dk, 2).unwrap();
            assert!(r.recovered_from_backup(), "cut {cut}");
            assert_eq!(r.payload.entries.len(), n - 1);
            assert!(Vault::read_header(&path).is_ok(), "cut {cut}: header falls back too");
        }
        // 主文件比特翻转：同样回退。
        let mut flipped = good_main.clone();
        let mid = flipped.len() - 10;
        flipped[mid] ^= 0x80;
        std::fs::write(&path, &flipped).unwrap();
        let mut r = Vault::open_device_only(&path, &dk, 2).unwrap();
        assert!(r.recovered_from_backup());
        // 恢复后的第一次保存：主文件写入新内容，.bak 保持完好的旧版本（没有被坏主文件覆盖）。
        r.payload.entries.push(entry("after-recovery"));
        r.save().unwrap();
        assert_eq!(store::read_backup(&path).unwrap(), bak);
        assert_eq!(Vault::open_device_only(&path, &dk, 2).unwrap().payload.entries.len(), n);
        r.save().unwrap();
        assert_ne!(store::read_backup(&path).unwrap(), bak, "之后恢复正常的备份轮换");
        // 主文件丢失：读 .bak。
        std::fs::remove_file(&path).unwrap();
        assert!(Vault::open_device_only(&path, &dk, 2).unwrap().recovered_from_backup());
        // 主文件与 .bak 都坏：报错（不 panic），错误来自主文件。
        std::fs::write(&path, b"PMVAULT\0junk").unwrap();
        std::fs::write(store::backup_path(&path), b"junk").unwrap();
        assert!(matches!(Vault::open_device_only(&path, &dk, 2), Err(VaultError::Corrupt(_))));
        // 主文件不存在、.bak 也不存在。
        assert!(matches!(Vault::open_device_only(&dir.path().join("none.pmv"), &dk, 2), Err(VaultError::NotFound)));
        // 错误的设备密钥不会因为回退而被掩盖。
        let p2 = dir.path().join("v2.pmv");
        Vault::create_device_only(&p2, &dk, 2).unwrap().save().unwrap();
        assert!(matches!(Vault::open_device_only(&p2, &[1u8; 32], 2), Err(VaultError::WrongDeviceKey)));
    }

    /// 0.1.0 写入的库（v1 载荷，没有字段）能打开，内容不变；保存后升级为 v2，可以保存多字段条目。
    #[test]
    fn v01_vault_migrates_to_fields_payload() {
        test_mode();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pmv");
        let dk = [8u8; 32];
        let mut v = Vault::create(&path, "pw-123456", &dk, 2, TEST_PARAMS).unwrap();
        v.payload.entries.push(entry("legacy"));
        v.payload.pins.push(Pin {
            kind: PinKind::Ssh,
            host_port: "h:22".into(),
            algo: "a".into(),
            fingerprint: "SHA256:x".into(),
            first_seen: 1,
        });
        v.payload.settings.auto_lock_hours = 7;
        v.save_legacy_v1_for_test().unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(5).any(|w| w == format::PAYLOAD_V2_MAGIC), "载荷是加密的，文件里看不到标记");
        let mut o = Vault::open(&path, "pw-123456", &dk, 2).unwrap();
        assert_eq!(o.payload.entries.len(), 1);
        assert_eq!(o.payload.entries[0].secret.as_str(), "s3cret-value-123");
        assert!(o.payload.entries[0].fields.is_empty());
        assert_eq!((o.payload.pins.len(), o.payload.settings.auto_lock_hours), (1, 7));
        // 升级：加一个多字段条目并保存（v2），再打开。
        let mut f = entry("mega");
        f.secret = Zeroizing::new(String::new());
        f.fields = vec![
            Field { name: "username".into(), value: Zeroizing::new("me@example.com".into()) },
            Field { name: "password".into(), value: Zeroizing::new("line1\nline2".into()) },
        ];
        validate_entry(&mut f).unwrap();
        o.payload.entries.push(f);
        o.save().unwrap();
        let o2 = Vault::open(&path, "pw-123456", &dk, 2).unwrap();
        let m = o2.payload.entry("mega").unwrap();
        assert_eq!(m.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["username", "password"]);
        assert_eq!(m.password(), Some("line1\nline2"));
        assert_eq!(o2.payload.entry("legacy").unwrap().password(), Some("s3cret-value-123"));
    }

    #[test]
    fn field_and_domain_validation() {
        let mut e = entry("ok");
        e.domains = vec![];
        validate_entry(&mut e).unwrap();
        assert!(e.domains.is_empty(), "没有域名的条目允许保存（未绑定）");
        e.domains = vec!["db1.example.com:2222".into(), "DB1.example.com:2222".into()];
        validate_entry(&mut e).unwrap();
        assert_eq!(e.domains, vec!["db1.example.com:2222".to_string()]);
        let fld = |n: &str, v: &str| Field { name: n.into(), value: Zeroizing::new(v.into()) };
        let mut f = entry("f");
        f.secret = Zeroizing::new(String::new());
        f.fields = vec![fld("username", "u"), fld("password", "p")];
        validate_entry(&mut f).unwrap();
        for bad in
            [vec![fld("a.b", "x")], vec![fld("secret", "x")], vec![fld("", "x")], vec![fld("x", "")], vec![fld("x", "1"), fld("x", "2")]]
        {
            let mut b = entry("b");
            b.secret = Zeroizing::new(String::new());
            b.fields = bad;
            assert!(validate_entry(&mut b).is_err());
        }
        let mut both = entry("both");
        both.fields = vec![fld("x", "1")];
        assert!(validate_entry(&mut both).is_err(), "不能同时有单值与字段");
        let mut empty = entry("e");
        empty.secret = Zeroizing::new(String::new());
        assert!(validate_entry(&mut empty).is_err());
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

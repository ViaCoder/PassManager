//! macOS：系统钥匙串（L2）。
//!
//! launchd 守护进程无法使用 Secure Enclave（Apple DTS：SE 需要用户上下文），因此不提供 L3。
//! 服务由 launchd 以 root 启动，先读取 `/Library/Keychains/System.keychain` 中的设备密钥，
//! 然后立即、不可逆地降权到 `_passmanager`。条目由已安装的 PassManager 二进制自己创建，
//! 因此默认 ACL 只信任该二进制（ad-hoc 签名时按 cdhash 识别）。
//!
//! 如果系统钥匙串不可用，退回 root 专属文件 `/var/db/passmanager/device.key`（root:wheel 0400），
//! 同样在 root 阶段读取后降权，边界同为"必须 root"，仍记为 L2。

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use security_framework::item::{ItemClass, ItemSearchOptions};
use security_framework::os::macos::keychain::SecKeychain;
use zeroize::Zeroizing;

use super::{RandFn, Sealer, key_from_bytes};

pub const METHOD_KEYCHAIN: &str = "macos-system-keychain";
pub const METHOD_ROOTFILE: &str = "macos-root-file";
const KEYCHAIN: &str = "/Library/Keychains/System.keychain";
const SERVICE: &str = "PassManager";
const ACCOUNT: &str = "device-key";

pub struct KeychainSealer;

impl KeychainSealer {
    pub fn new() -> Self {
        Self
    }

    fn open() -> io::Result<SecKeychain> {
        SecKeychain::open(KEYCHAIN).map_err(|e| io::Error::other(format!("open System keychain: {e}")))
    }

    /// 只按属性匹配、不读取内容的查询：不受条目 ACL 限制，其他二进制（如安装程序）调用也不会弹出授权框而卡住。
    fn query(kc: &SecKeychain) -> ItemSearchOptions {
        let mut q = ItemSearchOptions::new();
        q.class(ItemClass::generic_password()).keychains(std::slice::from_ref(kc)).service(SERVICE).account(ACCOUNT);
        q
    }
}

impl Default for KeychainSealer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sealer for KeychainSealer {
    fn method(&self) -> &'static str {
        METHOD_KEYCHAIN
    }

    fn level(&self) -> u8 {
        2
    }

    fn describe(&self) -> String {
        "macOS 系统钥匙串（由 /var/db/SystemKey 保护，ACL 只信任 PassManager 二进制）".into()
    }

    fn is_provisioned(&self) -> bool {
        Self::open().is_ok_and(|k| Self::query(&k).load_refs(true).search().is_ok_and(|v| !v.is_empty()))
    }

    fn seal(&self, key: &[u8; 32], _rand: RandFn) -> io::Result<()> {
        let kc = Self::open()?;
        let hexkey = Zeroizing::new(hex::encode(key));
        kc.set_generic_password(SERVICE, ACCOUNT, hexkey.as_bytes()).map_err(|e| io::Error::other(format!("keychain write: {e}")))
    }

    fn unseal(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        let kc = Self::open()?;
        let (pw, _item) = kc
            .find_generic_password(SERVICE, ACCOUNT)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("keychain read: {e}")))?;
        let hexkey = Zeroizing::new(String::from_utf8_lossy(pw.as_ref()).to_string());
        let raw = Zeroizing::new(hex::decode(hexkey.trim()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad keychain item"))?);
        key_from_bytes(&raw)
    }

    fn remove(&self) -> io::Result<()> {
        if let Ok(kc) = Self::open() {
            let _ = Self::query(&kc).delete();
        }
        Ok(())
    }
}

/// 退回方案：root 专属文件。
pub struct RootFileSealer {
    path: PathBuf,
}

impl RootFileSealer {
    pub fn new() -> Self {
        Self { path: PathBuf::from("/var/db/passmanager/device.key") }
    }
}

impl Default for RootFileSealer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sealer for RootFileSealer {
    fn method(&self) -> &'static str {
        METHOD_ROOTFILE
    }

    fn level(&self) -> u8 {
        2
    }

    fn describe(&self) -> String {
        "root 专属文件 /var/db/passmanager/device.key（root:wheel 0400，root 阶段读取后降权）".into()
    }

    fn is_provisioned(&self) -> bool {
        self.path.exists()
    }

    fn seal(&self, key: &[u8; 32], _rand: RandFn) -> io::Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Some(d) = self.path.parent() {
            fs::create_dir_all(d)?;
            fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
        }
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o400).open(&self.path)?;
        f.write_all(key)?;
        f.sync_all()
    }

    fn unseal(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        let data = Zeroizing::new(fs::read(&self.path)?);
        key_from_bytes(&data)
    }

    fn remove(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
}

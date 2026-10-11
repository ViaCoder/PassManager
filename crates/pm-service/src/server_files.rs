//! 服务器模式的持久文件（都在数据目录里，原子写入：临时文件 → fsync → rename → fsync 目录）。
//!
//! | 文件 | 内容 | 保护 |
//! |---|---|---|
//! | `server-keys.pub` | 内层通道公钥包（ML-KEM-1024 ek + McEliece pk） | 公开；指纹固定在每个 Agent 的 remote.toml 里 |
//! | `server-keys.sealed` | 内层通道私钥 | 设备密钥封存（devseal，标签 `inner-server-keys`） |
//! | `tls/cert.pem` | 证书链 | 公开 |
//! | `tls/key.sealed` | 证书私钥（P-384） | 设备密钥封存（`tls-key`） |
//! | `acme-account.sealed` | Let's Encrypt 账号凭据 | 设备密钥封存（`acme-account`） |
//! | `cf-token.sealed` | Cloudflare API token（安装时经 stdin 传入） | 设备密钥封存（`cloudflare-token`） |
//! | `acme-state.json` | 连续失败次数、上次尝试时间（退避用） | — |

use std::path::{Path, PathBuf};

use pm_crypto::devseal;
use pm_net::inner::ServerKeys;
use pm_platform::Layout;
use zeroize::Zeroizing;

pub const LABEL_SERVER_KEYS: &str = "inner-server-keys";
pub const LABEL_TLS_KEY: &str = "tls-key";
pub const LABEL_ACME: &str = "acme-account";
pub const LABEL_CF: &str = "cloudflare-token";

pub fn server_pub_path(l: &Layout) -> PathBuf {
    l.data_dir.join("server-keys.pub")
}
pub fn server_sealed_path(l: &Layout) -> PathBuf {
    l.data_dir.join("server-keys.sealed")
}
pub fn cert_path(l: &Layout) -> PathBuf {
    l.tls_dir().join("cert.pem")
}
pub fn tls_key_path(l: &Layout) -> PathBuf {
    l.tls_dir().join("key.sealed")
}
pub fn acme_account_path(l: &Layout) -> PathBuf {
    l.data_dir.join("acme-account.sealed")
}
pub fn cf_token_path(l: &Layout) -> PathBuf {
    l.data_dir.join("cf-token.sealed")
}
pub fn acme_state_path(l: &Layout) -> PathBuf {
    l.data_dir.join("acme-state.json")
}

/// 所有由服务账户读写的服务器文件（`init` 以 root 创建后要改属主）。
pub fn owned_paths(l: &Layout) -> Vec<PathBuf> {
    vec![
        server_pub_path(l),
        server_sealed_path(l),
        l.tls_dir(),
        cert_path(l),
        tls_key_path(l),
        acme_account_path(l),
        cf_token_path(l),
        acme_state_path(l),
        l.vault_path(),
        pm_vault::store::backup_path(&l.vault_path()),
        l.data_dir.join("tokens.json"),
    ]
}

fn write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    pm_platform::paths::write_atomic(path, data, 0o600)
}

fn sealed_write(path: &Path, dk: &[u8; 32], label: &str, data: &[u8]) -> Result<(), String> {
    let blob = devseal::seal(dk, label, data).map_err(|e| e.to_string())?;
    write(path, &blob).map_err(|e| format!("写入 {} 失败：{e}", path.display()))
}

fn sealed_read(path: &Path, dk: &[u8; 32], label: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    match std::fs::read(path) {
        Ok(b) => devseal::open(dk, label, &b)
            .map(Some)
            .map_err(|_| format!("{} 无法用本机设备密钥解开（文件损坏或来自别的机器）", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("读取 {} 失败：{e}", path.display())),
    }
}

/// 生成内层通道密钥（已存在时不覆盖，返回已有的）。
pub fn ensure_server_keys(l: &Layout, dk: &[u8; 32]) -> Result<ServerKeys, String> {
    if let Some(k) = load_server_keys(l, dk)? {
        return Ok(k);
    }
    let k = ServerKeys::generate().map_err(|e| e.to_string())?;
    // 先写私钥再写公钥：断电后只会出现"有私钥没公钥"（下次重新生成），不会出现公钥对应的私钥丢失却已发给 Agent。
    sealed_write(&server_sealed_path(l), dk, LABEL_SERVER_KEYS, &k.secret_bytes())?;
    write(&server_pub_path(l), k.bundle()).map_err(|e| e.to_string())?;
    Ok(k)
}

/// 读取内层通道密钥；不存在时返回 None；文件不配套或损坏时报错。
pub fn load_server_keys(l: &Layout, dk: &[u8; 32]) -> Result<Option<ServerKeys>, String> {
    let bundle = match std::fs::read(server_pub_path(l)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let Some(secret) = sealed_read(&server_sealed_path(l), dk, LABEL_SERVER_KEYS)? else {
        return Err("内层通道私钥文件缺失".into());
    };
    ServerKeys::from_parts(&bundle, &secret).map(Some).map_err(|e| format!("内层通道密钥损坏：{e}"))
}

pub fn store_cf_token(l: &Layout, dk: &[u8; 32], token: &str) -> Result<(), String> {
    let t = token.trim();
    if t.is_empty() || t.len() > 512 || !t.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("Cloudflare token 格式无效".into());
    }
    sealed_write(&cf_token_path(l), dk, LABEL_CF, t.as_bytes())
}

pub fn load_cf_token(l: &Layout, dk: &[u8; 32]) -> Result<Option<Zeroizing<String>>, String> {
    Ok(sealed_read(&cf_token_path(l), dk, LABEL_CF)?.map(|v| Zeroizing::new(String::from_utf8_lossy(&v).into_owned())))
}

pub fn store_cert(l: &Layout, dk: &[u8; 32], chain_pem: &str, key_pem: &str) -> Result<(), String> {
    // 先写私钥再写证书：读取时两者不匹配会被 CertStore 发现（keys_match），不会装入错误组合。
    sealed_write(&tls_key_path(l), dk, LABEL_TLS_KEY, key_pem.as_bytes())?;
    write(&cert_path(l), chain_pem.as_bytes()).map_err(|e| e.to_string())
}

pub fn load_cert(l: &Layout, dk: &[u8; 32]) -> Result<Option<(String, Zeroizing<String>)>, String> {
    let chain = match std::fs::read_to_string(cert_path(l)) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let Some(key) = sealed_read(&tls_key_path(l), dk, LABEL_TLS_KEY)? else { return Ok(None) };
    Ok(Some((chain, Zeroizing::new(String::from_utf8_lossy(&key).into_owned()))))
}

pub fn store_acme_account(l: &Layout, dk: &[u8; 32], json: &str) -> Result<(), String> {
    sealed_write(&acme_account_path(l), dk, LABEL_ACME, json.as_bytes())
}

pub fn load_acme_account(l: &Layout, dk: &[u8; 32]) -> Option<Zeroizing<String>> {
    sealed_read(&acme_account_path(l), dk, LABEL_ACME).ok().flatten().map(|v| Zeroizing::new(String::from_utf8_lossy(&v).into_owned()))
}

/// 证书申请的退避状态。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcmeState {
    pub failures: u32,
    pub last_attempt: i64,
}

pub fn load_acme_state(l: &Layout) -> AcmeState {
    std::fs::read(acme_state_path(l)).ok().and_then(|d| serde_json::from_slice(&d).ok()).unwrap_or_default()
}

pub fn store_acme_state(l: &Layout, s: &AcmeState) {
    if let Ok(d) = serde_json::to_vec(s) {
        let _ = write(&acme_state_path(l), &d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(dir: &Path) -> Layout {
        Layout { mode: pm_platform::Mode::User, data_dir: dir.join("data"), run_dir: dir.join("run"), socket: dir.join("run/s") }
    }

    #[test]
    fn server_keys_are_generated_once_and_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let l = layout(dir.path());
        let dk = [3u8; 32];
        assert!(load_server_keys(&l, &dk).unwrap().is_none());
        let k1 = ensure_server_keys(&l, &dk).unwrap();
        let k2 = ensure_server_keys(&l, &dk).unwrap();
        assert_eq!(k1.fingerprint(), k2.fingerprint(), "不重复生成");
        assert!(load_server_keys(&l, &[4u8; 32]).is_err(), "别的设备密钥解不开");
        // 私钥文件里没有明文（与公钥包里的任何 64 字节都不同，且有 devseal 魔数）。
        let sealed = std::fs::read(server_sealed_path(&l)).unwrap();
        assert!(sealed.starts_with(pm_crypto::devseal::MAGIC));
        // 私钥丢失：报错而不是悄悄重新生成（重新生成会让所有 Agent 的指纹失效）。
        std::fs::remove_file(server_sealed_path(&l)).unwrap();
        assert!(load_server_keys(&l, &dk).is_err());
        assert!(ensure_server_keys(&l, &dk).is_err());
        // 半写的公钥包：报错。
        std::fs::write(server_pub_path(&l), b"PMK1").unwrap();
        assert!(load_server_keys(&l, &dk).is_err());
    }

    #[test]
    fn sealed_secrets_roundtrip_and_validation() {
        let dir = tempfile::tempdir().unwrap();
        let l = layout(dir.path());
        let dk = [5u8; 32];
        assert!(load_cf_token(&l, &dk).unwrap().is_none());
        assert!(store_cf_token(&l, &dk, "").is_err());
        assert!(store_cf_token(&l, &dk, "a b").is_err());
        store_cf_token(&l, &dk, "  cf-token-123\n").unwrap();
        assert_eq!(load_cf_token(&l, &dk).unwrap().unwrap().as_str(), "cf-token-123");
        assert!(!std::fs::read(cf_token_path(&l)).unwrap().windows(9).any(|w| w == b"cf-token-"));
        assert!(load_cf_token(&l, &[6u8; 32]).is_err());
        let (c, k) = pm_net::tls::self_signed(&["pm.test"]);
        assert!(load_cert(&l, &dk).unwrap().is_none());
        store_cert(&l, &dk, &c, &k).unwrap();
        let (c2, k2) = load_cert(&l, &dk).unwrap().unwrap();
        assert_eq!((c2.as_str(), k2.as_str()), (c.as_str(), k.as_str()));
        assert!(!std::fs::read(tls_key_path(&l)).unwrap().windows(11).any(|w| w == b"PRIVATE KEY"));
        assert_eq!(load_acme_state(&l), AcmeState::default());
        store_acme_state(&l, &AcmeState { failures: 2, last_attempt: 9 });
        assert_eq!(load_acme_state(&l).failures, 2);
        std::fs::write(acme_state_path(&l), b"{half").unwrap();
        assert_eq!(load_acme_state(&l), AcmeState::default(), "半写的状态文件按默认值处理");
        assert!(load_acme_account(&l, &dk).is_none());
        store_acme_account(&l, &dk, "{}").unwrap();
        assert_eq!(load_acme_account(&l, &dk).unwrap().as_str(), "{}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [cf_token_path(&l), tls_key_path(&l), cert_path(&l)] {
                assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{}", p.display());
            }
        }
    }
}

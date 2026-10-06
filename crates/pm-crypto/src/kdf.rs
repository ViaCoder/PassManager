//! Argon2id 口令 KDF。

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::CryptoError;

/// 安全下限：内存 256 MiB、迭代 2 次。
pub const MIN_M_KIB: u32 = 256 * 1024;
pub const MIN_T: u32 = 2;
/// 默认：1 GiB、t=3、p=4。
pub const DEFAULT_M_KIB: u32 = 1024 * 1024;
pub const DEFAULT_T: u32 = 3;
pub const DEFAULT_P: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { m_kib: DEFAULT_M_KIB, t: DEFAULT_T, p: DEFAULT_P }
    }
}

/// 仅调试构建、且设置了 `PASSMANAGER_INSECURE_TEST_KDF=1` 时，才允许低于下限的参数（测试用）。
pub fn insecure_test_mode() -> bool {
    cfg!(debug_assertions) && std::env::var("PASSMANAGER_INSECURE_TEST_KDF").as_deref() == Ok("1")
}

/// 测试模式使用的极小参数。
pub const TEST_PARAMS: KdfParams = KdfParams { m_kib: 64, t: 1, p: 1 };

impl KdfParams {
    pub fn check_floor(&self) -> Result<(), CryptoError> {
        if insecure_test_mode() {
            return Ok(());
        }
        if self.m_kib < MIN_M_KIB || self.t < MIN_T || self.p == 0 || self.p > 64 {
            return Err(CryptoError::WeakKdf);
        }
        Ok(())
    }
}

/// 口令规范化：Unicode NFKC。
pub fn normalize_password(pw: &str) -> Zeroizing<String> {
    Zeroizing::new(pw.nfkc().collect())
}

/// Argon2id(NFKC(password), salt) → 32 字节。
pub fn derive(password: &str, salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    params.check_floor()?;
    let pw = normalize_password(password);
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| CryptoError::Invalid("argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(pw.as_bytes(), salt, out.as_mut()).map_err(|_| CryptoError::Internal("argon2 failed"))?;
    Ok(out)
}

/// 总物理内存（KiB），无法获取时返回 None。
fn total_memory_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                return rest.trim().trim_end_matches("kB").trim().parse().ok();
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// 按本机性能校准：内存按物理内存选择（1 GiB / 512 MiB / 256 MiB），
/// 然后增加迭代次数直到单次耗时 ≥ 1 秒（t 最多 10）。
pub fn calibrate() -> Result<(KdfParams, Duration), CryptoError> {
    if insecure_test_mode() {
        return Ok((TEST_PARAMS, Duration::from_millis(1)));
    }
    let m_kib = match total_memory_kib() {
        Some(total) if total < 2 * 1024 * 1024 => MIN_M_KIB,
        Some(total) if total < 4 * 1024 * 1024 => 512 * 1024,
        _ => DEFAULT_M_KIB,
    };
    let mut params = KdfParams { m_kib, t: DEFAULT_T, p: DEFAULT_P };
    loop {
        let start = Instant::now();
        derive("calibration", b"pm/calibration/salt", params)?;
        let took = start.elapsed();
        if took >= Duration::from_secs(1) || params.t >= 10 {
            return Ok((params, took));
        }
        params.t += 1;
    }
}

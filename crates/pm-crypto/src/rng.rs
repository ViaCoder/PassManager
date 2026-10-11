//! 双源随机数生成器。
//!
//! 源 1：操作系统 CSPRNG（`getrandom`）。
//! 源 2：AWS-LC 的 CTR-DRBG（`aws_lc_rs::rand::SystemRandom`）。
//!
//! 每次调用都实时读取两个源各 64 字节，再用 HKDF-SHA512 组合扩展：
//! `out = HKDF-SHA512(salt = "pm/rng/v1" ‖ counter, ikm = r1 ‖ r2)`。
//! 只要任一源可靠，输出即安全。不缓存内部状态，因此天然 fork 安全。
//!
//! 健康检测（失败即 fail-closed，此后所有调用都返回错误）：
//! - 启动：对每个源采样 4 KiB，做 SP 800-90B 重复计数测试（RCT）与自适应比例测试（APT），
//!   并拒绝全零、两源相同的输出。
//! - 连续：每次调用比较各源本次与上次输出的前 16 字节，以及两源之间是否相同。
//!
//! 可选的第三个源：TPM 2.0（`TPM2_GetRandom`，见 [`crate::tpm`]）。启动健康检测时自动探测
//! `/dev/tpmrm0`，能打开且 1 KiB 样本通过同样的 RCT/APT 检测才启用；之后每次调用额外读取 32 字节并入 IKM。
//! TPM 只是"加分项"：不存在、不可访问、命令失败或连续检测失败时**永久停用这个源**并继续用另外两个源，
//! 不会让整个 RNG 失败（getrandom 与 AWS-LC 仍然 fail-closed）。
//! 优先使用配置的 swtpm 套接字（`PASSMANAGER_TPM_SOCKET`，每次调用新建连接），其次内核设备。
//! 环境变量：`PASSMANAGER_TPM_RNG=0` 关闭探测；`PASSMANAGER_TPM_SOCKET` / `PASSMANAGER_TPM_DEVICE` 指定路径。

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;
use crate::hkdf::hkdf_sha512;

const SAMPLE: usize = 64;
const CHUNK: usize = 8192;
const TPM_SAMPLE: usize = 32;
/// 启用 TPM 源之前做健康检测的样本大小（每次 GetRandom 最多 32 字节，1 KiB 约 32 次调用）。
const TPM_HEALTH_SAMPLE: usize = 1024;

static FAILED: AtomicBool = AtomicBool::new(false);
static COUNTER: AtomicU64 = AtomicU64::new(0);
static LAST: Mutex<Option<([u8; 16], [u8; 16])>> = Mutex::new(None);
static TPM: Mutex<TpmSource> = Mutex::new(TpmSource { dev: None, last: None, status: TpmStatus::NotProbed });

/// TPM 随机数源的状态（安全状态页显示）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmStatus {
    /// 还没有探测（启动健康检测之前）。
    NotProbed,
    /// 没有可用的 TPM 设备（或被环境变量关闭）。
    Absent,
    /// 已通过健康检测并参与组合。
    Active,
    /// 健康检测或运行中出错，已永久停用。
    Disabled(&'static str),
}

struct TpmSource {
    dev: Option<Box<dyn crate::tpm::Device>>,
    last: Option<[u8; 16]>,
    status: TpmStatus,
}

impl TpmSource {
    fn disable(&mut self, why: &'static str) {
        self.dev = None;
        self.last = None;
        self.status = TpmStatus::Disabled(why);
    }
}

/// 当前 TPM 源的状态。
pub fn tpm_status() -> TpmStatus {
    TPM.lock().map(|t| t.status).unwrap_or(TpmStatus::Disabled("rng state poisoned"))
}

/// 对给定的 TPM 设备做健康检测，通过后作为第三个源启用。失败时永久停用并返回原因。
pub fn enable_tpm_device(mut dev: Box<dyn crate::tpm::Device>) -> Result<(), &'static str> {
    let mut sample = Zeroizing::new(vec![0u8; TPM_HEALTH_SAMPLE]);
    let r = crate::tpm::get_random(dev.as_mut(), &mut sample).and_then(|_| check_source(&sample));
    let mut t = TPM.lock().map_err(|_| "rng state poisoned")?;
    match r {
        Ok(()) => {
            t.dev = Some(dev);
            t.last = None;
            t.status = TpmStatus::Active;
            Ok(())
        }
        Err(why) => {
            t.disable(why);
            Err(why)
        }
    }
}

/// 探测默认的 TPM 设备（只做一次）。
fn probe_tpm() {
    {
        let Ok(t) = TPM.lock() else { return };
        if t.status != TpmStatus::NotProbed {
            return;
        }
    }
    let off = std::env::var("PASSMANAGER_TPM_RNG").is_ok_and(|v| v == "0");
    // 配置的 swtpm 套接字（服务单元通过 PASSMANAGER_TPM_SOCKET 传入，没有默认路径）优先，其次内核设备。
    #[cfg(unix)]
    let sock: Option<Box<dyn crate::tpm::Device>> = std::env::var_os("PASSMANAGER_TPM_SOCKET")
        .filter(|v| !v.is_empty())
        .and_then(|p| crate::tpm::SockDev::open(std::path::Path::new(&p)).ok())
        .map(|d| Box::new(d) as Box<dyn crate::tpm::Device>);
    #[cfg(not(unix))]
    let sock: Option<Box<dyn crate::tpm::Device>> = None;
    let path =
        std::env::var_os("PASSMANAGER_TPM_DEVICE").map(std::path::PathBuf::from).unwrap_or_else(|| crate::tpm::DEFAULT_DEVICE.into());
    let dev = sock.or_else(|| crate::tpm::DevFile::open(&path).ok().map(|d| Box::new(d) as Box<dyn crate::tpm::Device>));
    match dev {
        Some(d) if !off => {
            let _ = enable_tpm_device(d);
        }
        _ => {
            if let Ok(mut t) = TPM.lock() {
                t.status = TpmStatus::Absent;
            }
        }
    }
}

/// 从 TPM 源取 32 字节（未启用或出错时返回 false；出错会永久停用该源）。
fn source_tpm(buf: &mut [u8; TPM_SAMPLE]) -> bool {
    let Ok(mut t) = TPM.lock() else { return false };
    let Some(dev) = t.dev.as_mut() else { return false };
    if crate::tpm::get_random(dev.as_mut(), buf).is_err() {
        t.disable("TPM command failed");
        return false;
    }
    let mut head = [0u8; 16];
    head.copy_from_slice(&buf[..16]);
    if t.last == Some(head) {
        t.disable("TPM repeated its previous output (stuck)");
        return false;
    }
    t.last = Some(head);
    head.zeroize();
    true
}

/// 测试钩子：注入"卡死"源，用于验证 fail-closed。
#[cfg(any(test, feature = "test-hooks"))]
pub static STUCK_SOURCE_FOR_TEST: AtomicBool = AtomicBool::new(false);

fn source_os(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::RngFailure("getrandom failed"))?;
    #[cfg(any(test, feature = "test-hooks"))]
    if STUCK_SOURCE_FOR_TEST.load(Ordering::SeqCst) {
        buf.fill(0x5a);
    }
    Ok(())
}

fn source_awslc(buf: &mut [u8]) -> Result<(), CryptoError> {
    SystemRandom::new().fill(buf).map_err(|_| CryptoError::RngFailure("aws-lc DRBG failed"))
}

fn fail(reason: &'static str) -> CryptoError {
    FAILED.store(true, Ordering::SeqCst);
    CryptoError::RngFailure(reason)
}

/// 用组合随机数填充 `out`。
pub fn fill(out: &mut [u8]) -> Result<(), CryptoError> {
    if FAILED.load(Ordering::SeqCst) {
        return Err(CryptoError::RngFailure("RNG previously failed a health test"));
    }
    for chunk in out.chunks_mut(CHUNK) {
        let mut ikm = Zeroizing::new([0u8; 2 * SAMPLE + TPM_SAMPLE]);
        let (r12, r3) = ikm.split_at_mut(2 * SAMPLE);
        let (r1, r2) = r12.split_at_mut(SAMPLE);
        source_os(r1)?;
        source_awslc(r2)?;
        continuous_test(r1, r2)?;
        let mut tpm = Zeroizing::new([0u8; TPM_SAMPLE]);
        let used = if source_tpm(&mut tpm) {
            r3.copy_from_slice(tpm.as_ref());
            ikm.len()
        } else {
            2 * SAMPLE
        };
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut salt = b"pm/rng/v1".to_vec();
        salt.extend_from_slice(&counter.to_be_bytes());
        hkdf_sha512(&salt, &ikm[..used], &[b"out"], chunk)?;
    }
    Ok(())
}

/// 生成定长随机数组。
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut a = [0u8; N];
    fill(&mut a)?;
    Ok(a)
}

fn continuous_test(r1: &[u8], r2: &[u8]) -> Result<(), CryptoError> {
    if r1 == r2 {
        return Err(fail("two sources returned identical output"));
    }
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&r1[..16]);
    b.copy_from_slice(&r2[..16]);
    let mut last = LAST.lock().map_err(|_| fail("rng state poisoned"))?;
    if let Some((pa, pb)) = last.as_ref()
        && (*pa == a || *pb == b)
    {
        return Err(fail("a source repeated its previous output (stuck)"));
    }
    *last = Some((a, b));
    a.zeroize();
    b.zeroize();
    Ok(())
}

/// SP 800-90B 重复计数测试。按"每字节 8 bit 熵"、误报率 2^-40 计算，截断值 C = 1 + ⌈40/8⌉ = 6。
fn repetition_count_test(data: &[u8]) -> bool {
    const C: usize = 6;
    let mut run = 1;
    for w in data.windows(2) {
        if w[0] == w[1] {
            run += 1;
            if run >= C {
                return false;
            }
        } else {
            run = 1;
        }
    }
    true
}

/// SP 800-90B 自适应比例测试（非二元，窗口 512）。截断值 20（满熵下误报率约 2^-44）。
fn adaptive_proportion_test(data: &[u8]) -> bool {
    const W: usize = 512;
    const CUTOFF: usize = 20;
    for window in data.chunks(W) {
        let first = window[0];
        if window.iter().filter(|&&x| x == first).count() >= CUTOFF {
            return false;
        }
    }
    true
}

fn check_source(data: &[u8]) -> Result<(), &'static str> {
    if data.iter().all(|&b| b == 0) || data.iter().all(|&b| b == 0xff) {
        return Err("source returned constant output");
    }
    if !repetition_count_test(data) {
        return Err("repetition count test failed");
    }
    if !adaptive_proportion_test(data) {
        return Err("adaptive proportion test failed");
    }
    Ok(())
}

/// 启动健康检测。必须在任何密钥生成之前调用。
pub fn startup_health_test() -> Result<(), CryptoError> {
    let mut a = Zeroizing::new(vec![0u8; 4096]);
    let mut b = Zeroizing::new(vec![0u8; 4096]);
    source_os(&mut a)?;
    source_awslc(&mut b)?;
    check_source(&a).map_err(fail)?;
    check_source(&b).map_err(fail)?;
    if a.as_slice() == b.as_slice() {
        return Err(fail("two sources returned identical output"));
    }
    // 再走一遍组合路径，触发连续测试。
    let mut probe = [0u8; 64];
    fill(&mut probe)?;
    fill(&mut probe)?;
    check_source(&probe).map_err(fail)?;
    // 可选的 TPM 源：失败只停用它自己。
    probe_tpm();
    Ok(())
}

/// 当前 RNG 是否处于失败状态。
pub fn is_failed() -> bool {
    FAILED.load(Ordering::SeqCst)
}

/// 测试钩子：清除失败状态。
#[cfg(any(test, feature = "test-hooks"))]
pub fn reset_for_test() {
    FAILED.store(false, Ordering::SeqCst);
    *LAST.lock().unwrap() = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_tests_detect_bad_data() {
        assert!(check_source(&[0u8; 4096]).is_err());
        let mut runs = vec![0u8; 4096];
        for (i, b) in runs.iter_mut().enumerate() {
            *b = (i / 8) as u8;
        }
        assert!(check_source(&runs).is_err());
        let mut biased = vec![0u8; 4096];
        for (i, b) in biased.iter_mut().enumerate() {
            *b = if i % 3 == 0 { 7 } else { (i * 37 % 251) as u8 };
        }
        assert!(!adaptive_proportion_test(&biased));
    }
}

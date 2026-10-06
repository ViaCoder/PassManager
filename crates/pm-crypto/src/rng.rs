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

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;
use crate::hkdf::hkdf_sha512;

const SAMPLE: usize = 64;
const CHUNK: usize = 8192;

static FAILED: AtomicBool = AtomicBool::new(false);
static COUNTER: AtomicU64 = AtomicU64::new(0);
static LAST: Mutex<Option<([u8; 16], [u8; 16])>> = Mutex::new(None);

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
        let mut ikm = Zeroizing::new([0u8; 2 * SAMPLE]);
        let (r1, r2) = ikm.split_at_mut(SAMPLE);
        source_os(r1)?;
        source_awslc(r2)?;
        continuous_test(r1, r2)?;
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut salt = b"pm/rng/v1".to_vec();
        salt.extend_from_slice(&counter.to_be_bytes());
        hkdf_sha512(&salt, ikm.as_ref(), &[b"out"], chunk)?;
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

//! 单独的测试进程：TPM 随机数源的启用、健康检测失败与运行中停用（不影响组合 RNG 本身）。
use std::io;

use pm_crypto::rng::{self, TpmStatus};
use pm_crypto::tpm::{self, Device};

fn response(bytes: &[u8]) -> Vec<u8> {
    let mut r = vec![0x80, 0x01];
    r.extend_from_slice(&((12 + bytes.len()) as u32).to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    r.extend_from_slice(bytes);
    r
}

/// 正常的设备：返回操作系统随机数；`stuck_after` 次调用之后一直返回同一段数据；`fail_after` 之后 I/O 失败。
struct FakeTpm {
    calls: usize,
    stuck_after: usize,
    fail_after: usize,
}

impl Device for FakeTpm {
    fn transact(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        self.calls += 1;
        assert_eq!(&cmd[..10], &tpm::encode_get_random(0)[..10], "GetRandom command header");
        let n = u16::from_be_bytes([cmd[10], cmd[11]]) as usize;
        if self.calls > self.fail_after {
            return Err(io::Error::other("device removed"));
        }
        let mut b = vec![0u8; n];
        if self.calls > self.stuck_after {
            b.fill(0x42);
            b[0] = 1;
        } else {
            getrandom::fill(&mut b).unwrap();
        }
        Ok(response(&b))
    }
}

#[test]
fn tpm_source_lifecycle() {
    // 没有设备：探测结果为 Absent，RNG 照常工作。
    // SAFETY: 测试进程内设置环境变量（其余测试不依赖它）。
    unsafe {
        std::env::set_var("PASSMANAGER_TPM_DEVICE", "/nonexistent/tpmrm0");
        std::env::set_var("PASSMANAGER_TPM_SOCKET", "/nonexistent/tpm.sock");
    }
    rng::startup_health_test().unwrap();
    assert_eq!(rng::tpm_status(), TpmStatus::Absent);

    // 健康检测不通过（常量输出）：拒绝启用，状态为 Disabled，RNG 不受影响。
    let r = rng::enable_tpm_device(Box::new(FakeTpm { calls: 0, stuck_after: 0, fail_after: usize::MAX }));
    assert!(r.is_err());
    assert!(matches!(rng::tpm_status(), TpmStatus::Disabled(_)));
    let mut b = [0u8; 64];
    rng::fill(&mut b).unwrap();

    // 正常设备：启用并参与组合（每次 fill 都会调用设备）。
    rng::enable_tpm_device(Box::new(FakeTpm { calls: 0, stuck_after: usize::MAX, fail_after: usize::MAX })).unwrap();
    assert_eq!(rng::tpm_status(), TpmStatus::Active);
    let mut a = [0u8; 64];
    rng::fill(&mut a).unwrap();
    rng::fill(&mut b).unwrap();
    assert_ne!(a, b);

    // 运行中卡死：连续检测发现后永久停用 TPM 源，组合 RNG 继续正常输出（不 fail-closed）。
    rng::enable_tpm_device(Box::new(FakeTpm { calls: 0, stuck_after: 34, fail_after: usize::MAX })).unwrap();
    for _ in 0..4 {
        rng::fill(&mut a).unwrap();
    }
    assert_eq!(rng::tpm_status(), TpmStatus::Disabled("TPM repeated its previous output (stuck)"));
    rng::fill(&mut a).unwrap();
    assert!(!rng::is_failed());

    // 运行中设备消失：同样只停用 TPM 源。
    rng::enable_tpm_device(Box::new(FakeTpm { calls: 0, stuck_after: usize::MAX, fail_after: 33 })).unwrap();
    rng::fill(&mut a).unwrap();
    rng::fill(&mut a).unwrap();
    assert_eq!(rng::tpm_status(), TpmStatus::Disabled("TPM command failed"));
    rng::fill(&mut a).unwrap();
    assert!(!rng::is_failed());

    // 套接字形式的 TPM（swtpm）。
    #[cfg(unix)]
    {
        socket_device_step();
        assert_eq!(rng::tpm_status(), TpmStatus::Active);
        rng::fill(&mut a).unwrap();
    }
}

/// swtpm 套接字设备：经套接字收发 TPM2_GetRandom（每次新连接），通过健康检测后作为源启用。
#[cfg(unix)]
fn socket_device_step() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir().join(format!("pm-rng-sock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tpm.sock");
    let l = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { break };
            let mut cmd = [0u8; 12];
            if c.read_exact(&mut cmd).is_err() {
                continue;
            }
            let n = u16::from_be_bytes([cmd[10], cmd[11]]) as usize;
            let mut b = vec![0u8; n];
            getrandom::fill(&mut b).unwrap();
            let _ = c.write_all(&response(&b));
        }
    });
    let dev = tpm::SockDev::open(&path).unwrap();
    assert!(rng::enable_tpm_device(Box::new(dev)).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

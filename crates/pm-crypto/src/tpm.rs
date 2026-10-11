//! TPM 2.0 随机数源：直接向 `/dev/tpmrm0`（内核资源管理器）发送 `TPM2_GetRandom`。
//!
//! 只作为组合 RNG 的第三个、可选的源：设备不存在、不可访问、命令失败或健康检测不通过时自动跳过，
//! 不影响启动（另外两个源仍按原设计 fail-closed）。
//!
//! 命令格式（TPM 2.0 Part 3, §16.1，无会话）：
//! ```text
//! tag u16 = TPM_ST_NO_SESSIONS(0x8001) | commandSize u32 = 12 | commandCode u32 = TPM_CC_GetRandom(0x17B) | bytesRequested u16
//! ```
//! 响应：
//! ```text
//! tag u16 = 0x8001 | responseSize u32 | responseCode u32 (0 = 成功) | TPM2B_DIGEST { size u16 | bytes }
//! ```

use std::io::{self, Read, Write};
use std::path::Path;

pub const DEFAULT_DEVICE: &str = "/dev/tpmrm0";
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
/// 一次请求的字节数：TPM2B_DIGEST 的上限取决于 TPM 支持的最长摘要（通常 32/48/64），这里只请求 32。
pub const CHUNK: u16 = 32;

/// 编码一条 `TPM2_GetRandom` 命令。
pub fn encode_get_random(n: u16) -> [u8; 12] {
    let mut c = [0u8; 12];
    c[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c[2..6].copy_from_slice(&12u32.to_be_bytes());
    c[6..10].copy_from_slice(&TPM_CC_GET_RANDOM.to_be_bytes());
    c[10..12].copy_from_slice(&n.to_be_bytes());
    c
}

/// 解析 `TPM2_GetRandom` 的响应，返回随机字节。任何字段不符合规范都视为失败。
pub fn parse_get_random(resp: &[u8], requested: u16) -> Result<&[u8], &'static str> {
    if resp.len() < 10 {
        return Err("TPM response too short");
    }
    let tag = u16::from_be_bytes([resp[0], resp[1]]);
    let size = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    if size != resp.len() {
        return Err("TPM response size mismatch");
    }
    if rc != 0 {
        return Err("TPM returned an error code");
    }
    if tag != TPM_ST_NO_SESSIONS {
        return Err("unexpected TPM response tag");
    }
    if resp.len() < 12 {
        return Err("TPM response too short");
    }
    let n = u16::from_be_bytes([resp[10], resp[11]]) as usize;
    if n == 0 || n > requested as usize {
        return Err("TPM returned an invalid number of bytes");
    }
    if resp.len() != 12 + n {
        return Err("TPM response length mismatch");
    }
    Ok(&resp[12..])
}

/// 可以收发 TPM 命令的设备（真实设备或测试替身）。
pub trait Device: Send {
    fn transact(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>>;
}

/// `/dev/tpmrm0`：一次 write 一条命令，一次 read 一条响应。
pub struct DevFile(std::fs::File);

impl DevFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self(std::fs::OpenOptions::new().read(true).write(true).open(path)?))
    }
}

impl Device for DevFile {
    fn transact(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        self.0.write_all(cmd)?;
        let mut buf = vec![0u8; 4096];
        let n = self.0.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// swtpm 的 Unix 数据套接字（unixio，例如宿主机为容器提供的软件 TPM）：直接收发原始 TPM 命令。
/// 每次调用新建连接、用完即关（swtpm 同一时间只服务一个连接，不能长期占用，否则会阻塞 systemd-creds）。
#[cfg(unix)]
pub struct SockDev(std::path::PathBuf);

#[cfg(unix)]
impl SockDev {
    /// 路径必须是 Unix 套接字。
    pub fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::FileTypeExt;
        if !std::fs::metadata(path)?.file_type().is_socket() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a socket"));
        }
        Ok(Self(path.to_path_buf()))
    }
}

#[cfg(unix)]
impl Device for SockDev {
    fn transact(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        let mut s = std::os::unix::net::UnixStream::connect(&self.0)?;
        let t = Some(std::time::Duration::from_secs(2));
        s.set_read_timeout(t)?;
        s.set_write_timeout(t)?;
        s.write_all(cmd)?;
        // 先读 10 字节响应头，再按 responseSize 读完。
        let mut head = [0u8; 10];
        s.read_exact(&mut head)?;
        let size = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as usize;
        if !(10..=4096).contains(&size) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad TPM response size"));
        }
        let mut rest = vec![0u8; size - 10];
        s.read_exact(&mut rest)?;
        let mut out = head.to_vec();
        out.extend_from_slice(&rest);
        Ok(out)
    }
}

/// 用 `TPM2_GetRandom` 填满 `out`（每次最多 [`CHUNK`] 字节）。
pub fn get_random(dev: &mut dyn Device, out: &mut [u8]) -> Result<(), &'static str> {
    // 每次成功的响应至少带回 1 字节（见 parse_get_random），因此循环必然结束。
    let mut filled = 0;
    while filled < out.len() {
        let want = (out.len() - filled).min(CHUNK as usize) as u16;
        let resp = dev.transact(&encode_get_random(want)).map_err(|_| "TPM device I/O failed")?;
        let bytes = parse_get_random(&resp, want)?;
        out[filled..filled + bytes.len()].copy_from_slice(bytes);
        filled += bytes.len();
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 测试替身：按脚本返回响应，记录收到的命令。
    pub struct Fake {
        pub responses: std::collections::VecDeque<io::Result<Vec<u8>>>,
        pub seen: Vec<Vec<u8>>,
    }

    impl Device for Fake {
        fn transact(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
            self.seen.push(cmd.to_vec());
            self.responses.pop_front().unwrap_or_else(|| Err(io::Error::other("no more responses")))
        }
    }

    pub fn ok_response(bytes: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        r.extend_from_slice(&((12 + bytes.len()) as u32).to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        r.extend_from_slice(bytes);
        r
    }

    #[test]
    fn command_encoding_matches_spec() {
        assert_eq!(encode_get_random(32), [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7b, 0, 32]);
        assert_eq!(encode_get_random(0x0102)[10..], [1, 2]);
    }

    #[test]
    fn response_parsing_accepts_only_well_formed_success() {
        let good = ok_response(&[7u8; 32]);
        assert_eq!(parse_get_random(&good, 32).unwrap(), &[7u8; 32]);
        // 返回少于请求的字节数是允许的。
        assert_eq!(parse_get_random(&ok_response(&[1, 2, 3]), 32).unwrap(), &[1, 2, 3]);
        // 截断、长度字段不符、错误码、错误 tag、多余数据、零字节、超过请求量都拒绝。
        assert!(parse_get_random(&good[..9], 32).is_err());
        assert!(parse_get_random(&good[..good.len() - 1], 32).is_err());
        let mut rc = good.clone();
        rc[9] = 0x01;
        assert_eq!(parse_get_random(&rc, 32), Err("TPM returned an error code"));
        // 错误码响应只有 10 字节（没有 TPM2B）。
        let mut short_err = vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x09, 0x22];
        assert_eq!(parse_get_random(&short_err, 32), Err("TPM returned an error code"));
        short_err[9] = 0;
        assert!(parse_get_random(&short_err, 32).is_err());
        let mut tag = good.clone();
        tag[1] = 0x02;
        assert!(parse_get_random(&tag, 32).is_err());
        let mut extra = good.clone();
        extra.push(0);
        assert!(parse_get_random(&extra, 32).is_err());
        assert!(parse_get_random(&ok_response(&[]), 32).is_err());
        assert!(parse_get_random(&ok_response(&[1u8; 33]), 32).is_err());
        let mut lying = ok_response(&[1u8; 32]);
        lying[11] = 31;
        assert!(parse_get_random(&lying, 32).is_err());
    }

    #[test]
    fn get_random_loops_over_short_reads_and_reports_errors() {
        let mut f =
            Fake { responses: [ok_response(&[1u8; 16]), ok_response(&[2u8; 32]), ok_response(&[3u8; 16])].map(Ok).into(), seen: vec![] };
        let mut out = [0u8; 64];
        get_random(&mut f, &mut out).unwrap();
        assert_eq!(&out[..16], &[1u8; 16]);
        assert_eq!(&out[16..48], &[2u8; 32]);
        assert_eq!(&out[48..], &[3u8; 16]);
        assert_eq!(f.seen[0], encode_get_random(32));
        assert_eq!(f.seen[2], encode_get_random(16), "最后只请求剩余字节");
        let mut f = Fake { responses: [Err(io::Error::other("gone"))].into(), seen: vec![] };
        assert!(get_random(&mut f, &mut out).is_err());
        // 设备每次只给 1 字节：逐次补齐。
        let mut f = Fake { responses: (0..8).map(|_| Ok(ok_response(&[9]))).collect(), seen: vec![] };
        let mut small = [0u8; 8];
        get_random(&mut f, &mut small).unwrap();
        assert_eq!(small, [9u8; 8]);
        assert_eq!(f.seen.len(), 8);
    }

    #[test]
    #[cfg(unix)]
    fn missing_device_is_an_error_not_a_panic() {
        assert!(DevFile::open(Path::new("/nonexistent/tpmrm0")).is_err());
        assert!(SockDev::open(Path::new("/nonexistent/tpm.sock")).is_err());
        let f = std::env::temp_dir().join(format!("pm-notsock-{}", std::process::id()));
        std::fs::write(&f, b"").unwrap();
        assert!(SockDev::open(&f).is_err(), "普通文件不是套接字");
        let _ = std::fs::remove_file(&f);
    }

    /// 模拟 swtpm 的数据套接字：每个连接收一条命令、回一条响应；每次调用都是新连接。
    #[test]
    #[cfg(unix)]
    fn socket_device_speaks_raw_tpm_commands() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("pm-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tpm.sock");
        let l = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let mut n = 0;
            for c in l.incoming().take(3) {
                let mut c = c.unwrap();
                let mut cmd = [0u8; 12];
                c.read_exact(&mut cmd).unwrap();
                assert_eq!(cmd[..10], encode_get_random(0)[..10]);
                n += 1;
                if n == 3 {
                    c.write_all(&[0x80, 0x01, 0, 0, 0x10, 0]).unwrap(); // 响应长度字段荒谬（4 KiB 以上）
                } else {
                    c.write_all(&ok_response(&[n as u8; 32])).unwrap();
                }
            }
        });
        let mut d = SockDev::open(&path).unwrap();
        let mut out = [0u8; 64];
        get_random(&mut d, &mut out).unwrap();
        assert_eq!(&out[..32], &[1u8; 32]);
        assert_eq!(&out[32..], &[2u8; 32]);
        assert!(get_random(&mut d, &mut out).is_err());
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! 网页上传的二维码图片交给子进程解码（原因见 `pm_otp::qr`：解码库 panic 时服务器以 abort 退出，所以不在服务进程里解码）。
//!
//! 子进程是同一个程序的 `qr-decode` 子命令：清空环境变量，标准输入写入图片，标准输出读回 JSON，标准错误丢弃。
//! 子进程自己限制内存与 CPU 时间；这里另有 20 秒的总超时，超时或出错都杀掉子进程。

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

/// 一张图片的总超时。
const TIMEOUT: Duration = Duration::from_secs(20);

/// 子进程用的程序：Linux 上用 /proc/self/exe（部署时程序文件被 mv 替换后，它仍指向正在运行的这一版），其他系统用当前路径。
pub fn exe() -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from("/proc/self/exe")
    } else {
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("PassManager"))
    }
}

/// 用 `exe` 的 `qr-decode` 子命令解码一张图片。
pub async fn decode(exe: PathBuf, image: Zeroizing<Vec<u8>>) -> Result<Vec<Zeroizing<String>>, String> {
    decode_within(exe, image, TIMEOUT).await
}

/// 同 [`decode`]，超时可调（测试用较短的超时）。
async fn decode_within(exe: PathBuf, image: Zeroizing<Vec<u8>>, timeout: Duration) -> Result<Vec<Zeroizing<String>>, String> {
    let mut child = tokio::process::Command::new(exe)
        .arg("qr-decode")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "无法启动解码进程".to_string())?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.start_kill();
        return Err("无法启动解码进程".into());
    };
    let run = async {
        // 一边写图片一边读结果（避免管道写满时互相等待）
        let write = async {
            let _ = stdin.write_all(&image).await;
            // 关闭标准输入，子进程才知道图片读完了
            drop(stdin);
        };
        let read = async {
            let mut out = Zeroizing::new(Vec::new());
            let _ = stdout.take(pm_otp::qr::MAX_CHILD_OUTPUT as u64 + 1).read_to_end(&mut out).await;
            out
        };
        let ((), out) = tokio::join!(write, read);
        (child.wait().await, out)
    };
    let r = tokio::time::timeout(timeout, run).await;
    match r {
        // 正常退出：解析输出（里面可能是解码出的文本，也可能是原因）
        Ok((Ok(status), out)) if status.success() => pm_otp::qr::parse_child_output(&out),
        // 子进程崩溃、被上限杀掉
        Ok(_) => Err("图片无法解码".into()),
        // 超时：future 已丢弃，child 随之被杀（kill_on_drop）
        Err(_) => Err("解码超时".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_points_at_running_program() {
        if cfg!(target_os = "linux") {
            assert_eq!(exe(), PathBuf::from("/proc/self/exe"));
        }
    }

    /// 测试程序本身没有 qr-decode 子命令：用一个假程序代替，检查超时、崩溃与正常输出三种情况。
    #[cfg(unix)]
    #[test]
    fn decode_handles_success_crash_and_timeout() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pm-qr-child-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            p
        };
        // 把标准输入读完，输出固定的 JSON；参数必须是 qr-decode，环境变量必须已清空
        let ok = script(
            "ok",
            r#"[ "$1" = qr-decode ] || exit 9; [ -z "$HOME" ] || exit 8; cat >/dev/null; printf '{"texts":["otpauth://totp/x?secret=AAAA"]}'"#,
        );
        let crash = script("crash", "cat >/dev/null; kill -SEGV $$");
        let slow = script("slow", "exec sleep 60");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let img = || Zeroizing::new(vec![0u8; 200_000]);
        let t = rt.block_on(decode(ok, img())).unwrap();
        assert_eq!(t[0].as_str(), "otpauth://totp/x?secret=AAAA");
        assert_eq!(rt.block_on(decode(crash, img())).unwrap_err(), "图片无法解码");
        assert_eq!(rt.block_on(decode(dir.join("missing"), img())).unwrap_err(), "无法启动解码进程");
        let t0 = std::time::Instant::now();
        assert_eq!(rt.block_on(decode_within(slow, img(), Duration::from_secs(1))).unwrap_err(), "解码超时");
        assert!(t0.elapsed() < Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

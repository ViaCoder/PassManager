//! 设备密钥封存。
//!
//! | 等级 | 含义 |
//! |---|---|
//! | L3 | 硬件封存（TPM），整盘/目录被拷到别的机器上也解不开 |
//! | L2 | 操作系统封存（systemd 主机密钥 / DPAPI / macOS 系统钥匙串），必须本机 root/系统权限才能解开 |
//! | L1 | 仅文件权限保护（兜底，会持续显示警告） |

use std::io;

use zeroize::Zeroizing;

use crate::paths::{Layout, Mode};

pub mod file;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

pub type RandFn<'a> = &'a mut dyn FnMut(&mut [u8]) -> io::Result<()>;

pub trait Sealer: Send + Sync {
    /// 方法名（写入 install.json）。
    fn method(&self) -> &'static str;
    /// 安全等级 1/2/3。
    fn level(&self) -> u8;
    /// 中文说明（TUI 与诊断页显示）。
    fn describe(&self) -> String;
    fn is_provisioned(&self) -> bool;
    fn seal(&self, key: &[u8; 32], rand: RandFn) -> io::Result<()>;
    fn unseal(&self) -> io::Result<Zeroizing<[u8; 32]>>;
    fn remove(&self) -> io::Result<()>;
}

/// 安装时选择当前环境下最高等级的封存方式。
/// 返回值第二项是"为什么只能用这个等级"的说明（用于 L1 警告）。
pub fn best_available(layout: &Layout) -> (Box<dyn Sealer>, Option<String>) {
    if layout.mode == Mode::User {
        return (
            Box::new(file::FileSealer::new(layout)),
            Some("用户模式：服务与 Agent 运行在同一个系统用户下，设备密钥只能以文件形式保存。".into()),
        );
    }
    #[cfg(target_os = "linux")]
    {
        match linux::SystemdCredsSealer::probe(layout) {
            Ok(s) => (Box::new(s), None),
            Err(why) => (Box::new(file::FileSealer::new(layout)), Some(why)),
        }
    }
    #[cfg(target_os = "macos")]
    {
        (Box::new(macos::KeychainSealer::new()), None)
    }
    #[cfg(windows)]
    {
        (Box::new(windows::DpapiSealer::probe(layout)), None)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        (Box::new(file::FileSealer::new(layout)), Some("当前平台没有可用的系统级封存方式。".into()))
    }
}

/// 运行时按 install.json 中记录的方法获取封存器。
pub fn by_method(method: &str, layout: &Layout) -> Option<Box<dyn Sealer>> {
    match method {
        file::METHOD => Some(Box::new(file::FileSealer::new(layout))),
        #[cfg(target_os = "linux")]
        linux::METHOD_HOST | linux::METHOD_TPM => Some(Box::new(linux::SystemdCredsSealer::from_method(method, layout))),
        #[cfg(target_os = "macos")]
        macos::METHOD_KEYCHAIN => Some(Box::new(macos::KeychainSealer::new())),
        #[cfg(target_os = "macos")]
        macos::METHOD_ROOTFILE => Some(Box::new(macos::RootFileSealer::new())),
        #[cfg(windows)]
        windows::METHOD_DPAPI | windows::METHOD_DPAPI_TPM => Some(Box::new(windows::DpapiSealer::from_method(method, layout))),
        _ => None,
    }
}

/// 等级的中文名称。
pub fn level_label(level: u8) -> &'static str {
    match level {
        3 => "L3（硬件封存）",
        2 => "L2（系统封存）",
        _ => "L1（仅文件权限保护）",
    }
}

pub const L1_WARNING: &str = "L1：设备密钥仅受文件权限保护";

pub(crate) fn key_from_bytes(b: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    if b.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "device key has wrong length"));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(b);
    Ok(k)
}

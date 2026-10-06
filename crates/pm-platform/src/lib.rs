//! PassManager 平台层：目录布局、TTY 检测、设备密钥封存、安全检查与账户加固、进程加固。
//!
//! 本 crate 不依赖任何 C 加密库，因此可以单独为 Windows / macOS 目标做 `cargo check`。

pub mod harden;
pub mod paths;
pub mod process;
pub mod seal;
pub mod service_files;
pub mod tty;

pub use paths::{InstallInfo, Layout, Mode};

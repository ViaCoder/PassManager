//! 目录布局。
//!
//! - 系统模式（推荐）：服务以专用用户运行，数据放在 $HOME 之外。
//! - 用户模式（无管理员权限时的降级方案，L1）：服务以当前用户运行。
//! - `PASSMANAGER_HOME`：测试/开发用覆盖，所有文件放在该目录下（视为用户模式）。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const SERVICE_USER: &str = if cfg!(target_os = "macos") { "_passmanager" } else { "passmanager" };
pub const APP: &str = "PassManager";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    System,
    User,
}

#[derive(Clone, Debug)]
pub struct Layout {
    pub mode: Mode,
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
    /// Unix：socket 文件路径；Windows：命名管道名。
    pub socket: PathBuf,
}

/// 用户主目录。MCP 客户端启动子进程时环境变量可能很少，因此 Unix 上缺少 HOME 时从账户数据库读取。
fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    #[cfg(unix)]
    if let Ok(Some(u)) = nix::unistd::User::from_uid(nix::unistd::getuid()) {
        return u.dir;
    }
    PathBuf::from(".")
}

impl Layout {
    pub fn system() -> Self {
        #[cfg(target_os = "linux")]
        {
            let run = PathBuf::from("/run/passmanager");
            Self { mode: Mode::System, data_dir: "/var/lib/passmanager".into(), socket: run.join("passmanager.sock"), run_dir: run }
        }
        #[cfg(target_os = "macos")]
        {
            let run = PathBuf::from("/var/run/passmanager");
            Self {
                mode: Mode::System,
                data_dir: "/Library/Application Support/PassManager".into(),
                socket: run.join("passmanager.sock"),
                run_dir: run,
            }
        }
        #[cfg(windows)]
        {
            let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            let data = base.join(APP);
            Self { mode: Mode::System, run_dir: data.join("run"), data_dir: data, socket: PathBuf::from(r"\\.\pipe\PassManager") }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let run = PathBuf::from("/var/run/passmanager");
            Self { mode: Mode::System, data_dir: "/var/db/passmanager".into(), socket: run.join("passmanager.sock"), run_dir: run }
        }
    }

    pub fn user() -> Self {
        if let Some(h) = std::env::var_os("PASSMANAGER_HOME") {
            let h = PathBuf::from(h);
            // Windows 的本地 IPC 是命名管道，不能放在目录里：按目录路径派生一个管道名。
            #[cfg(windows)]
            let socket = PathBuf::from(format!(r"\\.\pipe\PassManager-{:016x}", fnv1a(h.to_string_lossy().as_bytes())));
            #[cfg(not(windows))]
            let socket = h.join("run").join("passmanager.sock");
            return Self { mode: Mode::User, data_dir: h.join("data"), socket, run_dir: h.join("run") };
        }
        #[cfg(windows)]
        {
            let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| home().join("AppData").join("Local"));
            let data = base.join(APP);
            // 管道名按用户 SID 生成，不依赖 USERNAME 等环境变量（MCP 客户端可能不传递它们）。
            let who = crate::process::current_user_sid().unwrap_or_else(|| std::env::var("USERNAME").unwrap_or_else(|_| "user".into()));
            Self {
                mode: Mode::User,
                run_dir: data.join("run"),
                data_dir: data,
                socket: PathBuf::from(format!(r"\\.\pipe\PassManager-{who}")),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let data = home().join("Library/Application Support/PassManager");
            Self { mode: Mode::User, run_dir: data.join("run"), socket: data.join("run").join("passmanager.sock"), data_dir: data }
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let data =
                std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".local/share")).join("passmanager");
            // socket 位置只由 uid 决定（/run/user/<uid>），不依赖 XDG_RUNTIME_DIR：
            // 服务（systemd --user）与 MCP 子进程看到的环境变量可能不同。
            let uid_run = PathBuf::from(format!("/run/user/{}", nix::unistd::getuid()));
            let run = if uid_run.is_dir() {
                uid_run.join("passmanager")
            } else {
                match std::env::var_os("XDG_RUNTIME_DIR") {
                    Some(r) => PathBuf::from(r).join("passmanager"),
                    None => data.join("run"),
                }
            };
            Self { mode: Mode::User, socket: run.join("passmanager.sock"), run_dir: run, data_dir: data }
        }
    }

    /// 客户端用：按优先级找到正在使用的布局（覆盖变量 > 系统模式 > 用户模式）。
    pub fn detect_client() -> Self {
        if std::env::var_os("PASSMANAGER_HOME").is_some() {
            return Self::user();
        }
        let sys = Self::system();
        #[cfg(windows)]
        {
            // 普通用户无权读取系统数据目录；通过列出 \\.\pipe\ 判断系统服务的管道是否存在
            // （打开管道会占用一个实例，因此不直接打开）。
            let running = std::fs::read_dir(r"\\.\pipe\")
                .map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case("PassManager")))
                .unwrap_or(false);
            if running || sys.data_dir.join("install.json").exists() {
                return sys;
            }
            Self::user()
        }
        #[cfg(not(windows))]
        {
            if sys.socket.exists() || sys.run_dir.exists() {
                return sys;
            }
            Self::user()
        }
    }

    pub fn vault_path(&self) -> PathBuf {
        self.data_dir.join("vault.pmv")
    }

    pub fn install_info_path(&self) -> PathBuf {
        self.data_dir.join("install.json")
    }

    pub fn harden_report_path(&self) -> PathBuf {
        self.run_dir.join("harden.json")
    }

    pub fn backup_dir(&self) -> PathBuf {
        self.data_dir.join("hardening-backup")
    }
}

/// FNV-1a 64 位哈希（只用于派生管道名，不涉及安全）。
#[cfg_attr(not(windows), allow(dead_code))]
fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x0000_0100_0000_01b3))
}

/// 安装信息（系统模式下由安装程序以 root 写入，服务只读）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallInfo {
    pub mode: Mode,
    /// 安装用户（Agent 与 TUI 所在的桌面用户）。
    pub client_user: String,
    #[serde(default)]
    pub client_uid: Option<u32>,
    #[serde(default)]
    pub client_gid: Option<u32>,
    #[serde(default)]
    pub client_sid: Option<String>,
    pub service_user: String,
    pub seal_method: String,
    pub seal_level: u8,
    pub binary: String,
}

impl InstallInfo {
    pub fn load(layout: &Layout) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(layout.install_info_path())?;
        serde_json::from_str(&s).map_err(std::io::Error::other)
    }

    pub fn store(&self, layout: &Layout) -> std::io::Result<()> {
        std::fs::create_dir_all(&layout.data_dir)?;
        let s = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(layout.install_info_path(), s)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(layout.install_info_path(), std::fs::Permissions::from_mode(0o644))?;
        }
        Ok(())
    }
}

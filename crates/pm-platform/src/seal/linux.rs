//! Linux：systemd-creds 封存。
//!
//! 有 TPM2 时使用 `--with-key=host+tpm2`（L3），否则 `--with-key=host`（L2）。
//! 不绑定 PCR（`--tpm2-pcrs=`），固件或内核升级后仍能解开。
//! 服务单元通过 `LoadCredentialEncrypted=passmanager-device-key:<cred>` 加载，
//! 解开后的明文只出现在该服务专属的 `$CREDENTIALS_DIRECTORY`（内存文件系统）中。

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use super::{RandFn, Sealer, key_from_bytes};
use crate::paths::Layout;

pub const METHOD_HOST: &str = "systemd-creds-host";
pub const METHOD_TPM: &str = "systemd-creds-host+tpm2";
pub const CRED_NAME: &str = "passmanager-device-key";

pub struct SystemdCredsSealer {
    tpm: bool,
    cred_path: PathBuf,
}

/// 解析 `systemctl --version` / `systemd-creds --version` 的主版本号。
pub fn systemd_version() -> Option<u32> {
    let out = Command::new("systemd-creds").arg("--version").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().nth(1)?.parse().ok()
}

pub fn has_tpm2() -> bool {
    Command::new("systemd-creds")
        .arg("has-tpm2")
        .arg("--quiet")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

impl SystemdCredsSealer {
    /// 检测是否可用；不可用时返回原因（用于 L1 警告）。
    pub fn probe(layout: &Layout) -> Result<Self, String> {
        if !std::path::Path::new("/run/systemd/system").exists() {
            return Err("未检测到以 systemd 启动的系统（可能是容器或使用其他 init 系统）。".into());
        }
        match systemd_version() {
            Some(v) if v >= 250 => {}
            Some(v) => return Err(format!("systemd 版本为 {v}，需要 ≥ 250 才支持 systemd-creds 封存。")),
            None => return Err("未找到 systemd-creds 命令。".into()),
        }
        Ok(Self { tpm: has_tpm2(), cred_path: layout.data_dir.join("device-key.cred") })
    }

    pub fn from_method(method: &str, layout: &Layout) -> Self {
        Self { tpm: method == METHOD_TPM, cred_path: layout.data_dir.join("device-key.cred") }
    }

    pub fn cred_path(&self) -> &PathBuf {
        &self.cred_path
    }
}

impl Sealer for SystemdCredsSealer {
    fn method(&self) -> &'static str {
        if self.tpm { METHOD_TPM } else { METHOD_HOST }
    }

    fn level(&self) -> u8 {
        if self.tpm { 3 } else { 2 }
    }

    fn describe(&self) -> String {
        if self.tpm {
            "systemd-creds：TPM2 + 主机密钥双重封存（不绑定 PCR）".into()
        } else {
            "systemd-creds：主机密钥封存（/var/lib/systemd/credential.secret，仅 root 可读）".into()
        }
    }

    fn is_provisioned(&self) -> bool {
        self.cred_path.exists()
    }

    fn seal(&self, key: &[u8; 32], _rand: RandFn) -> io::Result<()> {
        if let Some(d) = self.cred_path.parent() {
            fs::create_dir_all(d)?;
        }
        let with_key = if self.tpm { "host+tpm2" } else { "host" };
        let mut child = Command::new("systemd-creds")
            .args(["encrypt", &format!("--name={CRED_NAME}"), &format!("--with-key={with_key}"), "--tpm2-pcrs=", "-"])
            .arg(&self.cred_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().expect("stdin").write_all(key)?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!("systemd-creds encrypt failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.cred_path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn unseal(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        // 正常路径：由 systemd 通过 LoadCredentialEncrypted= 解密后提供。
        if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
            let p = PathBuf::from(dir).join(CRED_NAME);
            if p.exists() {
                let data = Zeroizing::new(fs::read(p)?);
                return key_from_bytes(&data);
            }
        }
        // 兜底（仅 root，例如安装程序自检）：直接调用 systemd-creds decrypt。
        let out = Command::new("systemd-creds")
            .args(["decrypt", &format!("--name={CRED_NAME}")])
            .arg(&self.cred_path)
            .arg("-")
            .stderr(Stdio::piped())
            .output()?;
        if !out.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("无法解封设备密钥：{}", String::from_utf8_lossy(&out.stderr).trim()),
            ));
        }
        let data = Zeroizing::new(out.stdout);
        key_from_bytes(&data)
    }

    fn remove(&self) -> io::Result<()> {
        match fs::remove_file(&self.cred_path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
}

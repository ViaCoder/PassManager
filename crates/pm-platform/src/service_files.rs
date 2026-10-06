//! 服务配置文件模板（systemd 单元 / launchd plist）。

use crate::paths::{InstallInfo, Layout};

pub const LINUX_UNIT_PATH: &str = "/etc/systemd/system/passmanager.service";
pub const LINUX_TMPFILES_PATH: &str = "/etc/tmpfiles.d/passmanager.conf";
pub const MACOS_PLIST_PATH: &str = "/Library/LaunchDaemons/com.passmanager.service.plist";
pub const MACOS_LABEL: &str = "com.passmanager.service";

/// 单元文件中必须出现的加固选项（诊断时逐项检查）。
pub const LINUX_REQUIRED_OPTIONS: &[&str] =
    &["NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "MemorySwapMax=0", "LimitCORE=0"];

pub fn linux_unit(info: &InstallInfo, layout: &Layout) -> String {
    let bin = &info.binary;
    let cred = if info.seal_method.starts_with("systemd-creds") {
        format!("LoadCredentialEncrypted=passmanager-device-key:{}\n", layout.data_dir.join("device-key.cred").display())
    } else {
        String::new()
    };
    format!(
        "# Managed by PassManager. Do not edit.\n\
[Unit]\n\
Description=PassManager vault service\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
User={user}\n\
Group={user}\n\
ExecStartPre=+{bin} service-prepare\n\
ExecStart={bin} service\n\
{cred}\
Restart=on-failure\n\
RestartSec=2\n\
UMask=0077\n\
NoNewPrivileges=yes\n\
ProtectSystem=strict\n\
ProtectHome=yes\n\
PrivateTmp=yes\n\
PrivateDevices=yes\n\
ProtectKernelTunables=yes\n\
ProtectKernelModules=yes\n\
ProtectKernelLogs=yes\n\
ProtectControlGroups=yes\n\
ProtectClock=yes\n\
ProtectHostname=yes\n\
RestrictSUIDSGID=yes\n\
RestrictRealtime=yes\n\
RestrictNamespaces=yes\n\
LockPersonality=yes\n\
MemoryDenyWriteExecute=yes\n\
SystemCallArchitectures=native\n\
CapabilityBoundingSet=\n\
AmbientCapabilities=\n\
MemorySwapMax=0\n\
LimitCORE=0\n\
# {run} 由 tmpfiles.d 在开机时创建（服务账户:安装用户的组 0750），建立挂载命名空间时必须已存在。\n\
ReadWritePaths={data} {run}\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n",
        user = info.service_user,
        data = layout.data_dir.display(),
        run = layout.run_dir.display(),
    )
}

/// tmpfiles.d：开机时创建 socket 目录。不用 RuntimeDirectory=，因为 systemd 会把它的属组
/// 递归改回服务账户的组，安装用户就连不上了。
pub fn linux_tmpfiles(info: &InstallInfo, layout: &Layout) -> String {
    let group = info.client_gid.map(|g| g.to_string()).unwrap_or_else(|| info.service_user.clone());
    format!("# Managed by PassManager. Do not edit.\nd {} 0750 {} {group} -\n", layout.run_dir.display(), info.service_user)
}

pub fn macos_plist(info: &InstallInfo) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Managed by PassManager. Do not edit. -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{MACOS_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/passmanager.log</string>
    <key>Umask</key>
    <integer>63</integer>
    <key>HardResourceLimits</key>
    <dict>
        <key>Core</key>
        <integer>0</integer>
    </dict>
    <key>SoftResourceLimits</key>
    <dict>
        <key>Core</key>
        <integer>0</integer>
    </dict>
</dict>
</plist>
"#,
        bin = info.binary
    )
}

/// 用户模式的 systemd --user 单元。
pub fn linux_user_unit(bin: &str) -> String {
    format!(
        "# Managed by PassManager (user mode, L1). Do not edit.\n\
[Unit]\n\
Description=PassManager vault service (user mode)\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={bin} service --user\n\
Restart=on-failure\n\
UMask=0077\n\
LimitCORE=0\n\
\n\
[Install]\n\
WantedBy=default.target\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Mode;

    fn info(method: &str) -> InstallInfo {
        InstallInfo {
            mode: Mode::System,
            client_user: "alice".into(),
            client_uid: Some(1000),
            client_gid: Some(1000),
            client_sid: None,
            service_user: "passmanager".into(),
            seal_method: method.into(),
            seal_level: 2,
            binary: "/usr/local/bin/PassManager".into(),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unit_contains_hardening_and_verifies() {
        let layout = Layout::system();
        let u = linux_unit(&info("systemd-creds-host"), &layout);
        for o in LINUX_REQUIRED_OPTIONS {
            assert!(u.lines().any(|l| l.trim() == *o), "missing {o}");
        }
        assert!(u.contains("LoadCredentialEncrypted=passmanager-device-key:/var/lib/passmanager/device-key.cred"));
        assert!(u.contains("ExecStartPre=+/usr/local/bin/PassManager service-prepare"));
        // 不能用 RuntimeDirectory=（systemd 会递归改掉属组）；运行目录由 tmpfiles.d 创建。
        assert!(!u.contains("RuntimeDirectory"));
        assert!(u.contains("ReadWritePaths=/var/lib/passmanager /run/passmanager"));
        assert_eq!(linux_tmpfiles(&info("file"), &layout).lines().last(), Some("d /run/passmanager 0750 passmanager 1000 -"));
        assert!(!linux_unit(&info("file"), &layout).contains("LoadCredentialEncrypted"));
        // 有 systemd-analyze 时做语法校验（ExecStart 指向 /bin/true 以便校验）。
        if std::process::Command::new("systemd-analyze").arg("--version").output().is_ok() {
            let dir = std::env::temp_dir().join(format!("pm-unit-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("passmanager.service");
            std::fs::write(&p, u.replace("/usr/local/bin/PassManager", "/bin/true")).unwrap();
            let out = std::process::Command::new("systemd-analyze").args(["verify", "--man=no"]).arg(&p).output().unwrap();
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            let _ = std::fs::remove_dir_all(&dir);
            let bad: Vec<&str> = err
                .lines()
                .filter(|l| l.contains("Unknown key") || l.contains("Failed to parse") || l.contains("Invalid") || l.contains("unknown"))
                .collect();
            assert!(bad.is_empty(), "systemd-analyze: {err}");
        }
    }

    #[test]
    fn plist_is_well_formed() {
        let p = macos_plist(&info("macos-system-keychain"));
        assert!(p.contains("<string>com.passmanager.service</string>"));
        assert!(p.contains("<string>/usr/local/bin/PassManager</string>"));
        assert_eq!(p.matches("<dict>").count(), p.matches("</dict>").count());
    }
}

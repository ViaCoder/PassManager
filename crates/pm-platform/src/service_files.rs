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

/// 服务器模式的进程退出码：真正的配置错误（不重启，`RestartPreventExitStatus=78`，EX_CONFIG）。
pub const EXIT_CONFIG: u8 = 78;
/// 服务器模式的进程退出码：暂时性故障（TPM 尚未出现、网络未就绪等），由 systemd 有限次重试。
pub const EXIT_TRANSIENT: u8 = 75;

/// 局域网在线版（服务器模式）的 systemd 单元。
///
/// 与单机版的区别：
/// - 设备密钥由 `ExecStartPre=+… service-prepare`（root）解密到 `/run/passmanager-key`，服务读后即删
///   （非特权 LXC 不支持 `LoadCredentialEncrypted=`）；ExecStartPre 内有限次等待 /dev/tpmrm0；
/// - 只授予 `CAP_NET_BIND_SERVICE`（监听 443/8443），其余能力全部丢弃；
/// - `Restart=on-failure` + 启动次数上限：开机时的暂时性失败会重试；退出码 78 表示配置错误，不再重启；
/// - 不用 `PrivateDevices=`（它会隐藏 /dev/tpmrm0），改为 `DevicePolicy=closed` 只放行 TPM 设备
///   （TPM 作为随机数的第三个源；没有 TPM 时这一行无效果）。
pub fn linux_server_unit(info: &InstallInfo, layout: &Layout, tpm_group: Option<&str>) -> String {
    let mut groups = tpm_group.map(|g| format!("SupplementaryGroups={g}\n")).unwrap_or_default();
    // 配置了 swtpm 套接字：告诉服务进程（TPM 随机数源）。
    if let Some(s) = info.server.as_ref().and_then(|s| s.tpm_socket.as_deref()) {
        groups.push_str(&format!("Environment=PASSMANAGER_TPM_SOCKET={s}\n"));
    }
    format!(
        "# Managed by PassManager (LAN server mode). Do not edit.\n\
[Unit]\n\
Description=PassManager vault service (LAN server)\n\
After=network-online.target\n\
Wants=network-online.target\n\
StartLimitIntervalSec=900\n\
StartLimitBurst=10\n\
\n\
[Service]\n\
Type=simple\n\
User={user}\n\
Group={user}\n\
{groups}\
ExecStartPre=+{bin} service-prepare\n\
ExecStart={bin} service\n\
ExecStopPost=+/bin/rm -f {handoff}\n\
Restart=on-failure\n\
RestartSec=15\n\
RestartPreventExitStatus={EXIT_CONFIG}\n\
TimeoutStartSec=180\n\
UMask=0077\n\
NoNewPrivileges=yes\n\
ProtectSystem=strict\n\
ProtectHome=yes\n\
PrivateTmp=yes\n\
DevicePolicy=closed\n\
DeviceAllow=/dev/tpmrm0 rw\n\
ProtectKernelTunables=yes\n\
ProtectKernelModules=yes\n\
ProtectKernelLogs=yes\n\
ProtectControlGroups=yes\n\
ProtectClock=yes\n\
ProtectHostname=yes\n\
RestrictSUIDSGID=yes\n\
RestrictRealtime=yes\n\
RestrictNamespaces=yes\n\
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n\
LockPersonality=yes\n\
MemoryDenyWriteExecute=yes\n\
SystemCallArchitectures=native\n\
SystemCallFilter=@system-service\n\
SystemCallFilter=~@privileged @mount @debug @cpu-emulation @obsolete @raw-io @reboot @swap\n\
SystemCallErrorNumber=EPERM\n\
CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
MemorySwapMax=0\n\
LimitCORE=0\n\
# {run} 与 {handoff_dir} 由 tmpfiles.d 在开机时创建，建立挂载命名空间时必须已存在。\n\
ReadWritePaths={data} {run} {handoff_dir}\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n",
        user = info.service_user,
        bin = info.binary,
        data = layout.data_dir.display(),
        run = layout.run_dir.display(),
        handoff = layout.key_handoff_path().display(),
        handoff_dir = layout.key_handoff_dir().display(),
    )
}

/// 服务器模式的 tmpfiles.d：socket 目录（只有 root 与服务账户）与密钥交接目录（只有服务账户）。
pub fn linux_server_tmpfiles(info: &InstallInfo, layout: &Layout) -> String {
    format!(
        "# Managed by PassManager (LAN server mode). Do not edit.\nd {} 0750 {u} {u} -\nd {} 0700 {u} {u} -\n",
        layout.run_dir.display(),
        layout.key_handoff_dir().display(),
        u = info.service_user
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
            server: None,
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

    /// 服务器模式单元：包含全部必需的加固选项、开机顺序、重试策略与 78 不重启，并通过 systemd-analyze verify。
    #[test]
    #[cfg(target_os = "linux")]
    fn server_unit_contains_hardening_restart_policy_and_verifies() {
        let layout = Layout::system();
        let mut i = info("systemd-creds-host");
        i.server = Some(crate::ServerConfig::default());
        let u = linux_server_unit(&i, &layout, Some("tss"));
        for o in LINUX_REQUIRED_OPTIONS {
            assert!(u.lines().any(|l| l.trim() == *o), "missing {o}");
        }
        for o in [
            "After=network-online.target",
            "Wants=network-online.target",
            "Restart=on-failure",
            "RestartPreventExitStatus=78",
            "StartLimitIntervalSec=900",
            "StartLimitBurst=10",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "ExecStartPre=+/usr/local/bin/PassManager service-prepare",
            "ExecStart=/usr/local/bin/PassManager service",
            "ExecStopPost=+/bin/rm -f /run/passmanager-key/device.key",
            "DeviceAllow=/dev/tpmrm0 rw",
            "SupplementaryGroups=tss",
            "ReadWritePaths=/var/lib/passmanager /run/passmanager /run/passmanager-key",
        ] {
            assert!(u.lines().any(|l| l == o), "missing {o}\n{u}");
        }
        // 不用 LoadCredentialEncrypted（非特权 LXC 不支持）与 PrivateDevices（会隐藏 TPM）。
        assert!(!u.contains("LoadCredentialEncrypted") && !u.contains("PrivateDevices"));
        assert!(!linux_server_unit(&i, &layout, None).contains("SupplementaryGroups"));
        assert!(!u.contains("Environment="), "没有配置套接字时不需要额外环境变量");
        let mut j = i.clone();
        j.server.as_mut().unwrap().tpm_socket = Some("/srv/tpm/tpm.sock".into());
        assert!(linux_server_unit(&j, &layout, None).lines().any(|l| l == "Environment=PASSMANAGER_TPM_SOCKET=/srv/tpm/tpm.sock"));
        let t = linux_server_tmpfiles(&i, &layout);
        assert!(t.contains("d /run/passmanager 0750 passmanager passmanager -"));
        assert!(t.contains("d /run/passmanager-key 0700 passmanager passmanager -"));
        assert_eq!(EXIT_CONFIG, 78);
        assert_ne!(EXIT_TRANSIENT, EXIT_CONFIG);
        if std::process::Command::new("systemd-analyze").arg("--version").output().is_ok() {
            let dir = std::env::temp_dir().join(format!("pm-sunit-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("passmanager.service");
            std::fs::write(&p, linux_server_unit(&i, &layout, None).replace("/usr/local/bin/PassManager", "/bin/true")).unwrap();
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

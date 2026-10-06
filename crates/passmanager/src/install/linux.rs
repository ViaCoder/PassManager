//! Linux 安装：systemd 服务 + 专用系统用户 + systemd-creds 封存。

use std::path::Path;
use std::process::Command;

use pm_platform::seal::{self, Sealer};
use pm_platform::service_files::{LINUX_TMPFILES_PATH, LINUX_UNIT_PATH, linux_tmpfiles, linux_unit, linux_user_unit};
use pm_platform::{InstallInfo, Layout, Mode};

use super::{copy_self, provision_device_key};

const BIN: &str = "/usr/local/bin/PassManager";
const SVC: &str = "passmanager";

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into())
    } else {
        Err(format!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn chown_mode(p: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    nix::unistd::chown(p, Some(nix::unistd::Uid::from_raw(uid)), Some(nix::unistd::Gid::from_raw(gid)))
        .map_err(|e| format!("chown {}: {e}", p.display()))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {}: {e}", p.display()))
}

fn has_systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

pub fn install(client: &str) -> Result<(Layout, InstallInfo, Option<String>), String> {
    let cu = nix::unistd::User::from_name(client).ok().flatten().ok_or_else(|| format!("用户 {client} 不存在"))?;
    let layout = Layout::system();
    println!("== 安装 PassManager（系统模式）==");

    copy_self(Path::new(BIN))?;
    chown_mode(Path::new(BIN), 0, 0, 0o755)?;
    println!("  · 程序：{BIN}");

    if nix::unistd::User::from_name(SVC).ok().flatten().is_none() {
        run(
            "useradd",
            &["--system", "--user-group", "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", SVC],
        )?;
    }
    let su = nix::unistd::User::from_name(SVC).ok().flatten().ok_or("创建服务账户失败")?;
    println!("  · 服务账户：{SVC}");

    std::fs::create_dir_all(&layout.data_dir).map_err(|e| e.to_string())?;
    chown_mode(&layout.data_dir, su.uid.as_raw(), su.gid.as_raw(), 0o700)?;

    // 重新安装时沿用原来的封存方式，避免使已有的库失效。
    let previous = InstallInfo::load(&layout).ok();
    let (sealer, l1_reason): (Box<dyn Sealer>, Option<String>) =
        match previous.as_ref().and_then(|p| seal::by_method(&p.seal_method, &layout)) {
            Some(s) if s.is_provisioned() => (s, None),
            _ => seal::best_available(&layout),
        };
    provision_device_key(sealer.as_ref())?;
    if sealer.method() == seal::file::METHOD {
        chown_mode(&layout.data_dir.join("device.key"), su.uid.as_raw(), su.gid.as_raw(), 0o600)?;
    }
    println!("  · 设备密钥：{}", sealer.describe());

    let info = InstallInfo {
        mode: Mode::System,
        client_user: client.to_string(),
        client_uid: Some(cu.uid.as_raw()),
        client_gid: Some(cu.gid.as_raw()),
        client_sid: None,
        service_user: SVC.into(),
        seal_method: sealer.method().into(),
        seal_level: sealer.level(),
        binary: BIN.into(),
    };
    info.store(&layout).map_err(|e| e.to_string())?;
    chown_mode(&layout.install_info_path(), 0, 0, 0o644)?;

    if has_systemd() {
        std::fs::write(LINUX_TMPFILES_PATH, linux_tmpfiles(&info, &layout)).map_err(|e| e.to_string())?;
        chown_mode(Path::new(LINUX_TMPFILES_PATH), 0, 0, 0o644)?;
        run("systemd-tmpfiles", &["--create", LINUX_TMPFILES_PATH])?;
        std::fs::write(LINUX_UNIT_PATH, linux_unit(&info, &layout)).map_err(|e| e.to_string())?;
        chown_mode(Path::new(LINUX_UNIT_PATH), 0, 0, 0o644)?;
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "passmanager.service"])?;
        run("systemctl", &["restart", "passmanager.service"])?;
        println!("  · 已启动 systemd 服务 passmanager.service");
    } else {
        // 没有 systemd（容器等）：手动准备并以服务账户后台启动。
        let _ = Command::new(BIN).arg("service-prepare").status();
        let st = Command::new("runuser").args(["-u", SVC, "--", "setsid", BIN, "service"]).spawn();
        if st.is_err() {
            return Err("没有 systemd，且无法用 runuser 启动服务。".into());
        }
        println!("  · 没有 systemd：已在后台以 {SVC} 身份启动服务（重启后需要重新启动）");
    }
    Ok((layout, info, l1_reason))
}

pub fn uninstall(layout: &Layout, _info: Option<&InstallInfo>) {
    let _ = run("systemctl", &["disable", "--now", "passmanager.service"]);
    let _ = std::fs::remove_file(LINUX_UNIT_PATH);
    let _ = std::fs::remove_file(LINUX_TMPFILES_PATH);
    let _ = run("systemctl", &["daemon-reload"]);
    let _ = run("pkill", &["-u", SVC]);
    let _ = std::fs::remove_file(pm_platform::harden::sudoers::HARDENING_FILE);
    let _ = run("userdel", &[SVC]);
    let _ = std::fs::remove_file(BIN);
    let _ = layout;
}

fn user_unit_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(Path::new(&home).join(".config/systemd/user/passmanager.service"))
}

pub fn start_user_unit(exe: &str) -> bool {
    if Command::new("systemctl").args(["--user", "is-system-running"]).output().map(|o| o.stdout.is_empty()).unwrap_or(true) {
        return false;
    }
    let Some(p) = user_unit_path() else { return false };
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if std::fs::write(&p, linux_user_unit(exe)).is_err() {
        return false;
    }
    run("systemctl", &["--user", "daemon-reload"]).is_ok()
        && run("systemctl", &["--user", "enable", "--now", "passmanager.service"]).is_ok()
}

pub fn stop_user_unit() {
    let _ = run("systemctl", &["--user", "disable", "--now", "passmanager.service"]);
    if let Some(p) = user_unit_path() {
        let _ = std::fs::remove_file(p);
    }
    let _ = run("systemctl", &["--user", "daemon-reload"]);
}

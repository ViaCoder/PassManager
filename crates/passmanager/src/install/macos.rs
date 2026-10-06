//! macOS 安装：LaunchDaemon（root 启动、读取钥匙串后降权到 _passmanager）+ 系统钥匙串（L2）。

use std::path::Path;
use std::process::Command;

use pm_platform::seal::macos::{KeychainSealer, RootFileSealer};
use pm_platform::seal::{self, Sealer};
use pm_platform::service_files::{MACOS_LABEL, MACOS_PLIST_PATH, macos_plist};
use pm_platform::{InstallInfo, Layout, Mode};

use super::copy_self;

/// 程序放在 root 拥有的目录里：/usr/local/bin 在很多 Mac 上归用户所有（Homebrew），
/// 用户（及其 Agent）可以替换其中的文件，而 LaunchDaemon 以 root 启动该程序。
const BIN_DIR: &str = "/Library/PassManager";
const BIN: &str = "/Library/PassManager/PassManager";
/// 命令行入口（符号链接）。
const LINK: &str = "/usr/local/bin/PassManager";
const SVC: &str = "_passmanager";
const CLIENT_GROUP: &str = "_passmanager_clients";

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

fn used_ids(kind: &str, attr: &str) -> Vec<u32> {
    run("dscl", &[".", "-list", kind, attr]).unwrap_or_default().lines().filter_map(|l| l.split_whitespace().last()?.parse().ok()).collect()
}

fn free_id() -> u32 {
    let users = used_ids("/Users", "UniqueID");
    let groups = used_ids("/Groups", "PrimaryGroupID");
    (400..500).rev().find(|i| !users.contains(i) && !groups.contains(i)).unwrap_or(499)
}

fn ensure_group(name: &str) -> Result<u32, String> {
    if let Ok(Some(g)) = nix::unistd::Group::from_name(name) {
        return Ok(g.gid.as_raw());
    }
    let id = free_id();
    let path = format!("/Groups/{name}");
    run("dscl", &[".", "-create", &path])?;
    run("dscl", &[".", "-create", &path, "PrimaryGroupID", &id.to_string()])?;
    run("dscl", &[".", "-create", &path, "RealName", name])?;
    Ok(id)
}

fn ensure_service_user() -> Result<(u32, u32), String> {
    if let Ok(Some(u)) = nix::unistd::User::from_name(SVC) {
        return Ok((u.uid.as_raw(), u.gid.as_raw()));
    }
    let gid = ensure_group(SVC)?;
    let uid = free_id();
    let path = format!("/Users/{SVC}");
    run("dscl", &[".", "-create", &path])?;
    for (k, v) in [
        ("UniqueID", uid.to_string()),
        ("PrimaryGroupID", gid.to_string()),
        ("UserShell", "/usr/bin/false".to_string()),
        ("NFSHomeDirectory", "/var/empty".to_string()),
        ("RealName", "PassManager service".to_string()),
        ("Password", "*".to_string()),
        ("IsHidden", "1".to_string()),
    ] {
        run("dscl", &[".", "-create", &path, k, &v])?;
    }
    Ok((uid, gid))
}

pub fn install(client: &str) -> Result<(Layout, InstallInfo, Option<String>), String> {
    let cu = nix::unistd::User::from_name(client).ok().flatten().ok_or_else(|| format!("用户 {client} 不存在"))?;
    let layout = Layout::system();
    println!("== 安装 PassManager（系统模式）==");

    // 升级：钥匙串条目的 ACL 只信任旧程序，先由旧程序导出设备密钥，换上新程序后再由它重新封存。
    let previous = InstallInfo::load(&layout).ok();
    let carried = previous
        .as_ref()
        .filter(|p| p.seal_method == seal::macos::METHOD_KEYCHAIN && Path::new(&p.binary).exists())
        .and_then(|p| run_timeout(&p.binary, &["export-device-key"], None).ok());
    if previous.as_ref().is_some_and(|p| p.seal_method == seal::macos::METHOD_KEYCHAIN) && carried.is_none() {
        return Err("无法从已安装的程序取出设备密钥（钥匙串只信任它）。请先运行 sudo PassManager uninstall 再安装。".into());
    }

    std::fs::create_dir_all(BIN_DIR).map_err(|e| e.to_string())?;
    chown_mode(Path::new(BIN_DIR), 0, 0, 0o755)?;
    copy_self(Path::new(BIN))?;
    chown_mode(Path::new(BIN), 0, 0, 0o755)?;
    let _ = run("codesign", &["--force", "--sign", "-", BIN]);
    let _ = std::fs::create_dir_all("/usr/local/bin");
    let _ = std::fs::remove_file(LINK);
    if let Err(e) = std::os::unix::fs::symlink(BIN, LINK) {
        println!("  · 无法创建 {LINK}：{e}（可直接运行 {BIN}）");
    }
    println!("  · 程序：{BIN}（命令 {LINK}）");

    let (suid, sgid) = ensure_service_user()?;
    println!("  · 服务账户：{SVC}");
    let cgid = ensure_group(CLIENT_GROUP)?;
    let _ = run("dseditgroup", &["-o", "edit", "-a", client, "-t", "user", CLIENT_GROUP]);

    std::fs::create_dir_all(&layout.data_dir).map_err(|e| e.to_string())?;
    chown_mode(&layout.data_dir, suid, sgid, 0o700)?;

    // 由已安装的程序创建钥匙串条目，使默认 ACL 只信任它。
    let method = match previous.as_ref().and_then(|p| seal::by_method(&p.seal_method, &layout)) {
        Some(s) if s.method() == seal::macos::METHOD_ROOTFILE && s.is_provisioned() => s.method().to_string(),
        _ => {
            let stdin = carried.as_ref().map(|k| k.as_bytes());
            let args: &[&str] = if stdin.is_some() { &["seal-device-key", "--stdin"] } else { &["seal-device-key"] };
            run_timeout(BIN, args, stdin).map_err(|e| format!("封存设备密钥失败：{e}"))?.trim().to_string()
        }
    };
    let sealer = seal::by_method(&method, &layout).ok_or("未知的封存方式")?;
    println!("  · 设备密钥：{}", sealer.describe());

    let info = InstallInfo {
        mode: Mode::System,
        client_user: client.to_string(),
        client_uid: Some(cu.uid.as_raw()),
        client_gid: Some(cgid),
        client_sid: None,
        service_user: SVC.into(),
        seal_method: method,
        seal_level: sealer.level(),
        binary: BIN.into(),
    };
    info.store(&layout).map_err(|e| e.to_string())?;
    chown_mode(&layout.install_info_path(), 0, 0, 0o644)?;

    std::fs::write(MACOS_PLIST_PATH, macos_plist(&info)).map_err(|e| e.to_string())?;
    chown_mode(Path::new(MACOS_PLIST_PATH), 0, 0, 0o644)?;
    let _ = run("launchctl", &["bootout", &format!("system/{MACOS_LABEL}")]);
    run("launchctl", &["bootstrap", "system", MACOS_PLIST_PATH])?;
    let _ = run("launchctl", &["enable", &format!("system/{MACOS_LABEL}")]);
    let _ = run("launchctl", &["kickstart", "-k", &format!("system/{MACOS_LABEL}")]);
    println!("  · 已启动 LaunchDaemon {MACOS_LABEL}");
    Ok((layout, info, None))
}

/// 在已安装的程序中以 root 身份执行：生成（或用 --stdin 传入的十六进制）设备密钥，
/// 优先写入系统钥匙串（替换旧条目），失败时退回 root 专属文件。输出所用方法。
pub fn seal_device_key(from_stdin: bool) -> std::process::ExitCode {
    let fail = |e: String| {
        eprintln!("{e}");
        std::process::ExitCode::from(1)
    };
    if let Err(e) = pm_crypto::selftest::run_all() {
        return fail(format!("自检失败：{e}"));
    }
    let key: zeroize::Zeroizing<[u8; 32]> = if from_stdin {
        let mut line = zeroize::Zeroizing::new(String::new());
        let _ = std::io::stdin().read_line(&mut line);
        let raw = zeroize::Zeroizing::new(hex::decode(line.trim()).unwrap_or_default());
        match <[u8; 32]>::try_from(raw.as_slice()) {
            Ok(k) => zeroize::Zeroizing::new(k),
            Err(_) => return fail("设备密钥格式错误".into()),
        }
    } else {
        match pm_crypto::rng::random_array::<32>() {
            Ok(k) => zeroize::Zeroizing::new(k),
            Err(e) => return fail(e.to_string()),
        }
    };
    let mut rand = |b: &mut [u8]| pm_crypto::rng::fill(b).map_err(std::io::Error::other);
    let kc = KeychainSealer::new();
    let _ = kc.remove();
    if kc.seal(&key, &mut rand).is_ok() && kc.unseal().is_ok_and(|k| *k == *key) {
        println!("{}", kc.method());
        return std::process::ExitCode::SUCCESS;
    }
    let rf = RootFileSealer::new();
    let _ = rf.remove();
    match rf.seal(&key, &mut rand) {
        Ok(()) => {
            println!("{}", rf.method());
            std::process::ExitCode::SUCCESS
        }
        Err(e) => fail(format!("封存设备密钥失败：{e}")),
    }
}

/// 升级时由旧程序（钥匙串只信任它）以 root 身份导出设备密钥（十六进制），交给安装程序。
pub fn export_device_key() -> std::process::ExitCode {
    if !pm_platform::process::is_elevated() {
        eprintln!("需要 root");
        return std::process::ExitCode::from(1);
    }
    match KeychainSealer::new().unseal() {
        Ok(k) => {
            println!("{}", zeroize::Zeroizing::new(hex::encode(*k)).as_str());
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::from(1)
        }
    }
}

pub fn uninstall(_layout: &Layout, _info: Option<&InstallInfo>) {
    let _ = run("launchctl", &["bootout", &format!("system/{MACOS_LABEL}")]);
    let _ = std::fs::remove_file(MACOS_PLIST_PATH);
    let _ = std::fs::remove_file(pm_platform::harden::sudoers::HARDENING_FILE);
    let _ = run("dscl", &[".", "-delete", &format!("/Users/{SVC}")]);
    let _ = run("dscl", &[".", "-delete", &format!("/Groups/{SVC}")]);
    let _ = run("dscl", &[".", "-delete", &format!("/Groups/{CLIENT_GROUP}")]);
    if std::fs::read_link(LINK).is_ok_and(|t| t == Path::new(BIN)) {
        let _ = std::fs::remove_file(LINK);
    }
    let _ = std::fs::remove_file(BIN);
    let _ = std::fs::remove_dir(BIN_DIR);
}

/// 运行子程序并取得标准输出；最多等 30 秒（钥匙串万一要求交互授权时不至于卡住）。
fn run_timeout(bin: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<zeroize::Zeroizing<String>, String> {
    use std::io::{Read, Write};
    use std::process::Stdio;
    let mut child = Command::new(bin)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{bin}: {e}"))?;
    if let (Some(data), Some(mut w)) = (stdin, child.stdin.take()) {
        let _ = w.write_all(data);
    }
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st;
        }
        if start.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{bin} {} 超时", args.join(" ")));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let mut out = zeroize::Zeroizing::new(String::new());
    let mut err = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut out);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    if status.success() { Ok(out) } else { Err(err.trim().to_string()) }
}

//! 一键安装、卸载、安全检查与账户加固、服务入口。

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use pm_platform::harden::{self, Ctx, Report};
use pm_platform::seal::{self, L1_WARNING, level_label};
use pm_platform::{InstallInfo, Layout, Mode};
use pm_proto::{Client, Hello, PROTO_V};

use crate::prompt;

/// 安装选项。
#[derive(Clone, Default)]
pub struct InstallOpts {
    pub user: bool,
    pub client_user: Option<String>,
    /// 不询问，直接执行自动修改。
    pub yes: bool,
    /// 非交互：从标准输入读取口令（第一行），视为已确认"没有恢复机制"。用于自动化部署与 CI。
    pub password_stdin: bool,
    /// 只检查，不执行任何自动修改。
    pub no_fix: bool,
}

impl InstallOpts {
    fn interactive(&self) -> bool {
        !self.password_stdin
    }

    fn harden_mode(&self) -> HardenMode {
        if self.no_fix {
            HardenMode::CheckOnly
        } else if self.yes {
            HardenMode::Fix
        } else {
            HardenMode::Ask
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardenMode {
    Ask,
    Fix,
    CheckOnly,
}

pub(crate) fn fail(msg: impl AsRef<str>) -> ExitCode {
    eprintln!("错误：{}", msg.as_ref());
    ExitCode::from(1)
}

const RED: &str = "\x1b[1;31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

pub(crate) fn print_report(r: &Report) {
    if let Some(s) = &r.skipped {
        println!("{YELLOW}{s}{RESET}");
        return;
    }
    for f in &r.findings {
        if f.ok {
            println!("  {GREEN}✔{RESET} {}", f.title);
        } else if f.advisory {
            println!("  {YELLOW}⚠{RESET} {}（建议，不影响使用）", f.title);
            for l in f.detail.lines().chain(f.steps.lines()) {
                println!("      {l}");
            }
        } else if f.auto_fix {
            println!("  {YELLOW}●{RESET} {}（可自动修改）", f.title);
            for l in f.detail.lines() {
                println!("      {l}");
            }
        } else {
            println!("  {RED}✘{RESET} {}（需要你处理）", f.title);
            for l in f.detail.lines() {
                println!("      {l}");
            }
            for l in f.steps.lines() {
                println!("      → {l}");
            }
        }
    }
}

/// 检查 → （确认后）自动修改 → 复查 → 保存报告。返回最终报告。
pub(crate) fn run_harden(layout: &Layout, info: &InstallInfo, mode: HardenMode) -> Report {
    let ctx = Ctx { layout, info };
    println!("\n== 安全检查（推荐架构：禁用内置管理员；日常账户提权必须输入口令；Agent 不以管理员运行）==");
    let mut report = harden::check(&ctx);
    print_report(&report);
    let fixable = report.failing().filter(|f| f.auto_fix).count();
    if fixable > 0 && mode != HardenMode::CheckOnly {
        let go = mode == HardenMode::Fix
            || prompt::confirm(
                &format!("\n以上 {fixable} 项可以自动修改（修改前会备份到 {}）。现在修改吗？", layout.backup_dir().display()),
                true,
            );
        if go {
            for l in harden::fix(&ctx, &report) {
                println!("  · {l}");
            }
            report = harden::check(&ctx);
            println!("\n== 复查 ==");
            print_report(&report);
        }
    }
    if let Err(e) = report.store(layout) {
        eprintln!("保存检查报告失败：{e}");
    }
    let manual: Vec<_> = report.failing().collect();
    if manual.is_empty() {
        println!("{GREEN}全部检查通过。{RESET}");
    } else {
        println!(
            "\n{RED}还有 {} 项未通过。全部通过之前库会保持锁定。{RESET}处理完后运行 PassManager，在\"诊断\"页点 [重新检查]。",
            manual.len()
        );
    }
    report
}

pub(crate) fn l1_warning(reason: Option<&str>, interactive: bool) {
    println!("\n{RED}┌──────────────────────────────────────────────────────────────┐{RESET}");
    println!("{RED}│  {L1_WARNING}{RESET}");
    if let Some(r) = reason {
        println!("{RED}│  原因：{r}{RESET}");
    }
    println!("{RED}│  改进：在支持 systemd ≥ 250 的 Linux、Windows 或 macOS 上以管理员身份安装。{RESET}");
    println!("{RED}└──────────────────────────────────────────────────────────────┘{RESET}");
    if interactive {
        prompt::press_enter("我已了解");
    }
}

/// 等待服务的 socket 出现。
pub(crate) fn wait_for_service(layout: &Layout) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        #[cfg(unix)]
        if layout.socket.exists() {
            return true;
        }
        // 不打开管道（会占用一个实例），而是列出 \\.\pipe\ 判断管道是否已创建。
        #[cfg(windows)]
        if let Some(name) = layout.socket.file_name()
            && std::fs::read_dir(r"\\.\pipe\").is_ok_and(|rd| rd.flatten().any(|e| e.file_name().eq_ignore_ascii_case(name)))
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

/// 从标准输入读取口令（第一行）。
fn password_from_stdin() -> Option<zeroize::Zeroizing<String>> {
    use std::io::BufRead;
    let mut line = zeroize::Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line).ok()?;
    let pw = zeroize::Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string());
    if pw.chars().count() < 8 {
        eprintln!("口令至少需要 8 个字符。");
        return None;
    }
    Some(pw)
}

/// 首次设置口令（库不存在时）。
pub(crate) fn setup_vault(layout: &Layout, opts: &InstallOpts) -> bool {
    if layout.vault_path().exists() {
        println!("库已存在，跳过口令设置。");
        return true;
    }
    println!("\n== 设置口令 ==");
    println!("口令与本机的设备密钥共同保护库文件。");
    println!("{YELLOW}注意：PassManager 没有任何恢复机制。换机器、重装系统、清空 TPM 后库将永久无法打开，凭据需要重新录入。{RESET}");
    let pw = if opts.interactive() {
        if !prompt::confirm("我知道换机器或重装系统后需要重新录入凭据", false) {
            println!("已取消。之后可以重新运行安装程序完成设置。");
            return false;
        }
        prompt::new_password()
    } else {
        password_from_stdin()
    };
    let Some(pw) = pw else { return false };
    println!("正在创建库（校准 Argon2id 并生成 ML-KEM-1024 与 Classic McEliece 密钥，约需数秒）……");
    match Client::connect_at(&layout.socket, &Hello::Setup { v: PROTO_V, password: pw.to_string() }) {
        Ok(_) => {
            println!("{GREEN}库已创建。{RESET}");
            true
        }
        Err(e) => {
            eprintln!("创建库失败：{}", e.message);
            false
        }
    }
}

#[cfg(unix)]
fn client_user_name(arg: Option<String>) -> Option<String> {
    arg.or_else(|| std::env::var("SUDO_USER").ok()).filter(|u| !u.is_empty() && u != "root")
}

pub fn install(opts: InstallOpts) -> ExitCode {
    if let Err(e) = pm_crypto::selftest::run_all() {
        return fail(format!("密码学自检失败：{e}"));
    }
    if opts.user || std::env::var_os("PASSMANAGER_HOME").is_some() {
        return install_user_mode(&opts);
    }
    #[cfg(windows)]
    {
        windows::install(&opts)
    }
    #[cfg(not(windows))]
    {
        if !pm_platform::process::is_elevated() {
            return fail(
                "系统模式安装需要管理员权限，请运行：sudo PassManager install\n（没有管理员权限时可用 PassManager install --user，但只能达到 L1）",
            );
        }
        let Some(client) = client_user_name(opts.client_user.clone()) else {
            return fail("无法确定日常使用的账户。请用 sudo 从你的账户运行，或加上 --client-user <用户名>。");
        };
        #[cfg(target_os = "linux")]
        let r = linux::install(&client);
        #[cfg(target_os = "macos")]
        let r = macos::install(&client);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let r: Result<(Layout, InstallInfo, Option<String>), String> = Err("不支持的平台".into());
        let (layout, info, l1_reason) = match r {
            Ok(x) => x,
            Err(e) => return fail(e),
        };
        finish_install(&layout, &info, l1_reason.as_deref(), &opts, Some(&client))
    }
}

pub(crate) fn finish_install(
    layout: &Layout,
    info: &InstallInfo,
    l1_reason: Option<&str>,
    opts: &InstallOpts,
    client: Option<&str>,
) -> ExitCode {
    println!("\n设备密钥封存等级：{}", level_label(info.seal_level));
    let _ = run_harden(layout, info, opts.harden_mode());
    if !wait_for_service(layout) {
        return fail("服务没有启动，请查看系统日志（Linux：journalctl -u passmanager）。");
    }
    if !setup_vault(layout, opts) {
        return ExitCode::from(1);
    }
    if info.seal_level == 1 {
        l1_warning(l1_reason, opts.interactive());
    }
    println!("\n安装完成。接下来在你自己的终端（不要加 sudo）运行：{GREEN}PassManager{RESET}");
    println!("在界面里添加凭据，并在\"Agent 接入\"页一键接入你的 AI Agent。");
    #[cfg(unix)]
    if let Some(c) = client
        && opts.interactive()
        && pm_platform::tty::is_real_tty()
        && prompt::confirm("现在打开 PassManager 吗？", true)
    {
        let _ = std::process::Command::new("sudo").args(["-u", c, "-H", &info.binary]).status();
    }
    #[cfg(not(unix))]
    let _ = client;
    ExitCode::SUCCESS
}

fn install_user_mode(opts: &InstallOpts) -> ExitCode {
    let layout = Layout::user();
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    println!("用户模式安装：服务与 Agent 运行在同一个系统用户下（L1，没有账户隔离）。");
    if let Err(e) = std::fs::create_dir_all(&layout.data_dir) {
        return fail(e.to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&layout.data_dir, std::fs::Permissions::from_mode(0o700));
    }
    if !start_user_service(&layout, &exe) {
        return fail("无法启动服务。");
    }
    if !wait_for_service(&layout) {
        return fail("服务没有启动。");
    }
    if !setup_vault(&layout, opts) {
        return ExitCode::from(1);
    }
    l1_warning(Some("用户模式：服务与 Agent 运行在同一个系统用户下。"), opts.interactive());
    println!("\n安装完成。运行 {GREEN}PassManager{RESET} 添加凭据并接入 Agent。");
    ExitCode::SUCCESS
}

/// 用户模式：优先用 systemd --user，否则后台启动。
fn start_user_service(layout: &Layout, exe: &str) -> bool {
    #[cfg(target_os = "linux")]
    if std::env::var_os("PASSMANAGER_HOME").is_none() && linux::start_user_unit(exe) {
        return true;
    }
    spawn_detached(layout, exe)
}

pub(crate) fn spawn_detached(layout: &Layout, exe: &str) -> bool {
    let log = std::fs::OpenOptions::new().create(true).append(true).open(layout.data_dir.join("service.log"));
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["service", "--user"]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null());
    if let Ok(f) = log {
        cmd.stderr(f);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: 子进程中只调用 setsid。
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    cmd.spawn().is_ok()
}

pub fn uninstall(user: bool, restore: bool, yes: bool) -> ExitCode {
    println!("{RED}卸载会永久删除库中的全部凭据（没有任何恢复机制）。{RESET}");
    if !yes && prompt::line("输入 DELETE 确认：") != "DELETE" {
        println!("已取消。");
        return ExitCode::SUCCESS;
    }
    if user || std::env::var_os("PASSMANAGER_HOME").is_some() {
        let layout = Layout::user();
        #[cfg(target_os = "linux")]
        linux::stop_user_unit();
        #[cfg(unix)]
        if let Ok(pid) = std::fs::read_to_string(layout.data_dir.join("service.pid"))
            && let Ok(pid) = pid.trim().parse::<i32>()
        {
            // SAFETY: 向记录的服务进程发送 SIGTERM。
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let _ = std::fs::remove_dir_all(&layout.data_dir);
        let _ = std::fs::remove_dir_all(&layout.run_dir);
        println!("已卸载（用户模式）。");
        return ExitCode::SUCCESS;
    }
    if !pm_platform::process::is_elevated() {
        return fail("需要管理员权限：sudo PassManager uninstall");
    }
    let layout = Layout::system();
    let info = InstallInfo::load(&layout).ok();
    #[cfg(target_os = "linux")]
    linux::uninstall(&layout, info.as_ref());
    #[cfg(target_os = "macos")]
    macos::uninstall(&layout, info.as_ref());
    #[cfg(windows)]
    windows::uninstall(&layout, info.as_ref());
    if restore {
        for l in harden::restore_backups(&layout) {
            println!("  · {l}");
        }
    }
    if let Some(i) = &info
        && let Some(s) = seal::by_method(&i.seal_method, &layout)
    {
        // 删除封存的设备密钥；系统密钥库万一要求交互授权，最多等 15 秒，不让卸载卡住。
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(s.remove());
        });
        if rx.recv_timeout(Duration::from_secs(15)).is_err() {
            eprintln!("删除封存的设备密钥超时，已跳过（没有库文件它也无法再被使用）。");
        }
    }
    let _ = std::fs::remove_dir_all(&layout.data_dir);
    let _ = std::fs::remove_dir_all(&layout.run_dir);
    println!("已卸载。");
    ExitCode::SUCCESS
}

pub fn harden_cmd(check_only: bool, fix: bool, yes: bool) -> ExitCode {
    let layout = Layout::detect_client();
    let layout = if layout.mode == Mode::User { Layout::user() } else { Layout::system() };
    let info = match InstallInfo::load(&layout) {
        Ok(i) => i,
        Err(e) => return fail(format!("读取安装信息失败（是否已安装？）：{e}")),
    };
    if layout.mode == Mode::System && !pm_platform::process::is_elevated() {
        return fail("需要管理员权限：sudo PassManager harden");
    }
    let report = if check_only && !fix {
        let r = harden::check(&Ctx { layout: &layout, info: &info });
        print_report(&r);
        let _ = r.store(&layout);
        r
    } else {
        run_harden(&layout, &info, if yes { HardenMode::Fix } else { HardenMode::Ask })
    };
    if report.passed() { ExitCode::SUCCESS } else { ExitCode::from(2) }
}

/// 服务入口。
pub fn service(user: bool) -> ExitCode {
    let layout = if user || std::env::var_os("PASSMANAGER_HOME").is_some() { Layout::user() } else { Layout::system() };
    #[cfg(windows)]
    if layout.mode == Mode::System {
        return windows::run_service();
    }
    #[cfg(target_os = "macos")]
    if let Err(e) = pm_service::macos_root_phase(&layout) {
        return fail(e);
    }
    match pm_service::run(layout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

/// 服务启动前以 root/SYSTEM 执行：准备 socket 目录、生成安全检查报告（只检查不修改）。
pub fn service_prepare() -> ExitCode {
    let layout = Layout::system();
    let info = match InstallInfo::load(&layout) {
        Ok(i) => i,
        Err(e) => return fail(format!("读取安装信息失败：{e}")),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(Some(u)) = nix::unistd::User::from_name(&info.service_user) {
            let _ = std::fs::create_dir_all(&layout.run_dir);
            let gid = info.client_gid.map(nix::unistd::Gid::from_raw).unwrap_or(u.gid);
            let _ = nix::unistd::chown(&layout.run_dir, Some(u.uid), Some(gid));
            let _ = std::fs::set_permissions(&layout.run_dir, std::fs::Permissions::from_mode(0o750));
        }
    }
    #[cfg(windows)]
    let _ = std::fs::create_dir_all(&layout.run_dir);
    let report = harden::check(&Ctx { layout: &layout, info: &info });
    if let Err(e) = report.store(&layout) {
        return fail(format!("保存检查报告失败：{e}"));
    }
    ExitCode::SUCCESS
}

/// macOS：由已安装的程序在 root 身份下封存设备密钥（使钥匙串 ACL 信任该程序）。
pub fn seal_device_key_cmd(from_stdin: bool) -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        macos::seal_device_key(from_stdin)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = from_stdin;
        fail("仅用于 macOS 安装程序")
    }
}

/// macOS 升级：旧程序导出设备密钥。
pub fn export_device_key_cmd() -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        macos::export_device_key()
    }
    #[cfg(not(target_os = "macos"))]
    fail("仅用于 macOS 安装程序")
}

/// 复制可执行文件到安装路径（已在该路径运行时跳过）。
pub(crate) fn copy_self(dst: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if exe.canonicalize().ok() == dst.canonicalize().ok() {
        return Ok(());
    }
    if let Some(d) = dst.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let tmp = dst.with_extension("new");
    std::fs::copy(&exe, &tmp).map_err(|e| format!("复制程序失败：{e}"))?;
    std::fs::rename(&tmp, dst).map_err(|e| format!("安装程序失败：{e}"))?;
    Ok(())
}

/// 生成并封存设备密钥（已封存时跳过）。
#[cfg(target_os = "linux")]
pub(crate) fn provision_device_key(sealer: &dyn seal::Sealer) -> Result<(), String> {
    if sealer.is_provisioned() {
        return Ok(());
    }
    let key = zeroize::Zeroizing::new(pm_crypto::rng::random_array::<32>().map_err(|e| e.to_string())?);
    let mut rand = |b: &mut [u8]| pm_crypto::rng::fill(b).map_err(std::io::Error::other);
    sealer.seal(&key, &mut rand).map_err(|e| format!("封存设备密钥失败：{e}"))
}

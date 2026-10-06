//! Windows 安装：Windows 服务（虚拟账户 NT SERVICE\PassManager）+ DPAPI/TPM 封存。

use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Duration;

use pm_platform::seal;
use pm_platform::{InstallInfo, Layout, Mode};
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::{InstallOpts, copy_self, fail, finish_install};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SERVICE: &str = "PassManager";
const TASK: &str = "PassManagerSecurityCheck";

fn bin() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    pf.join("PassManager").join("PassManager.exe")
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    // 去掉可能来自 PowerShell 7 的 PSModulePath，避免 Windows PowerShell 5 加载内置模块失败。
    let out = Command::new(cmd)
        .args(args)
        .env_remove("PSModulePath")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into())
    } else {
        Err(format!(
            "{cmd} {}: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

pub fn install(opts: &InstallOpts) -> ExitCode {
    if !pm_platform::process::is_elevated() {
        // 双击运行：请求一次 UAC 提权，以提权身份重新运行安装程序。
        if opts.password_stdin {
            return fail("非交互安装需要在已提权的终端中运行。");
        }
        let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
        let st = Command::new("powershell.exe")
            .env_remove("PSModulePath")
            .args(["-NoProfile", "-Command", &format!("Start-Process -FilePath '{exe}' -ArgumentList 'install' -Verb RunAs -Wait")])
            .status();
        return if st.map(|s| s.success()).unwrap_or(false) { ExitCode::SUCCESS } else { fail("需要管理员权限") };
    }
    let layout = Layout::system();
    let dst = bin();
    println!("== 安装 PassManager（系统模式）==");
    if let Err(e) = copy_self(&dst) {
        return fail(e);
    }
    println!("  · 程序：{}", dst.display());
    if let Err(e) = std::fs::create_dir_all(&layout.run_dir) {
        return fail(e.to_string());
    }
    // 日常使用的账户：默认为运行安装程序的账户，也可用 --client-user 指定。
    let (client, client_sid) = match &opts.client_user {
        Some(name) => {
            let sid = run(
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "(New-Object System.Security.Principal.NTAccount('{name}')).Translate([System.Security.Principal.SecurityIdentifier]).Value"
                    ),
                ],
            );
            match sid {
                Ok(s) => (name.clone(), Some(s.trim().to_string())),
                Err(e) => return fail(format!("找不到账户 {name}：{e}")),
            }
        }
        None => (std::env::var("USERNAME").unwrap_or_default(), pm_platform::process::current_user_sid()),
    };
    let previous = InstallInfo::load(&layout).ok();
    let (sealer, _) = match previous.as_ref().and_then(|p| seal::by_method(&p.seal_method, &layout)) {
        Some(s) => (s, None),
        None => seal::best_available(&layout),
    };
    let info = InstallInfo {
        mode: Mode::System,
        client_user: client,
        client_uid: None,
        client_gid: None,
        client_sid,
        service_user: format!(r"NT SERVICE\{SERVICE}"),
        seal_method: sealer.method().into(),
        seal_level: sealer.level(),
        binary: dst.display().to_string(),
    };
    if let Err(e) = info.store(&layout) {
        return fail(e.to_string());
    }
    println!("  · 设备密钥：{}（服务首次启动时生成）", sealer.describe());

    let bin_path = format!("\"{}\" service", dst.display());
    let _ = run("sc.exe", &["stop", SERVICE]);
    let _ = run("sc.exe", &["delete", SERVICE]);
    std::thread::sleep(Duration::from_secs(1));
    if let Err(e) = run(
        "sc.exe",
        &[
            "create",
            SERVICE,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "obj=",
            &format!(r"NT SERVICE\{SERVICE}"),
            "DisplayName=",
            "PassManager",
        ],
    ) {
        return fail(e);
    }
    let _ = run("sc.exe", &["sidtype", SERVICE, "unrestricted"]);
    let _ = run("sc.exe", &["failure", SERVICE, "reset=", "60", "actions=", "restart/5000"]);
    let _ = run(
        "schtasks.exe",
        &["/Create", "/F", "/TN", TASK, "/SC", "ONSTART", "/RU", "SYSTEM", "/TR", &format!("\"{}\" service-prepare", dst.display())],
    );
    // 先以管理员身份收紧 PassManager 自己的数据目录与程序文件 ACL（授予服务 SID），再启动服务。
    // 这里只修改 PassManager 自己的文件；账户相关的修改在 finish_install 中经用户确认后执行。
    let ctx = pm_platform::harden::Ctx { layout: &layout, info: &info };
    let mut pre = pm_platform::harden::check(&ctx);
    pre.findings.retain(|f| f.id == "data_dir" || f.id == "binary");
    for l in pm_platform::harden::fix(&ctx, &pre) {
        println!("  · {l}");
    }
    let _ = Command::new(&dst).arg("service-prepare").creation_flags(CREATE_NO_WINDOW).status();
    if let Err(e) = run("sc.exe", &["start", SERVICE]) {
        return fail(e);
    }
    println!("  · 已启动 Windows 服务 {SERVICE}");
    finish_install(&layout, &info, None, opts, None)
}

pub fn uninstall(_layout: &Layout, _info: Option<&InstallInfo>) {
    let _ = run("sc.exe", &["stop", SERVICE]);
    std::thread::sleep(Duration::from_secs(1));
    let _ = run("sc.exe", &["delete", SERVICE]);
    let _ = run("schtasks.exe", &["/Delete", "/F", "/TN", TASK]);
    let _ = std::fs::remove_file(bin());
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let handler = |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            pm_service::request_shutdown();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(SERVICE, handler) else { return };
    let mk = |state, accept| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = status.set_service_status(mk(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN));
    if let Err(e) = pm_service::run(Layout::system()) {
        eprintln!("{e}");
    }
    let _ = status.set_service_status(mk(ServiceState::Stopped, ServiceControlAccept::empty()));
}

pub fn run_service() -> ExitCode {
    match service_dispatcher::start(SERVICE, ffi_service_main) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(format!("必须由 Windows 服务管理器启动：{e}")),
    }
}

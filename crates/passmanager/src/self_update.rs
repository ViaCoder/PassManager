//! 客户端运行前自动更新（Linux / macOS）。
//!
//! 已注册的客户端在运行 MCP、lookup、http、ssh、scp、run 等命令之前，最多每 10 分钟问一次服务器：
//! 服务器正在运行的正式发布（见 `pm_proto::update`）比自己新时，经已经固定指纹的双层加密通道取回程序，
//! 然后依次：
//! 1. 再核对一遍版本（只升不降）和 SHA-256；
//! 2. 写到程序所在目录的临时文件（0755），运行它的 `build-info`，必须报告同一个版本和发布标签；
//! 3. 把当前程序留一份为 `.PassManager.previous`，再把新程序原子地换到原来的位置；
//! 4. 用同样的参数重新执行新程序（带上 [`ENV_DONE`]，新程序不再检查）。
//!
//! 只有自己也是正式发布构建时才自动更新（开发构建从不被替换）。连不上服务器、服务器太旧或没有更新时什么都不说，
//! 照常运行；拿到了更新却装不上（例如目录不可写）时在标准错误输出一行原因。设置 [`ENV_OFF`] 可以关掉。

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pm_proto::update::{ClientUpdateView, client_targets, newer};

/// 设置为任意非空值时不自动更新。
pub const ENV_OFF: &str = "PASSMANAGER_NO_AUTO_UPDATE";
/// 刚更新并重新执行过：不再检查（防止循环）。值是新版本。
pub const ENV_DONE: &str = "PASSMANAGER_UPDATED";
/// 上次检查的时间（Unix 秒），放在客户端配置目录里。
const STAMP_FILE: &str = "update-check";
/// 两次检查的最短间隔。
const EVERY: Duration = Duration::from_secs(600);
/// 运行新程序 `build-info` 的时间上限。
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// 一次检查的结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 已经换成了这个版本（程序路径）。
    Updated(String, PathBuf),
    /// 没有更新可用。
    Current,
}

/// 运行前调用：需要时检查并更新，更新成功就重新执行新程序（不返回）；其他情况照常返回。
pub fn before_run() {
    // 关掉了、刚更新过、或者这个平台不支持：不检查
    if env_set(ENV_OFF) || env_set(ENV_DONE) || client_targets().is_empty() {
        return;
    }
    // 自己必须是正式发布构建
    let own = pm_service::build_info();
    if own.pinned().is_none() {
        return;
    }
    // 测试布局（设了 PASSMANAGER_HOME、没有指定远程配置目录）与没有注册（没有远程配置）：不检查
    if std::env::var_os("PASSMANAGER_HOME").is_some() && std::env::var_os("PASSMANAGER_CONFIG_DIR").is_none() {
        return;
    }
    let d = crate::remote::dir();
    let Some(Ok(cfg)) = crate::remote::load_in(&d) else { return };
    // 距上次检查不到 10 分钟：不检查；先记下这次的时间，并发运行的其他进程就不会一起去问
    let stamp = d.join(STAMP_FILE);
    let now = unix_now();
    if !due(std::fs::read_to_string(&stamp).ok().as_deref(), now) {
        return;
    }
    let _ = pm_platform::paths::write_atomic(&stamp, now.to_string().as_bytes(), 0o600);
    // 问服务器；连不上或服务器不认识这个请求时静默（后面的命令自己会报连接错误）
    let Ok(offer) = fetch(&d, &cfg, &own.version) else { return };
    match apply(offer, &own.version) {
        Ok(Outcome::Updated(v, exe)) => {
            eprintln!("PassManager：已自动更新 {} → {v}（服务器 {} 确认的正式发布）", own.version, cfg.server);
            reexec(&exe, &v);
        }
        Ok(Outcome::Current) => {}
        Err(m) => eprintln!("PassManager：自动更新没有完成（{m}），继续使用 {}。", own.version),
    }
}

/// `passmanager self-update`：不管间隔，立即检查一次并说明结果。
pub fn cmd() -> ExitCode {
    let own = pm_service::build_info();
    if client_targets().is_empty() {
        return crate::install::fail("自动更新只支持 Linux 与 macOS。");
    }
    if own.pinned().is_none() {
        return crate::install::fail(format!("这是开发构建（{}），不会被自动更新替换。", own.version));
    }
    let d = crate::remote::dir();
    let cfg = match crate::remote::load_in(&d) {
        Some(Ok(c)) => c,
        Some(Err(m)) => return crate::install::fail(m),
        None => return crate::install::fail("这台机器还没有注册到 PassManager 服务器（passmanager enroll）。"),
    };
    let _ = pm_platform::paths::write_atomic(&d.join(STAMP_FILE), unix_now().to_string().as_bytes(), 0o600);
    let offer = match fetch(&d, &cfg, &own.version) {
        Ok(o) => o,
        Err(m) => return crate::install::fail(format!("检查更新失败：{m}")),
    };
    match apply(offer, &own.version) {
        Ok(Outcome::Updated(v, exe)) => {
            println!("已更新 {} → {v}（服务器 {} 确认的正式发布）：{}", own.version, cfg.server, exe.display());
            ExitCode::SUCCESS
        }
        Ok(Outcome::Current) => {
            println!("已是最新：{}（服务器 {} 没有更新的正式发布）", own.version, cfg.server);
            ExitCode::SUCCESS
        }
        Err(m) => crate::install::fail(format!("更新没有完成：{m}")),
    }
}

/// 环境变量是否设置为非空值。
fn env_set(k: &str) -> bool {
    std::env::var_os(k).is_some_and(|v| !v.is_empty())
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 是否到了该检查的时候：没有记录、记录不是数字、已过间隔，或记录在将来（时钟被调过）。
pub fn due(stamp: Option<&str>, now: u64) -> bool {
    match stamp.and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(t) if t <= now => now - t >= EVERY.as_secs(),
        // 记录比现在晚一分钟以上：时钟被往回调过，重新检查
        Some(t) => t > now + 60,
        None => true,
    }
}

/// 问服务器有没有更新：返回服务器给的更新（没有时为 None）。
fn fetch(d: &Path, cfg: &crate::remote::RemoteConfig, have: &str) -> Result<Option<ClientUpdateView>, String> {
    let mut c = crate::remote::connect_in(d, cfg).map_err(|e| e.message)?;
    let req = pm_proto::Request::ClientUpdate { targets: client_targets().iter().map(|t| t.to_string()).collect(), have: have.into() };
    c.call_as::<Option<ClientUpdateView>>(&req).map_err(|e| format!("{}: {}", e.code, e.message))
}

/// 有更新就装到当前程序的位置（见模块说明的第 1–3 步）。
fn apply(offer: Option<ClientUpdateView>, own: &str) -> Result<Outcome, String> {
    let Some(v) = offer else { return Ok(Outcome::Current) };
    let exe = current_exe()?;
    install_at(&exe, &v, own)?;
    Ok(Outcome::Updated(v.version, exe))
}

/// 当前程序的真实路径（解开 `passmanager` → `PassManager` 这样的符号链接）。
fn current_exe() -> Result<PathBuf, String> {
    let p = std::env::current_exe().map_err(|e| format!("找不到当前程序：{e}"))?;
    std::fs::canonicalize(&p).map_err(|e| format!("找不到当前程序 {}：{e}", p.display()))
}

/// 把更新装到 `exe`：核对版本与 SHA-256 → 写临时文件 → 试运行 `build-info` → 留旧程序 → 原子替换。
pub fn install_at(exe: &Path, v: &ClientUpdateView, own: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // 1. 只升不降；SHA-256 必须一致
    if !newer(&v.version, own) {
        return Err(format!("服务器给的 {} 不比当前的 {own} 新", v.version));
    }
    let bin = v.binary()?;
    if !hex::encode(pm_crypto::sha256(&bin)).eq_ignore_ascii_case(&v.sha256) {
        return Err("收到的程序与服务器给出的 SHA-256 不一致".into());
    }
    // 2. 临时文件放在同一个目录（之后的改名才是原子的），名字带进程号，并发的进程互不干扰
    let dir = exe.parent().ok_or("程序路径没有上级目录")?;
    let tmp = dir.join(format!(".PassManager.update-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let written = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o755).open(&tmp)?;
        f.write_all(&bin)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("不能写入 {}：{e}", dir.display()));
    }
    // 试运行：必须报告同一个版本和发布标签
    if let Err(m) = probe(&tmp, &v.version) {
        let _ = std::fs::remove_file(&tmp);
        return Err(m);
    }
    // 3. 留一份旧程序（硬链接，不行就复制；失败不影响更新），再原子替换
    let prev = dir.join(".PassManager.previous");
    let _ = std::fs::remove_file(&prev);
    if std::fs::hard_link(exe, &prev).is_err() {
        let _ = std::fs::copy(exe, &prev);
    }
    if let Err(e) = std::fs::rename(&tmp, exe) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("不能替换 {}：{e}", exe.display()));
    }
    Ok(())
}

/// 运行新程序的 `build-info`，输出里必须有 `version <版本>` 和 `tag v<版本>` 两行；最多等 [`PROBE_TIMEOUT`]。
fn probe(bin: &Path, version: &str) -> Result<(), String> {
    use std::io::Read;
    // 刚写完的文件：别的线程恰好在 fork 时会短暂报 "Text file busy"，稍等重试几次
    let mut tries = 0;
    let mut child = loop {
        let r = std::process::Command::new(bin)
            .arg("build-info")
            .env(ENV_OFF, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        match r {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 5 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            r => break r.map_err(|e| format!("新程序不能运行：{e}"))?,
        }
    };
    // 等它结束（输出只有三行，不会把管道写满）
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() < PROBE_TIMEOUT => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("新程序没有按时结束".into());
            }
        }
    };
    let mut out = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    let want_v = format!("version {version}");
    let want_t = format!("tag v{version}");
    if status.success() && lines.contains(&want_v.as_str()) && lines.contains(&want_t.as_str()) {
        Ok(())
    } else {
        Err(format!("新程序报告的版本不是正式发布 {version}"))
    }
}

/// 用同样的参数重新执行新程序；失败时说明一句并继续用当前进程（旧版本）运行。
fn reexec(exe: &Path, version: &str) {
    use std::os::unix::process::CommandExt;
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_else(|| exe.as_os_str().to_owned());
    let e = std::process::Command::new(exe).arg0(argv0).args(args).env(ENV_DONE, version).exec();
    eprintln!("PassManager：不能启动新程序（{e}），这次继续使用旧版本。");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_checks_interval_and_clock_changes() {
        let now = 1_800_000_000;
        assert!(due(None, now), "没有记录");
        assert!(due(Some("garbage"), now));
        assert!(!due(Some(&now.to_string()), now), "刚检查过");
        assert!(!due(Some(&(now - 599).to_string()), now));
        assert!(due(Some(&(now - 600).to_string()), now));
        assert!(due(Some(&format!(" {}\n", now - 3600)), now), "允许空白");
        assert!(!due(Some(&(now + 30).to_string()), now), "稍微在将来：时钟误差");
        assert!(due(Some(&(now + 3600).to_string()), now), "远在将来：时钟被往回调过");
    }

    /// 写一个假的"新程序"：shell 脚本，`build-info` 时输出给定的内容。
    fn fake_bin(body: &str) -> Vec<u8> {
        format!("#!/bin/sh\n[ \"$1\" = build-info ] || exit 9\n{body}\n").into_bytes()
    }

    fn view(version: &str, bin: &[u8]) -> ClientUpdateView {
        ClientUpdateView::new(version, "x86_64-unknown-linux-gnu", &hex::encode(pm_crypto::sha256(bin)), bin)
    }

    #[test]
    fn install_at_replaces_after_checks() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("PassManager");
        std::fs::write(&exe, b"old").unwrap();
        let good = fake_bin("printf 'version 0.3.11-rc.24\\ntag v0.3.11-rc.24\\ncommit %040d\\n' 0");
        install_at(&exe, &view("0.3.11-rc.24", &good), "0.3.11-rc.23").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), good);
        // 旧程序留了一份，没有留下临时文件，新程序可执行
        assert_eq!(std::fs::read(t.path().join(".PassManager.previous")).unwrap(), b"old");
        let names: Vec<_> = std::fs::read_dir(t.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert!(!names.iter().any(|n| n.contains("update-")), "{names:?}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777, 0o755);
    }

    #[test]
    fn install_at_refuses_bad_updates() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("PassManager");
        let unchanged = |what: &str| {
            assert_eq!(std::fs::read(t.path().join("PassManager")).unwrap(), b"old", "{what}");
            let n = std::fs::read_dir(t.path()).unwrap().count();
            assert_eq!(n, 1, "{what}：没有留下别的文件");
        };
        std::fs::write(&exe, b"old").unwrap();
        let good = fake_bin("printf 'version 0.3.11-rc.24\\ntag v0.3.11-rc.24\\n'");
        // 不比当前新：拒绝（从不降级）
        assert!(install_at(&exe, &view("0.3.11-rc.24", &good), "0.3.11-rc.24").unwrap_err().contains("不比"));
        assert!(install_at(&exe, &view("0.3.11-rc.24", &good), "0.3.11").is_err());
        unchanged("同版本、降级");
        // SHA-256 不一致
        let mut v = view("0.3.11-rc.24", &good);
        v.sha256 = "00".repeat(32);
        assert!(install_at(&exe, &v, "0.3.11-rc.23").unwrap_err().contains("SHA-256"));
        unchanged("SHA-256");
        // 新程序报告的版本不对、没有发布标签、运行失败、不是可执行文件
        for (what, bin) in [
            ("版本不对", fake_bin("printf 'version 0.3.11-rc.25\\ntag v0.3.11-rc.25\\n'")),
            ("开发构建", fake_bin("printf 'version 0.3.11-rc.24\\ntag none (development build)\\n'")),
            ("退出码非 0", fake_bin("printf 'version 0.3.11-rc.24\\ntag v0.3.11-rc.24\\n'; exit 1")),
            ("不是程序", b"\x00\x01garbage".to_vec()),
        ] {
            assert!(install_at(&exe, &view("0.3.11-rc.24", &bin), "0.3.11-rc.23").is_err(), "{what}");
            unchanged(what);
        }
    }

    #[test]
    fn install_at_reports_unwritable_dir() {
        // root 能写任何目录，这一项只在普通用户下有意义
        if unsafe { libc_geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("PassManager");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let good = fake_bin("printf 'version 0.3.11-rc.24\\ntag v0.3.11-rc.24\\n'");
        let e = install_at(&exe, &view("0.3.11-rc.24", &good), "0.3.11-rc.23").unwrap_err();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(e.contains("不能写入"), "{e}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
    }

    unsafe extern "C" {
        #[link_name = "geteuid"]
        fn libc_geteuid() -> u32;
    }
}

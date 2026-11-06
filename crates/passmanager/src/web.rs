//! `passmanager web`：在自己的电脑上一步打开网页管理。
//!
//! 经本机已注册的 PassManager 通道 ssh 到服务器运行 `passmanager login --auto`，拿到一次性链接后在浏览器里打开，自动进入管理界面。
//! 链接是令牌：不放在命令行参数里（`/proc` 对其他用户可见），也不打印；写进一个 0600 的跳转页，打开这个文件，几秒后删除。
//!
//! `--install` 注册 `passmanager-web://` 协议，登录页的“一键登录”按钮由它接管。处理程序**不接收链接里的任何内容**：
//! 网页只能触发这一条固定的命令，传不进参数。

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use serde_json::json;

/// 记住 `--ssh` 的文件（只是地址，不含秘密）。
const TARGET_FILE: &str = "web-ssh";
/// 跳转页的文件名。放在主目录下而不是隐藏目录：snap 版浏览器读不了隐藏目录。
const PAGE_FILE: &str = "passmanager-login.html";
/// 浏览器打开后，跳转页保留多久。
const KEEP_OPENED: Duration = Duration::from_secs(15);
/// 打不开浏览器时，留给用户手动打开的时间（与链接的有效期相同）。
const KEEP_MANUAL: Duration = Duration::from_secs(120);

/// `passmanager login --auto` 的输出里的登录链接；形状不对时 None（不把任意内容写进页面）。
pub fn login_url(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("https://") && l.contains("/l/"))
        .filter(|l| l.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'/' | b'.' | b'-' | b'_' | b'%')))
        .map(str::to_string)
}

/// 跳转页：立刻转到登录链接，不发送 Referer。
pub fn redirect_page(url: &str) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\">\
         <meta http-equiv=\"refresh\" content=\"0;url={url}\"><title>PassManager</title>"
    )
}

/// 从按钮启动时没有终端：错误显示在浏览器里。
pub fn error_page(msg: &str) -> String {
    let m = msg.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>PassManager</title><h1>无法登录网页管理</h1><p>{m}</p>\
         <p>在终端运行 <code>passmanager web --ssh root@&lt;服务器&gt;</code> 可以看到详细信息。</p>"
    )
}

/// 要连接的 SSH 目标：命令行 > 上次记住的 > 注册的服务器。
pub fn pick_target(given: Option<&str>, saved: Option<&str>, server: Option<&str>) -> Option<String> {
    given.or(saved).map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).or_else(|| server.map(|s| format!("root@{s}")))
}

/// 这个平台打开文件的命令。
pub fn opener() -> (&'static str, &'static [&'static str]) {
    if cfg!(target_os = "macos") {
        ("open", &[])
    } else if cfg!(windows) {
        ("cmd", &["/C", "start", ""])
    } else {
        ("xdg-open", &[])
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Linux 的协议处理程序。Exec 里没有 %u：链接内容不会传给程序。
pub fn desktop_entry(exe: &str) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=PassManager Web\nExec=\"{exe}\" web\nTerminal=false\nNoDisplay=true\n\
         MimeType=x-scheme-handler/passmanager-web;\n"
    )
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// macOS 协议处理程序的 Info.plist。
pub fn mac_plist() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
     <key>CFBundleIdentifier</key><string>com.viacoder.passmanager.web</string>\
     <key>CFBundleName</key><string>PassManager Web</string>\
     <key>CFBundleExecutable</key><string>passmanager-web</string>\
     <key>CFBundlePackageType</key><string>APPL</string>\
     <key>LSBackgroundOnly</key><true/>\
     <key>CFBundleURLTypes</key><array><dict>\
     <key>CFBundleURLName</key><string>PassManager Web</string>\
     <key>CFBundleURLSchemes</key><array><string>passmanager-web</string></array>\
     </dict></array></dict></plist>\n"
        .to_string()
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// macOS 应用包里的启动脚本（不转发参数）。
pub fn mac_launcher(exe: &str) -> String {
    format!("#!/bin/sh\nexec '{}' web\n", exe.replace('\'', "'\\''"))
}

fn home() -> PathBuf {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

/// 写页面：只有本人可读。
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(text.as_bytes())
}

/// 在浏览器里打开本地页面，返回是否成功。
fn open_page(path: &Path) -> bool {
    let (cmd, args) = opener();
    Command::new(cmd).args(args).arg(path).status().is_ok_and(|s| s.success())
}

/// 经 PassManager 通道到服务器取一次性链接。
fn fetch_link(target: &str) -> Result<String, String> {
    let v = crate::mcp::call_tool("ssh", &json!({"target": target, "command": "passmanager login --auto"}))
        .map_err(|e| format!("{}: {}", e.code, e.message))?;
    let code = v.get("exit_code").and_then(|c| c.as_i64()).unwrap_or(-1);
    let out = v.get("stdout").and_then(|s| s.as_str()).unwrap_or_default();
    match login_url(out) {
        Some(u) if code == 0 => Ok(u),
        _ => Err(format!("服务器上的 passmanager login --auto 没有给出链接（退出码 {code}），服务器需要 0.3.11-rc.7 或更新")),
    }
}

/// `passmanager web [--ssh 目标]`
pub fn run(ssh: Option<String>) -> ExitCode {
    let file = crate::remote::write_dir().join(TARGET_FILE);
    let saved = std::fs::read_to_string(&file).ok();
    let target = pick_target(ssh.as_deref(), saved.as_deref(), crate::remote::server_host().as_deref());
    let page = home().join(PAGE_FILE);
    let result = match &target {
        None => Err("这台电脑还没有注册到 PassManager（passmanager enroll）".to_string()),
        Some(t) => fetch_link(t),
    };
    let link = match result {
        Ok(u) => u,
        Err(m) => {
            eprintln!("错误：{m}");
            // 从按钮启动时看不到终端，把原因显示在浏览器里。
            if write_private(&page, &error_page(&m)).is_ok() && open_page(&page) {
                std::thread::sleep(KEEP_OPENED);
            }
            let _ = std::fs::remove_file(&page);
            return ExitCode::from(1);
        }
    };
    // 成功过的目标才记住。
    if let (Some(given), Some(dir)) = (ssh.as_deref(), file.parent()) {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(&file, given);
    }
    if let Err(e) = write_private(&page, &redirect_page(&link)) {
        eprintln!("错误：无法写入 {}：{e}", page.display());
        return ExitCode::from(1);
    }
    let opened = open_page(&page);
    if !opened {
        eprintln!("无法自动打开浏览器：请在 2 分钟内用浏览器打开 {}", page.display());
    }
    std::thread::sleep(if opened { KEEP_OPENED } else { KEEP_MANUAL });
    let _ = std::fs::remove_file(&page);
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
fn register(exe: &str) -> Result<String, String> {
    let dir = home().join(".local/share/applications");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let f = dir.join("passmanager-web.desktop");
    std::fs::write(&f, desktop_entry(exe)).map_err(|e| e.to_string())?;
    let _ = Command::new("update-desktop-database").arg(&dir).status();
    let ok = Command::new("xdg-mime").args(["default", "passmanager-web.desktop", "x-scheme-handler/passmanager-web"]).status();
    match ok {
        Ok(s) if s.success() => Ok(f.display().to_string()),
        _ => Err("xdg-mime 失败（这台机器有桌面环境吗？）".into()),
    }
}

#[cfg(target_os = "macos")]
fn register(exe: &str) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;
    let app = home().join("Applications/PassManager Web.app");
    let macos = app.join("Contents/MacOS");
    std::fs::create_dir_all(&macos).map_err(|e| e.to_string())?;
    std::fs::write(app.join("Contents/Info.plist"), mac_plist()).map_err(|e| e.to_string())?;
    let run = macos.join("passmanager-web");
    std::fs::write(&run, mac_launcher(exe)).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let ls = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
    match Command::new(ls).args(["-f"]).arg(&app).status() {
        Ok(s) if s.success() => Ok(app.display().to_string()),
        _ => Err("lsregister 失败".into()),
    }
}

#[cfg(windows)]
fn register(exe: &str) -> Result<String, String> {
    let key = r"HKCU\Software\Classes\passmanager-web";
    let command = format!("\"{exe}\" web");
    let steps: [Vec<&str>; 3] = [
        vec!["add", key, "/ve", "/d", "URL:PassManager Web", "/f"],
        vec!["add", key, "/v", "URL Protocol", "/d", "", "/f"],
        vec!["add", r"HKCU\Software\Classes\passmanager-web\shell\open\command", "/ve", "/d", &command, "/f"],
    ];
    for s in &steps {
        if !Command::new("reg").args(s).status().is_ok_and(|r| r.success()) {
            return Err("reg add 失败".into());
        }
    }
    Ok(key.into())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn register(_: &str) -> Result<String, String> {
    Err("这个系统不支持注册协议".into())
}

/// `passmanager web --install`
pub fn install() -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(p) => p.display().to_string(),
        Err(e) => return crate::install::fail(e.to_string()),
    };
    match register(&exe) {
        Ok(place) => {
            println!("已注册 passmanager-web:// 协议（{place}）。现在可以用登录页的“一键登录”按钮了。");
            ExitCode::SUCCESS
        }
        Err(e) => crate::install::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_url_takes_only_a_clean_link() {
        assert_eq!(login_url("https://pm.example.com:8120/l/AbC-_1\n").as_deref(), Some("https://pm.example.com:8120/l/AbC-_1"));
        assert_eq!(login_url("note\n  https://pm.example.com/l/x  \n").as_deref(), Some("https://pm.example.com/l/x"));
        for bad in
            ["", "https://pm.example.com/", "http://pm.example.com/l/x", "https://pm.example.com/l/x\"><script>", "https://e.com/l/a b"]
        {
            assert_eq!(login_url(bad), None, "{bad}");
        }
    }

    #[test]
    fn pages() {
        let p = redirect_page("https://pm.example.com/l/x");
        assert!(p.contains("content=\"0;url=https://pm.example.com/l/x\"") && p.contains("no-referrer"));
        let e = error_page("a <b> & c");
        assert!(e.contains("a &lt;b&gt; &amp; c") && !e.contains("<b>"));
    }

    #[test]
    fn target_order() {
        assert_eq!(pick_target(Some("root@a"), Some("root@b"), Some("c")).as_deref(), Some("root@a"));
        assert_eq!(pick_target(None, Some(" root@b\n"), Some("c")).as_deref(), Some("root@b"));
        assert_eq!(pick_target(None, None, Some("c")).as_deref(), Some("root@c"));
        assert_eq!(pick_target(None, Some("  "), Some("c")).as_deref(), Some("root@c"), "空文件不算");
        assert_eq!(pick_target(None, None, None), None);
    }

    #[test]
    fn handlers_never_forward_the_link() {
        let d = desktop_entry("/usr/bin/PassManager");
        assert!(d.contains("Exec=\"/usr/bin/PassManager\" web\n") && d.contains("x-scheme-handler/passmanager-web"));
        assert!(!d.contains("%u") && !d.contains("%U"), "链接内容不能传给程序");
        let m = mac_launcher("/a b/it's");
        assert!(m.contains("exec '/a b/it'\\''s' web\n") && !m.contains("$@") && !m.contains("$1"));
        assert!(mac_plist().contains("<string>passmanager-web</string>"));
    }

    #[test]
    fn opener_has_a_command() {
        assert!(!opener().0.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn page_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("p.html");
        std::fs::write(&f, "old").unwrap();
        write_private(&f, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

//! `passmanager run <命令> [参数…]`：只为这一条命令准备经服务器转发的认证，命令结束就全部清除。
//!
//! - git（HTTPS）：在 127.0.0.1 的随机端口上开一个临时转发口，路径令牌是一次性的。只通过环境变量
//!   （`GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`）告诉这条命令及其子进程里的 git：把
//!   `https://<主机>/` 改写到这个转发口。不写任何 git 配置文件；令牌只在这个进程树的环境里（`/proc/<pid>/environ`
//!   只有本人和 root 能读）。请求照旧经双层加密通道交给服务器，由服务器带上访问令牌：令牌从不离开服务器。
//! - ssh（以及 scp、rsync、经 SSH 的 git）：在只有本人能访问的临时目录里开一个 agent 套接字，经 `SSH_AUTH_SOCK`
//!   交给这条命令；签名照旧由服务器完成：私钥从不离开服务器。
//! - 命令结束后转发口关闭、临时目录删除。按 Ctrl-C 时信号交给命令本身，本进程照常清理。退出码与命令相同。
//! - 上次异常退出留下的临时目录（目录名里的进程已经不存在）在下次运行时删除。

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};

/// 临时目录名的前缀（后面接进程号）
const DIR_PREFIX: &str = "passmanager-run-";

/// 这条命令要用的 git 环境变量：接在已有的 `GIT_CONFIG_COUNT` 之后，为每个主机追加一条 insteadOf。
pub fn git_env(existing: Option<&str>, port: u16, token: &str, hosts: &[String]) -> Vec<(String, String)> {
    // 已有的条数（不是数字时按 0 算；那种写法 git 自己也会报错）
    let start: usize = existing.and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    let mut out = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        // 与 git-proxy 相同的改写格式：http://127.0.0.1:<端口>/<令牌>/https/<主机>/
        out.push((format!("GIT_CONFIG_KEY_{}", start + i), format!("url.http://127.0.0.1:{port}/{token}/https/{h}/.insteadOf")));
        out.push((format!("GIT_CONFIG_VALUE_{}", start + i), format!("https://{h}/")));
    }
    if !hosts.is_empty() {
        out.push(("GIT_CONFIG_COUNT".into(), (start + hosts.len()).to_string()));
    }
    out
}

/// 临时目录放在哪里：优先 `$XDG_RUNTIME_DIR`（只有本人能访问，重启后清空），否则放在配置目录里。
pub fn base_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => crate::remote::dir(),
    }
}

/// 删除上次异常退出留下的临时目录（目录名里的进程已经不存在），返回删除的个数。
pub fn clean_stale(base: &Path, alive: &dyn Fn(u32) -> bool) -> usize {
    let Ok(rd) = std::fs::read_dir(base) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.strip_prefix(DIR_PREFIX)).and_then(|p| p.parse::<u32>().ok()) else { continue };
        if !alive(pid) && std::fs::remove_dir_all(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}

/// 进程是否还在。
fn alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
    // SAFETY: 信号 0 只检查进程是否存在，不发送任何信号。
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// 退出状态转成退出码：正常退出用它自己的码；被信号终止时用 128 + 信号编号（和 shell 一样）。
pub fn exit_code(status: ExitStatus) -> u8 {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(c), _) => (c & 0xff) as u8,
        (None, Some(sig)) => u8::try_from(128 + sig).unwrap_or(255),
        _ => 1,
    }
}

/// 启动失败时的退出码：找不到命令 127，不能执行 126（和 shell 一样），其他 1。
pub fn spawn_error_code(kind: std::io::ErrorKind) -> u8 {
    match kind {
        std::io::ErrorKind::NotFound => 127,
        std::io::ErrorKind::PermissionDenied => 126,
        _ => 1,
    }
}

/// 本进程忽略 Ctrl-C 与 Ctrl-\，让信号只作用于命令本身。必须在子进程启动之后调用：忽略状态会被子进程继承。
fn ignore_interrupts() {
    // SAFETY: 只把两个信号的处理方式设为忽略，不注册任何处理函数。
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
}

/// 打开 git 转发口：随机端口、一次性令牌；返回要交给命令的环境变量。
fn start_git_relay(hosts: &[String]) -> Result<Vec<(String, String)>, String> {
    let token = crate::git_proxy::new_token()?;
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("无法打开本机转发口：{e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    let mut envs = git_env(std::env::var("GIT_CONFIG_COUNT").ok().as_deref(), port, &token, hosts);
    // 认证失败时不要让 git 在终端里索要口令（令牌在服务器上，本机输入也没用）
    if std::env::var_os("GIT_TERMINAL_PROMPT").is_none() {
        envs.push(("GIT_TERMINAL_PROMPT".into(), "0".into()));
    }
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let token = token.clone();
            std::thread::spawn(move || crate::git_proxy::serve_conn(s, &token, &crate::remote::connect_if_configured));
        }
    });
    Ok(envs)
}

/// 打开临时 agent 套接字（目录 0700、套接字 0600）；返回套接字路径。
fn start_agent(dir: &Path) -> Result<PathBuf, String> {
    let sock = dir.join("agent.sock");
    let l = crate::ssh_agent::bind(&sock)?;
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            std::thread::spawn(move || crate::ssh_agent::serve_conn(s, &crate::ssh_agent::Remote));
        }
    });
    Ok(sock)
}

/// `passmanager run`：`hosts` 为空时用服务器上有 git 用途条目的主机。
pub fn run(hosts: Vec<String>, command: Vec<String>) -> ExitCode {
    if crate::remote::load_in(&crate::remote::dir()).is_none() {
        return crate::install::fail("没有远程配置：先运行 passmanager enroll '<注册码>'");
    }
    let Some((program, args)) = command.split_first() else {
        return crate::install::fail("用法：passmanager run <命令> [参数…]，例如 passmanager run git push");
    };
    let hosts = if hosts.is_empty() {
        crate::git_service::default_hosts().unwrap_or_else(|e| {
            eprintln!("[PassManager run] 无法取得 git 主机（{e}）：这条命令里的 git 不经 PassManager");
            vec![]
        })
    } else {
        hosts
    };
    let base = base_dir();
    clean_stale(&base, &alive);
    let dir = base.join(format!("{DIR_PREFIX}{}", std::process::id()));
    let mut envs = match start_agent(&dir) {
        Ok(sock) => vec![("SSH_AUTH_SOCK".to_string(), sock.display().to_string())],
        Err(e) => return crate::install::fail(e),
    };
    if !hosts.is_empty() {
        match start_git_relay(&hosts) {
            Ok(v) => envs.extend(v),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return crate::install::fail(e);
            }
        }
    }
    let code = match Command::new(program).args(args).envs(envs).spawn() {
        Ok(mut child) => {
            ignore_interrupts();
            child.wait().map(exit_code).unwrap_or(1)
        }
        Err(e) => {
            eprintln!("[PassManager run] 无法运行 {program}：{e}");
            spawn_error_code(e.kind())
        }
    };
    let _ = std::fs::remove_dir_all(&dir);
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_env_appends_after_existing_entries() {
        let hosts = vec!["github.com".to_string(), "git.example.com:8121".to_string()];
        let v = git_env(None, 4242, "ab", &hosts);
        assert_eq!(
            v,
            vec![
                ("GIT_CONFIG_KEY_0".into(), "url.http://127.0.0.1:4242/ab/https/github.com/.insteadOf".into()),
                ("GIT_CONFIG_VALUE_0".into(), "https://github.com/".into()),
                ("GIT_CONFIG_KEY_1".into(), "url.http://127.0.0.1:4242/ab/https/git.example.com:8121/.insteadOf".into()),
                ("GIT_CONFIG_VALUE_1".into(), "https://git.example.com:8121/".into()),
                ("GIT_CONFIG_COUNT".into(), "2".into()),
            ]
        );
        // 已有 3 条：从第 3 号开始追加，总数变成 4
        let v = git_env(Some(" 3 "), 1, "t", &hosts[..1]);
        assert_eq!(v[0].0, "GIT_CONFIG_KEY_3");
        assert_eq!(v.last().unwrap(), &("GIT_CONFIG_COUNT".to_string(), "4".to_string()));
        // 已有的值不是数字：按 0 算
        assert_eq!(git_env(Some("x"), 1, "t", &hosts[..1])[0].0, "GIT_CONFIG_KEY_0");
        // 没有主机：什么都不加（连 GIT_CONFIG_COUNT 也不改）
        assert!(git_env(Some("2"), 1, "t", &[]).is_empty());
    }

    #[test]
    fn stale_dirs_are_removed_only_for_dead_processes() {
        let base = std::env::temp_dir().join(format!("pm-run-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["passmanager-run-11", "passmanager-run-22", "passmanager-run-x", "other-33"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        // 11 已经不在，22 还在；名字不合规则的不动
        assert_eq!(clean_stale(&base, &|pid| pid == 22), 1);
        let mut left: Vec<String> =
            std::fs::read_dir(&base).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, ["other-33", "passmanager-run-22", "passmanager-run-x"]);
        // 目录不存在：0
        assert_eq!(clean_stale(&base.join("none"), &|_| false), 0);
        std::fs::remove_dir_all(&base).unwrap();
        // 本进程一定还在，进程号 0 之外的极大值一定不在
        assert!(alive(std::process::id()) && !alive(u32::MAX / 2));
    }

    #[test]
    fn exit_codes_follow_the_shell() {
        let st = |script: &str| Command::new("sh").args(["-c", script]).status().unwrap();
        assert_eq!(exit_code(st("exit 0")), 0);
        assert_eq!(exit_code(st("exit 7")), 7);
        // 被 SIGTERM（15）终止：128 + 15
        assert_eq!(exit_code(st("kill -TERM $$")), 143);
        assert_eq!(spawn_error_code(std::io::ErrorKind::NotFound), 127);
        assert_eq!(spawn_error_code(std::io::ErrorKind::PermissionDenied), 126);
        assert_eq!(spawn_error_code(std::io::ErrorKind::Other), 1);
    }

    #[test]
    fn tokens_are_fresh_hex() {
        let a = crate::git_proxy::new_token().unwrap();
        let b = crate::git_proxy::new_token().unwrap();
        assert!(a.len() == 32 && a.bytes().all(|c| c.is_ascii_hexdigit()) && a != b);
    }
}

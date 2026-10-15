//! `passmanager run` 端到端（Linux，真实 git 与 OpenSSH）：认证只为一条命令经服务器转发，命令结束就全部清除。
//! 覆盖：git push / clone（默认主机来自服务器上的 git 条目）、不写任何 git 配置文件、转发口与临时 agent 目录在命令结束后
//! 关闭和删除、ssh-add -L 与真实 ssh 登录经临时 agent 由服务器签名、退出码透传、PAT 不出现在客户端的任何输出里、未注册时报错。
#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::Ordering;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;

const PAT: &str = "ghp_FakePatForRunTests_0123456789abcdefXYZ";

/// 普通的 git（不经 PassManager），只用来准备仓库。
fn plain_git(home: &Path, dir: &Path, args: &[&str]) -> Output {
    Command::new("git").args(args).current_dir(dir).env("HOME", home).env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap()
}

#[test]
fn run_forwards_git_and_ssh_for_one_command() {
    if !have("git") {
        eprintln!("跳过：没有 git");
        return;
    }
    let env = Env::setup("run");
    // Agent 机器上的主目录（与 agent_cmd 设置的 HOME 相同）和测试自己的运行目录。
    let home = env.base.join("agent-home");
    std::fs::create_dir_all(&home).unwrap();
    let runtime = env.base.join("runtime");
    let run = |dir: &Path, args: &[&str]| -> Output {
        let mut all = vec!["run"];
        all.extend_from_slice(args);
        env.agent_cmd(&all)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("XDG_RUNTIME_DIR", &runtime)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };

    // 上游：TLS 上的 git http-backend，要求假 PAT；服务器上的条目只有 git 用途。
    let root = env.base.join("repos");
    std::fs::create_dir_all(&root).unwrap();
    assert!(plain_git(&home, &root, &["init", "-q", "--bare", "-b", "main", "repo.git"]).status.success());
    let (port, counts) = git_server(root.clone(), PAT);
    let upstream = format!("127.0.0.1:{port}");
    let o = env
        .run_stdin(&["import", "--name", "gitpat", "--domain", &upstream, "--ops", "git", "--self-signed"], format!("{PAT}\n").as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));

    // 工作区。
    let work = env.base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    assert!(plain_git(&home, &work, &["init", "-q", "-b", "main"]).status.success());
    std::fs::write(work.join("README"), "hello via run\n").unwrap();
    assert!(plain_git(&home, &work, &["add", "."]).status.success());
    assert!(
        plain_git(&home, &work, &["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init"]).status.success()
    );

    // push 与 clone：不写 --host，主机来自服务器上有 git 用途的条目。
    let url = format!("https://{upstream}/repo.git");
    let mut outputs = String::new();
    let o = run(&work, &["git", "push", "-q", &url, "main"]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "push: {}", stderr(&o));
    let o = run(&env.base, &["git", "clone", "-q", &url, "cloned"]);
    outputs += &(stdout(&o) + &stderr(&o));
    assert!(o.status.success(), "clone: {}", stderr(&o));
    assert_eq!(std::fs::read_to_string(env.base.join("cloned/README")).unwrap(), "hello via run\n");
    assert!(counts.authed.load(Ordering::SeqCst) >= 2, "上游的请求都带 PAT");
    assert_eq!(counts.rejected.load(Ordering::SeqCst), 0);

    // 没有写任何 git 配置文件。
    for f in [".gitconfig", ".config/git/config"] {
        assert!(!home.join(f).exists(), "不应写入 {f}");
    }

    // 命令里能看到改写规则和 agent 套接字；命令结束后转发口关闭、临时目录删除。
    let o = run(&env.base, &["sh", "-c", "printf '%s\\n%s\\n%s\\n' \"$GIT_CONFIG_COUNT\" \"$GIT_CONFIG_KEY_0\" \"$SSH_AUTH_SOCK\""]);
    let out = stdout(&o);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert_eq!(lines[0], "1");
    assert!(lines[1].ends_with(&format!("/https/{upstream}/.insteadOf")), "{out}");
    let relay: u16 = lines[1].strip_prefix("url.http://127.0.0.1:").unwrap().split('/').next().unwrap().parse().unwrap();
    let sock = std::path::PathBuf::from(lines[2]);
    assert!(sock.starts_with(&runtime), "临时目录在 XDG_RUNTIME_DIR 下：{}", sock.display());
    assert!(std::net::TcpStream::connect(("127.0.0.1", relay)).is_err(), "命令结束后转发口应已关闭");
    assert!(!sock.parent().unwrap().exists(), "命令结束后临时目录应已删除");

    // 退出码透传；找不到命令时 127。
    assert_eq!(run(&env.base, &["sh", "-c", "exit 7"]).status.code(), Some(7));
    assert_eq!(run(&env.base, &["definitely-not-a-command-pm-run"]).status.code(), Some(127));

    // ssh：临时 agent 由服务器签名（需要 OpenSSH）。
    if Path::new("/usr/sbin/sshd").exists() && have("ssh") && have("ssh-keygen") && have("ssh-add") {
        let kd = env.base.join("keys");
        std::fs::create_dir_all(&kd).unwrap();
        let (client_key, client_fp) = keygen(&kd, "srv", "");
        let sshd = start_sshd(&env.base.join("sshd"), &client_key.with_extension("pub"));
        let host_pub = std::fs::read_to_string(sshd.host_key.with_extension("pub")).unwrap();
        let pem = std::fs::read_to_string(&client_key).unwrap();
        let o = env.run_stdin(&["import", "--name", "srv", "--kind", "ssh-key", "--host-key", host_pub.trim()], pem.as_bytes());
        assert!(o.status.success() && stdout(&o).contains(&client_fp), "{}", stderr(&o));
        // ssh-add -L 经临时 agent 列出服务器上的公钥。
        let o = run(&env.base, &["ssh-add", "-L"]);
        assert!(o.status.success() && stdout(&o).trim_end().ends_with(" srv"), "{}{}", stdout(&o), stderr(&o));
        // 真实 ssh 登录。
        let user = String::from_utf8_lossy(&Command::new("id").arg("-un").output().unwrap().stdout).trim().to_string();
        let port = sshd.port.to_string();
        let target = format!("{user}@127.0.0.1");
        let o = run(
            &env.base,
            &[
                "ssh",
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "IdentityFile=/nonexistent-pm-test",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "LogLevel=ERROR",
                "-p",
                &port,
                &target,
                "echo run-ok-$((40+2))",
            ],
        );
        assert!(o.status.success() && stdout(&o).contains("run-ok-42"), "{}{}", stdout(&o), stderr(&o));
    } else {
        eprintln!("跳过 ssh 部分：需要 OpenSSH（sshd、ssh、ssh-keygen、ssh-add）");
    }

    // PAT 不出现在客户端的任何输出里；服务端有审计记录。
    assert!(!outputs.contains(PAT) && !outputs.contains(&STANDARD.encode(format!("x-access-token:{PAT}"))), "PAT 出现在客户端");
    assert!(!env.service_log().contains(PAT));
    assert!(env.service_log().contains("git-proxy: entry=gitpat"), "服务端审计");

    // 没有注册（空的配置目录）：报错并提示先 enroll。
    let empty = env.base.join("empty-config");
    std::fs::create_dir_all(&empty).unwrap();
    let o = env.agent_cmd(&["run", "true"]).env("PASSMANAGER_CONFIG_DIR", &empty).stdin(Stdio::null()).output().unwrap();
    assert!(!o.status.success() && stderr(&o).contains("enroll"), "{}", stderr(&o));
}

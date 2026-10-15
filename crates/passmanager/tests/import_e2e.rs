//! `passmanager import` 端到端（真实服务进程，Linux）：标准输入导入（单值多行、多字段含 CRLF），
//! 经 Agent 的 HTTP 请求证明服务端发出的字节与导入的完全一致（摘要服务只回 SHA-256），
//! 任何输出与服务日志里都不出现密钥；终端输入被拒绝、大小与空输入限制、重复与 --replace、
//! 非 root 拒绝、库锁定时报错、没有域名的条目显示"未绑定域名"。
#![cfg(target_os = "linux")]

mod common;

use std::process::{Command, Stdio};

use common::*;

const BLOB: &str = "-----BEGIN NOTE-----\nfirst line with symbols !@#$%^&*()\n  indented second line  \nthird=line\n-----END NOTE-----";
const USER: &str = "svc-account@example.com";
const PASS: &str = "Pa$$ w0rd with spaces & quotes'\"";

fn http_digest(env: &Env, port: u16, body: &str) -> (bool, String) {
    let url = format!("https://127.0.0.1:{port}/submit");
    let o = env.agent(&["http", "POST", &url, "-d", body]);
    (o.status.success(), stdout(&o) + &stderr(&o))
}

fn digest_of(s: &str) -> String {
    format!("sha256={}", hex(&pm_crypto::sha256(s.as_bytes())))
}

#[test]
fn import_from_stdin() {
    let env = Env::setup("import");
    let port = digest_server();
    let d = format!("127.0.0.1:{port}");
    let mut outputs = String::new();

    // ---- 单值、多行，原样保存（只去掉一个末尾换行） ----
    let o = env.run_stdin(&["import", "--name", "blob", "--domain", &d, "--self-signed"], format!("{BLOB}\n").as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o).trim(), format!("已导入 blob（{} 字节，1 个域名）", BLOB.len()));
    outputs += &(stdout(&o) + &stderr(&o));
    let (ok, out) = http_digest(&env, port, "{{blob}}");
    assert!(ok && out.contains(&digest_of(BLOB)), "{out}");
    outputs += &out;

    // ---- 多字段，CRLF 输入 ----
    let o = env.run_stdin(
        &["import", "--name", "creds", "--fields", "username,password", "--domain", &d, "--self-signed"],
        format!("{USER}\r\n{PASS}\r\n").as_bytes(),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o).trim(), format!("已导入 creds（{} 字节，1 个域名）", USER.len() + PASS.len()));
    outputs += &(stdout(&o) + &stderr(&o));
    let (ok, out) = http_digest(&env, port, "{{creds.username}}:{{creds.password}}");
    assert!(ok && out.contains(&digest_of(&format!("{USER}:{PASS}"))), "{out}");
    outputs += &out;
    // lookup 只给字段名（没有值、没有域名、没有备注）。
    let o = env.agent(&["lookup", "{{creds}}"]);
    let found = stdout(&o);
    assert!(found.contains("\"username\"") && found.contains("\"password\"") && !found.contains("127.0.0.1"), "{found}");
    outputs += &found;

    // ---- 回显服务：每个字段值、多行值的每一行、各种编码都被脱敏 ----
    let echo = echo_server();
    let ed = format!("127.0.0.1:{echo}");
    assert!(
        env.run_stdin(
            &["import", "--name", "ef", "--fields", "username,password", "--domain", &ed, "--self-signed"],
            format!("{USER}\n{PASS}\n").as_bytes()
        )
        .status
        .success()
    );
    assert!(env.run_stdin(&["import", "--name", "eb", "--domain", &ed, "--self-signed"], BLOB.as_bytes()).status.success());
    let url = format!("https://127.0.0.1:{echo}/e?u={{{{ef.username}}}}");
    let o = env.agent(&["http", "POST", &url, "-H", "X-P: {{ef.password}}", "-d", "{{eb}} | {{ef.username}}"]);
    let out = stdout(&o);
    assert!(o.status.success(), "{out}");
    // 相同的值在别的条目里也有，标签取第一个匹配的条目；这里只检查每个值都被替换、没有残留。
    assert!(out.matches("[REDACTED:").count() >= 4 && out.contains(".username]") && out.contains(".password]"), "{out}");
    assert!(leaks(&out, &[USER, PASS, BLOB]).is_empty(), "{out}");
    outputs += &out;

    // ---- 行数不符、空输入、超限：失败，且不回显内容 ----
    for (args, input) in [
        (vec!["import", "--name", "bad", "--fields", "username,password", "--domain", &d], format!("{USER}\n").into_bytes()),
        (
            vec!["import", "--name", "bad", "--fields", "username,password", "--domain", &d],
            format!("{USER}\n{PASS}\nextra-line-xyz\n").into_bytes(),
        ),
        (vec!["import", "--name", "bad", "--domain", &d], Vec::new()),
        (vec!["import", "--name", "bad", "--domain", &d], b"\n".to_vec()),
        (vec!["import", "--name", "bad", "--domain", &d], vec![b'x'; 64 * 1024 + 1]),
    ] {
        let o = env.run_stdin(&args, &input);
        assert!(!o.status.success(), "{args:?}");
        let text = stdout(&o) + &stderr(&o);
        assert!(!text.contains("extra-line-xyz") && leaks(&text, &[USER, PASS]).is_empty(), "{text}");
        outputs += &text;
    }
    assert!(env.run_stdin(&["import", "--name", "max", "--domain", &d], &vec![b'y'; 64 * 1024]).status.success(), "正好 64 KiB 可以");

    // ---- 重复与 --replace ----
    let o = env.run_stdin(&["import", "--name", "blob", "--domain", &d, "--self-signed"], b"other");
    assert!(!o.status.success() && stderr(&o).contains("已存在"));
    let o = env.run_stdin(&["import", "--name", "blob", "--domain", &d, "--self-signed", "--replace"], b"replaced-value-123\n");
    assert!(o.status.success(), "{}", stderr(&o));
    let (ok, out) = http_digest(&env, port, "{{blob}}");
    assert!(ok && out.contains(&digest_of("replaced-value-123")), "{out}");
    outputs += &out;

    // ---- 没有域名：保存，但标为未绑定，Agent 不能使用 ----
    let o = env.run_stdin(&["import", "--name", "spare"], b"spare-secret-value\n");
    assert!(o.status.success() && stdout(&o).contains("0 个域名") && stdout(&o).contains("没有绑定域名"), "{}", stdout(&o));
    let found = stdout(&env.agent(&["lookup", "{{spare}}"]));
    assert!(
        found.contains("DOMAIN_MISMATCH") && found.contains("not bound to any domain") && found.contains("passmanager update"),
        "{found}"
    );
    let (ok, out) = http_digest(&env, port, "{{spare}}");
    assert!(!ok && out.contains("DOMAIN_MISMATCH") && out.contains("not bound"), "{out}");
    outputs += &out;

    // ---- update：只改绑定 / 用途 / 备注，密钥不变；可疑备注给出警告 ----
    let o = env.run(&["update", "--name", "spare", "--domain", &d, "--note", "token file /root/x"]);
    assert!(o.status.success() && stdout(&o).contains("密钥未改动") && stderr(&o).contains("警告"), "{}{}", stdout(&o), stderr(&o));
    let o = env.run(&["update", "--name", "spare", "--note", "spare key", "--add-op", "http"]);
    assert!(o.status.success() && stderr(&o).is_empty(), "{}{}", stdout(&o), stderr(&o));
    // 绑定生效：不再是 DOMAIN_MISMATCH（spare 不是自签条目，所以到本地自签服务器的 TLS 校验失败——说明请求已经发出）。
    let (ok, out) = http_digest(&env, port, "{{spare}}");
    assert!(!ok && out.contains("UPSTREAM_ERROR") && !out.contains("DOMAIN_MISMATCH"), "{out}");
    outputs += &out;
    assert!(!env.run(&["update", "--name", "nope", "--note", "x"]).status.success());
    assert!(!env.run(&["update", "--name", "spare"]).status.success(), "没有要修改的内容");

    // ---- 标准输入是终端：拒绝 ----
    let mut master = 0;
    let mut slave = 0;
    // SAFETY: openpty 写入两个文件描述符。
    let rc = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) };
    assert_eq!(rc, 0);
    use std::os::fd::FromRawFd;
    // SAFETY: slave 是刚打开的、本进程独占的描述符。
    let tty = unsafe { std::fs::File::from_raw_fd(slave) };
    let o = env.cmd(&["import", "--name", "tty", "--domain", &d]).stdin(Stdio::from(tty)).output().unwrap();
    // SAFETY: 关闭 master。
    unsafe { libc::close(master) };
    assert!(!o.status.success() && stderr(&o).contains("终端"), "{}", stderr(&o));

    // ---- 库锁定 ----
    assert!(env.run(&["lock"]).status.success());
    let o = env.run_stdin(&["import", "--name", "while-locked", "--domain", &d], b"x-secret\n");
    assert!(!o.status.success() && stderr(&o).contains("已锁定"), "{}", stderr(&o));
    assert!(env.run(&["unlock"]).status.success());

    // ---- 非 root（系统布局）：拒绝 ----
    let o = Command::new(BIN).args(["import", "--name", "x"]).env_remove("PASSMANAGER_HOME").stdin(Stdio::null()).output().unwrap();
    if !nix_is_root() {
        assert!(!o.status.success() && stderr(&o).contains("root"), "{}", stderr(&o));
    }

    // ---- 所有输出与服务日志里都没有密钥 ----
    outputs += &env.service_log();
    let bad = leaks(&outputs, &[BLOB, USER, PASS, "replaced-value-123", "spare-secret-value"]);
    assert!(bad.is_empty(), "secret leaked: {bad:?}");
}

fn nix_is_root() -> bool {
    // SAFETY: geteuid 没有副作用。
    unsafe { libc::geteuid() == 0 }
}

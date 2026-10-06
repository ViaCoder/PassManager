//! macOS 检查与修复（需要 root）。

use std::path::Path;

use super::sudoers::{self, Who};
use super::unix_perm::{self as up, check_owner_mode, fix_root_owned, groups_of, root_owned_not_writable, run, set_owner_mode};
use super::{Ctx, Finding, backup_file};
use crate::service_files::MACOS_PLIST_PATH;

const LOGINWINDOW: &str = "/Library/Preferences/com.apple.loginwindow";

fn root_enabled() -> bool {
    // root 被禁用时没有 AuthenticationAuthority，Password 为 "*"。
    match run("dscl", &[".", "-read", "/Users/root", "AuthenticationAuthority"]) {
        Ok(out) => out.contains("ShadowHash") || out.contains("Kerberos"),
        Err(_) => false,
    }
}

fn user_has_empty_password(user: &str) -> bool {
    run("dscl", &[".", "-authonly", user, ""]).is_ok()
}

fn autologin_user() -> Option<String> {
    run("defaults", &["read", LOGINWINDOW, "autoLoginUser"]).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn sip_enabled() -> bool {
    run("csrutil", &["status"]).map(|o| o.contains("enabled.")).unwrap_or(false)
}

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut f = Vec::new();
    let user = &ctx.info.client_user;
    let empty_pw = user_has_empty_password(user);
    f.push(if !empty_pw {
        Finding::pass("user_password", &format!("用户 {user} 已设置口令"))
    } else {
        Finding::manual(
            "user_password",
            &format!("用户 {user} 已设置口令"),
            "该用户口令为空，提权将无法要求输入口令。",
            "打开 系统设置 → 用户与群组，为该用户设置口令，然后点 [重新检查]。",
        )
    });

    f.push(if !root_enabled() {
        Finding::pass("root_locked", "内置 root 账户已禁用")
    } else {
        Finding::fixable("root_locked", "内置 root 账户已禁用", "root 账户处于启用状态，将禁用它。")
    });

    let (uid, groups) = match up::user(user) {
        Some(u) => (u.uid, groups_of(&u.name, u.gid)),
        None => (u32::MAX, vec![]),
    };
    let issues = sudoers::scan(&Who { user, uid, groups: &groups });
    f.push(if issues.is_empty() {
        Finding::pass("sudo_nopasswd", "sudo 提权必须输入口令")
    } else {
        let detail =
            issues.iter().map(|i| format!("{}:{}  {}", i.file.display(), i.line_no + 1, i.line.trim())).collect::<Vec<_>>().join("\n");
        if empty_pw {
            Finding::manual("sudo_nopasswd", "sudo 提权必须输入口令", detail, "先为该用户设置口令，再点 [一键修复]。")
        } else {
            Finding::fixable(
                "sudo_nopasswd",
                "sudo 提权必须输入口令",
                format!("以下规则允许免口令提权（将把 NOPASSWD: 改为 PASSWD:）：\n{detail}"),
            )
        }
    });

    f.push(if sudoers::hardening_dropin_ok() {
        Finding::pass("sudo_tickets", "sudo 凭据按终端隔离且 5 分钟过期")
    } else {
        Finding::fixable("sudo_tickets", "sudo 凭据按终端隔离且 5 分钟过期", format!("将写入 {}。", sudoers::HARDENING_FILE))
    });

    f.push(match autologin_user() {
        None => Finding::pass("autologin", "自动登录已关闭"),
        Some(u) => Finding::fixable(
            "autologin",
            "自动登录已关闭",
            format!("已为 {u} 开启自动登录，开机即可不输入口令使用该账户。将关闭自动登录。"),
        ),
    });

    f.push(if sip_enabled() {
        Finding::pass("sip", "系统完整性保护（SIP）已开启")
    } else {
        Finding::manual(
            "sip",
            "系统完整性保护（SIP）已开启",
            "SIP 处于关闭状态，root 级别的保护被削弱。",
            "重启进入恢复模式（Apple 芯片：长按电源键；Intel：Command-R），打开终端运行 csrutil enable，重启后点 [重新检查]。",
        )
    });

    let filevault = run("fdesetup", &["status"]).map(|o| o.contains("FileVault is On")).unwrap_or(false);
    f.push(if filevault {
        Finding::pass("filevault", "FileVault 已开启")
    } else {
        Finding::advice(
            "filevault",
            "FileVault 已开启（建议）",
            "FileVault 未开启。Apple 芯片 / T2 机型的磁盘本身由硬件加密，但开启 FileVault 后开机必须输入口令才能解开磁盘。",
            "打开 系统设置 → 隐私与安全性 → FileVault，点\"打开\"。",
        )
    });

    // 服务账户
    let svc = &ctx.info.service_user;
    match up::user(svc) {
        Some(su) if su.shell == "/usr/bin/false" => f.push(Finding::pass("service_account", &format!("服务账户 {svc} 不可登录"))),
        Some(_) => f.push(Finding::fixable("service_account", &format!("服务账户 {svc} 不可登录"), "将把登录 shell 设为 /usr/bin/false。")),
        None => f.push(Finding::manual(
            "service_account",
            "服务账户存在",
            format!("找不到服务账户 {svc}。"),
            "重新运行 sudo PassManager install。",
        )),
    }

    // PassManager 自身文件
    let suid = up::user(svc).map(|u| u.uid).unwrap_or(u32::MAX);
    let mut push = |id: &str, title: &str, r: Result<(), String>| {
        f.push(match r {
            Ok(()) => Finding::pass(id, title),
            Err(e) => Finding::fixable(id, title, e),
        })
    };
    push("data_dir", "数据目录权限（服务账户 0700）", check_owner_mode(&ctx.layout.data_dir, suid, None, 0o700));
    if ctx.layout.vault_path().exists() {
        push("vault_file", "库文件权限（服务账户 0600）", check_owner_mode(&ctx.layout.vault_path(), suid, None, 0o600));
    }
    push("install_info", "安装信息文件（root 0644）", check_owner_mode(&ctx.layout.install_info_path(), 0, None, 0o644));
    push("run_dir", "socket 目录（服务账户:用户组 0750）", check_owner_mode(&ctx.layout.run_dir, suid, ctx.info.client_gid, 0o750));
    push("binary", "程序文件只有 root 可写", root_owned_not_writable(Path::new(&ctx.info.binary)));
    push("plist", "LaunchDaemon 配置（root 0644）", check_owner_mode(Path::new(MACOS_PLIST_PATH), 0, None, 0o644));
    f
}

pub fn fix(ctx: &Ctx, ids: &[&str]) -> Vec<String> {
    let mut log = Vec::new();
    let backup = |p: &str| backup_file(ctx.layout, p);
    let user = &ctx.info.client_user;
    for id in ids {
        match *id {
            "root_locked" => {
                let a = run("dscl", &[".", "-delete", "/Users/root", "AuthenticationAuthority"]);
                let b = run("dscl", &[".", "-create", "/Users/root", "Password", "*"]);
                log.push(match (a, b) {
                    (Ok(_), Ok(_)) => "已禁用 root 账户".into(),
                    (Err(e), _) | (_, Err(e)) => format!("禁用 root 失败：{e}"),
                });
            }
            "sudo_nopasswd" => {
                let (uid, groups) = match up::user(user) {
                    Some(u) => (u.uid, groups_of(&u.name, u.gid)),
                    None => (u32::MAX, vec![]),
                };
                let issues = sudoers::scan(&Who { user, uid, groups: &groups });
                log.extend(sudoers::fix(&issues, &backup));
            }
            "sudo_tickets" => log.push(match sudoers::write_hardening_dropin() {
                Ok(()) => format!("已写入 {}", sudoers::HARDENING_FILE),
                Err(e) => format!("写入 sudo 加固配置失败：{e}"),
            }),
            "autologin" => {
                let _ = run("defaults", &["delete", LOGINWINDOW, "autoLoginUser"]);
                let _ = std::fs::remove_file("/etc/kcpassword");
                log.push("已关闭自动登录".into());
            }
            "service_account" => {
                let svc = &ctx.info.service_user;
                log.push(match run("dscl", &[".", "-create", &format!("/Users/{svc}"), "UserShell", "/usr/bin/false"]) {
                    Ok(_) => format!("已加固服务账户 {svc}"),
                    Err(e) => format!("加固服务账户失败：{e}"),
                });
            }
            "data_dir" | "vault_file" | "install_info" | "run_dir" | "binary" | "plist" => {
                let Some(svc) = up::user(&ctx.info.service_user) else { continue };
                let r = match *id {
                    "data_dir" => set_owner_mode(&ctx.layout.data_dir, svc.uid, svc.gid, 0o700),
                    "vault_file" => set_owner_mode(&ctx.layout.vault_path(), svc.uid, svc.gid, 0o600),
                    "install_info" => set_owner_mode(&ctx.layout.install_info_path(), 0, 0, 0o644),
                    "run_dir" => {
                        let _ = std::fs::create_dir_all(&ctx.layout.run_dir);
                        set_owner_mode(&ctx.layout.run_dir, svc.uid, ctx.info.client_gid.unwrap_or(svc.gid), 0o750)
                    }
                    "binary" => fix_root_owned(Path::new(&ctx.info.binary)),
                    _ => set_owner_mode(Path::new(MACOS_PLIST_PATH), 0, 0, 0o644),
                };
                log.push(match r {
                    Ok(()) => format!("已修正权限：{id}"),
                    Err(e) => format!("修正 {id} 失败：{e}"),
                });
            }
            _ => {}
        }
    }
    log
}

//! Linux 检查与修复（需要 root）。

use std::path::Path;

use super::sudoers::{self, Who};
use super::unix_perm::{self as up, check_owner_mode, fix_root_owned, groups_of, root_owned_not_writable, run, set_owner_mode};
use super::{Ctx, Finding, backup_file};
use crate::service_files::{LINUX_REQUIRED_OPTIONS, LINUX_UNIT_PATH, linux_unit};

const DANGER_GROUPS: &[&str] = &["docker", "lxd", "incus", "disk"];
const SUDO_GROUPS: &[&str] = &["sudo", "wheel", "admin"];
const NOLOGIN: &[&str] = &["/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"];

struct Shadow {
    name: String,
    pw: String,
}

fn shadow() -> Vec<Shadow> {
    std::fs::read_to_string("/etc/shadow")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut it = l.split(':');
            Some(Shadow { name: it.next()?.to_string(), pw: it.next()?.to_string() })
        })
        .collect()
}

fn pw_locked(pw: &str) -> bool {
    pw.starts_with('!') || pw.starts_with('*')
}

fn pw_set(pw: &str) -> bool {
    !pw.is_empty() && !pw_locked(pw)
}

/// 用户能否通过 sudo 提权（以 root 身份查询）。
fn user_can_sudo(user: &str) -> bool {
    run("sudo", &["-l", "-U", user]).map(|o| o.contains("may run the following")).unwrap_or(false)
}

fn who_groups(ctx: &Ctx) -> (u32, Vec<(String, u32)>) {
    match up::user(&ctx.info.client_user) {
        Some(u) => (u.uid, groups_of(&u.name, u.gid)),
        None => (u32::MAX, vec![]),
    }
}

/// 扫描 PATH 目录中带危险文件能力（capabilities）的程序。
fn dangerous_file_caps() -> Vec<String> {
    // CAP_DAC_OVERRIDE=1, CAP_DAC_READ_SEARCH=2, CAP_SETUID=7, CAP_SYS_PTRACE=19, CAP_SYS_ADMIN=21
    const BITS: &[(u32, &str)] =
        &[(1, "cap_dac_override"), (2, "cap_dac_read_search"), (7, "cap_setuid"), (19, "cap_sys_ptrace"), (21, "cap_sys_admin")];
    let mut out = Vec::new();
    for dir in ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"] {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let Ok(cpath) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) else { continue };
            let mut buf = [0u8; 24];
            // SAFETY: 缓冲区大小与传入长度一致。
            let n = unsafe {
                libc::getxattr(cpath.as_ptr(), c"security.capability".as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n < 12 {
                continue;
            }
            let permitted = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            let names: Vec<&str> = BITS.iter().filter(|(b, _)| permitted & (1 << b) != 0).map(|(_, n)| *n).collect();
            if !names.is_empty() {
                out.push(format!("{}（{}）", p.display(), names.join(", ")));
            }
        }
    }
    out
}

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut f = Vec::new();
    let user = &ctx.info.client_user;
    let sh = shadow();
    let user_pw_ok = sh.iter().find(|s| &s.name == user).is_some_and(|s| pw_set(&s.pw));
    let (uid, groups) = who_groups(ctx);

    // 1. 当前用户已设置口令（提权时必须输入口令的前提）。
    f.push(if user_pw_ok {
        Finding::pass("user_password", &format!("用户 {user} 已设置口令"))
    } else {
        Finding::manual(
            "user_password",
            &format!("用户 {user} 已设置口令"),
            "该用户没有设置口令（或口令被锁定），提权将无法要求输入口令。",
            format!("在你自己的终端中运行：sudo passwd {user}，设置一个口令后点 [重新检查]。"),
        )
    });

    // 2. 内置 root 账户已锁定。
    let root_locked = sh.iter().find(|s| s.name == "root").is_some_and(|s| pw_locked(&s.pw));
    f.push(if root_locked {
        Finding::pass("root_locked", "内置 root 账户已锁定")
    } else if user_pw_ok && user_can_sudo(user) {
        Finding::fixable("root_locked", "内置 root 账户已锁定", "root 账户可以直接用口令登录（或口令为空）。将执行 passwd -l root。")
    } else {
        Finding::manual(
            "root_locked",
            "内置 root 账户已锁定",
            "root 账户未锁定；但当前用户还不能通过 sudo 提权，直接锁定 root 可能导致无法再获得管理员权限。",
            format!("先让 {user} 拥有 sudo 权限并设置口令（例如 usermod -aG sudo {user}），再点 [一键修复]。"),
        )
    });

    // 3. sudo 规则不得免口令。
    let who = Who { user, uid, groups: &groups };
    let issues = sudoers::scan(&who);
    f.push(if issues.is_empty() {
        Finding::pass("sudo_nopasswd", "sudo 提权必须输入口令")
    } else {
        let detail =
            issues.iter().map(|i| format!("{}:{}  {}", i.file.display(), i.line_no + 1, i.line.trim())).collect::<Vec<_>>().join("\n");
        if user_pw_ok {
            Finding::fixable(
                "sudo_nopasswd",
                "sudo 提权必须输入口令",
                format!("以下规则允许免口令提权（将把 NOPASSWD: 改为 PASSWD:）：\n{detail}"),
            )
        } else {
            Finding::manual(
                "sudo_nopasswd",
                "sudo 提权必须输入口令",
                format!("以下规则允许免口令提权：\n{detail}"),
                "先为该用户设置口令（见上一项），再点 [一键修复]。",
            )
        }
    });

    // 4. sudo 凭据按终端隔离、5 分钟过期。
    f.push(if sudoers::hardening_dropin_ok() {
        Finding::pass("sudo_tickets", "sudo 凭据按终端隔离且 5 分钟过期")
    } else {
        Finding::fixable("sudo_tickets", "sudo 凭据按终端隔离且 5 分钟过期", format!("将写入 {}。", sudoers::HARDENING_FILE))
    });

    // 5. 没有空口令账户。
    let empty: Vec<&str> = sh.iter().filter(|s| s.pw.is_empty() && &s.name != user).map(|s| s.name.as_str()).collect();
    f.push(if empty.is_empty() {
        Finding::pass("empty_passwords", "不存在空口令账户")
    } else {
        Finding::fixable("empty_passwords", "不存在空口令账户", format!("以下账户口令为空，将被锁定：{}", empty.join(", ")))
    });

    // 6. 当前用户不在等同 root 的组中。
    let danger: Vec<&str> = groups.iter().map(|(n, _)| n.as_str()).filter(|n| DANGER_GROUPS.contains(n)).collect();
    f.push(if danger.is_empty() {
        Finding::pass("danger_groups", "用户不在等同 root 的组（docker/lxd/incus/disk）中")
    } else {
        Finding::manual(
            "danger_groups",
            "用户不在等同 root 的组（docker/lxd/incus/disk）中",
            format!("{user} 属于 {}，这些组的成员不输入口令即可获得 root 权限（Agent 同样可以）。", danger.join(", ")),
            format!(
                "运行 sudo gpasswd -d {user} <组名> 退出这些组（docker 可改用 rootless 模式或在需要时用 sudo docker），然后重新登录并点 [重新检查]。"
            ),
        )
    });

    // 7. 没有带危险文件能力的程序。
    let caps = dangerous_file_caps();
    f.push(if caps.is_empty() {
        Finding::pass("file_caps", "系统程序没有危险的文件能力")
    } else {
        Finding::manual(
            "file_caps",
            "系统程序没有危险的文件能力",
            format!("以下程序带有可绕过文件权限的能力，任何用户运行它们都可以读取 PassManager 的文件：\n{}", caps.join("\n")),
            "确认用途后运行 sudo setcap -r <程序路径> 移除能力，然后点 [重新检查]。",
        )
    });

    // 8. 服务账户不可登录、不在管理员组。
    let svc = &ctx.info.service_user;
    match up::user(svc) {
        Some(su) => {
            let locked = sh.iter().find(|s| &s.name == svc).is_none_or(|s| !pw_set(&s.pw));
            let nologin = NOLOGIN.contains(&su.shell.as_str());
            let sg: Vec<String> = groups_of(svc, su.gid)
                .into_iter()
                .map(|g| g.0)
                .filter(|n| SUDO_GROUPS.contains(&n.as_str()) || DANGER_GROUPS.contains(&n.as_str()))
                .collect();
            f.push(if locked && nologin && sg.is_empty() {
                Finding::pass("service_account", &format!("服务账户 {svc} 不可登录且无管理员权限"))
            } else {
                Finding::fixable(
                    "service_account",
                    &format!("服务账户 {svc} 不可登录且无管理员权限"),
                    "将设置 nologin、锁定口令并移出管理员组。",
                )
            });
        }
        None => f.push(Finding::manual(
            "service_account",
            "服务账户存在",
            format!("找不到服务账户 {svc}。"),
            "重新运行 sudo PassManager install。",
        )),
    }

    // 9. PassManager 自身的文件与目录。
    f.extend(own_files(ctx));
    f
}

fn own_files(ctx: &Ctx) -> Vec<Finding> {
    let mut f = Vec::new();
    let svc = up::user(&ctx.info.service_user);
    let suid = svc.as_ref().map(|u| u.uid).unwrap_or(u32::MAX);
    let data = &ctx.layout.data_dir;
    let mut push = |id: &str, title: &str, r: Result<(), String>| {
        f.push(match r {
            Ok(()) => Finding::pass(id, title),
            Err(e) => Finding::fixable(id, title, e),
        })
    };
    push("data_dir", "数据目录权限（服务账户 0700）", check_owner_mode(data, suid, None, 0o700).and_then(|_| root_safe_parent(data)));
    let vault = ctx.layout.vault_path();
    if vault.exists() {
        push("vault_file", "库文件权限（服务账户 0600）", check_owner_mode(&vault, suid, None, 0o600));
    }
    push("install_info", "安装信息文件（root 0644）", check_owner_mode(&ctx.layout.install_info_path(), 0, None, 0o644));
    if ctx.info.seal_method.starts_with("systemd-creds") {
        push("device_key", "封存的设备密钥（root 0600）", check_owner_mode(&data.join("device-key.cred"), 0, None, 0o600));
        push(
            "systemd_secret",
            "systemd 主机密钥（root 0400）",
            check_owner_mode(Path::new("/var/lib/systemd/credential.secret"), 0, None, 0o400),
        );
    } else {
        push("device_key", "设备密钥文件（服务账户 0600）", check_owner_mode(&data.join("device.key"), suid, None, 0o600));
    }
    let client_gid = ctx.info.client_gid;
    push("run_dir", "socket 目录（服务账户:用户组 0750）", check_owner_mode(&ctx.layout.run_dir, suid, client_gid, 0o750));
    push("binary", "程序文件只有 root 可写", root_owned_not_writable(Path::new(&ctx.info.binary)));
    let unit = std::fs::read_to_string(LINUX_UNIT_PATH).unwrap_or_default();
    let missing: Vec<&str> = LINUX_REQUIRED_OPTIONS.iter().copied().filter(|o| !unit.lines().any(|l| l.trim() == *o)).collect();
    push(
        "unit",
        "服务单元包含全部加固选项",
        if unit.is_empty() {
            Err(format!("{LINUX_UNIT_PATH} 不存在"))
        } else if !missing.is_empty() {
            Err(format!("缺少：{}", missing.join(", ")))
        } else {
            root_owned_not_writable(Path::new(LINUX_UNIT_PATH))
        },
    );
    f
}

fn root_safe_parent(p: &Path) -> Result<(), String> {
    up::ancestors_root_safe(p)
}

pub fn fix(ctx: &Ctx, ids: &[&str]) -> Vec<String> {
    let mut log = Vec::new();
    let backup = |p: &str| backup_file(ctx.layout, p);
    let user = &ctx.info.client_user;
    for id in ids {
        match *id {
            "root_locked" => {
                let _ = backup("/etc/shadow");
                log.push(match run("passwd", &["-l", "root"]) {
                    Ok(_) => "已锁定 root 账户".into(),
                    Err(e) => format!("锁定 root 失败：{e}"),
                });
            }
            "sudo_nopasswd" => {
                let (uid, groups) = who_groups(ctx);
                let issues = sudoers::scan(&Who { user, uid, groups: &groups });
                log.extend(sudoers::fix(&issues, &backup));
            }
            "sudo_tickets" => log.push(match sudoers::write_hardening_dropin() {
                Ok(()) => format!("已写入 {}", sudoers::HARDENING_FILE),
                Err(e) => format!("写入 sudo 加固配置失败：{e}"),
            }),
            "empty_passwords" => {
                let _ = backup("/etc/shadow");
                for s in shadow().iter().filter(|s| s.pw.is_empty() && &s.name != user) {
                    log.push(match run("passwd", &["-l", &s.name]) {
                        Ok(_) => format!("已锁定空口令账户 {}", s.name),
                        Err(e) => format!("锁定 {} 失败：{e}", s.name),
                    });
                }
            }
            "service_account" => {
                let svc = &ctx.info.service_user;
                let _ = run("usermod", &["-s", "/usr/sbin/nologin", svc]);
                let _ = run("passwd", &["-l", svc]);
                if let Some(su) = up::user(svc) {
                    for (g, _) in groups_of(svc, su.gid) {
                        if SUDO_GROUPS.contains(&g.as_str()) || DANGER_GROUPS.contains(&g.as_str()) {
                            let _ = run("gpasswd", &["-d", svc, &g]);
                        }
                    }
                }
                log.push(format!("已加固服务账户 {svc}"));
            }
            "data_dir" | "vault_file" | "install_info" | "device_key" | "run_dir" | "binary" | "systemd_secret" => {
                log.push(fix_perm(ctx, id));
            }
            "unit" => {
                let content = linux_unit(ctx.info, ctx.layout);
                log.push(match std::fs::write(LINUX_UNIT_PATH, content) {
                    Ok(()) => {
                        let _ = set_owner_mode(Path::new(LINUX_UNIT_PATH), 0, 0, 0o644);
                        let _ = run("systemctl", &["daemon-reload"]);
                        "已重写服务单元（需要重启服务生效）".into()
                    }
                    Err(e) => format!("重写服务单元失败：{e}"),
                });
            }
            _ => {}
        }
    }
    log
}

fn fix_perm(ctx: &Ctx, id: &str) -> String {
    let Some(svc) = up::user(&ctx.info.service_user) else { return "找不到服务账户".into() };
    let data = &ctx.layout.data_dir;
    let r = match id {
        "data_dir" => set_owner_mode(data, svc.uid, svc.gid, 0o700),
        "vault_file" => set_owner_mode(&ctx.layout.vault_path(), svc.uid, svc.gid, 0o600),
        "install_info" => set_owner_mode(&ctx.layout.install_info_path(), 0, 0, 0o644),
        "device_key" if ctx.info.seal_method.starts_with("systemd-creds") => set_owner_mode(&data.join("device-key.cred"), 0, 0, 0o600),
        "device_key" => set_owner_mode(&data.join("device.key"), svc.uid, svc.gid, 0o600),
        "systemd_secret" => set_owner_mode(Path::new("/var/lib/systemd/credential.secret"), 0, 0, 0o400),
        "run_dir" => {
            let _ = std::fs::create_dir_all(&ctx.layout.run_dir);
            set_owner_mode(&ctx.layout.run_dir, svc.uid, ctx.info.client_gid.unwrap_or(svc.gid), 0o750)
        }
        "binary" => fix_root_owned(Path::new(&ctx.info.binary)),
        _ => Ok(()),
    };
    match r {
        Ok(()) => format!("已修正权限：{id}"),
        Err(e) => format!("修正 {id} 失败：{e}"),
    }
}

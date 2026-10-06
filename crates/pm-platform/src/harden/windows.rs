//! Windows 检查与修复（完整检查需要管理员权限：安装时、一键修复时、以及开机时以 SYSTEM 运行的计划任务）。

use std::os::windows::process::CommandExt;
use std::process::Command;

use serde::Deserialize;

use super::{Ctx, Finding};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const UAC_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

fn ps(script: &str) -> Result<String, String> {
    // 从 PowerShell 7 启动 Windows PowerShell 5 时会继承 PS7 的 PSModulePath，导致
    // Microsoft.PowerShell.Security（Get-Acl / Set-Acl）等内置模块无法加载；去掉它让 PS5 使用默认路径。
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .env_remove("PSModulePath")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("powershell: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn reg_dword(name: &str) -> Option<u32> {
    let out = Command::new("reg").args(["query", UAC_KEY, "/v", name]).creation_flags(CREATE_NO_WINDOW).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().find(|l| l.contains(name))?;
    let hexv = line.split_whitespace().last()?;
    u32::from_str_radix(hexv.trim_start_matches("0x"), 16).ok()
}

fn reg_set(name: &str, value: u32) -> Result<(), String> {
    let st = Command::new("reg")
        .args(["add", UAC_KEY, "/v", name, "/t", "REG_DWORD", "/d", &value.to_string(), "/f"])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| e.to_string())?;
    if st.success() { Ok(()) } else { Err(format!("reg add {name} 失败")) }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct LocalUser {
    name: String,
    sid: String,
    enabled: bool,
    password_required: bool,
    #[serde(default)]
    password_last_set: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct Member {
    name: String,
    sid: String,
}

fn json_list<T: for<'de> Deserialize<'de>>(s: &str) -> Vec<T> {
    let s = s.trim();
    if s.is_empty() {
        return vec![];
    }
    if s.starts_with('[') {
        serde_json::from_str(s).unwrap_or_default()
    } else {
        serde_json::from_str::<T>(s).map(|x| vec![x]).unwrap_or_default()
    }
}

fn local_users() -> Vec<LocalUser> {
    json_list(&ps("Get-LocalUser | Select-Object Name,@{n='Sid';e={$_.SID.Value}},Enabled,PasswordRequired,@{n='PasswordLastSet';e={if($_.PasswordLastSet){$_.PasswordLastSet.ToString('o')}else{$null}}} | ConvertTo-Json -Compress").unwrap_or_default())
}

fn group_members(sid: &str) -> Vec<Member> {
    json_list(
        &ps(&format!("Get-LocalGroupMember -SID {sid} | Select-Object Name,@{{n='Sid';e={{$_.SID.Value}}}} | ConvertTo-Json -Compress"))
            .unwrap_or_default(),
    )
}

fn service_sid() -> Option<String> {
    let out = Command::new("sc").args(["showsid", "PassManager"]).creation_flags(CREATE_NO_WINDOW).output().ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| l.split_once("SERVICE SID:").map(|(_, s)| s.trim().to_string()))
}

fn short_name(n: &str) -> &str {
    n.rsplit('\\').next().unwrap_or(n)
}

fn data_dir_sddl(ctx: &Ctx) -> Option<String> {
    ps(&format!("(Get-Acl -LiteralPath '{}').Sddl", ctx.layout.data_dir.display())).ok().map(|s| s.trim().to_string())
}

fn data_dir_acl_ok(ctx: &Ctx) -> Result<(), String> {
    let sddl = data_dir_sddl(ctx).ok_or("无法读取数据目录 ACL")?;
    let svc = service_sid().ok_or("找不到 PassManager 服务 SID")?;
    let dacl = sddl.split("D:").nth(1).ok_or("ACL 中没有 DACL")?;
    if !dacl.starts_with('P') {
        return Err("数据目录仍继承上级 ACL（应关闭继承）".into());
    }
    for ace in dacl.split('(').skip(1) {
        let sid = ace.trim_end_matches(')').rsplit(';').next().unwrap_or("");
        if sid != "SY" && sid != svc && sid != "S-1-5-18" {
            return Err(format!("数据目录 ACL 中存在多余的授权：{sid}"));
        }
    }
    Ok(())
}

fn binary_acl_ok(ctx: &Ctx) -> Result<(), String> {
    let n = ps(&format!(
        "(Get-Acl -LiteralPath '{}').Access | Where-Object {{ $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -match 'Users|Everyone|Authenticated|INTERACTIVE' -and $_.FileSystemRights -match 'Write|Modify|FullControl' }} | Measure-Object | Select-Object -ExpandProperty Count",
        ctx.info.binary
    ))?;
    if n.trim() == "0" { Ok(()) } else { Err("普通用户可以修改 PassManager 程序文件".into()) }
}

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut f = Vec::new();
    let users = local_users();
    let admins = group_members("S-1-5-32-544");
    let builtin = users.iter().find(|u| u.sid.ends_with("-500"));
    let other_admin_with_pw = admins.iter().any(|m| {
        users
            .iter()
            .any(|u| u.sid == m.sid && !u.sid.ends_with("-500") && u.enabled && u.password_required && u.password_last_set.is_some())
    });

    f.push(match builtin {
        Some(b) if b.enabled => {
            if other_admin_with_pw {
                Finding::fixable("builtin_admin", "内置 Administrator 已禁用", format!("内置管理员 {} 处于启用状态，将禁用它。", b.name))
            } else {
                Finding::manual(
                    "builtin_admin",
                    "内置 Administrator 已禁用",
                    "内置管理员处于启用状态；但没有找到另一个已启用且设置了口令的管理员账户，直接禁用可能导致无法再获得管理员权限。",
                    "先把你的日常账户加入 Administrators 组并设置口令（设置 → 账户），再点 [一键修复]。",
                )
            }
        }
        _ => Finding::pass("builtin_admin", "内置 Administrator 已禁用"),
    });

    let lua = reg_dword("EnableLUA").unwrap_or(1);
    let consent = reg_dword("ConsentPromptBehaviorAdmin").unwrap_or(5);
    let secure = reg_dword("PromptOnSecureDesktop").unwrap_or(1);
    f.push(if lua == 1 && consent == 1 && secure == 1 {
        Finding::pass("uac", "UAC 开启，提权时要求输入口令（安全桌面）")
    } else {
        Finding::fixable(
            "uac",
            "UAC 开启，提权时要求输入口令（安全桌面）",
            format!(
                "当前 EnableLUA={lua}、ConsentPromptBehaviorAdmin={consent}、PromptOnSecureDesktop={secure}。将改为 1/1/1（管理员提权时必须输入口令）。{}",
                if lua != 1 { "修改 EnableLUA 后需要重启。" } else { "" }
            ),
        )
    });

    let guest = users.iter().find(|u| u.sid.ends_with("-501"));
    f.push(match guest {
        Some(g) if g.enabled => Finding::fixable("guest", "Guest 账户已禁用", "Guest 账户处于启用状态，将禁用它。"),
        _ => Finding::pass("guest", "Guest 账户已禁用"),
    });

    let client = ctx.info.client_user.to_lowercase();
    let backup_ops = group_members("S-1-5-32-551");
    let in_backup = backup_ops.iter().any(|m| short_name(&m.name).to_lowercase() == client || Some(&m.sid) == ctx.info.client_sid.as_ref());
    f.push(if !in_backup {
        Finding::pass("backup_operators", "用户不在 Backup Operators 组中")
    } else {
        Finding::manual(
            "backup_operators",
            "用户不在 Backup Operators 组中",
            "Backup Operators 组成员可以绕过文件 ACL 读取任何文件（包括 PassManager 的数据）。",
            "以管理员身份运行：net localgroup \"Backup Operators\" <你的用户名> /delete，然后注销重新登录并点 [重新检查]。",
        )
    });

    // 显式授予用户的危险特权（需要管理员才能导出安全策略）。
    if let Ok(out) =
        ps("$t=[IO.Path]::GetTempFileName(); secedit /export /cfg $t /areas USER_RIGHTS | Out-Null; Get-Content $t; Remove-Item $t")
    {
        let sid = ctx.info.client_sid.clone().unwrap_or_default();
        let bad: Vec<&str> = out
            .lines()
            .filter(|l| l.starts_with("SeDebugPrivilege") || l.starts_with("SeBackupPrivilege"))
            .filter(|l| (!sid.is_empty() && l.contains(&sid)) || l.to_lowercase().contains(&client))
            .collect();
        f.push(if bad.is_empty() {
            Finding::pass("privileges", "用户没有被单独授予调试/备份特权")
        } else {
            Finding::manual(
                "privileges",
                "用户没有被单独授予调试/备份特权",
                format!("以下特权被直接授予了你的账户：\n{}", bad.join("\n")),
                "运行 secpol.msc → 本地策略 → 用户权限分配，从\"调试程序\"和\"备份文件和目录\"中移除你的账户，然后点 [重新检查]。",
            )
        });
    }

    let no_pw: Vec<String> = admins
        .iter()
        .filter_map(|m| users.iter().find(|u| u.sid == m.sid))
        .filter(|u| u.enabled && (!u.password_required || u.password_last_set.is_none()))
        .map(|u| u.name.clone())
        .collect();
    f.push(if no_pw.is_empty() {
        Finding::pass("admin_passwords", "所有管理员账户都设置了口令")
    } else {
        Finding::manual(
            "admin_passwords",
            "所有管理员账户都设置了口令",
            format!("以下管理员账户可能没有口令：{}", no_pw.join(", ")),
            "在 设置 → 账户 → 登录选项 中为这些账户设置口令（或禁用不用的账户），然后点 [重新检查]。",
        )
    });

    f.push(match data_dir_acl_ok(ctx) {
        Ok(()) => Finding::pass("data_dir", "数据目录 ACL 只授权 SYSTEM 与服务账户"),
        Err(e) => Finding::fixable("data_dir", "数据目录 ACL 只授权 SYSTEM 与服务账户", e),
    });
    f.push(match binary_acl_ok(ctx) {
        Ok(()) => Finding::pass("binary", "程序文件只有管理员可写"),
        Err(e) => Finding::fixable("binary", "程序文件只有管理员可写", e),
    });
    f
}

pub fn fix(ctx: &Ctx, ids: &[&str]) -> Vec<String> {
    let mut log = Vec::new();
    for id in ids {
        match *id {
            "builtin_admin" => log.push(match ps("Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Disable-LocalUser") {
                Ok(_) => "已禁用内置 Administrator".into(),
                Err(e) => format!("禁用内置 Administrator 失败：{e}"),
            }),
            "uac" => {
                let r: Vec<Result<(), String>> =
                    vec![reg_set("EnableLUA", 1), reg_set("ConsentPromptBehaviorAdmin", 1), reg_set("PromptOnSecureDesktop", 1)];
                log.push(if r.iter().all(|x| x.is_ok()) {
                    "已设置 UAC：提权时要求输入口令（如修改了 EnableLUA，需要重启）".into()
                } else {
                    format!("设置 UAC 失败：{:?}", r.into_iter().filter_map(|x| x.err()).collect::<Vec<_>>())
                });
            }
            "guest" => log.push(match ps("Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser") {
                Ok(_) => "已禁用 Guest".into(),
                Err(e) => format!("禁用 Guest 失败：{e}"),
            }),
            "data_dir" => {
                let Some(svc) = service_sid() else {
                    log.push("找不到服务 SID，无法修正数据目录 ACL".into());
                    continue;
                };
                let p = ctx.layout.data_dir.display();
                let script = format!(
                    "$a=Get-Acl -LiteralPath '{p}'; $a.SetSecurityDescriptorSddlForm('O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;{svc})'); Set-Acl -LiteralPath '{p}' -AclObject $a"
                );
                log.push(match ps(&script) {
                    Ok(_) => "已修正数据目录 ACL".into(),
                    Err(e) => format!("修正数据目录 ACL 失败：{e}"),
                });
            }
            "binary" => {
                let p = &ctx.info.binary;
                log.push(match ps(&format!("icacls '{p}' /reset | Out-Null")) {
                    Ok(_) => "已重置程序文件 ACL".into(),
                    Err(e) => format!("重置程序文件 ACL 失败：{e}"),
                });
            }
            _ => {}
        }
    }
    log
}

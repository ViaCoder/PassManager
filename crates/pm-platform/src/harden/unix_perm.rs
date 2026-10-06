//! Unix 文件权限与用户/组查询辅助函数。

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use nix::unistd::{Gid, Group, Uid, User, chown};

pub struct UserInfo {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub shell: String,
}

pub fn user(name: &str) -> Option<UserInfo> {
    let u = User::from_name(name).ok()??;
    Some(UserInfo { name: u.name, uid: u.uid.as_raw(), gid: u.gid.as_raw(), shell: u.shell.to_string_lossy().into() })
}

/// 用户所属的全部组（名称、gid）。
pub fn groups_of(name: &str, gid: u32) -> Vec<(String, u32)> {
    let Ok(cname) = std::ffi::CString::new(name) else { return vec![] };
    #[cfg(target_os = "linux")]
    let list = nix::unistd::getgrouplist(&cname, Gid::from_raw(gid)).unwrap_or_default();
    #[cfg(not(target_os = "linux"))]
    let list = {
        let _ = &cname;
        groups_via_scan(name, gid)
    };
    list.into_iter()
        .map(|g| {
            let n = Group::from_gid(g).ok().flatten().map(|g| g.name).unwrap_or_else(|| g.as_raw().to_string());
            (n, g.as_raw())
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn groups_via_scan(name: &str, gid: u32) -> Vec<Gid> {
    // macOS：通过 `id -G` 获取（支持动态组成员解析）。
    let mut out = vec![Gid::from_raw(gid)];
    if let Ok(o) = std::process::Command::new("id").arg("-G").arg(name).output() {
        for g in String::from_utf8_lossy(&o.stdout).split_whitespace() {
            if let Ok(g) = g.parse::<u32>() {
                let g = Gid::from_raw(g);
                if !out.contains(&g) {
                    out.push(g);
                }
            }
        }
    }
    out
}

/// 检查路径属主与权限。`mode` 为期望的权限位（精确匹配低 12 位中的 rwx 部分）。
pub fn check_owner_mode(path: &Path, uid: u32, gid: Option<u32>, mode: u32) -> Result<(), String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| format!("{}：{e}", path.display()))?;
    if m.file_type().is_symlink() {
        return Err(format!("{} 不应是符号链接", path.display()));
    }
    if m.uid() != uid {
        return Err(format!("{} 属主应为 uid {uid}，实际为 {}", path.display(), m.uid()));
    }
    if let Some(g) = gid
        && m.gid() != g
    {
        return Err(format!("{} 属组应为 gid {g}，实际为 {}", path.display(), m.gid()));
    }
    let actual = m.mode() & 0o7777;
    if actual != mode {
        return Err(format!("{} 权限应为 {mode:o}，实际为 {actual:o}", path.display()));
    }
    Ok(())
}

/// 路径及其所有上级目录都必须由 root 拥有且不可被组/其他用户写入（防止被替换）。
pub fn ancestors_root_safe(path: &Path) -> Result<(), String> {
    let mut cur = path.parent();
    while let Some(p) = cur {
        if p.as_os_str().is_empty() {
            break;
        }
        let m = std::fs::metadata(p).map_err(|e| format!("{}：{e}", p.display()))?;
        if m.uid() != 0 {
            return Err(format!("上级目录 {} 不属于 root", p.display()));
        }
        if m.mode() & 0o022 != 0 {
            return Err(format!("上级目录 {} 可被其他用户写入", p.display()));
        }
        cur = p.parent();
    }
    Ok(())
}

/// 文件由 root 拥有且组/其他用户不可写。
pub fn root_owned_not_writable(path: &Path) -> Result<(), String> {
    let m = std::fs::metadata(path).map_err(|e| format!("{}：{e}", path.display()))?;
    if m.uid() != 0 {
        return Err(format!("{} 不属于 root", path.display()));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!("{} 可被其他用户写入", path.display()));
    }
    ancestors_root_safe(path)
}

/// 修正程序文件：文件改为 root 0755；上级目录改为 root 拥有并去掉组/其他用户的写权限。
/// 带粘滞位的公共目录（如 /tmp）不修改，交给用户把程序装到别处。
pub fn fix_root_owned(path: &Path) -> std::io::Result<()> {
    let mut dirs = Vec::new();
    let mut cur = path.parent();
    while let Some(p) = cur.filter(|p| !p.as_os_str().is_empty()) {
        let m = std::fs::metadata(p)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            if m.mode() & 0o1000 != 0 {
                return Err(std::io::Error::other(format!("{} 是公共目录，请把程序安装到其他位置", p.display())));
            }
            dirs.push((p.to_path_buf(), m.mode() & 0o7755));
        }
        cur = p.parent();
    }
    for (d, mode) in dirs {
        chown(&d, Some(Uid::from_raw(0)), None).map_err(std::io::Error::from)?;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode))?;
    }
    set_owner_mode(path, 0, 0, 0o755)
}

pub fn set_owner_mode(path: &Path, uid: u32, gid: u32, mode: u32) -> std::io::Result<()> {
    chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(std::io::Error::from)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

pub fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(format!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

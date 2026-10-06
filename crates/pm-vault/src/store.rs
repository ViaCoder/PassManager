//! 原子写入：写临时文件 → fsync → 备份旧文件为 `.bak` → rename → fsync 目录。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub fn backup_path(path: &Path) -> PathBuf {
    with_suffix(path, ".bak")
}

fn create_private(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn sync_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(dir) = path.parent()
        && let Ok(d) = File::open(dir)
    {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = with_suffix(path, ".tmp");
    {
        let mut f = create_private(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if path.exists() {
        let bak_tmp = with_suffix(path, ".bak.tmp");
        {
            let old = fs::read(path)?;
            let mut f = create_private(&bak_tmp)?;
            f.write_all(&old)?;
            f.sync_all()?;
        }
        fs::rename(&bak_tmp, backup_path(path))?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(path);
    Ok(())
}

/// 读取库文件；主文件缺失（例如写入时断电）时回退到 `.bak`。
pub fn read(path: &Path) -> std::io::Result<Vec<u8>> {
    match fs::read(path) {
        Ok(d) => Ok(d),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && backup_path(path).exists() => fs::read(backup_path(path)),
        Err(e) => Err(e),
    }
}

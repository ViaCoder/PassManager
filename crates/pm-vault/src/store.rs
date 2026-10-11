//! 原子写入：写临时文件 → fsync → 备份旧文件为 `.bak` → rename → fsync 目录。
//!
//! 任何一步之间断电或进程被杀：主文件要么是旧的完整内容，要么是新的完整内容；
//! 残留的 `.tmp` / `.bak.tmp` 半写文件不会被读取，下次写入时直接覆盖。
//! 主文件缺失或损坏时，读取方回退到 `.bak`（见 [`read`]、`Vault::open`）。

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

/// 崩溃注入点（测试用）：在对应步骤之前"断电"，直接返回错误、不做后续步骤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// 临时文件只写了一半。
    HalfWrittenTemp,
    /// 临时文件已写完并 fsync，但还没有更新 .bak。
    BeforeBackup,
    /// .bak 已更新，但还没有 rename 到主文件。
    BeforeRename,
}

#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    /// 本线程下一次 `write_atomic` 在哪一步"崩溃"（只触发一次）。
    pub static CRASH_AT: std::cell::Cell<Option<CrashPoint>> = const { std::cell::Cell::new(None) };
}

#[cfg_attr(not(any(test, feature = "test-hooks")), allow(unused_variables))]
fn crash(point: CrashPoint) -> std::io::Result<()> {
    #[cfg(any(test, feature = "test-hooks"))]
    if CRASH_AT.with(|c| c.get()) == Some(point) {
        CRASH_AT.with(|c| c.set(None));
        return Err(std::io::Error::other(format!("simulated crash at {point:?}")));
    }
    Ok(())
}

pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_opts(path, data, true)
}

/// `keep_backup = false`：不把当前主文件复制为 `.bak`（主文件已损坏、内容是从 `.bak` 恢复出来时使用，
/// 避免用坏文件覆盖唯一完好的备份）。
pub fn write_atomic_opts(path: &Path, data: &[u8], keep_backup: bool) -> std::io::Result<()> {
    let tmp = with_suffix(path, ".tmp");
    {
        let mut f = create_private(&tmp)?;
        if crash(CrashPoint::HalfWrittenTemp).is_err() {
            f.write_all(&data[..data.len() / 2])?;
            let _ = f.sync_all();
            return Err(std::io::Error::other("simulated crash at HalfWrittenTemp"));
        }
        f.write_all(data)?;
        f.sync_all()?;
    }
    crash(CrashPoint::BeforeBackup)?;
    if keep_backup && path.exists() {
        let bak_tmp = with_suffix(path, ".bak.tmp");
        {
            let old = fs::read(path)?;
            let mut f = create_private(&bak_tmp)?;
            f.write_all(&old)?;
            f.sync_all()?;
        }
        fs::rename(&bak_tmp, backup_path(path))?;
    }
    crash(CrashPoint::BeforeRename)?;
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

/// 只读主文件（不回退）。
pub fn read_main(path: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(path)
}

/// 只读 `.bak`。
pub fn read_backup(path: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(backup_path(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_crash_point_leaves_old_or_new_content() {
        for point in [CrashPoint::HalfWrittenTemp, CrashPoint::BeforeBackup, CrashPoint::BeforeRename] {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("f.json");
            write_atomic(&p, b"old-content").unwrap();
            CRASH_AT.with(|c| c.set(Some(point)));
            assert!(write_atomic(&p, b"new-content-longer").is_err(), "{point:?}");
            // 主文件仍是完整的旧内容；残留的临时文件不会被读到。
            assert_eq!(read(&p).unwrap(), b"old-content", "{point:?}");
            // 下一次写入覆盖残留的临时文件并成功。
            write_atomic(&p, b"newest").unwrap();
            assert_eq!(read(&p).unwrap(), b"newest");
            assert_eq!(read_backup(&p).unwrap(), b"old-content");
            assert!(!with_suffix(&p, ".tmp").exists());
        }
    }

    #[test]
    fn missing_main_falls_back_to_backup_and_skip_backup_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.json");
        write_atomic(&p, b"v1").unwrap();
        write_atomic(&p, b"v2").unwrap();
        fs::remove_file(&p).unwrap();
        assert_eq!(read(&p).unwrap(), b"v1");
        // 主文件损坏时用 keep_backup=false 写回，.bak 不被坏数据覆盖。
        fs::write(&p, b"garbage").unwrap();
        write_atomic_opts(&p, b"v3", false).unwrap();
        assert_eq!(read_backup(&p).unwrap(), b"v1");
        assert_eq!(read_main(&p).unwrap(), b"v3");
        assert!(read(&dir.path().join("nope")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        write_atomic(&p, b"a").unwrap();
        write_atomic(&p, b"b").unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(backup_path(&p)).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

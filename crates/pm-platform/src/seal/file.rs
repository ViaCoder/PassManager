//! L1：受文件权限保护的设备密钥文件（0600）。

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use zeroize::Zeroizing;

use super::{RandFn, Sealer, key_from_bytes};
use crate::paths::Layout;

pub const METHOD: &str = "file";

pub struct FileSealer {
    path: PathBuf,
}

impl FileSealer {
    pub fn new(layout: &Layout) -> Self {
        Self { path: layout.data_dir.join("device.key") }
    }
}

impl Sealer for FileSealer {
    fn method(&self) -> &'static str {
        METHOD
    }

    fn level(&self) -> u8 {
        1
    }

    fn describe(&self) -> String {
        format!("文件 {}（仅文件权限保护）", self.path.display())
    }

    fn is_provisioned(&self) -> bool {
        self.path.exists()
    }

    fn seal(&self, key: &[u8; 32], _rand: RandFn) -> io::Result<()> {
        if let Some(d) = self.path.parent() {
            fs::create_dir_all(d)?;
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        f.write_all(key)?;
        f.sync_all()
    }

    fn unseal(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        let data = Zeroizing::new(fs::read(&self.path)?);
        key_from_bytes(&data)
    }

    fn remove(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
}

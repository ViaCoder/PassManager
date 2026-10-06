//! Windows：DPAPI（服务账户用户范围，L2），有 TPM 时再叠加 TPM 不可导出密钥（L3）。
//!
//! L3 时：`k_hw` 随机生成，用 TPM（Microsoft Platform Crypto Provider）中的不可导出 RSA 密钥加密保存；
//! `k_os = device_key XOR k_hw` 用 DPAPI 封存。两者缺一不可。
//! TPM 的 RSA 只提供"硬件绑定"；对称部分（DPAPI）始终保留，因此 RSA 被量子攻破也不会单独导致泄露。

use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::PathBuf;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    CryptProtectData, CryptUnprotectData, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE, NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
};
use windows::core::{PCWSTR, w};
use zeroize::Zeroizing;

use super::{RandFn, Sealer, key_from_bytes};
use crate::paths::Layout;

pub const METHOD_DPAPI: &str = "windows-dpapi";
pub const METHOD_DPAPI_TPM: &str = "windows-dpapi+tpm";
const TPM_KEY_NAME: PCWSTR = w!("PassManagerDeviceKey");

pub struct DpapiSealer {
    tpm: bool,
    os_blob: PathBuf,
    hw_blob: PathBuf,
}

fn dpapi_protect(data: &[u8]) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: 输入缓冲区在调用期间有效；输出由系统分配，使用后 LocalFree。
    unsafe {
        CryptProtectData(&input, w!("PassManager"), None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|e| io::Error::other(format!("CryptProtectData: {e}")))?;
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut c_void)));
        Ok(v)
    }
}

fn dpapi_unprotect(data: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: 同上。
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("CryptUnprotectData: {e}")))?;
        let slice = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let v = Zeroizing::new(slice.to_vec());
        slice.fill(0);
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut c_void)));
        Ok(v)
    }
}

struct Tpm {
    prov: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
}

impl Drop for Tpm {
    fn drop(&mut self) {
        // SAFETY: 句柄由 NCrypt 返回，只释放一次。
        unsafe {
            if !self.key.is_invalid() {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.key.0));
            }
            if !self.prov.is_invalid() {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.prov.0));
            }
        }
    }
}

impl Tpm {
    fn open(create: bool) -> io::Result<Self> {
        let mut t = Tpm { prov: NCRYPT_PROV_HANDLE::default(), key: NCRYPT_KEY_HANDLE::default() };
        // SAFETY: 输出参数指向本地变量。
        unsafe {
            NCryptOpenStorageProvider(&mut t.prov, MS_PLATFORM_CRYPTO_PROVIDER, 0)
                .map_err(|e| io::Error::other(format!("TPM provider: {e}")))?;
            if NCryptOpenKey(t.prov, &mut t.key, TPM_KEY_NAME, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0)).is_ok() {
                return Ok(t);
            }
            if !create {
                return Err(io::Error::new(io::ErrorKind::NotFound, "TPM key not found"));
            }
            // 默认导出策略为"不可导出"。
            NCryptCreatePersistedKey(t.prov, &mut t.key, BCRYPT_RSA_ALGORITHM, TPM_KEY_NAME, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0))
                .map_err(|e| io::Error::other(format!("TPM create key: {e}")))?;
            NCryptFinalizeKey(t.key, NCRYPT_FLAGS(0)).map_err(|e| io::Error::other(format!("TPM finalize: {e}")))?;
        }
        Ok(t)
    }

    fn available() -> bool {
        let mut prov = NCRYPT_PROV_HANDLE::default();
        // SAFETY: 输出参数指向本地变量。
        unsafe {
            if NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0).is_ok() {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0));
                return true;
            }
        }
        false
    }

    fn padding() -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM, pbLabel: std::ptr::null_mut(), cbLabel: 0 }
    }

    fn encrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let pad = Self::padding();
        let mut size = 0u32;
        // SAFETY: 缓冲区与长度一致。
        unsafe {
            NCryptEncrypt(self.key, Some(data), Some(&pad as *const _ as *const c_void), None, &mut size, NCRYPT_PAD_OAEP_FLAG)
                .map_err(|e| io::Error::other(format!("TPM encrypt: {e}")))?;
            let mut out = vec![0u8; size as usize];
            NCryptEncrypt(self.key, Some(data), Some(&pad as *const _ as *const c_void), Some(&mut out), &mut size, NCRYPT_PAD_OAEP_FLAG)
                .map_err(|e| io::Error::other(format!("TPM encrypt: {e}")))?;
            out.truncate(size as usize);
            Ok(out)
        }
    }

    fn decrypt(&self, data: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let pad = Self::padding();
        let mut size = 0u32;
        // SAFETY: 缓冲区与长度一致。
        unsafe {
            NCryptDecrypt(self.key, Some(data), Some(&pad as *const _ as *const c_void), None, &mut size, NCRYPT_PAD_OAEP_FLAG)
                .map_err(|e| io::Error::other(format!("TPM decrypt: {e}")))?;
            let mut out = Zeroizing::new(vec![0u8; size as usize]);
            NCryptDecrypt(self.key, Some(data), Some(&pad as *const _ as *const c_void), Some(&mut out), &mut size, NCRYPT_PAD_OAEP_FLAG)
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("TPM decrypt: {e}")))?;
            out.truncate(size as usize);
            Ok(out)
        }
    }
}

impl DpapiSealer {
    pub fn probe(layout: &Layout) -> Self {
        Self::new(Tpm::available(), layout)
    }

    pub fn from_method(method: &str, layout: &Layout) -> Self {
        Self::new(method == METHOD_DPAPI_TPM, layout)
    }

    fn new(tpm: bool, layout: &Layout) -> Self {
        Self { tpm, os_blob: layout.data_dir.join("device-key.dpapi"), hw_blob: layout.data_dir.join("device-key.tpm") }
    }
}

impl Sealer for DpapiSealer {
    fn method(&self) -> &'static str {
        if self.tpm { METHOD_DPAPI_TPM } else { METHOD_DPAPI }
    }

    fn level(&self) -> u8 {
        if self.tpm { 3 } else { 2 }
    }

    fn describe(&self) -> String {
        if self.tpm {
            "DPAPI（服务账户）+ TPM 不可导出密钥".into()
        } else {
            "DPAPI（服务账户，由 LSA 系统机密保护）".into()
        }
    }

    fn is_provisioned(&self) -> bool {
        self.os_blob.exists() && (!self.tpm || self.hw_blob.exists())
    }

    fn seal(&self, key: &[u8; 32], rand: RandFn) -> io::Result<()> {
        if let Some(d) = self.os_blob.parent() {
            fs::create_dir_all(d)?;
        }
        let mut k_os = Zeroizing::new(*key);
        if self.tpm {
            let mut k_hw = Zeroizing::new([0u8; 32]);
            rand(k_hw.as_mut())?;
            let tpm = Tpm::open(true)?;
            fs::write(&self.hw_blob, tpm.encrypt(k_hw.as_ref())?)?;
            for (a, b) in k_os.iter_mut().zip(k_hw.iter()) {
                *a ^= *b;
            }
        }
        fs::write(&self.os_blob, dpapi_protect(k_os.as_ref())?)
    }

    fn unseal(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        let os = dpapi_unprotect(&fs::read(&self.os_blob)?)?;
        let mut key = key_from_bytes(&os)?;
        if self.tpm {
            let tpm = Tpm::open(false)?;
            let hw = tpm.decrypt(&fs::read(&self.hw_blob)?)?;
            let hw = key_from_bytes(&hw)?;
            for (a, b) in key.iter_mut().zip(hw.iter()) {
                *a ^= *b;
            }
        }
        Ok(key)
    }

    fn remove(&self) -> io::Result<()> {
        let _ = fs::remove_file(&self.os_blob);
        let _ = fs::remove_file(&self.hw_blob);
        if self.tpm
            && let Ok(t) = Tpm::open(false)
        {
            // SAFETY: 删除后句柄失效，避免 Drop 再次释放。
            unsafe {
                let _ = NCryptDeleteKey(t.key, 0);
            }
            std::mem::forget(t);
        }
        Ok(())
    }
}

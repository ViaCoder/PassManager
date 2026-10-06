//! HKDF-SHA512（aws-lc-rs）。

use aws_lc_rs::hkdf::{HKDF_SHA256, HKDF_SHA512, KeyType, Salt};
use zeroize::Zeroizing;

use crate::CryptoError;

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA512：`out.len()` 最多 255*64 字节。
pub fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<(), CryptoError> {
    if out.len() > 255 * 64 {
        return Err(CryptoError::Invalid("hkdf output too long"));
    }
    let prk = Salt::new(HKDF_SHA512, salt).extract(ikm);
    prk.expand(info, Len(out.len()))?.fill(out)?;
    Ok(())
}

/// 便捷函数：派生 32 字节密钥。
pub fn derive32(salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf_sha512(salt, ikm, info, out.as_mut())?;
    Ok(out)
}

/// 仅用于自检：HKDF-SHA256（RFC 5869 测试向量）。
pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<(), CryptoError> {
    let prk = Salt::new(HKDF_SHA256, salt).extract(ikm);
    prk.expand(info, Len(out.len()))?.fill(out)?;
    Ok(())
}

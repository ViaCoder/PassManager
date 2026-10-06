//! 库文件格式：
//!
//! ```text
//! "PMVAULT\0" | u32 LE header_len | header (postcard) | sealed payload (postcard)
//! ```
//!
//! 文件头（静态部分）的 SHA-512 作为双层加密的 AAD，因此任何字段被篡改都会导致解密失败。

use pm_crypto::envelope::SealedPayload;
use pm_crypto::kdf::KdfParams;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::VaultError;
use crate::model::Payload;

pub const MAGIC: &[u8; 8] = b"PMVAULT\0";
pub const VERSION: u16 = 1;
const PAD: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub version: u16,
    pub vault_id: [u8; 16],
    /// 设备密钥封存等级（1/2/3），写入后受认证保护，防止降级。
    pub seal_level: u8,
    /// 设备密钥校验值。
    pub kcv: [u8; 16],
    pub kdf: KdfParams,
    pub salt: [u8; 32],
    pub ek_mlkem: Vec<u8>,
    pub pk_mce: Vec<u8>,
    pub wrap_a: Vec<u8>,
    pub wrap_b: Vec<u8>,
}

impl Header {
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        postcard::to_allocvec(self).map_err(|_| VaultError::Corrupt("header encode"))
    }

    pub fn hash(&self) -> Result<[u8; 64], VaultError> {
        Ok(pm_crypto::sha512(&self.to_bytes()?))
    }
}

pub fn encode_file(header: &Header, sealed: &SealedPayload) -> Result<Vec<u8>, VaultError> {
    let h = header.to_bytes()?;
    let s = postcard::to_allocvec(sealed).map_err(|_| VaultError::Corrupt("payload encode"))?;
    let mut out = Vec::with_capacity(12 + h.len() + s.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(h.len() as u32).to_le_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(&s);
    Ok(out)
}

pub fn decode_file(data: &[u8]) -> Result<(Header, SealedPayload), VaultError> {
    if data.len() < 12 || &data[..8] != MAGIC {
        return Err(VaultError::Corrupt("not a PassManager vault"));
    }
    let hlen = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    if data.len() < 12 + hlen {
        return Err(VaultError::Corrupt("truncated header"));
    }
    let header: Header = postcard::from_bytes(&data[12..12 + hlen]).map_err(|_| VaultError::Corrupt("header"))?;
    if header.version != VERSION {
        return Err(VaultError::Corrupt("unsupported vault version"));
    }
    let sealed: SealedPayload = postcard::from_bytes(&data[12 + hlen..]).map_err(|_| VaultError::Corrupt("sealed payload"))?;
    Ok((header, sealed))
}

/// 序列化载荷并填充到 4 KiB 的整数倍（隐藏条目数量与长度）。
pub fn encode_payload(p: &Payload) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let body = Zeroizing::new(postcard::to_allocvec(p).map_err(|_| VaultError::Corrupt("payload encode"))?);
    let total = (4 + body.len()).div_ceil(PAD) * PAD;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out.resize(total, 0);
    Ok(out)
}

pub fn decode_payload(data: &[u8]) -> Result<Payload, VaultError> {
    if data.len() < 4 {
        return Err(VaultError::Corrupt("payload"));
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if data.len() < 4 + len {
        return Err(VaultError::Corrupt("payload length"));
    }
    postcard::from_bytes(&data[4..4 + len]).map_err(|_| VaultError::Corrupt("payload decode"))
}

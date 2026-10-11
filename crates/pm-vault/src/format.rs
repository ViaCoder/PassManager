//! 库文件格式：
//!
//! ```text
//! "PMVAULT\0" | u32 LE header_len | header (postcard) | sealed payload (postcard)
//! ```
//!
//! 文件头（静态部分）的 SHA-512 作为双层加密的 AAD，因此任何字段被篡改都会导致解密失败。
//!
//! 文件头有两个版本：v1（口令模式，0.1.0 的原始格式）与 v2（无口令模式，多一个模式字节）。
//! 重新编码时严格按读入时的版本写回，保证 AAD 与原文件一致。

use pm_crypto::envelope::SealedPayload;
use pm_crypto::kdf::KdfParams;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::VaultError;
use crate::model::Payload;

pub const MAGIC: &[u8; 8] = b"PMVAULT\0";
/// 口令模式（原始格式，保持不变）。
pub const VERSION: u16 = 1;
/// 无口令模式（服务器在线版）：文件头多一个模式字段。
pub const VERSION_DEVICE_ONLY: u16 = 2;
const PAD: usize = 4096;

/// 库的解锁方式。写入文件头（受双层 AEAD 的 AAD 保护），并参与 KEK 派生（HKDF info 不同），
/// 因此把无口令库改成口令库、或反过来，都只会导致解密失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultMode {
    /// IKM = Argon2id(口令) ‖ 设备密钥。
    Password,
    /// IKM = 设备密钥（不运行 Argon2）。
    DeviceOnly,
}

const MODE_DEVICE_ONLY: u8 = 1;

#[derive(Clone, Debug)]
pub struct Header {
    pub version: u16,
    pub mode: VaultMode,
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

/// v1 文件头的线上格式（与 0.1.0 完全相同）。
#[derive(Serialize, Deserialize)]
struct WireV1 {
    version: u16,
    vault_id: [u8; 16],
    seal_level: u8,
    kcv: [u8; 16],
    kdf: KdfParams,
    salt: [u8; 32],
    ek_mlkem: Vec<u8>,
    pk_mce: Vec<u8>,
    wrap_a: Vec<u8>,
    wrap_b: Vec<u8>,
}

/// v2 文件头：在版本号之后多一个模式字节。
#[derive(Serialize, Deserialize)]
struct WireV2 {
    version: u16,
    mode: u8,
    vault_id: [u8; 16],
    seal_level: u8,
    kcv: [u8; 16],
    kdf: KdfParams,
    salt: [u8; 32],
    ek_mlkem: Vec<u8>,
    pk_mce: Vec<u8>,
    wrap_a: Vec<u8>,
    wrap_b: Vec<u8>,
}

impl Header {
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let h = self.clone();
        let r = match (self.mode, self.version) {
            (VaultMode::Password, VERSION) => postcard::to_allocvec(&WireV1 {
                version: h.version,
                vault_id: h.vault_id,
                seal_level: h.seal_level,
                kcv: h.kcv,
                kdf: h.kdf,
                salt: h.salt,
                ek_mlkem: h.ek_mlkem,
                pk_mce: h.pk_mce,
                wrap_a: h.wrap_a,
                wrap_b: h.wrap_b,
            }),
            (VaultMode::DeviceOnly, VERSION_DEVICE_ONLY) => postcard::to_allocvec(&WireV2 {
                version: h.version,
                mode: MODE_DEVICE_ONLY,
                vault_id: h.vault_id,
                seal_level: h.seal_level,
                kcv: h.kcv,
                kdf: h.kdf,
                salt: h.salt,
                ek_mlkem: h.ek_mlkem,
                pk_mce: h.pk_mce,
                wrap_a: h.wrap_a,
                wrap_b: h.wrap_b,
            }),
            _ => return Err(VaultError::Corrupt("header mode does not match its version")),
        };
        r.map_err(|_| VaultError::Corrupt("header encode"))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        let (version, _) = postcard::take_from_bytes::<u16>(data).map_err(|_| VaultError::Corrupt("header"))?;
        match version {
            VERSION => {
                let w: WireV1 = postcard::from_bytes(data).map_err(|_| VaultError::Corrupt("header"))?;
                Ok(Self {
                    version: w.version,
                    mode: VaultMode::Password,
                    vault_id: w.vault_id,
                    seal_level: w.seal_level,
                    kcv: w.kcv,
                    kdf: w.kdf,
                    salt: w.salt,
                    ek_mlkem: w.ek_mlkem,
                    pk_mce: w.pk_mce,
                    wrap_a: w.wrap_a,
                    wrap_b: w.wrap_b,
                })
            }
            VERSION_DEVICE_ONLY => {
                let w: WireV2 = postcard::from_bytes(data).map_err(|_| VaultError::Corrupt("header"))?;
                if w.mode != MODE_DEVICE_ONLY {
                    return Err(VaultError::Corrupt("unknown vault mode"));
                }
                Ok(Self {
                    version: w.version,
                    mode: VaultMode::DeviceOnly,
                    vault_id: w.vault_id,
                    seal_level: w.seal_level,
                    kcv: w.kcv,
                    kdf: w.kdf,
                    salt: w.salt,
                    ek_mlkem: w.ek_mlkem,
                    pk_mce: w.pk_mce,
                    wrap_a: w.wrap_a,
                    wrap_b: w.wrap_b,
                })
            }
            _ => Err(VaultError::Corrupt("unsupported vault version")),
        }
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
    let header = Header::from_bytes(&data[12..12 + hlen])?;
    let sealed: SealedPayload = postcard::from_bytes(&data[12 + hlen..]).map_err(|_| VaultError::Corrupt("sealed payload"))?;
    Ok((header, sealed))
}

/// v2 载荷的标记（放在 postcard 数据之前）。v1 载荷的第一个字节是条目数，第二个字节是第一个引用名的长度
/// （≤ 64），不可能是 `'M'`（77），所以不会与旧格式混淆。
pub const PAYLOAD_V2_MAGIC: &[u8; 5] = b"PMP2\0";

/// 序列化载荷（v2：支持多字段条目）并填充到 4 KiB 的整数倍（隐藏条目数量与长度）。
pub fn encode_payload(p: &Payload) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut v = Zeroizing::new(PAYLOAD_V2_MAGIC.to_vec());
    v.extend_from_slice(&Zeroizing::new(postcard::to_allocvec(p).map_err(|_| VaultError::Corrupt("payload encode"))?));
    pad(v)
}

/// 0.1.0 的载荷编码（只用于测试旧库迁移）。
#[doc(hidden)]
pub fn encode_payload_v1(p: &crate::model::PayloadV1) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    pad(Zeroizing::new(postcard::to_allocvec(p).map_err(|_| VaultError::Corrupt("payload encode"))?))
}

fn pad(body: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, VaultError> {
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
    let body = &data[4..4 + len];
    match body.strip_prefix(PAYLOAD_V2_MAGIC.as_slice()) {
        Some(v2) => postcard::from_bytes(v2).map_err(|_| VaultError::Corrupt("payload decode")),
        // 0.1.0 写入的库：按旧结构读入，下一次保存时自动升级为 v2。
        None => postcard::from_bytes::<crate::model::PayloadV1>(body).map(Payload::from).map_err(|_| VaultError::Corrupt("payload decode")),
    }
}

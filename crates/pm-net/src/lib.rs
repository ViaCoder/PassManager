//! PassManager 网络层（局域网在线版）：
//! - [`tls`]：外层 TLS 1.3 策略（只允许混合后量子密钥交换 + AES-256-GCM-SHA384）、可热替换的证书；
//! - [`acme`]：Let's Encrypt DNS-01（Cloudflare）签发与续期判断；
//! - [`inner`]：Agent 通道的第二层（ML-KEM-1024 + Classic McEliece 6688128，ChaCha20-Poly1305 帧）；
//! - [`enroll`]：一次性注册码 `pm-enroll://…`。

pub mod acme;
pub mod client;
pub mod enroll;
pub mod inner;
pub mod tls;

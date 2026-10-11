//! ssh-agent 桥的服务端部分：私钥从不离开服务器，只按严格条件代为签名。
//!
//! 签名前必须满足：
//! 1. 客户端（OpenSSH ≥ 8.9）发来了 `session-bind@openssh.com`，且不是转发会话（`is_forwarding = false`）；
//! 2. 绑定里的主机密钥对会话标识的签名有效（证明 ssh 确实在与这台主机通信）；
//! 3. 该主机密钥属于条目允许的主机：条目上显式绑定的主机密钥指纹，或 PassManager 指纹库里与条目域名匹配的记录（TOFU）；
//! 4. 待签数据是针对同一会话标识、同一公钥的 `SSH_MSG_USERAUTH_REQUEST`（publickey）——不能被用来签任意数据；
//! 5. 速率限制；每次签名记审计日志（条目、公钥指纹、主机密钥指纹，不记录数据）。

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use russh::keys::signature::{Signer, Verifier};
use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::{self, HashAlg, PublicKey};

/// SSH_MSG_USERAUTH_REQUEST
const USERAUTH_REQUEST: u8 = 50;
/// SSH_AGENT_RSA_SHA2_256 / SSH_AGENT_RSA_SHA2_512
pub const FLAG_RSA_SHA2_256: u32 = 2;
pub const FLAG_RSA_SHA2_512: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuth {
    pub session_id: Vec<u8>,
    pub key_blob: Vec<u8>,
    /// `publickey-hostbound-v00@openssh.com` 时携带的主机密钥。
    pub host_key: Option<Vec<u8>>,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        if self.0.len() < 4 {
            return None;
        }
        let n = u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as usize;
        if self.0.len() < 4 + n {
            return None;
        }
        let v = &self.0[4..4 + n];
        self.0 = &self.0[4 + n..];
        Some(v)
    }
    fn byte(&mut self) -> Option<u8> {
        let (b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*b)
    }
}

/// 解析待签数据：必须是 publickey 方式的 `SSH_MSG_USERAUTH_REQUEST`。
pub fn parse_userauth(data: &[u8]) -> Result<UserAuth, &'static str> {
    let mut r = Reader(data);
    let session_id = r.string().ok_or("truncated")?.to_vec();
    if r.byte() != Some(USERAUTH_REQUEST) {
        return Err("not a userauth request");
    }
    let _user = r.string().ok_or("truncated")?;
    let _service = r.string().ok_or("truncated")?;
    let method = r.string().ok_or("truncated")?;
    let hostbound = match method {
        b"publickey" => false,
        b"publickey-hostbound-v00@openssh.com" => true,
        _ => return Err("not a publickey request"),
    };
    if r.byte() != Some(1) {
        return Err("not a signed publickey request");
    }
    let _alg = r.string().ok_or("truncated")?;
    let key_blob = r.string().ok_or("truncated")?.to_vec();
    let host_key = if hostbound { Some(r.string().ok_or("truncated")?.to_vec()) } else { None };
    if !r.0.is_empty() {
        return Err("trailing data");
    }
    Ok(UserAuth { session_id, key_blob, host_key })
}

/// 校验 session-bind：主机密钥对会话标识的签名。返回主机密钥的 SHA256 指纹。
pub fn verify_binding(host_key: &[u8], session_id: &[u8], signature: &[u8]) -> Result<String, &'static str> {
    let pk = PublicKey::from_bytes(host_key).map_err(|_| "bad host key")?;
    let sig = ssh_key::Signature::try_from(signature).map_err(|_| "bad signature encoding")?;
    Verifier::verify(&pk, session_id, &sig).map_err(|_| "host key signature does not verify")?;
    Ok(pk.fingerprint(HashAlg::Sha256).to_string())
}

/// 规范化主机密钥：接受 `SHA256:…` 指纹，或 OpenSSH 公钥行（`算法 base64 [注释]`，也可以是带主机名前缀的 known_hosts 行），返回指纹。
pub fn host_key_fingerprint(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.starts_with("SHA256:") {
        pm_vault::validate_host_key_fp(s)?;
        return Ok(s.to_string());
    }
    let try_parse = |line: &str| PublicKey::from_openssh(line).ok().map(|k| k.fingerprint(HashAlg::Sha256).to_string());
    try_parse(s)
        .or_else(|| s.split_once(char::is_whitespace).and_then(|(_, rest)| try_parse(rest.trim())))
        .ok_or_else(|| "无法识别的主机密钥（需要 SHA256:… 指纹或 OpenSSH 公钥行）".to_string())
}

/// 公钥（SSH 线上格式）。
pub fn public_blob(pem: &str) -> Result<Vec<u8>, String> {
    let k = russh::keys::decode_secret_key(pem, None).map_err(|_| "无法解析 SSH 私钥".to_string())?;
    k.public_key().to_bytes().map_err(|e| e.to_string())
}

/// 用私钥签名，返回 SSH 线上格式的签名。RSA 按 flags 选择 rsa-sha2-256 / rsa-sha2-512（默认 512）。
pub fn sign(pem: &str, data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
    let k = russh::keys::decode_secret_key(pem, None).map_err(|_| "无法解析 SSH 私钥".to_string())?;
    let sig: ssh_key::Signature = match k.key_data() {
        ssh_key::private::KeypairData::Rsa(rsa) => {
            let hash = if flags & FLAG_RSA_SHA2_256 != 0 { HashAlg::Sha256 } else { HashAlg::Sha512 };
            Signer::try_sign(&(rsa, Some(hash)), data).map_err(|e| e.to_string())?
        }
        _ => Signer::try_sign(&k, data).map_err(|e| e.to_string())?,
    };
    let mut out = Vec::new();
    sig.encode(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// 滑动窗口速率限制。
pub struct SignLimiter {
    max: usize,
    window: Duration,
    times: VecDeque<Instant>,
}

impl SignLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self { max, window, times: VecDeque::new() }
    }

    pub fn allow_at(&mut self, now: Instant) -> bool {
        while self.times.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            self.times.pop_front();
        }
        if self.times.len() >= self.max {
            return false;
        }
        self.times.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[u8]) -> Vec<u8> {
        let mut o = (v.len() as u32).to_be_bytes().to_vec();
        o.extend_from_slice(v);
        o
    }

    pub fn userauth(session: &[u8], key: &[u8], hostkey: Option<&[u8]>) -> Vec<u8> {
        let mut d = s(session);
        d.push(USERAUTH_REQUEST);
        d.extend(s(b"deploy"));
        d.extend(s(b"ssh-connection"));
        d.extend(s(if hostkey.is_some() { b"publickey-hostbound-v00@openssh.com" as &[u8] } else { b"publickey" }));
        d.push(1);
        d.extend(s(b"ecdsa-sha2-nistp384"));
        d.extend(s(key));
        if let Some(h) = hostkey {
            d.extend(s(h));
        }
        d
    }

    /// 确定性的一次性测试密钥（Ed25519，由种子生成；P-384 由端到端测试用 ssh-keygen 覆盖）。
    fn test_key(seed: u8) -> russh::keys::PrivateKey {
        let kp = ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]);
        russh::keys::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(kp), "test").unwrap()
    }

    #[test]
    fn userauth_parsing() {
        let u = parse_userauth(&userauth(b"sess", b"KEY", None)).unwrap();
        assert_eq!((u.session_id.as_slice(), u.key_blob.as_slice(), u.host_key), (&b"sess"[..], &b"KEY"[..], None));
        let u = parse_userauth(&userauth(b"sess", b"KEY", Some(b"HOST"))).unwrap();
        assert_eq!(u.host_key.as_deref(), Some(&b"HOST"[..]));
        let good = userauth(b"sess", b"KEY", None);
        assert!(parse_userauth(&good[..good.len() - 1]).is_err());
        let mut extra = good.clone();
        extra.push(0);
        assert!(parse_userauth(&extra).is_err());
        let mut not_auth = good.clone();
        not_auth[8] = 51;
        assert!(parse_userauth(&not_auth).is_err());
        assert!(parse_userauth(b"arbitrary data to sign").is_err(), "任意数据不能签");
        let mut d = s(b"sess");
        d.push(USERAUTH_REQUEST);
        d.extend(s(b"u"));
        d.extend(s(b"ssh-connection"));
        d.extend(s(b"password"));
        assert!(parse_userauth(&d).is_err());
    }

    #[test]
    fn binding_signature_and_signing() {
        let host = test_key(1);
        let session = b"session-identifier-123";
        let sig = Signer::<ssh_key::Signature>::try_sign(&host, session).unwrap();
        let mut sig_blob = Vec::new();
        sig.encode(&mut sig_blob).unwrap();
        let host_blob = host.public_key().to_bytes().unwrap();
        let fp = verify_binding(&host_blob, session, &sig_blob).unwrap();
        assert_eq!(fp, host.public_key().fingerprint(HashAlg::Sha256).to_string());
        assert!(verify_binding(&host_blob, b"other-session", &sig_blob).is_err());
        let other = test_key(2);
        assert!(verify_binding(&other.public_key().to_bytes().unwrap(), session, &sig_blob).is_err());
        assert!(verify_binding(b"junk", session, &sig_blob).is_err());
        assert!(verify_binding(&host_blob, session, b"junk").is_err());
        // 签名能被对应的公钥验证。
        let client = test_key(3);
        let pem = client.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let data = userauth(session, &client.public_key().to_bytes().unwrap(), None);
        let out = sign(&pem, &data, 0).unwrap();
        let sig = ssh_key::Signature::try_from(out.as_slice()).unwrap();
        Verifier::verify(client.public_key(), &data, &sig).unwrap();
        assert_eq!(public_blob(&pem).unwrap(), client.public_key().to_bytes().unwrap());
        assert!(sign("not a key", &data, 0).is_err());
    }

    #[test]
    fn host_key_inputs() {
        let k = test_key(9);
        let fp = k.public_key().fingerprint(HashAlg::Sha256).to_string();
        let line = k.public_key().to_openssh().unwrap();
        assert_eq!(host_key_fingerprint(&line).unwrap(), fp);
        assert_eq!(host_key_fingerprint(&format!("db1.example.com {line}")).unwrap(), fp, "known_hosts 行");
        assert_eq!(host_key_fingerprint(&fp).unwrap(), fp);
        assert!(host_key_fingerprint("SHA256:short").is_err());
        assert!(host_key_fingerprint("garbage").is_err());
    }

    #[test]
    fn limiter() {
        let mut l = SignLimiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(l.allow_at(t0) && l.allow_at(t0) && l.allow_at(t0));
        assert!(!l.allow_at(t0 + Duration::from_secs(59)));
        assert!(l.allow_at(t0 + Duration::from_secs(60)));
    }
}

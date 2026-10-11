//! 一次性注册码：`pm-enroll://<主机>:<端口>/<注册码>#<服务端公钥指纹>`。
//!
//! - 注册码：32 字节随机数（base64url，43 个字符），10 分钟有效、只能使用一次；服务端只在内存里保存它的 SHA-256；
//! - 指纹：内层通道服务端公钥包的 SHA-384（base64url，64 个字符），Agent 用它核对下载的公钥（固定，不是 TOFU）；
//! - 主机必须写明（没有默认服务器）；省略端口时为 8443。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::inner::FPR_LEN;

pub const SCHEME: &str = "pm-enroll://";
pub const DEFAULT_PORT: u16 = 8443;
pub const CODE_LEN: usize = 43;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollUrl {
    pub host: String,
    pub port: u16,
    pub code: String,
    pub fpr: [u8; FPR_LEN],
}

pub fn fpr_text(fpr: &[u8; FPR_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(fpr)
}

pub fn parse_fpr(s: &str) -> Result<[u8; FPR_LEN], String> {
    let v = URL_SAFE_NO_PAD.decode(s.trim()).map_err(|_| "指纹格式无效".to_string())?;
    v.try_into().map_err(|_| "指纹长度无效（应为 SHA-384）".to_string())
}

fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// 新的随机注册码。
pub fn new_code() -> Result<String, pm_crypto::CryptoError> {
    let raw: [u8; 32] = pm_crypto::rng::random_array()?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

impl EnrollUrl {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let rest = s.strip_prefix(SCHEME).ok_or_else(|| format!("注册码必须以 {SCHEME} 开头"))?;
        let (main, fpr) = rest.split_once('#').ok_or("注册码缺少 #<指纹> 部分")?;
        let fpr = parse_fpr(fpr)?;
        let (authority, code) = main.split_once('/').ok_or("注册码缺少服务器地址（pm-enroll://主机:端口/注册码#指纹）")?;
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), p.parse::<u16>().map_err(|_| "端口无效".to_string())?),
            None => (authority.to_ascii_lowercase(), DEFAULT_PORT),
        };
        if !host_ok(&host) || port == 0 {
            return Err("服务器地址无效".into());
        }
        if code.len() != CODE_LEN || !code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err("注册码格式无效".into());
        }
        Ok(Self { host, port, code: code.to_string(), fpr })
    }
}

impl std::fmt::Display for EnrollUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SCHEME}{}:{}/{}#{}", self.host, self.port, self.code, fpr_text(&self.fpr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_default_port() {
        let code = new_code().unwrap();
        assert_eq!(code.len(), CODE_LEN);
        let u = EnrollUrl { host: "pm.example.com".into(), port: 8443, code: code.clone(), fpr: [7u8; 48] };
        let s = u.to_string();
        assert!(s.starts_with("pm-enroll://pm.example.com:8443/"));
        assert_eq!(EnrollUrl::parse(&s).unwrap(), u);
        assert_eq!(EnrollUrl::parse(&format!("  {s}\n")).unwrap(), u);
        // 没有服务器地址的简写不再接受（没有默认服务器）。
        assert!(EnrollUrl::parse(&format!("pm-enroll://{code}#{}", fpr_text(&[7u8; 48]))).is_err());
        let no_port = format!("pm-enroll://PM.example.com/{code}#{}", fpr_text(&[7u8; 48]));
        let p = EnrollUrl::parse(&no_port).unwrap();
        assert_eq!((p.host.as_str(), p.port), ("pm.example.com", 8443));
    }

    #[test]
    fn malformed_urls_are_rejected() {
        let code = new_code().unwrap();
        let f = fpr_text(&[1u8; 48]);
        for bad in [
            format!("https://pm.example.com/{code}#{f}"),
            format!("pm-enroll://pm.example.com:8443/{code}"),
            format!("pm-enroll://pm.example.com:8443/{code}#"),
            format!("pm-enroll://pm.example.com:8443/{code}#{}", &f[..60]),
            format!("pm-enroll://pm.example.com:8443/{code}#{f}AAAA"),
            format!("pm-enroll://pm.example.com:99999/{code}#{f}"),
            format!("pm-enroll://pm.example.com:0/{code}#{f}"),
            format!("pm-enroll://evil host/{code}#{f}"),
            format!("pm-enroll://:8443/{code}#{f}"),
            format!("pm-enroll://pm.example.com:8443/{}#{f}", &code[1..]),
            format!("pm-enroll://pm.example.com:8443/{}!#{f}", &code[1..]),
            format!("pm-enroll://pm.example.com:8443/a/{code}#{f}"),
            String::new(),
        ] {
            assert!(EnrollUrl::parse(&bad).is_err(), "{bad}");
        }
    }
}

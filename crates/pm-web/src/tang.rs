//! Tang（网络绑定加密，NBDE）的 HTTPS 入口：把 Clevis 的请求原样转给本机回环上的 tangd（Debian 的 `tang` 包）。
//! - `GET /tang/adv`、`/tang/adv/{thp}`：tangd 签名的公钥广告（JWS）；
//! - `POST /tang/rec/{kid}`：McCallum-Relyea 交换（tangd 只做一次点乘，看不到客户端的密钥）。
//!
//! 访问控制与网页相同：来源必须在局域网网段或允许列表（`front`），Host 必须是本站（`guard_check`）；
//! 传输是网页端口的 TLS 1.3 + 混合后量子组。tangd 每个连接只处理一个请求、读到 EOF 才回答，
//! 所以写完请求后关闭写方向，再读到 EOF。只转发 tangd 的两种回答类型，其余一律 502。

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::St;

/// 连接、发送与读取回答的总时限。
const TIMEOUT: Duration = Duration::from_secs(10);
/// tangd 的回答（广告或 JWK）只有几 KB。
const REPLY_LIMIT: usize = 64 << 10;
/// Clevis 发送的 JWK 只有几百字节。
pub const BODY_LIMIT: usize = 8 << 10;
/// 广告的类型（adv）与交换结果的类型（rec）。
const JOSE: &str = "application/jose+json";
const JWK: &str = "application/jwk+json";

/// 公钥指纹与密钥 ID：tangd 的路由同样只接受 `[0-9A-Za-z_-]`。
pub fn id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `GET /tang/adv`（以及 `/tang/adv/`）：全部签名密钥的广告。
pub async fn adv(State(st): State<St>) -> Response {
    forward(st.cfg.tang, "GET", "/adv", None).await
}

/// `GET /tang/adv/{thp}`：用指纹为 thp 的签名密钥签的广告（Clevis 给了 thp 时这样取）。
pub async fn adv_thp(State(st): State<St>, Path(thp): Path<String>) -> Response {
    if !id_ok(&thp) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    forward(st.cfg.tang, "GET", &format!("/adv/{thp}"), None).await
}

/// `POST /tang/rec/{kid}`：Clevis 解密时的交换请求（JWK）。
pub async fn rec(State(st): State<St>, Path(kid): Path<String>, h: HeaderMap, body: Bytes) -> Response {
    if !id_ok(&kid) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let ct = h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.trim().eq_ignore_ascii_case(JWK) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected application/jwk+json").into_response();
    }
    if body.len() > BODY_LIMIT {
        return (StatusCode::PAYLOAD_TOO_LARGE, "too large").into_response();
    }
    forward(st.cfg.tang, "POST", &format!("/rec/{kid}"), Some(&body)).await
}

/// 发给 tangd，把回答换成本站的回答；tangd 不可用或回答异常时 502（不透露细节）。
async fn forward(up: Option<SocketAddr>, method: &str, path: &str, body: Option<&[u8]>) -> Response {
    let Some(up) = up else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let raw = match tokio::time::timeout(TIMEOUT, exchange(up, &request(method, path, body))).await {
        Ok(Ok(raw)) => raw,
        _ => return (StatusCode::BAD_GATEWAY, "tang unavailable").into_response(),
    };
    match parse_reply(&raw) {
        // 成功：只接受 tangd 的两种类型，正文原样返回。
        Some((200, Some(ct), b)) if ct == JOSE || ct == JWK => {
            ([(header::CONTENT_TYPE, if ct == JOSE { JOSE } else { JWK })], b).into_response()
        }
        // tangd 的拒绝（请求格式不对、密钥不存在等）：只转发状态码。
        Some((c @ (400 | 403 | 404 | 405 | 413), _, _)) => {
            (StatusCode::from_u16(c).unwrap_or(StatusCode::BAD_GATEWAY), "tang refused").into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "tang unavailable").into_response(),
    }
}

/// 一次交换：连接 tangd，发送请求，关闭写方向（tangd 读到 EOF 才处理），读回答（有上限）。
async fn exchange(up: SocketAddr, req: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(up).await?;
    s.write_all(req).await?;
    s.shutdown().await?;
    let mut raw = Vec::new();
    (&mut s).take(REPLY_LIMIT as u64 + 1).read_to_end(&mut raw).await?;
    if raw.len() > REPLY_LIMIT {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(raw)
}

/// 发给 tangd 的 HTTP/1.1 请求（路径已校验；只有 rec 带正文）。
pub fn request(method: &str, path: &str, body: Option<&[u8]>) -> Vec<u8> {
    let mut r = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(b) = body {
        r.push_str(&format!("Content-Type: {JWK}\r\nContent-Length: {}\r\n", b.len()));
    }
    r.push_str("\r\n");
    let mut out = r.into_bytes();
    out.extend_from_slice(body.unwrap_or_default());
    out
}

/// 解析 tangd 的回答：状态码、Content-Type（小写、去掉参数）与正文（有 Content-Length 时按它截取，不足即无效）。
pub fn parse_reply(raw: &[u8]) -> Option<(u16, Option<String>, Vec<u8>)> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?;
    let mut it = status.splitn(3, ' ');
    if !it.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let code: u16 = it.next()?.parse().ok()?;
    let (mut ct, mut len) = (None, None);
    for l in lines {
        let (k, v) = l.split_once(':')?;
        match k.trim().to_ascii_lowercase().as_str() {
            "content-type" => ct = Some(v.split(';').next().unwrap_or("").trim().to_ascii_lowercase()),
            "content-length" => len = Some(v.trim().parse::<usize>().ok()?),
            _ => {}
        }
    }
    let rest = &raw[end + 4..];
    let body = match len {
        Some(n) if rest.len() >= n => rest[..n].to_vec(),
        Some(_) => return None,
        None => rest.to_vec(),
    };
    Some((code, ct, body))
}

/// 向 tangd 取广告并算出签名密钥的指纹（lookup 的 Tang 说明用）。tangd 不可用或回答异常时 Err（不含细节以外的内容）。
pub async fn thumbprints(up: SocketAddr) -> Result<Vec<String>, String> {
    let raw = match tokio::time::timeout(TIMEOUT, exchange(up, &request("GET", "/adv", None))).await {
        Ok(Ok(raw)) => raw,
        Ok(Err(e)) => return Err(format!("tangd unavailable ({e})")),
        Err(_) => return Err("tangd did not answer in time".into()),
    };
    match parse_reply(&raw) {
        Some((200, Some(ct), b)) if ct == JOSE => adv_thumbprints(&b),
        _ => Err("tangd gave an unexpected answer".into()),
    }
}

/// 广告（JWS，正文是 base64url 的 JWK 集合）里签名密钥（`key_ops` 含 `verify`）的指纹，
/// 与 `tang-show-keys` 和 Clevis 配置里的 `thp` 相同。格式不对或没有签名密钥时 Err。
pub fn adv_thumbprints(adv: &[u8]) -> Result<Vec<String>, String> {
    use base64::Engine;
    let jws: serde_json::Value = serde_json::from_slice(adv).map_err(|_| "advertisement is not JSON")?;
    let payload = jws.get("payload").and_then(|p| p.as_str()).ok_or("advertisement has no payload")?;
    let set: serde_json::Value = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("advertisement payload is not a JWK set")?;
    let keys = set.get("keys").and_then(|k| k.as_array()).ok_or("advertisement has no keys")?;
    // 只取签名密钥：交换密钥（deriveKey）不是 thp 的对象。
    let thps: Vec<String> = keys
        .iter()
        .filter(|k| k.get("key_ops").and_then(|o| o.as_array()).is_some_and(|o| o.iter().any(|x| x == "verify")))
        .filter_map(jwk_thumbprint)
        .collect();
    if thps.is_empty() {
        return Err("advertisement has no signing key".into());
    }
    Ok(thps)
}

/// RFC 7638 指纹（SHA-256）：只取该密钥类型的必需成员，按名字排序、无空白序列化，取哈希后 base64url（无填充）。
/// 不认识的类型或缺成员时 None。
pub fn jwk_thumbprint(k: &serde_json::Value) -> Option<String> {
    use base64::Engine;
    let names: &[&str] = match k.get("kty")?.as_str()? {
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        "RSA" => &["e", "kty", "n"],
        _ => return None,
    };
    // BTreeMap 按字节序排列键名，与 RFC 7638 要求的字典序相同（成员名都是 ASCII）。
    let mut m = std::collections::BTreeMap::new();
    for n in names {
        m.insert(*n, k.get(*n)?.as_str()?);
    }
    let canon = serde_json::to_string(&m).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pm_crypto::sha256(canon.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_follow_tangd_routes() {
        // tangd 的路由字符集；空、过长、路径符号、编码字符都拒绝。
        assert!(id_ok("Aa0_-") && id_ok(&"a".repeat(128)));
        for bad in ["", "a/b", "..", "a%2f", "a b", "a.b", &"a".repeat(129)] {
            assert!(!id_ok(bad), "{bad}");
        }
    }

    #[test]
    fn request_shape() {
        assert_eq!(request("GET", "/adv", None), b"GET /adv HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let r = String::from_utf8(request("POST", "/rec/k1", Some(b"{}"))).unwrap();
        assert!(r.starts_with("POST /rec/k1 HTTP/1.1\r\n"));
        assert!(r.contains("Content-Type: application/jwk+json\r\nContent-Length: 2\r\n\r\n{}"));
    }

    #[test]
    fn reply_parsing() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: application/jose+json\r\nContent-Length: 2\r\n\r\n{}extra";
        assert_eq!(parse_reply(ok), Some((200, Some(JOSE.into()), b"{}".to_vec())), "按 Content-Length 截取");
        let p = b"HTTP/1.1 200 OK\r\ncontent-type: Application/JWK+json; charset=utf-8\r\n\r\n{\"k\":1}";
        assert_eq!(parse_reply(p).unwrap().1.as_deref(), Some(JWK), "类型不区分大小写、去掉参数");
        assert_eq!(parse_reply(b"HTTP/1.1 404 Not Found\r\n\r\n").map(|r| r.0), Some(404));
        // 正文不足、没有头部结束、不是 HTTP、坏的长度：都无效。
        for bad in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}"[..],
            b"HTTP/1.1 200 OK\r\n",
            b"SSH-2.0-x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
        ] {
            assert!(parse_reply(bad).is_none());
        }
    }

    /// RFC 7638 第 3.1 节的例子（RSA 密钥及其 SHA-256 指纹）。
    const RFC_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    const RFC_THP: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    #[test]
    fn jwk_thumbprint_matches_rfc7638() {
        // 多余成员（alg、kid）不参与；成员顺序不影响结果。
        let k = serde_json::json!({"kid": "2011-04-29", "alg": "RS256", "e": "AQAB", "n": RFC_N, "kty": "RSA"});
        assert_eq!(jwk_thumbprint(&k).as_deref(), Some(RFC_THP));
        // EC 只取 crv、kty、x、y：多余成员不改变指纹，缺 y 或不认识的类型没有指纹。
        let ec = serde_json::json!({"kty": "EC", "crv": "P-521", "x": "eA", "y": "eQ"});
        let mut more = ec.clone();
        more["key_ops"] = serde_json::json!(["verify"]);
        assert_eq!(jwk_thumbprint(&ec), jwk_thumbprint(&more));
        assert!(jwk_thumbprint(&serde_json::json!({"kty": "EC", "crv": "P-521", "x": "eA"})).is_none());
        assert!(jwk_thumbprint(&serde_json::json!({"kty": "oct", "k": "AA"})).is_none());
    }

    /// 测试用的广告：正文是给定 JWK 集合的 base64url。
    fn adv_with(keys: serde_json::Value) -> Vec<u8> {
        use base64::Engine;
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::json!({ "keys": keys }).to_string());
        serde_json::json!({"payload": p, "protected": "e30", "signature": "AA"}).to_string().into_bytes()
    }

    #[test]
    fn adv_thumbprints_lists_signing_keys_only() {
        let sign = serde_json::json!({"kty": "RSA", "e": "AQAB", "n": RFC_N, "key_ops": ["verify"]});
        let exch = serde_json::json!({"kty": "EC", "crv": "P-521", "x": "eA", "y": "eQ", "key_ops": ["deriveKey"]});
        assert_eq!(adv_thumbprints(&adv_with(serde_json::json!([exch.clone(), sign]))).unwrap(), vec![RFC_THP]);
        // 只有交换密钥、不是 JSON、正文不是 base64url 的 JWK 集合：都是错误。
        assert!(adv_thumbprints(&adv_with(serde_json::json!([exch]))).is_err());
        assert!(adv_thumbprints(b"not json").is_err());
        assert!(adv_thumbprints(br#"{"payload":"!!"}"#).is_err());
    }
}

//! `otpauth://` 链接（Google 身份验证器的 Key Uri Format）：
//! `otpauth://totp/发行方:账户?secret=BASE32&issuer=发行方&algorithm=SHA1&digits=6&period=30`。
//! 标签里的冒号可以是原样或 `%3A`；`issuer` 参数优先于标签里的前缀；缺省值是 SHA1、6 位、30 秒。

use percent_encoding::percent_decode_str;
use zeroize::Zeroizing;

use crate::{Account, Alg, Kind, Params, Skipped, base32_decode, label_of};

/// 解析一条 `otpauth://` 链接。失败时返回带名称（能解析出来的话）和原因的 [`Skipped`]。
pub fn parse(link: &str) -> Result<Account, Skipped> {
    // 链接里带着种子，整理过程中的副本都放进 Zeroizing
    let link = Zeroizing::new(link.trim().to_string());
    // 协议名不分大小写
    let rest = strip_prefix_ci(&link, "otpauth://").ok_or_else(|| Skipped::new("（链接）", "不是 otpauth:// 链接"))?;
    // 类型：totp、steam；hotp 不支持
    let (kind_s, rest) = rest.split_once('/').ok_or_else(|| Skipped::new("（链接）", "链接里缺少类型"))?;
    // 标签在 ? 之前，参数在 ? 之后（没有 ? 时没有参数）
    let (label_raw, query) = rest.split_once('?').unwrap_or((rest, ""));
    // 标签：先百分号解码，再按第一个冒号分成发行方与账户
    let label = decode(label_raw);
    let (mut issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };
    // 读参数
    let mut secret: Option<Zeroizing<Vec<u8>>> = None;
    let mut secret_bad = false;
    let mut params = Params::default();
    let mut bad: Option<&'static str> = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        // 参数值也是百分号编码的；secret 的解码结果是种子，放进 Zeroizing
        let v = Zeroizing::new(decode(v));
        match k.to_ascii_lowercase().as_str() {
            "secret" => match base32_decode(&v) {
                Some(s) => secret = Some(s),
                None => secret_bad = true,
            },
            // issuer 参数优先（wiki：两者都有时应当相同）
            "issuer" if !v.trim().is_empty() => issuer = v.trim().to_string(),
            "algorithm" => match Alg::parse(&v) {
                Some(a) => params.alg = a,
                None => bad = Some("算法不支持（只支持 SHA1、SHA224、SHA256、SHA384、SHA512）"),
            },
            "digits" => match v.trim().parse::<u8>() {
                Ok(d) => params.digits = d,
                Err(_) => bad = Some("验证码位数不是数字"),
            },
            "period" => match v.trim().parse::<u32>() {
                Ok(p) => params.period = p,
                Err(_) => bad = Some("周期不是数字"),
            },
            // 其他参数（counter、image 等）忽略
            _ => {}
        }
    }
    let name = label_of(&issuer, &account);
    // 类型
    params.kind = match kind_s.to_ascii_lowercase().as_str() {
        "totp" => Kind::Totp,
        "steam" => Kind::Steam,
        "hotp" => return Err(Skipped::new(name, "HOTP（计数器型）验证码不支持")),
        _ => return Err(Skipped::new(name, "验证码类型不支持")),
    };
    if let Some(reason) = bad {
        return Err(Skipped::new(name, reason));
    }
    // secret 必须有，且是合法的 Base32
    if secret_bad {
        return Err(Skipped::new(name, "secret 不是合法的 Base32"));
    }
    let secret = secret.ok_or_else(|| Skipped::new(name.clone(), "链接里没有 secret"))?;
    // Steam 固定 5 位
    if params.kind == Kind::Steam {
        params.digits = 5;
    }
    Ok(Account { issuer, account, secret, params })
}

/// 生成 `otpauth://` 链接（"显示密钥"与二维码用）：标签是"发行方:账户"，参数写全（secret、issuer、algorithm、digits、period），
/// Steam 写成 `otpauth://steam/`。结果里有种子，放在 Zeroizing 里。
pub fn build(issuer: &str, account: &str, secret: &[u8], p: &crate::Params) -> Zeroizing<String> {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    // 标签与参数值里除字母数字外都编码（冒号也编码，账户名里的冒号不会被当成分隔符）
    let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    let label = match (issuer.is_empty(), account.is_empty()) {
        (false, false) => format!("{}:{}", enc(issuer), enc(account)),
        // 只有发行方时保留冒号，解析回来账户名为空，不会被当成账户名
        (false, true) => format!("{}:", enc(issuer)),
        _ => enc(account),
    };
    let kind = match p.kind {
        Kind::Totp => "totp",
        Kind::Steam => "steam",
    };
    let b32 = Zeroizing::new(data_encoding::BASE32_NOPAD.encode(secret));
    let mut s = Zeroizing::new(format!("otpauth://{kind}/{label}?secret={}", b32.as_str()));
    if !issuer.is_empty() {
        s.push_str(&format!("&issuer={}", enc(issuer)));
    }
    s.push_str(&format!("&algorithm={}&digits={}&period={}", p.alg.name(), p.digits, p.period));
    s
}

/// 种子的 Base32（不带填充），"显示密钥"用。
pub fn base32(secret: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(data_encoding::BASE32_NOPAD.encode(secret))
}

/// 百分号解码（非 UTF-8 的字节换成替换字符）。
fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// 不分大小写地去掉前缀。
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) { Some(&s[prefix.len()..]) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_google_wiki_example() {
        // Google wiki 的示例链接
        let a = parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example").unwrap();
        assert_eq!(a.issuer, "Example");
        assert_eq!(a.account, "alice@google.com");
        assert_eq!(*a.secret, data_encoding::BASE32_NOPAD.decode(b"JBSWY3DPEHPK3PXP").unwrap());
        assert_eq!(a.params, Params::default());
    }

    #[test]
    fn handles_encoding_case_and_optional_parts() {
        // 百分号编码的冒号与空格、小写 secret、带 =、协议名大写
        let a = parse("OTPAUTH://totp/ACME%20Co%3Ajohn.doe%40email.com?secret=jbswy3dpehpk3pxp%3D%3D&algorithm=sha256&digits=8&period=60")
            .unwrap();
        assert_eq!((a.issuer.as_str(), a.account.as_str()), ("ACME Co", "john.doe@email.com"));
        assert_eq!(a.params, Params { kind: Kind::Totp, alg: Alg::Sha256, digits: 8, period: 60 });
        // issuer 参数优先于标签前缀
        let b = parse("otpauth://totp/Old:bob?secret=JBSWY3DPEHPK3PXP&issuer=New").unwrap();
        assert_eq!(b.issuer, "New");
        // 只有账户、没有发行方
        let c = parse("otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!((c.issuer.as_str(), c.account.as_str()), ("", "bob"));
        // Steam：位数固定 5
        let s = parse("otpauth://steam/Steam:carol?secret=JBSWY3DPEHPK3PXP&digits=6").unwrap();
        assert_eq!((s.params.kind, s.params.digits), (Kind::Steam, 5));
    }

    #[test]
    fn build_round_trips_through_parse() {
        let cases = [
            ("Example", "alice@example.com", Params::default()),
            ("ACME Co", "john:doe", Params { kind: Kind::Totp, alg: Alg::Sha512, digits: 8, period: 60 }),
            ("", "bob", Params { alg: Alg::Sha256, ..Params::default() }),
            ("Steam", "carol", Params { kind: Kind::Steam, alg: Alg::Sha1, digits: 5, period: 30 }),
            ("数字 & 符号/?", "", Params::default()),
        ];
        for (issuer, account, p) in cases {
            let link = build(issuer, account, b"12345678901234567890", &p);
            let a = parse(&link).unwrap_or_else(|e| panic!("{link:?}: {e:?}"));
            assert_eq!((a.issuer.as_str(), a.account.as_str(), a.params), (issuer, account, p), "{}", link.as_str());
            assert_eq!(*a.secret, b"12345678901234567890".to_vec());
        }
        // 参数写全，种子是不带填充的 Base32
        let l = build("Example", "alice", b"12345678901234567890", &Params::default());
        assert_eq!(
            l.as_str(),
            "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30"
        );
        assert_eq!(base32(b"Hello!").as_str(), "JBSWY3DPEE");
    }

    #[test]
    fn rejects_bad_links_with_reasons() {
        let r = |l: &str| parse(l).unwrap_err().reason;
        assert!(r("otpauth://totp/Example:alice?issuer=Example").contains("没有 secret"));
        assert!(r("otpauth://totp/Example:alice?secret=JBSW1Y3DP").contains("Base32"));
        assert!(r("otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&counter=1").contains("HOTP"));
        assert!(r("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").contains("算法"));
        assert!(r("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=x").contains("位数"));
        assert!(r("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&period=-1").contains("周期"));
        assert!(r("otpauth://foo/x?secret=JBSWY3DPEHPK3PXP").contains("类型"));
        assert!(r("otpauth://nolabel").contains("类型"));
        assert!(r("https://example.com/").contains("不是"));
        // 失败时名称照样能说明是哪一个
        assert_eq!(parse("otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP").unwrap_err().label, "Example:alice");
        // 失败原因里不带种子
        let e = parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").unwrap_err();
        assert!(!format!("{e:?}").contains("JBSWY3DPEHPK3PXP"));
    }
}

//! Google 身份验证器"转移账户"导出的二维码：`otpauth-migration://offline?data=<base64>`。
//!
//! `data` 是百分号编码的 base64，里面是一段 protobuf（字段号取自 dim13/otpauth 的 migration.proto）：
//!
//! ```text
//! Payload        { repeated OtpParameters otp_parameters = 1; int32 version = 2; batch_size = 3; batch_index = 4; batch_id = 5; }
//! OtpParameters  { bytes secret = 1; string name = 2; string issuer = 3; Algorithm algorithm = 4;
//!                  DigitCount digits = 5; OtpType type = 6; uint64 counter = 7; string unique_id = 8; }
//! Algorithm  0 未指定 1 SHA1 2 SHA256 3 SHA512 4 MD5；DigitCount 0 未指定 1 六位 2 八位；OtpType 0 未指定 1 HOTP 2 TOTP
//! ```
//!
//! 这里只手写了读这几个字段的小解析器（不引入 protobuf 库）：每段长度都检查，varint 最多 10 字节，未知字段跳过。

use base64::Engine;
use percent_encoding::percent_decode_str;
use zeroize::Zeroizing;

use crate::{Account, Alg, Kind, Params, Parsed, Skipped, label_of};

/// 一个载荷最多读这么多账户（Google 每张码只放十来个）。
const MAX_ACCOUNTS: usize = 1000;

/// 解析一条迁移链接。整条链接坏了时，结果里只有一项说明原因的 skipped。
pub fn parse(link: &str) -> Parsed {
    let mut out = Parsed::default();
    match payload(link) {
        Ok(data) => read_payload(&data, &mut out),
        Err(reason) => out.skipped.push(Skipped::new("（迁移码）", reason)),
    }
    out
}

/// 从链接里取出 protobuf 字节。
fn payload(link: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    // 只认 otpauth-migration://offline?…（不分大小写）
    let lower = link.trim().to_ascii_lowercase();
    let q = lower.strip_prefix("otpauth-migration://offline?").ok_or("不是 otpauth-migration://offline 链接")?;
    // 在原始链接里取 data 参数（base64 区分大小写，不能用转成小写的那份）
    let start = link.trim().len() - q.len();
    let query = &link.trim()[start..];
    let raw = query.split('&').find_map(|p| p.strip_prefix("data=")).ok_or("链接里没有 data 参数")?;
    // 百分号解码后是 base64（标准字母表；带不带 = 都接受，空白去掉）
    let b64: Zeroizing<String> =
        Zeroizing::new(percent_decode_str(raw).decode_utf8_lossy().chars().filter(|c| !c.is_whitespace()).collect());
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    engine.decode(b64.as_bytes()).map(Zeroizing::new).map_err(|_| "data 不是合法的 base64")
}

/// 读整个 Payload：字段 1 是账户，其余字段（版本、分批信息）跳过。
fn read_payload(buf: &[u8], out: &mut Parsed) {
    let mut r = Reader { buf, pos: 0 };
    let mut n = 0;
    while !r.done() {
        let Some((field, wire)) = r.key() else {
            out.skipped.push(Skipped::new("（迁移码）", "数据已损坏"));
            return;
        };
        if field == 1 && wire == 2 {
            // 一个账户
            let Some(body) = r.bytes() else {
                out.skipped.push(Skipped::new("（迁移码）", "数据已损坏"));
                return;
            };
            n += 1;
            if n > MAX_ACCOUNTS {
                out.skipped.push(Skipped::new("（迁移码）", "账户太多，后面的没有读"));
                return;
            }
            match read_params(body) {
                Ok(a) => out.push(a),
                Err(s) => out.skipped.push(s),
            }
        } else if r.skip(wire).is_none() {
            out.skipped.push(Skipped::new("（迁移码）", "数据已损坏"));
            return;
        }
    }
}

/// 读一个 OtpParameters。
fn read_params(buf: &[u8]) -> Result<Account, Skipped> {
    let mut r = Reader { buf, pos: 0 };
    let mut secret = Zeroizing::new(Vec::new());
    let (mut name, mut issuer) = (String::new(), String::new());
    let (mut alg, mut digits, mut kind) = (0u64, 0u64, 0u64);
    let broken = |n: &str, i: &str| Skipped::new(label_of(i, n), "数据已损坏");
    while !r.done() {
        let (field, wire) = r.key().ok_or_else(|| broken(&name, &issuer))?;
        match (field, wire) {
            (1, 2) => secret = Zeroizing::new(r.bytes().ok_or_else(|| broken(&name, &issuer))?.to_vec()),
            (2, 2) => name = String::from_utf8_lossy(r.bytes().ok_or_else(|| broken(&name, &issuer))?).into_owned(),
            (3, 2) => issuer = String::from_utf8_lossy(r.bytes().ok_or_else(|| broken(&name, &issuer))?).into_owned(),
            (4, 0) => alg = r.varint().ok_or_else(|| broken(&name, &issuer))?,
            (5, 0) => digits = r.varint().ok_or_else(|| broken(&name, &issuer))?,
            (6, 0) => kind = r.varint().ok_or_else(|| broken(&name, &issuer))?,
            // counter、unique_id 与未知字段跳过
            _ => r.skip(wire).ok_or_else(|| broken(&name, &issuer))?,
        }
    }
    // name 通常是"发行方:账户"或只有账户：有 issuer 时去掉重复的前缀，没有时按冒号拆开
    let account = match name.split_once(':') {
        Some((i, a)) if issuer.is_empty() => {
            issuer = i.trim().to_string();
            a.trim().to_string()
        }
        Some((i, a)) if i.trim() == issuer.trim() => a.trim().to_string(),
        _ => name.trim().to_string(),
    };
    let label = label_of(issuer.trim(), &account);
    // 枚举值：未指定的按默认值（SHA1、6 位、TOTP）
    let alg = match alg {
        0 | 1 => Alg::Sha1,
        2 => Alg::Sha256,
        3 => Alg::Sha512,
        4 => return Err(Skipped::new(label, "MD5 算法不支持")),
        _ => return Err(Skipped::new(label, "算法不支持")),
    };
    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        _ => return Err(Skipped::new(label, "验证码位数不支持")),
    };
    match kind {
        0 | 2 => {}
        1 => return Err(Skipped::new(label, "HOTP（计数器型）验证码不支持")),
        _ => return Err(Skipped::new(label, "验证码类型不支持")),
    }
    Ok(Account { issuer: issuer.trim().to_string(), account, secret, params: Params { kind: Kind::Totp, alg, digits, period: 30 } })
}

/// protobuf 读取器：只读 varint 与长度前缀两种值，越界一律返回 None。
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// 读完了没有。
    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// varint：每字节低 7 位是数据，最高位表示后面还有；最多 10 字节（64 位）。
    fn varint(&mut self) -> Option<u64> {
        let mut v: u64 = 0;
        for i in 0..10 {
            let b = *self.buf.get(self.pos)?;
            self.pos += 1;
            v |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        // 第 10 字节之后还有后续位：不是合法的 varint
        None
    }

    /// 字段键：字段号 = 键 >> 3，类型 = 键 & 7。字段号 0 不合法。
    fn key(&mut self) -> Option<(u64, u8)> {
        let k = self.varint()?;
        let field = k >> 3;
        if field == 0 { None } else { Some((field, (k & 7) as u8)) }
    }

    /// 长度前缀的字节串（长度不能超出剩下的数据）。
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.varint()?).ok()?;
        let end = self.pos.checked_add(len)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// 跳过一个值：0 varint、1 定长 8 字节、2 长度前缀、5 定长 4 字节；分组（3、4）不支持。
    fn skip(&mut self, wire: u8) -> Option<()> {
        match wire {
            0 => self.varint().map(|_| ()),
            1 => self.advance(8),
            2 => self.bytes().map(|_| ()),
            5 => self.advance(4),
            _ => None,
        }
    }

    /// 前进 n 字节（不能越界）。
    fn advance(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 测试用的 protobuf 拼装：varint。
    pub fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    /// 长度前缀字段。
    pub fn field_bytes(n: u64, data: &[u8], out: &mut Vec<u8>) {
        varint(n << 3 | 2, out);
        varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    /// varint 字段。
    pub fn field_varint(n: u64, v: u64, out: &mut Vec<u8>) {
        varint(n << 3, out);
        varint(v, out);
    }

    /// 一个 OtpParameters。
    pub fn params(secret: &[u8], name: &str, issuer: &str, alg: u64, digits: u64, kind: u64) -> Vec<u8> {
        let mut p = Vec::new();
        field_bytes(1, secret, &mut p);
        field_bytes(2, name.as_bytes(), &mut p);
        field_bytes(3, issuer.as_bytes(), &mut p);
        field_varint(4, alg, &mut p);
        field_varint(5, digits, &mut p);
        field_varint(6, kind, &mut p);
        p
    }

    /// 把一组 OtpParameters 包成链接（附上版本与分批字段，测试解析器会跳过它们）。
    pub fn link(items: &[Vec<u8>], percent: bool) -> String {
        let mut payload = Vec::new();
        for it in items {
            field_bytes(1, it, &mut payload);
        }
        field_varint(2, 1, &mut payload);
        field_varint(3, 1, &mut payload);
        field_varint(4, 0, &mut payload);
        field_varint(5, 123456, &mut payload);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let data = if percent { b64.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D") } else { b64 };
        format!("otpauth-migration://offline?data={data}")
    }

    #[test]
    fn reads_accounts_and_skips_unsupported() {
        let items = vec![
            // 未指定的枚举值：SHA1、6 位、TOTP；name 带发行方前缀
            params(b"12345678901234567890", "Example:alice@example.com", "Example", 0, 0, 0),
            // SHA256、8 位、TOTP；name 里没有发行方
            params(b"abcdefghij", "bob", "GitHub", 2, 2, 2),
            // HOTP、MD5 不支持
            params(b"abcdefghij", "carol", "Old", 1, 1, 1),
            params(b"abcdefghij", "dave", "Weird", 4, 1, 2),
            // 没有 issuer、name 里有冒号
            params(b"abcdefghij", "Acme:erin", "", 3, 1, 2),
        ];
        let p = parse(&link(&items, true));
        let labels: Vec<String> = p.accounts.iter().map(|a| a.label()).collect();
        assert_eq!(labels, ["Example:alice@example.com", "GitHub:bob", "Acme:erin"]);
        assert_eq!(*p.accounts[0].secret, b"12345678901234567890".to_vec());
        assert_eq!(p.accounts[0].params, Params::default());
        assert_eq!(p.accounts[1].params, Params { kind: Kind::Totp, alg: Alg::Sha256, digits: 8, period: 30 });
        assert_eq!(p.accounts[2].params.alg, Alg::Sha512);
        let reasons: Vec<(&str, &str)> = p.skipped.iter().map(|s| (s.label.as_str(), s.reason.as_str())).collect();
        assert_eq!(reasons, [("Old:carol", "HOTP（计数器型）验证码不支持"), ("Weird:dave", "MD5 算法不支持")]);
        // 不做百分号编码的 data 也能读
        assert_eq!(parse(&link(&items, false)).accounts.len(), 3);
    }

    #[test]
    fn rejects_broken_payloads_without_panicking() {
        let one = params(b"12345678901234567890", "alice", "Example", 1, 1, 2);
        let good = link(std::slice::from_ref(&one), false);
        // 链接本身不对
        assert!(parse("otpauth-migration://online?data=AA").skipped[0].reason.contains("不是"));
        assert!(parse("otpauth-migration://offline?x=1").skipped[0].reason.contains("data"));
        assert!(parse("otpauth-migration://offline?data=%%%").skipped[0].reason.contains("base64"));
        // 截断的数据：任何位置截断都不 panic，只报"数据已损坏"或少读
        let mut payload = Vec::new();
        field_bytes(1, &one, &mut payload);
        for cut in 0..payload.len() {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&payload[..cut]);
            let p = parse(&format!("otpauth-migration://offline?data={b64}"));
            assert!(p.accounts.is_empty() || cut == payload.len());
        }
        // 超长的 varint（11 个后续字节）
        let b64 = base64::engine::general_purpose::STANDARD.encode([0xffu8; 11]);
        assert_eq!(parse(&format!("otpauth-migration://offline?data={b64}")).skipped[0].reason, "数据已损坏");
        // 长度前缀超出数据
        let b64 = base64::engine::general_purpose::STANDARD.encode([0x0a, 0x7f, 0x00]);
        assert_eq!(parse(&format!("otpauth-migration://offline?data={b64}")).skipped[0].reason, "数据已损坏");
        // 分组类型（3）不支持
        let b64 = base64::engine::general_purpose::STANDARD.encode([0x0b]);
        assert_eq!(parse(&format!("otpauth-migration://offline?data={b64}")).skipped[0].reason, "数据已损坏");
        // 字段号 0
        let b64 = base64::engine::general_purpose::STANDARD.encode([0x00]);
        assert_eq!(parse(&format!("otpauth-migration://offline?data={b64}")).skipped[0].reason, "数据已损坏");
        // 正常的仍能读
        assert_eq!(parse(&good).accounts.len(), 1);
    }

    #[test]
    fn skips_unknown_fields_and_fixed_width_values() {
        let mut p = params(b"12345678901234567890", "alice", "Example", 1, 1, 2);
        // 未知字段：定长 8 字节（类型 1）、定长 4 字节（类型 5）、counter（7）、unique_id（8）
        varint(9 << 3 | 1, &mut p);
        p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        varint(10 << 3 | 5, &mut p);
        p.extend_from_slice(&[1, 2, 3, 4]);
        field_varint(7, 42, &mut p);
        field_bytes(8, b"uuid", &mut p);
        let parsed = parse(&link(&[p], false));
        assert_eq!(parsed.accounts.len(), 1, "{:?}", parsed.skipped);
        assert_eq!(parsed.accounts[0].label(), "Example:alice");
    }

    #[test]
    fn caps_number_of_accounts() {
        let one = params(b"12345678901234567890", "a", "E", 1, 1, 2);
        let items = vec![one; MAX_ACCOUNTS + 5];
        let p = parse(&link(&items, false));
        assert_eq!(p.accounts.len(), MAX_ACCOUNTS);
        assert!(p.skipped.iter().any(|s| s.reason.contains("太多")));
    }
}

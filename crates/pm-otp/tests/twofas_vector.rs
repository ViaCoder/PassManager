//! 与独立实现的交叉测试：下面的加密 2FAS 备份由 Python cryptography 41（PBKDF2HMAC-SHA256 10000 次、AESGCM、
//! 随机 256 字节盐与 12 字节 IV）按 2FAS 安卓版源码的格式生成，不经过 PassManager 的任何代码。
//! 口令是测试用的 "correct horse battery staple"，账户里的种子是 RFC 4226 的公开测试种子 "12345678901234567890"。
//! 期望的验证码由 Python 标准库 hmac 按 RFC 独立算出。

/// Python 生成的加密备份（原样）。
const ENCRYPTED: &str = r#"{"services": [], "groups": [], "updatedAt": 0, "schemaVersion": 4, "appVersionCode": 0, "appVersionName": "", "appOrigin": "android", "servicesEncrypted": "jCFrWjcwiiuEMmT5Nw47dAjEyESL6qMsbBZZCLzxURIeTzFEvsxoA3MPmEpeu/7NKBwoxRfFhqm78VyFX0akBsZjT7s1m8EmX654B2wicHWcWcs0qizGls2BGeOGprjmWhheWTyJQkpqQ/2cRjNVJ0z2BvtJEeIdkq/o+2EX5cXikterr0gPm417JJSX2yk4Lr9B7EyD72IagGD5Pj8LWsZSfbomk2xxfSleKwHkGog9phVkFF7QFQsxGRC91f53MOCrPLRS4c3elbdTO3oouQHmoGKVIKNGplOkAbnW4ouGypOoB7Xjfwf0pnPAiVANbcaKX+9ld6LbR/Wnvdwf2mnGgGL0upvC7nVrGM5VLeJVHycho1oVAWzzVqjQm1gPdzZBUGhYhn+cFjmVYsTn/iRiUKTz5UOu3AdJs58le66WfLxW8rzPMY4BHQxRRYBN+2CShBv8fO1L7ah9fJ2aMLknuXEb3WFsmePYWt1dOjmfpOQgXOd1HIKl+GVAzjHY1FOsXLAHTfVX9HRe14DfV1z68Cv+knYhTfPG3kB6uz1OO1SCalANyaQu3LY8zxe1HqX/0qIzpI+5n+Iabe/i9acf1okEcGWZTag0yPbsH8SqEqGMYFu6usDf6eHiI0ai20XK4wvjyYrsG8vDJs4wUBgqMzTb8uHeiqNFly5BHNQFOZ8z99TQ2VIduDScE9dTeBYopgbVeNgtUkxcQj4nmRGOa3Hynon7H3Ty3PJC:vjwhpNEEZ3rzgPS+D74ql2qoa2ZohOnGrhQP3cONC1dqlnHXgm7ZwkhRES8oVoLSCaOKSCEcQ92R8cNIXyhoin5xfpmg0XrVnN4htSgs9eRgXDNn3yjRchwYwTTl9yqf1MCRWc3I071huzf3CMKgsqLc2EtGY+URevom5gLXKK+Ki7oLEMOjd4rFwI6Dn0XsbQUIkVYKMOeObzVIhuhN/dSfm2bV4BTiH0vnrnYhdUDkrREdCMTMMmdGmB6NVmnmOmTr2MlMiDuCjCExZqBPtYchePENUwSYVCTMPo61BYkpvZe2P79NSxVNauiwbb/rvcAd/XFD8SLW45PHBCoJaw==:ZU25YqprWZPOW1lH", "reference": "O66lynoZqo5HW9RMDqsuijK92BzLyTQLxFL4VkYjMZ3C9dLdqbkQ32SGyiBhEdYtF8ms67D4Mk3CJ1MZKLZdIR8Ui9O2n8n5eJQD6Yqh8WiP+GzSIYTZ8cxlnbGBj9g6fQg7Ky0J58+6XcE+qhuf4xzqLDzWMupjOn9FFnTbrI4XwEnfz44sKt9P+49cwzRS/zW8LY4cJzmOQ+TXiQp5Ban0jqaYRvhQklFajwaF1HDBusKxLPoePB9c1RTyGPd/oddDu9aJsRN9oQ9JHN0M3nrWFhB9cKEvoDpvzp2uWZodXhgJQCoK226FFnArTaqsoWINJMwvBraM1KcKU/8ABlC4L97Y/8w3doZK/wm4NfQ=:vjwhpNEEZ3rzgPS+D74ql2qoa2ZohOnGrhQP3cONC1dqlnHXgm7ZwkhRES8oVoLSCaOKSCEcQ92R8cNIXyhoin5xfpmg0XrVnN4htSgs9eRgXDNn3yjRchwYwTTl9yqf1MCRWc3I071huzf3CMKgsqLc2EtGY+URevom5gLXKK+Ki7oLEMOjd4rFwI6Dn0XsbQUIkVYKMOeObzVIhuhN/dSfm2bV4BTiH0vnrnYhdUDkrREdCMTMMmdGmB6NVmnmOmTr2MlMiDuCjCExZqBPtYchePENUwSYVCTMPo61BYkpvZe2P79NSxVNauiwbb/rvcAd/XFD8SLW45PHBCoJaw==:xYWacck4ahABhHfN"}"#;

#[test]
fn decrypts_backup_made_by_independent_implementation() {
    let p = pm_otp::twofas::parse(ENCRYPTED.as_bytes(), Some("correct horse battery staple")).unwrap();
    assert!(p.skipped.is_empty(), "{:?}", p.skipped);
    let labels: Vec<String> = p.accounts.iter().map(|a| a.label()).collect();
    assert_eq!(labels, ["Example:alice@example.com", "Steam:bob"]);
    // 种子解出来就是 RFC 4226 的测试种子
    assert_eq!(*p.accounts[0].secret, b"12345678901234567890".to_vec());
    // t = 59：计数器 1，6 位码 287082（RFC 4226 附录 D）；Steam 在 t = 29（计数器 0）是 GG5F5
    assert_eq!(pm_otp::code::at(&p.accounts[0].secret, &p.accounts[0].params, 59).as_str(), "287082");
    assert_eq!(pm_otp::code::at(&p.accounts[1].secret, &p.accounts[1].params, 29).as_str(), "GG5F5");
    // 口令错
    assert_eq!(pm_otp::twofas::parse(ENCRYPTED.as_bytes(), Some("correct horse battery stapl")).unwrap_err(), "备份口令不对");
}

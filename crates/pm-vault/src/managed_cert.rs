//! 托管证书：服务器用自己的 ACME 账号与 Cloudflare 令牌为别的主机签发证书，
//! 签好后经 SSH（库里绑定该主机的凭据）把证书与私钥放到远端临时目录、执行安装命令，再删掉临时文件。
//! 远端主机既拿不到 Cloudflare 令牌，也不需要 PassManager 客户端。

use serde::{Deserialize, Serialize};

/// 一张托管证书的配置（按域名唯一）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedCert {
    /// 证书域名（小写，单个 FQDN）。
    pub domain: String,
    /// SSH 目标：`user@host[:port]`，可写 `跳板>目标`（与 `passmanager ssh` 相同的写法）。
    pub target: String,
    /// 远端临时目录（绝对路径）：证书写成 `<domain>.pem`、私钥写成 `<domain>.key`，权限 0600，命令结束后删除。
    pub dir: String,
    /// 上传后在远端执行的安装命令（退出码 0 表示成功）。
    pub after: String,
}

/// 域名字面检查：每段只含字母数字和 `-`，至少两段，总长 ≤ 253。
pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()                                                        // 不能为空
        && d.len() <= 253                                                // 总长上限
        && d.contains('.')                                               // 至少两段
        && d.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63                               // 每段 1–63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') // 只有字母数字与连字符
                && !l.starts_with('-') && !l.ends_with('-')              // 连字符不在两端
        })
}

/// 校验并规范化：域名转小写；目标、目录、命令去掉首尾空白，拒绝控制字符与不合规格的写法。
pub fn validate_managed_cert(c: &mut ManagedCert) -> Result<(), String> {
    c.domain = c.domain.trim().trim_end_matches('.').to_ascii_lowercase(); // 规范化域名
    if !valid_domain(&c.domain) {
        return Err(format!("域名无效：{}", c.domain));
    }
    c.target = c.target.trim().to_string(); // SSH 目标
    if c.target.is_empty()
        || c.target.len() > 512
        || !c.target.contains('@')
        || c.target.chars().any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err("SSH 目标写成 user@host[:port]（可带 跳板>目标）".into());
    }
    c.dir = c.dir.trim().trim_end_matches('/').to_string(); // 远端目录
    if !c.dir.starts_with('/')
        || c.dir.len() > 512
        || c.dir.chars().any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\'')
        || c.dir.split('/').any(|s| s == "..")
    {
        return Err("远端目录必须是绝对路径，不含空白、引号与 ..".into());
    }
    c.after = c.after.trim().to_string(); // 安装命令
    if c.after.is_empty() || c.after.len() > 4000 || c.after.chars().any(|ch| ch.is_control() && ch != '\t') {
        return Err("安装命令不能为空，不能含换行等控制字符，长度不超过 4000".into());
    }
    Ok(())
}

/// 远端的证书与私钥路径：`<dir>/<domain>.pem`、`<dir>/<domain>.key`。
pub fn remote_paths(c: &ManagedCert) -> (String, String) {
    (format!("{}/{}.pem", c.dir, c.domain), format!("{}/{}.key", c.dir, c.domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> ManagedCert {
        ManagedCert {
            domain: " Lab.Example.COM. ".into(),
            target: " root@198.51.100.23 ".into(),
            dir: "/root/pm-cert/ ".into(),
            after: " pvenode cert set /root/pm-cert/lab.example.com.pem /root/pm-cert/lab.example.com.key --force --restart ".into(),
        }
    }

    #[test]
    fn validate_normalizes_and_builds_paths() {
        let mut c = cert();
        validate_managed_cert(&mut c).unwrap();
        assert_eq!((c.domain.as_str(), c.target.as_str(), c.dir.as_str()), ("lab.example.com", "root@198.51.100.23", "/root/pm-cert"));
        assert!(c.after.starts_with("pvenode") && c.after.ends_with("--restart"), "首尾空白去掉");
        assert_eq!(remote_paths(&c), ("/root/pm-cert/lab.example.com.pem".to_string(), "/root/pm-cert/lab.example.com.key".to_string()));
        // 跳板写法与端口都接受。
        c.target = "root@gate.example.com>root@198.51.100.23:2222".into();
        validate_managed_cert(&mut c).unwrap();
    }

    #[test]
    fn validate_rejects_bad_fields() {
        for (field, value) in [
            ("domain", "localhost"), // 只有一段
            ("domain", "-bad.example.com"),
            ("domain", "a b.example.com"),
            ("domain", ""),
            ("target", "198.51.100.23"), // 没有用户名
            ("target", "root@h ost"),
            ("target", ""),
            ("dir", "relative/dir"),
            ("dir", "/tmp/../etc"),
            ("dir", "/tmp/with space"),
            ("dir", "/tmp/it's"),
            ("after", ""),
            ("after", "echo a\necho b"),
        ] {
            let mut c = cert();
            match field {
                "domain" => c.domain = value.into(),
                "target" => c.target = value.into(),
                "dir" => c.dir = value.into(),
                _ => c.after = value.into(),
            }
            assert!(validate_managed_cert(&mut c).is_err(), "{field}={value:?} 应被拒绝");
        }
        assert!(valid_domain("pm.example.com") && !valid_domain("pm..example.com") && !valid_domain(&"a.".repeat(130)));
    }
}

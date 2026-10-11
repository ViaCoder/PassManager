//! `passmanager init` 的参数与配置合并（与平台无关，服务器命令本身只支持 Linux）。

use std::path::PathBuf;

use pm_platform::ServerConfig;

#[derive(Clone, Debug, Default)]
pub struct InitOpts {
    pub domain: Option<String>,
    pub lan: Vec<String>,
    pub bind: Option<String>,
    pub web_port: Option<u16>,
    pub agent_port: Option<u16>,
    /// 单端口模式：网页与 Agent 共用这个端口（优先于 web_port / agent_port）。
    pub port: Option<u16>,
    /// 允许列表（每个值可含多个以空格分隔的条目）。Some(空) 表示清空；None 表示不改。
    pub allow: Option<Vec<String>>,
    pub acme_directory: Option<String>,
    pub acme_root_pem: Option<PathBuf>,
    pub dns: Option<String>,
    pub tpm_socket: Option<String>,
    pub cf_token_stdin: bool,
    pub skip_acme: bool,
    pub no_start: bool,
}

/// 允许列表：每个值可以含多个以空格（或逗号）分隔的条目；去掉空项与重复项，保持顺序。
pub fn split_allow(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        for e in v.split(|c: char| c.is_whitespace() || c == ',').filter(|e| !e.is_empty()) {
            if !out.iter().any(|x| x == e) {
                out.push(e.to_string());
            }
        }
    }
    out
}

/// 合并已有配置与命令行参数（重复运行 `init` 时只改指定的项）。
pub fn merge_config(prev: Option<ServerConfig>, o: &InitOpts) -> ServerConfig {
    let mut c = prev.unwrap_or_default();
    if let Some(d) = &o.domain {
        c.domain = d.trim().to_ascii_lowercase();
    }
    if !o.lan.is_empty() {
        c.lan = o.lan.clone();
    }
    if let Some(b) = &o.bind {
        c.bind = b.clone();
    }
    if let Some(p) = o.web_port {
        c.web_port = p;
    }
    if let Some(p) = o.agent_port {
        c.agent_port = p;
    }
    if let Some(p) = o.port {
        c.web_port = p;
        c.agent_port = p;
    }
    if let Some(a) = &o.allow {
        c.allow = split_allow(a);
    }
    if let Some(a) = &o.acme_directory {
        c.acme_directory = a.clone();
    }
    if o.acme_root_pem.is_some() {
        c.acme_root_pem = o.acme_root_pem.clone();
    }
    if let Some(d) = &o.dns {
        c.dns = d.clone();
    }
    if let Some(s) = &o.tpm_socket {
        // 空字符串表示取消配置（只自动检测 /dev/tpmrm0）。
        c.tpm_socket = Some(s.trim().to_string()).filter(|s| !s.is_empty());
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_merge_keeps_previous_values() {
        let o = InitOpts { domain: Some(" PM.Example.COM ".into()), lan: vec!["198.51.100.0/24".into()], ..Default::default() };
        let c = merge_config(None, &o);
        assert_eq!(c.domain, "pm.example.com");
        assert_eq!(c.lan, vec!["198.51.100.0/24".to_string()]);
        assert_eq!((c.web_port, c.agent_port), (443, 8443));
        let again = merge_config(Some(c.clone()), &InitOpts::default());
        assert_eq!(again, c, "不带参数重新运行不改配置");
        let o2 = InitOpts {
            agent_port: Some(9443),
            tpm_socket: Some("/srv/tpm.sock".into()),
            dns: Some("challtest:http://x".into()),
            ..Default::default()
        };
        let c2 = merge_config(Some(c), &o2);
        assert_eq!((c2.agent_port, c2.tpm_socket.as_deref(), c2.domain.as_str()), (9443, Some("/srv/tpm.sock"), "pm.example.com"));
    }

    #[test]
    fn no_site_defaults() {
        // 没有任何站点默认值：不指定域名与网段时配置无效（服务拒绝启动网络监听）。
        let c = merge_config(None, &InitOpts::default());
        assert!(c.domain.is_empty() && c.lan.is_empty() && c.tpm_socket.is_none());
        assert!(c.validate().is_err());
        let o = InitOpts {
            lan: vec!["198.51.100.0/24".into(), "198.51.100.0/24".into()],
            domain: Some("pm.example.com".into()),
            ..Default::default()
        };
        merge_config(None, &o).validate().unwrap();
        let cleared = merge_config(
            Some(ServerConfig { tpm_socket: Some("/x.sock".into()), ..Default::default() }),
            &InitOpts { tpm_socket: Some(String::new()), ..Default::default() },
        );
        assert!(cleared.tpm_socket.is_none());
    }

    #[test]
    fn single_port_and_allow_list() {
        let base = InitOpts { domain: Some("pm.example.com".into()), lan: vec!["198.51.100.0/24".into()], ..Default::default() };
        let c = merge_config(None, &InitOpts { port: Some(8121), ..base.clone() });
        assert_eq!((c.web_port, c.agent_port), (8121, 8121));
        assert!(c.single_port() && c.validate().is_ok());
        // 重新运行回到两端口模式（安装脚本总是给出端口）。
        let c2 = merge_config(Some(c.clone()), &InitOpts { web_port: Some(443), agent_port: Some(8443), ..Default::default() });
        assert!(!c2.single_port());
        // 允许列表：一个值里多个条目、逗号、重复；不给时保留，给空值时清空。
        let a = merge_config(
            Some(c),
            &InitOpts { allow: Some(vec!["203.0.113.7 203.0.113.8".into(), "2001:db8::/32,203.0.113.7".into()]), ..Default::default() },
        );
        assert_eq!(a.allow, vec!["203.0.113.7", "203.0.113.8", "2001:db8::/32"]);
        assert!(a.validate().is_ok());
        assert_eq!(merge_config(Some(a.clone()), &InitOpts::default()).allow.len(), 3, "不给 --allow 时保留");
        assert!(
            merge_config(Some(a.clone()), &InitOpts { allow: Some(vec!["".into()]), ..Default::default() }).allow.is_empty(),
            "空值清空"
        );
        let bad = merge_config(Some(a), &InitOpts { allow: Some(vec!["203.0.113.1/24".into()]), ..Default::default() });
        assert!(bad.validate().is_err(), "无效条目：配置错误");
    }
}

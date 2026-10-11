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
    pub acme_directory: Option<String>,
    pub acme_root_pem: Option<PathBuf>,
    pub dns: Option<String>,
    pub tpm_socket: Option<String>,
    pub cf_token_stdin: bool,
    pub skip_acme: bool,
    pub no_start: bool,
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
}

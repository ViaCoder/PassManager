//! CLI（与 MCP 工具一一对应，输出 JSON）。

use std::io::Read;
use std::process::ExitCode;

use pm_proto::ApiError;
use serde_json::{Value, json};

fn print_result(r: Result<Value, ApiError>) -> ExitCode {
    match r {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Err(e) => {
            let mut v = json!({"error": e.code, "message": e.message});
            if let Some(n) = crate::mcp::next(&e) {
                v["next"] = Value::String(n);
            }
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            ExitCode::from(1)
        }
    }
}

pub fn tool(name: &str, args: Value) -> ExitCode {
    print_result(crate::mcp::call_tool(name, &args))
}

fn read_data(d: &str) -> Result<String, ApiError> {
    match d.strip_prefix('@') {
        Some("-") => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map_err(|e| ApiError::new("BAD_REQUEST", format!("cannot read stdin: {e}")))?;
            Ok(s)
        }
        Some(f) => std::fs::read_to_string(f).map_err(|e| ApiError::new("BAD_REQUEST", format!("cannot read {f}: {e}"))),
        None => Ok(d.to_string()),
    }
}

/// curl 风格：`http [METHOD] URL [-X M] [-H ..] [-d ..] [--json ..]`。
pub fn http_args(
    args: Vec<String>,
    request: Option<String>,
    headers: Vec<String>,
    data: Vec<String>,
    json_body: Option<String>,
) -> Result<Value, ApiError> {
    let (method, url) = match args.as_slice() {
        [url] => (None, url.clone()),
        [m, url] => (Some(m.clone()), url.clone()),
        _ => return Err(ApiError::new("BAD_REQUEST", "usage: PassManager http [METHOD] <URL>")),
    };
    let mut hs: Vec<(String, String)> = Vec::new();
    for h in headers {
        match h.split_once(':') {
            Some((k, v)) => hs.push((k.trim().to_string(), v.trim().to_string())),
            None => return Err(ApiError::new("BAD_REQUEST", format!("invalid header \"{h}\", expected 'Name: value'"))),
        }
    }
    let mut body = None;
    if !data.is_empty() {
        let parts: Result<Vec<String>, ApiError> = data.iter().map(|d| read_data(d)).collect();
        body = Some(parts?.join("&"));
        if !hs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
            hs.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
        }
    }
    if let Some(j) = json_body {
        body = Some(read_data(&j)?);
        if !hs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
            hs.push(("Content-Type".into(), "application/json".into()));
        }
        if !hs.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept")) {
            hs.push(("Accept".into(), "application/json".into()));
        }
    }
    let method = request.or(method).unwrap_or_else(|| if body.is_some() { "POST".into() } else { "GET".into() });
    Ok(json!({"method": method, "url": url, "headers": hs, "body": body}))
}

pub fn http(args: Vec<String>, request: Option<String>, headers: Vec<String>, data: Vec<String>, json_body: Option<String>) -> ExitCode {
    match http_args(args, request, headers, data, json_body) {
        Ok(a) => tool("http", a),
        Err(e) => print_result(Err(e)),
    }
}

/// OpenSSH 风格的目标：支持 ssh://user@host:port，以及 -l / -p。
pub fn ssh_target(port: Option<u16>, login: Option<String>, target: &str) -> String {
    let mut t = target.trim().trim_start_matches("ssh://").trim_end_matches('/').to_string();
    if let Some(l) = login
        && !t.contains('@')
    {
        t = format!("{l}@{t}");
    }
    if let Some(p) = port {
        let host_part = t.rsplit('@').next().unwrap_or("");
        let has_port = if host_part.starts_with('[') { host_part.contains("]:") } else { host_part.matches(':').count() == 1 };
        if !has_port {
            t = format!("{t}:{p}");
        }
    }
    t
}

pub fn ssh(port: Option<u16>, login: Option<String>, target: String, command: Vec<String>) -> ExitCode {
    tool("ssh", json!({"target": ssh_target(port, login, &target), "command": command.join(" ")}))
}

/// scp 风格：-P 端口加到远程一侧。
pub fn scp_spec(port: Option<u16>, spec: &str) -> String {
    match (port, crate::mcp::split_remote(spec)) {
        (Some(p), Some((target, path))) if !target.rsplit('@').next().unwrap_or("").contains(':') => format!("{target}:{p}:{path}"),
        _ => spec.to_string(),
    }
}

pub fn scp(port: Option<u16>, source: String, destination: String) -> ExitCode {
    tool("scp", json!({"source": scp_spec(port, &source), "destination": scp_spec(port, &destination)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_style() {
        let v =
            http_args(vec!["https://a.example.com/x".into()], None, vec!["Authorization: Bearer {{secret}}".into()], vec![], None).unwrap();
        assert_eq!(v["method"], "GET");
        let v = http_args(vec!["https://a".into()], Some("PUT".into()), vec![], vec!["a=1".into(), "b=2".into()], None).unwrap();
        assert_eq!((v["method"].as_str(), v["body"].as_str()), (Some("PUT"), Some("a=1&b=2")));
        let v = http_args(vec!["https://a".into()], None, vec![], vec![], Some("{\"k\":\"{{secret}}\"}".into())).unwrap();
        assert_eq!(v["method"], "POST");
        assert_eq!(v["headers"][0], json!(["Content-Type", "application/json"]));
        let v = http_args(vec!["delete".into(), "https://a".into()], None, vec![], vec![], None).unwrap();
        assert_eq!(v["method"], "delete");
        assert!(http_args(vec!["https://a".into()], None, vec!["bad".into()], vec![], None).is_err());
    }

    #[test]
    fn ssh_style() {
        assert_eq!(ssh_target(None, None, "deploy@db1"), "deploy@db1");
        assert_eq!(ssh_target(Some(2222), Some("deploy".into()), "db1"), "deploy@db1:2222");
        assert_eq!(ssh_target(Some(2222), None, "u@db1:22"), "u@db1:22");
        assert_eq!(ssh_target(None, None, "ssh://u@db1:2200/"), "u@db1:2200");
        assert_eq!(ssh_target(Some(2200), None, "u@[::1]"), "u@[::1]:2200");
        assert_eq!(scp_spec(Some(2222), "u@db1:/tmp/a"), "u@db1:2222:/tmp/a");
        assert_eq!(scp_spec(Some(2222), "./local.txt"), "./local.txt");
    }

    #[test]
    fn clap_parses_common_forms() {
        use clap::Parser;
        for argv in [
            vec!["PassManager", "http", "https://api.github.com/user", "-H", "Authorization: Bearer {{secret}}", "-s"],
            vec!["PassManager", "http", "-X", "POST", "https://a", "-d", "x=1", "-L"],
            vec!["PassManager", "http", "POST", "https://a", "--json", "{}"],
            vec!["PassManager", "ssh", "-p", "2222", "-o", "StrictHostKeyChecking=no", "deploy@db1", "ls", "-la"],
            vec!["PassManager", "ssh", "deploy@db1", "sudo systemctl restart nginx"],
            vec!["PassManager", "scp", "-P", "2222", "a.txt", "deploy@db1:/tmp/a.txt"],
            vec!["PassManager", "list"],
            vec!["PassManager", "lookup", "https://api.github.com/user"],
            vec!["PassManager", "lookup", "root@db1", "--use", "scp"],
            vec!["PassManager", "update", "--name", "x", "--domain", "a.example.com", "--add-op", "git,http", "--note", "y"],
        ] {
            assert!(crate::Cli::try_parse_from(&argv).is_ok(), "failed to parse {argv:?}");
        }
    }

    /// `show` 的各种形式；被它取代的命令不再存在。
    #[test]
    fn clap_show_and_removed_commands() {
        use clap::Parser;
        let parse = |argv: &[&str]| crate::Cli::try_parse_from(argv);
        let show = |argv: &[&str]| match parse(argv).unwrap_or_else(|e| panic!("{argv:?}: {e}")).cmd {
            Some(crate::Cmd::Show { label, url, rules, lang, .. }) => (label, url, rules, lang),
            _ => panic!("not show: {argv:?}"),
        };
        assert_eq!(show(&["PassManager", "show"]), (None, false, false, "zh".to_string()), "默认中文");
        assert_eq!(show(&["PassManager", "show", "--label", "laptop"]), (Some("laptop".into()), false, false, "zh".into()));
        assert_eq!(show(&["PassManager", "show", "--label", "laptop", "--lang", "en"]), (Some("laptop".into()), false, false, "en".into()));
        assert_eq!(show(&["PassManager", "show", "--label", "laptop", "--url"]), (Some("laptop".into()), true, false, "zh".into()));
        assert_eq!(show(&["PassManager", "show", "--rules", "--lang", "en"]), (None, false, true, "en".into()));
        for bad in [
            &["PassManager", "show", "--url"][..],
            &["PassManager", "show", "--rules", "--label", "x"],
            &["PassManager", "show", "--rules", "--url"],
            &["PassManager", "show", "--write"],
            &["PassManager", "lookup"],
            &["PassManager", "update", "--domain", "a"],
            &["PassManager", "show", "--label"],
            &["PassManager", "agent-setup", "--label", "x"],
            &["PassManager", "agent-instructions"],
            &["PassManager", "token", "add", "laptop"],
        ] {
            assert!(parse(bad).is_err(), "should be rejected: {bad:?}");
        }
        for ok in [
            &["PassManager", "token", "list"][..],
            &["PassManager", "token", "revoke", "1a2b3c4d"],
            &["PassManager", "enroll", "pm-enroll://x"],
            &["PassManager", "show", "--rules", "--write"],
        ] {
            assert!(parse(ok).is_ok(), "{ok:?}");
        }
        // enroll 与 git-proxy 的新选项。
        match parse(&["PassManager", "enroll", "--no-git-proxy", "--git-proxy-listen", "127.0.0.1:7000", "pm-enroll://x"]).unwrap().cmd {
            Some(crate::Cmd::Enroll { no_git_proxy, git_proxy_listen, .. }) => {
                assert!(no_git_proxy && git_proxy_listen.as_deref() == Some("127.0.0.1:7000"))
            }
            _ => panic!(),
        }
        match parse(&["PassManager", "git-proxy", "--install", "--host", "github.com"]).unwrap().cmd {
            Some(crate::Cmd::GitProxy { install, uninstall, hosts, .. }) => assert!(install && !uninstall && hosts == ["github.com"]),
            _ => panic!(),
        }
        assert!(parse(&["PassManager", "git-proxy", "--uninstall"]).is_ok());
        assert!(parse(&["PassManager", "git-proxy", "--install", "--uninstall"]).is_err());
        assert!(parse(&["PassManager", "git-proxy", "--uninstall", "--host", "x"]).is_err());
        // 帮助里有新命令、没有旧命令。
        let help = crate::Cli::try_parse_from(["PassManager", "--help"]).err().unwrap().to_string();
        assert!(help.contains("show") && !help.contains("agent-setup") && !help.contains("agent-instructions"), "{help}");
    }
}

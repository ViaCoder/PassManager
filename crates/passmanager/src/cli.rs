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
            println!("{}", serde_json::to_string_pretty(&json!({"error": e.code, "message": e.message})).unwrap_or_default());
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
        ] {
            assert!(crate::Cli::try_parse_from(&argv).is_ok(), "failed to parse {argv:?}");
        }
    }
}

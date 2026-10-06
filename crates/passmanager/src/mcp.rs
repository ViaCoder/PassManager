//! MCP 服务器（stdio，JSON-RPC 2.0，按行分隔）。
//!
//! 只提供 5 个工具，参数扁平、描述简短，小模型也能正确调用。
//! 本进程不持有任何密钥：每次调用都用 `PASSMANAGER_TOKEN` 连接本地服务。

use std::io::{BufRead, Write};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pm_proto::{ApiError, Client, DownloadResult, ENV_TOKEN, Hello, PROTO_V, Request};
use serde_json::{Value, json};

const SUPPORTED: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "PassManager uses stored secrets for you; you never see them. \
http: write {{secret}} where the secret goes, e.g. header Authorization: Bearer {{secret}}. \
ssh/scp: use user@host as usual. \
If a result says LOCKED, NOT_READY or HOST_KEY_CHANGED, tell the user the command in the message.";

fn tools() -> Value {
    json!([
        {
            "name": "list",
            "description": "List the hosts that have stored secrets.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "http",
            "description": "HTTPS request. Write {{secret}} where the secret goes (header, body or query); the secret stored for the URL's host is filled in. Secrets in the response are shown as [REDACTED].",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "description": "GET, POST, PUT, PATCH, DELETE ..."},
                    "url": {"type": "string", "description": "https:// URL"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"}
                },
                "required": ["method", "url"]
            }
        },
        {
            "name": "ssh",
            "description": "Run a command over SSH with the stored password or key. Commands starting with sudo get the password automatically.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "user@host or user@host:port"},
                    "command": {"type": "string"}
                },
                "required": ["target", "command"]
            }
        },
        {
            "name": "scp",
            "description": "Copy a file to or from a host. Write the remote side as user@host:/path.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"}
                },
                "required": ["source", "destination"]
            }
        }
    ])
}

fn s(args: &Value, k: &str) -> Option<String> {
    args.get(k).and_then(|v| v.as_str()).map(str::to_string)
}

fn need(args: &Value, k: &str) -> Result<String, ApiError> {
    s(args, k).filter(|v| !v.is_empty()).ok_or_else(|| ApiError::new("BAD_REQUEST", format!("missing argument \"{k}\"")))
}

pub fn connect() -> Result<Client, ApiError> {
    let token = std::env::var(ENV_TOKEN).unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::new(
            "NO_TOKEN",
            "PASSMANAGER_TOKEN is not set. Ask the user to open PassManager → Agent 接入 and connect this agent.",
        ));
    }
    Client::connect_at(&pm_platform::Layout::detect_client().socket, &Hello::Token { v: PROTO_V, token })
}

/// scp 风格的远程路径：`[name/]user@host[:port]:/path`（IPv6：`user@[::1]:/path`）。
/// 返回 (target, path)；本地路径（含 Windows 盘符 `C:\...`）返回 None。
pub fn split_remote(spec: &str) -> Option<(String, String)> {
    if let Some(i) = spec.find("]:") {
        return Some((spec[..=i].to_string(), spec[i + 2..].to_string()));
    }
    let (left, rest) = spec.split_once(':')?;
    if left.len() < 2 || left.contains(['\\']) || left.starts_with('.') || left.starts_with('/') {
        return None;
    }
    // 可选端口：user@host:2222:/path
    if let Some((port, path)) = rest.split_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return Some((format!("{left}:{port}"), path.to_string()));
    }
    Some((left.to_string(), rest.to_string()))
}

fn first(args: &Value, keys: &[&str]) -> Option<Value> {
    keys.iter().find_map(|k| args.get(*k).filter(|v| !v.is_null()).cloned())
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(as_text).collect::<Vec<_>>().join(" "),
        other => other.to_string(),
    }
}

/// 请求头：对象、`[["K","V"]]`、`["K: V"]`、或多行 `"K: V"` 字符串都接受。
fn headers_of(v: Option<Value>) -> Vec<(String, String)> {
    let line = |l: &str| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).filter(|(k, _)| !k.is_empty());
    match v {
        Some(Value::Object(m)) => {
            m.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect()
        }
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| match x {
                Value::Array(p) if p.len() == 2 => Some((as_text(&p[0]), as_text(&p[1]))),
                Value::String(s) => line(s),
                Value::Object(o) => Some((as_text(o.get("name").or(o.get("key"))?), as_text(o.get("value")?))),
                _ => None,
            })
            .collect(),
        Some(Value::String(s)) => s.lines().filter_map(line).collect(),
        _ => vec![],
    }
}

/// 把各种常见写法规范成 (工具名, 标准参数)。旧工具名与参数别名都接受，但不出现在工具列表中。
pub fn normalize(name: &str, args: &Value) -> Result<(&'static str, Value), ApiError> {
    let n = name.trim().to_ascii_lowercase().replace('-', "_");
    let str_of = |keys: &[&str]| first(args, keys).map(|v| as_text(&v));
    match n.as_str() {
        "list" | "list_credentials" | "list_secrets" | "credentials" => Ok(("list", json!({}))),
        "http" | "http_request" | "request" | "https" | "fetch" | "curl" => {
            let mut headers = headers_of(first(args, &["headers", "header"]));
            let body = first(args, &["body", "data", "json", "payload"]).map(|b| match b {
                Value::String(s) => s,
                other => {
                    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                        headers.push(("Content-Type".into(), "application/json".into()));
                    }
                    other.to_string()
                }
            });
            let method = str_of(&["method", "verb"]).unwrap_or_else(|| if body.is_some() { "POST".into() } else { "GET".into() });
            let url = str_of(&["url", "uri", "endpoint"]).ok_or_else(|| ApiError::new("BAD_REQUEST", "missing argument \"url\""))?;
            Ok(("http", json!({"method": method, "url": url, "headers": headers, "body": body})))
        }
        "ssh" | "ssh_exec" | "exec" | "run" | "shell" => {
            let mut target = str_of(&["target", "destination", "host", "hostname", "server"])
                .ok_or_else(|| ApiError::new("BAD_REQUEST", "missing argument \"target\" (user@host)"))?;
            if let Some(u) = str_of(&["user", "username", "login"])
                && !target.contains('@')
            {
                target = format!("{u}@{target}");
            }
            if let Some(p) = str_of(&["port"])
                && !target.rsplit('@').next().unwrap_or("").contains(':')
            {
                target = format!("{target}:{p}");
            }
            if let Some(c) = str_of(&["credential", "name"]) {
                target = format!("{c}/{target}");
            }
            let mut command = str_of(&["command", "cmd", "script", "args"])
                .ok_or_else(|| ApiError::new("BAD_REQUEST", "missing argument \"command\""))?;
            if first(args, &["sudo"]).and_then(|v| v.as_bool()).unwrap_or(false) && !command.trim_start().starts_with("sudo ") {
                command = format!("sudo {command}");
            }
            Ok(("ssh", json!({"target": target, "command": command})))
        }
        "scp" | "copy" | "sftp" | "ssh_upload" | "ssh_download" | "upload" | "download" => {
            let mut source = str_of(&["source", "src", "from"]);
            let mut destination = str_of(&["destination", "dest", "dst", "to"]);
            // 旧写法：host + local_path + remote_path（+ user / port / credential）。
            if let (Some(host), Some(local), Some(remote)) =
                (str_of(&["host"]), str_of(&["local_path", "local"]), str_of(&["remote_path", "remote"]))
            {
                let mut t = host;
                if let Some(u) = str_of(&["user", "username"]) {
                    t = format!("{u}@{t}");
                }
                if let Some(p) = str_of(&["port"]) {
                    t = format!("{t}:{p}");
                }
                if let Some(c) = str_of(&["credential", "name"]) {
                    t = format!("{c}/{t}");
                }
                let remote = format!("{t}:{remote}");
                (source, destination) = if n.contains("download") { (Some(remote), Some(local)) } else { (Some(local), Some(remote)) };
            }
            match (source, destination) {
                (Some(s), Some(d)) => Ok(("scp", json!({"source": s, "destination": d}))),
                _ => Err(ApiError::new("BAD_REQUEST", "missing \"source\" or \"destination\" (remote side: user@host:/path)")),
            }
        }
        other => Err(ApiError::new("BAD_REQUEST", format!("unknown tool {other}; available: list, http, ssh, scp"))),
    }
}

/// 执行一个工具调用（MCP 与 CLI 共用）。
pub fn call_tool(name: &str, args: &Value) -> Result<Value, ApiError> {
    let (name, norm) = normalize(name, args)?;
    let args = &norm;
    let req = match name {
        "list" => Request::List,
        "http" => {
            let headers: Vec<(String, String)> = serde_json::from_value(args["headers"].clone()).unwrap_or_default();
            Request::Http { method: need(args, "method")?, url: need(args, "url")?, headers, body: s(args, "body") }
        }
        "ssh" => Request::Ssh { target: need(args, "target")?, command: need(args, "command")? },
        "scp" => {
            let (src, dst) = (need(args, "source")?, need(args, "destination")?);
            return match (split_remote(&src), split_remote(&dst)) {
                (None, Some((target, path))) => {
                    let data = std::fs::read(&src).map_err(|e| ApiError::new("BAD_REQUEST", format!("cannot read {src}: {e}")))?;
                    if data.len() > pm_proto::MAX_FILE {
                        return Err(ApiError::new("TOO_LARGE", "file exceeds 64 MiB"));
                    }
                    connect()?.call(&Request::Upload { target, path, data_base64: STANDARD.encode(data) })
                }
                (Some((target, path)), None) => {
                    let r: DownloadResult = connect()?.call_as(&Request::Download { target, path })?;
                    let data = STANDARD.decode(r.data_base64).map_err(|_| ApiError::new("INTERNAL", "bad data"))?;
                    std::fs::write(&dst, &data).map_err(|e| ApiError::new("BAD_REQUEST", format!("cannot write {dst}: {e}")))?;
                    Ok(json!({"saved": dst, "size": data.len(), "redactions": r.redactions}))
                }
                _ => Err(ApiError::new("BAD_REQUEST", "exactly one side must be remote, written as user@host:/path")),
            };
        }
        other => return Err(ApiError::new("BAD_REQUEST", format!("unknown tool {other}"))),
    };
    connect()?.call(&req)
}

fn reply(out: &mut impl Write, id: &Value, result: Value) {
    let msg = json!({"jsonrpc": "2.0", "id": id, "result": result});
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

fn reply_err(out: &mut impl Write, id: &Value, code: i64, message: &str) {
    let msg = json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}});
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

fn handle(msg: &Value, out: &mut impl Write) {
    let Some(method) = msg.get("method").and_then(|m| m.as_str()) else { return };
    let id = msg.get("id").cloned();
    // 通知（没有 id）不回复。
    let Some(id) = id else { return };
    match method {
        "initialize" => {
            let requested = msg.pointer("/params/protocolVersion").and_then(|v| v.as_str()).unwrap_or(SUPPORTED[0]);
            let version = if SUPPORTED.contains(&requested) { requested } else { SUPPORTED[0] };
            reply(
                out,
                &id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "PassManager", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": INSTRUCTIONS
                }),
            );
        }
        "ping" => reply(out, &id, json!({})),
        "tools/list" => reply(out, &id, json!({"tools": tools()})),
        "tools/call" => {
            let name = msg.pointer("/params/name").and_then(|v| v.as_str()).unwrap_or("");
            let args = msg.pointer("/params/arguments").cloned().unwrap_or(json!({}));
            let (text, is_error) = match call_tool(name, &args) {
                Ok(v) => (serde_json::to_string_pretty(&v).unwrap_or_default(), false),
                Err(e) => (format!("{}: {}", e.code, e.message), true),
            };
            reply(out, &id, json!({"content": [{"type": "text", "text": text}], "isError": is_error}));
        }
        "resources/list" => reply(out, &id, json!({"resources": []})),
        "resources/templates/list" => reply(out, &id, json!({"resourceTemplates": []})),
        "logging/setLevel" => reply(out, &id, json!({})),
        "prompts/list" => reply(out, &id, json!({"prompts": []})),
        _ => reply_err(out, &id, -32601, &format!("method not found: {method}")),
    }
}

pub fn run() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        // 兼容 BOM 与 CRLF。
        let line = line.trim_start_matches('\u{feff}').trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Array(batch)) => {
                for m in batch {
                    handle(&m, &mut out);
                }
            }
            Ok(m) => handle(&m, &mut out),
            Err(_) => reply_err(&mut out, &Value::Null, -32700, "parse error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_variants() {
        let n = |name: &str, a: Value| normalize(name, &a).unwrap();
        let (t, v) =
            n("http_request", json!({"url": "https://x.example.com", "headers": ["Authorization: Bearer {{secret}}"], "body": {"a": 1}}));
        assert_eq!(t, "http");
        assert_eq!(v["method"], "POST");
        assert_eq!(v["headers"][0], json!(["Authorization", "Bearer {{secret}}"]));
        assert_eq!(v["headers"][1], json!(["Content-Type", "application/json"]));
        assert_eq!(v["body"], "{\"a\":1}");
        let (_, v) = n("http", json!({"method": "get", "url": "https://x", "headers": {"X-Key": "{{secret}}"}}));
        assert_eq!(v["headers"][0], json!(["X-Key", "{{secret}}"]));
        let (_, v) = n("http", json!({"url": "https://x", "headers": [["A", "1"]]}));
        assert_eq!(v["method"], "GET");
        let (t, v) = n(
            "ssh_exec",
            json!({"credential": "srv", "host": "db1", "user": "deploy", "port": 2222, "command": "systemctl restart x", "sudo": true}),
        );
        assert_eq!(t, "ssh");
        assert_eq!(v["target"], "srv/deploy@db1:2222");
        assert_eq!(v["command"], "sudo systemctl restart x");
        let (_, v) = n("ssh", json!({"target": "deploy@db1", "command": ["ls", "-la"]}));
        assert_eq!(v["command"], "ls -la");
        let (t, v) = n("ssh_download", json!({"host": "db1", "user": "u", "remote_path": "/etc/a", "local_path": "a"}));
        assert_eq!(t, "scp");
        assert_eq!(v, json!({"source": "u@db1:/etc/a", "destination": "a"}));
        let (_, v) = n("scp", json!({"from": "a.txt", "to": "u@db1:/tmp/a.txt"}));
        assert_eq!(v["destination"], "u@db1:/tmp/a.txt");
        assert!(normalize("nope", &json!({})).is_err());
    }

    #[test]
    fn remote_specs() {
        let r = |s: &str| split_remote(s);
        assert_eq!(r("deploy@db1:/etc/a.conf"), Some(("deploy@db1".into(), "/etc/a.conf".into())));
        assert_eq!(r("deploy@db1:2222:/tmp/x"), Some(("deploy@db1:2222".into(), "/tmp/x".into())));
        assert_eq!(r("ops/deploy@db1:/x"), Some(("ops/deploy@db1".into(), "/x".into())));
        assert_eq!(r("u@[::1]:/tmp/x"), Some(("u@[::1]".into(), "/tmp/x".into())));
        assert_eq!(r("C:\\Users\\a.txt"), None);
        assert_eq!(r("./a:b"), None);
        assert_eq!(r("/tmp/a.txt"), None);
        assert_eq!(r("notes.txt"), None);
    }

    #[test]
    fn protocol_basics() {
        let mut out = Vec::new();
        handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}), &mut out);
        handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}), &mut out);
        handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}), &mut out);
        handle(&json!({"jsonrpc":"2.0","id":3,"method":"nope"}), &mut out);
        let lines: Vec<Value> = String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 4);
        assert_eq!(lines[2]["error"]["code"], -32601);
    }
}

//! MCP 服务器（stdio，JSON-RPC 2.0，按行分隔）。
//!
//! 只提供 4 个工具（lookup、http、ssh、scp），参数扁平；说明逐步披露：服务器说明 → 工具描述（附示例）→ lookup 的 how → 错误的 Next:。
//! 本进程不持有任何密钥：每次调用都用 `PASSMANAGER_TOKEN` 连接本地服务；
//! 注册过远程服务器（`passmanager enroll`）时改为经双层加密通道连接服务器，用法不变。

use std::io::{BufRead, Write};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pm_proto::{ApiError, Client, DownloadResult, ENV_TOKEN, Hello, PROTO_V, Request};
use serde_json::{Value, json};

const SUPPORTED: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// 服务器级说明（逐步披露的第一层，≤ 5 行）：只讲固定流程与边界。具体写法由 lookup 的 `how` 给出，错误处理由 `Next:` 给出。
const INSTRUCTIONS: &str = "PassManager lets you use stored secrets without ever seeing them.
1. Call lookup with the URL or user@host you need.
2. Copy its `how` into http, ssh or scp; replace only the <...> parts.
Never ask for, print or store a secret, and never try to reveal one.
If a result is an error, do exactly what its Next: line says; do not retry the same call.";

/// 工具（第二层）：每个 2~3 句加一个最小示例；只靠这些描述也能正确使用（不是每个客户端都读全局指令文件）。
fn tools() -> Value {
    json!([
        {
            "name": "lookup",
            "title": "Find credential",
            "description": "Call this first. Finds the stored credential for one target and returns `how`: a ready-to-copy http, ssh or scp call with the right placeholders. target is the URL, user@host or host you will use (or {{name}} when the user names a credential; or tang to keep a secret file on a remote host encrypted at rest). Example: {\"target\":\"https://api.github.com/user\"}",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL, user@host[:port] or host"},
                    "use": {"type": "string", "enum": ["http", "ssh", "scp", "git"], "description": "optional; guessed from target"}
                },
                "required": ["target"],
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        },
        {
            "name": "http",
            "title": "HTTPS request",
            "description": "Send one HTTPS request. Write placeholders exactly as lookup's how shows (e.g. {{secret}}); PassManager fills them in and redacts secrets from the response. Example: {\"method\":\"GET\",\"url\":\"https://api.github.com/user\",\"headers\":{\"Authorization\":\"Bearer {{secret}}\"}}",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "description": "GET, POST, PUT, PATCH, DELETE ..."},
                    "url": {"type": "string", "description": "https:// URL, or {{name.base_url}}/path when lookup says so"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"}
                },
                "required": ["method", "url"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true}
        },
        {
            "name": "ssh",
            "title": "Run SSH command",
            "description": "Run one shell command on user@host[:port] with the stored password or key; output is redacted. A command starting with \"sudo \" gets the password automatically. To go through a jump host write jumpuser@jumphost>user@host; each hop uses its own stored credential. Example: {\"target\":\"root@192.0.2.10\",\"command\":\"uptime\"}",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "user@host or user@host:port (name/user@host to pick a credential; jumpuser@jumphost>user@host through one jump host)"},
                    "command": {"type": "string"}
                },
                "required": ["target", "command"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true}
        },
        {
            "name": "scp",
            "title": "Copy file over SSH",
            "description": "Copy one file (max 64 MiB) to or from a host. Exactly one side is remote, written user@host:/path (or jumpuser@jumphost>user@host:/path through one jump host); downloaded content is redacted. Example: {\"source\":\"./app.conf\",\"destination\":\"root@192.0.2.10:/etc/app.conf\"}",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"}
                },
                "required": ["source", "destination"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true}
        }
    ])
}

/// 错误的文字（MCP 与 CLI 共用）：`代码: 信息`，有下一步时另起一行 `Next: …`。
pub fn error_text(e: &ApiError) -> String {
    match next(e) {
        Some(n) => format!("{}: {}\nNext: {n}", e.code, e.message),
        None => format!("{}: {}", e.code, e.message),
    }
}

/// 错误码对应的下一步（服务器主机取自本机的注册配置）。
pub fn next(e: &ApiError) -> Option<String> {
    pm_proto::agent_text::next_step(&e.code, crate::remote::server_host().as_deref())
}

fn s(args: &Value, k: &str) -> Option<String> {
    args.get(k).and_then(|v| v.as_str()).map(str::to_string)
}

fn need(args: &Value, k: &str) -> Result<String, ApiError> {
    s(args, k).filter(|v| !v.is_empty()).ok_or_else(|| ApiError::new("BAD_REQUEST", format!("missing argument \"{k}\"")))
}

pub fn connect() -> Result<Client, ApiError> {
    // 远程模式（passmanager enroll 之后）：经双层加密通道连接局域网里的服务器。
    if let Some(r) = crate::remote::connect_if_configured() {
        return r;
    }
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
    // 跳板：jump[:port]>user@host[:port]:/path——跳板部分原样保留，只拆最后一跳（`>` 前已有 `:/` 时它属于路径）。
    if let Some((jump, rest)) = spec.split_once('>')
        && !jump.contains(":/")
        && !jump.starts_with(['.', '/'])
    {
        return split_remote(rest).map(|(t, p)| (format!("{jump}>{t}"), p));
    }
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
        // 旧的 list：不再列出条目（见 call_tool）。
        "list" | "list_credentials" | "list_secrets" | "credentials" => Ok(("list", json!({}))),
        "lookup" | "find" | "search" | "resolve" | "find_credential" | "lookup_credential" | "credential" => {
            let target = str_of(&["target", "url", "uri", "host", "hostname", "destination", "server", "name"])
                .ok_or_else(|| ApiError::new("BAD_REQUEST", "missing argument \"target\" (the URL or user@host you want to use)"))?;
            let use_ = str_of(&["use", "op", "purpose", "for", "type"]);
            Ok(("lookup", json!({"target": target, "use": use_})))
        }
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
        other => Err(ApiError::new("BAD_REQUEST", format!("unknown tool {other}; available: lookup, http, ssh, scp"))),
    }
}

/// 执行一个工具调用（MCP 与 CLI 共用）。
pub fn call_tool(name: &str, args: &Value) -> Result<Value, ApiError> {
    let (name, norm) = normalize(name, args)?;
    let args = &norm;
    let req = match name {
        "list" => {
            return Err(ApiError::new("USE_LOOKUP", "list was replaced by lookup: it only shows the credential for one target"));
        }
        "lookup" => Request::Lookup { target: need(args, "target")?, use_: s(args, "use") },
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
                Err(e) => (error_text(&e), true),
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
        // 跳板：只拆最后一跳；跳板可以带端口与引用名。
        assert_eq!(r("root@198.51.100.1>root@db1:/tmp/x"), Some(("root@198.51.100.1>root@db1".into(), "/tmp/x".into())));
        assert_eq!(r("root@198.51.100.1:2222>root@db1:/tmp/x"), Some(("root@198.51.100.1:2222>root@db1".into(), "/tmp/x".into())));
        assert_eq!(r("pw/root@j:2222>u@db1:2200:/x"), Some(("pw/root@j:2222>u@db1:2200".into(), "/x".into())));
        // `>` 在路径里、本地文件名里：不是跳板。
        assert_eq!(r("u@db1:/tmp/a>b"), Some(("u@db1".into(), "/tmp/a>b".into())));
        assert_eq!(r("a>b.txt"), None);
        assert_eq!(r("./a>u@b:/x"), None);
        assert_eq!(r("C:\\a>b.txt"), None);
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

    /// 不臃肿：4 个工具、说明 ≤ 5 行、整个工具列表有大小上限；每个工具都有示例与 annotations。
    #[test]
    fn surface_stays_small() {
        let t = tools();
        let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["lookup", "http", "ssh", "scp"]);
        let size = serde_json::to_string(&t).unwrap().len();
        assert!(size <= 3600, "tools/list is {size} bytes");
        assert!(INSTRUCTIONS.lines().count() <= 5);
        for x in t.as_array().unwrap() {
            assert!(x["description"].as_str().unwrap().contains("Example: {"), "{x}");
            assert!(x["annotations"]["readOnlyHint"].is_boolean(), "{x}");
        }
        assert_eq!(t[0]["annotations"]["readOnlyHint"], true);
        assert!(!INSTRUCTIONS.contains("list"));
    }

    #[test]
    fn lookup_and_legacy_list() {
        let (t, v) = normalize("find_credential", &json!({"url": "https://x.example.com/a", "op": "http"})).unwrap();
        assert_eq!((t, v["target"].as_str(), v["use"].as_str()), ("lookup", Some("https://x.example.com/a"), Some("http")));
        assert!(normalize("lookup", &json!({})).is_err());
        let e = call_tool("list", &json!({})).unwrap_err();
        assert_eq!(e.code, "USE_LOOKUP");
        assert!(error_text(&e).contains("\nNext: call lookup"), "{}", error_text(&e));
    }
}

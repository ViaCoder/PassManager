#![cfg(target_os = "linux")]
//! `passmanager run --http` 端到端（验收测试 a–i）：真实服务 + 假的 HTTPS 上游 + 真实的 `passmanager run`。
//! 子程序只把拿到的环境变量写进文件然后等待；请求由测试自己用原始 HTTP/1.1 发给本地中继，这样能精确地计时与检查字节。

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{Env, stderr, stdout};

/// 测试凭据（只存在于服务器的库里）。
const SECRET: &str = "sk-or-v1-relay-e2e-SECRET-0123456789abcdef";
const REQ_MARKER: &str = "BODY-MARKER-REQ-7f3a";
const RESP_MARKER: &str = "RESP-MARKER-models-91c2";

// ---- 假的上游 ----

/// 上游看到的一个请求。
#[derive(Clone, Debug)]
struct Seen {
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// `/slow` 的连接被服务器关闭的时刻（本机程序断开后，服务器应取消上游请求）。
static SLOW_CLOSED: Mutex<Option<Instant>> = Mutex::new(None);

/// 写一个分块并立刻发出。
fn chunk<W: Write>(w: &mut W, d: &[u8]) {
    let _ = write!(w, "{:x}\r\n", d.len());
    let _ = w.write_all(d);
    let _ = w.write_all(b"\r\n");
    let _ = w.flush();
}

/// 自签 HTTPS 上游（127.0.0.1）。返回端口与请求记录。
fn upstream() -> (u16, Log) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cfg = Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let (cfg, log) = (cfg.clone(), log2.clone());
            std::thread::spawn(move || serve_upstream(s, cfg, log, port));
        }
    });
    (port, log)
}

fn serve_upstream(s: TcpStream, cfg: Arc<rustls::ServerConfig>, log: Log, port: u16) {
    let conn = rustls::ServerConnection::new(cfg).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, s);
    // 请求头与请求体
    let mut raw = String::new();
    let mut headers = Vec::new();
    let mut len = 0usize;
    {
        let mut r = BufReader::new(&mut tls);
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            raw.push_str(&line);
            if line == "\r\n" {
                break;
            }
            if let Some((k, v)) = line.trim_end().split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    len = v.trim().parse().unwrap_or(0);
                }
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let mut body = vec![0u8; len];
        let _ = r.read_exact(&mut body);
        let target = raw.split(' ').nth(1).unwrap_or("/").to_string();
        log.lock().unwrap().push(Seen { target, headers: headers.clone(), body });
    }
    let seen = log.lock().unwrap().last().cloned().unwrap();
    let (path, query) = seen.target.split_once('?').unwrap_or((seen.target.as_str(), ""));
    let auth = headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone()).unwrap_or_default();
    let mode = query.split('&').find_map(|kv| kv.strip_prefix("mode=")).unwrap_or("plain");
    let plain = |tls: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>, status: &str, extra: &str, body: &[u8]| {
        let _ = write!(tls, "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = tls.write_all(body);
    };
    match path {
        "/api/v1/echo" => {
            // 回显：请求头原文与它的各种编码、查询串、请求体；响应头里也放凭据
            let pct = percent_encoding::utf8_percent_encode(&raw, percent_encoding::NON_ALPHANUMERIC).to_string();
            let json = serde_json::to_string(&raw).unwrap();
            let body = format!(
                "{raw}\nQUERY:{query}\nB64:{}\nB64URL:{}\nPCT:{pct}\nJSON:{json}\nBODY:{}",
                STANDARD.encode(&raw),
                URL_SAFE_NO_PAD.encode(&raw),
                String::from_utf8_lossy(&seen.body)
            );
            let extra = format!(
                "Content-Type: text/plain\r\nX-Request-Id: {}\r\nX-Echo: {auth}\r\nSet-Cookie: s={auth}\r\n",
                STANDARD.encode(&auth)
            );
            match mode {
                "gzip" => {
                    // 无视 Accept-Encoding: identity，照样压缩
                    let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    g.write_all(body.as_bytes()).unwrap();
                    plain(&mut tls, "200 OK", &format!("{extra}Content-Encoding: gzip\r\n"), &g.finish().unwrap());
                }
                "sse-split" => {
                    // 凭据在每一个字节位置被切成两块发出
                    let _ = write!(
                        tls,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    );
                    let a = auth.as_bytes();
                    for k in 0..=a.len() {
                        chunk(&mut tls, &[b"data: ", &a[..k]].concat());
                        std::thread::sleep(Duration::from_millis(1));
                        chunk(&mut tls, &[&a[k..], b"\n\n"].concat());
                    }
                    chunk(&mut tls, &[]);
                }
                _ => plain(&mut tls, "200 OK", &extra, body.as_bytes()),
            }
        }
        "/api/v1/stream" => {
            // 20 个事件，间隔 200 ms
            let _ = write!(
                tls,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            );
            for i in 0..20 {
                if i > 0 {
                    std::thread::sleep(Duration::from_millis(200));
                }
                chunk(&mut tls, format!("data: {{\"i\":{i}}}\n\n").as_bytes());
            }
            chunk(&mut tls, &[]);
        }
        "/api/v1/models" => {
            plain(&mut tls, "200 OK", "Content-Type: application/json\r\n", format!("{{\"data\":[],\"m\":\"{RESP_MARKER}\"}}").as_bytes())
        }
        "/api/v1/slow" => {
            // 60 秒不回答；服务器关闭连接（读到 EOF 或 close_notify）时记下时刻
            let _ = tls.sock.set_read_timeout(Some(Duration::from_millis(100)));
            let t0 = Instant::now();
            let mut b = [0u8; 1];
            while t0.elapsed() < Duration::from_secs(60) {
                match tls.sock.peek(&mut b) {
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                    _ => {
                        *SLOW_CLOSED.lock().unwrap() = Some(Instant::now());
                        return;
                    }
                }
            }
            plain(&mut tls, "200 OK", "", b"late")
        }
        "/api/v1/redirect-in" => plain(&mut tls, "302 Found", "Location: /api/v1/models\r\n", b""),
        "/api/v1/redirect-out" => plain(&mut tls, "302 Found", &format!("Location: https://127.0.0.2:{port}/api/v1/models\r\n"), b""),
        _ => plain(&mut tls, "404 Not Found", "", b"no"),
    }
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn seen_count(log: &Log, path: &str) -> usize {
    log.lock().unwrap().iter().filter(|s| s.target.split('?').next() == Some(path)).count()
}

// ---- 访问本地中继的原始 HTTP 客户端 ----

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    /// 状态行、响应头与响应体拼在一起（查泄露时全部算上）。
    fn all(&self) -> String {
        let h: String = self.headers.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
        format!("{}\n{h}{}", self.status, self.text())
    }
}

/// 拆开 `http://127.0.0.1:<端口><路径>`。
fn split_url(url: &str) -> (String, String) {
    let rest = url.strip_prefix("http://").unwrap();
    let i = rest.find('/').unwrap_or(rest.len());
    (rest[..i].to_string(), if i < rest.len() { rest[i..].to_string() } else { "/".into() })
}

/// 发请求，读回响应头；返回读响应体用的 reader。
fn send(url: &str, method: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, Vec<(String, String)>, BufReader<TcpStream>) {
    let (hp, path) = split_url(url);
    let mut s = TcpStream::connect(&hp).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {hp}\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status: u16 = line.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let mut hs = Vec::new();
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
            break;
        }
        if let Some((k, v)) = l.trim_end().split_once(':') {
            hs.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    (status, hs, r)
}

/// 读一个分块：None 表示结束。
fn read_chunk(r: &mut BufReader<TcpStream>) -> Option<Vec<u8>> {
    let mut line = String::new();
    if r.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let n = usize::from_str_radix(line.trim(), 16).ok()?;
    if n == 0 {
        return None;
    }
    let mut buf = vec![0u8; n + 2];
    r.read_exact(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

fn request(url: &str, method: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
    let (status, headers, mut r) = send(url, method, headers, body);
    let chunked = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let mut out = Vec::new();
    if chunked {
        while let Some(c) = read_chunk(&mut r) {
            out.extend(c);
        }
    } else {
        let _ = r.read_to_end(&mut out);
    }
    Resp { status, headers, body: out }
}

// ---- 运行 `passmanager run --http` ----

struct Running {
    child: Child,
    stop: PathBuf,
    vars: Vec<(String, String)>,
}

impl Running {
    fn var(&self, k: &str) -> String {
        self.vars.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap_or_else(|| panic!("no {k}"))
    }
    /// 让子程序退出，返回 run 的输出。
    fn finish(self) -> std::process::Output {
        std::fs::write(&self.stop, "").unwrap();
        self.child.wait_with_output().unwrap()
    }
}

/// 启动 run：子程序把 `names` 里的变量写进文件后等待 stop 文件出现。
fn start(env: &Env, tag: &str, args: &[&str], names: &[&str]) -> Running {
    let dir = env.base.join(format!("child-{tag}"));
    std::fs::create_dir_all(&dir).unwrap();
    let (vars, stop) = (dir.join("vars"), dir.join("stop"));
    let pattern = format!("^({})=", names.join("|"));
    let script = r#"env | grep -E "$2" > "$0.tmp"; mv "$0.tmp" "$0"; while [ ! -e "$1" ]; do sleep 0.05; done"#;
    let mut all = vec!["run"];
    all.extend_from_slice(args);
    all.extend_from_slice(&["sh", "-c", script]);
    let mut c = env.agent_cmd(&all);
    c.arg(&vars)
        .arg(&stop)
        .arg(&pattern)
        .env("XDG_RUNTIME_DIR", env.base.join("runtime"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    std::fs::create_dir_all(env.base.join("runtime")).unwrap();
    let mut child = c.spawn().unwrap();
    let t0 = Instant::now();
    while !vars.exists() {
        if let Ok(Some(st)) = child.try_wait() {
            let o = child.wait_with_output().unwrap();
            panic!("run exited early ({st}): {}{}", stdout(&o), stderr(&o));
        }
        assert!(t0.elapsed() < Duration::from_secs(60), "run did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let text = std::fs::read_to_string(&vars).unwrap();
    std::fs::remove_file(&vars).unwrap();
    let vars = text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
    Running { child, stop, vars }
}

/// 本机上所有能读的进程的环境变量与命令行里，以及 `dir` 之下所有文件里，是否出现 `needle`。
fn found_on_client(needle: &str, dir: &Path) -> Vec<String> {
    let mut hits = Vec::new();
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        if !e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        for f in ["environ", "cmdline"] {
            if let Ok(b) = std::fs::read(e.path().join(f))
                && String::from_utf8_lossy(&b).contains(needle)
            {
                hits.push(format!("{}/{f}", e.path().display()));
            }
        }
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(b) = std::fs::read(&p)
                && String::from_utf8_lossy(&b).contains(needle)
            {
                hits.push(p.display().to_string());
            }
        }
    }
    hits
}

/// 凭据在 base64 里"只由它自己决定"的那段字符：3 种字节偏移 × 标准 / URL 安全两种字母表。
fn b64_cores() -> Vec<String> {
    let mut out = Vec::new();
    for off in 0..3usize {
        let mut buf = vec![0u8; off];
        buf.extend_from_slice(SECRET.as_bytes());
        for enc in [STANDARD.encode(&buf), URL_SAFE_NO_PAD.encode(&buf)] {
            let (a, b) = ((8 * off).div_ceil(6), (8 * (off + SECRET.len())) / 6);
            out.push(enc[a..b].to_string());
        }
    }
    out
}

/// 一段文本里有没有凭据的任何编码形式：原文、百分号编码、JSON 转义、base64 / base64url（任意偏移）。
fn has_secret(t: &str) -> bool {
    let pct = percent_encoding::utf8_percent_encode(SECRET, percent_encoding::NON_ALPHANUMERIC).to_string();
    let json = serde_json::to_string(SECRET).unwrap();
    t.contains(SECRET) || t.contains(&pct) || t.contains(&json[1..json.len() - 1]) || b64_cores().iter().any(|c| t.contains(c.as_str()))
}

#[test]
fn run_http_relays_with_policy_and_never_exposes_the_credential() {
    let env = Env::setup("relay");
    let (port, log) = upstream();
    let origin = format!("https://127.0.0.1:{port}");

    // 服务器上：凭据只允许 http，root 设中继策略
    let o = env.run_stdin(&["import", "--name", "or", "--domain", "127.0.0.1", "--ops", "http", "--self-signed"], SECRET.as_bytes());
    assert!(o.status.success(), "{}", stderr(&o));
    let o = env.run(&[
        "relay",
        "set",
        "--name",
        "or",
        "--allow",
        "POST /api/v1/echo",
        "--allow",
        "GET /api/v1/*",
        "--max-requests-day",
        "1000",
    ]);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&env.run(&["relay", "list"])).contains("允许：GET /api/v1/*"));
    // 策略不能写管理接口
    assert!(!env.run(&["relay", "set", "--name", "or", "--allow", "GET /api/v1/keys"]).status.success());

    // lookup 告诉 Agent 怎样用 run --http
    let o = env.agent(&["lookup", &format!("{origin}/api/v1/models")]);
    assert!(stdout(&o).contains("passmanager run --http"), "{}", stdout(&o));

    // 一次运行，两组变量名（i）
    let names = ["JW_URL", "JW_KEY", "OPENAI_BASE_URL", "OPENAI_API_KEY"];
    let args = [
        "--http",
        &origin,
        "--env-url",
        "JW_URL=/api/v1",
        "--env-key",
        "JW_KEY",
        "--env-url",
        "OPENAI_BASE_URL=/api/v1",
        "--env-key",
        "OPENAI_API_KEY",
    ];
    let r = start(&env, "main", &args, &names);
    let (jw, oa, dummy) = (r.var("JW_URL"), r.var("OPENAI_BASE_URL"), r.var("OPENAI_API_KEY"));
    assert!(jw.starts_with("http://127.0.0.1:") && jw.ends_with("/api/v1") && jw == oa, "{jw} {oa}");
    assert!(dummy.starts_with("pm-relay-") && dummy == r.var("JW_KEY"));
    let relay_port: u16 = split_url(&jw).0.rsplit(':').next().unwrap().parse().unwrap();
    let token = split_url(&jw).1.trim_start_matches('/').split('/').next().unwrap().to_string();
    let bearer = format!("Bearer {dummy}");

    // (a) 上游收到真实凭据，占位值不见了；其余请求头与请求体逐字节相同；带凭据的查询参数被去掉
    let body = format!("{{\"model\":\"m1\",\"note\":\"{REQ_MARKER}\",\"bin\":\"\\u00e9\\t\"}}");
    let resp = request(
        &format!("{jw}/echo?mode=plain&key={dummy}&keep=1"),
        "POST",
        &[("Authorization", &bearer), ("X-Test", "abc 123"), ("Content-Type", "application/json"), ("Accept-Encoding", "gzip")],
        body.as_bytes(),
    );
    assert_eq!(resp.status, 200, "{}", resp.all());
    let seen = log.lock().unwrap().last().cloned().unwrap();
    let h = |k: &str| seen.headers.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
    assert_eq!(h("authorization").as_deref(), Some(format!("Bearer {SECRET}").as_str()), "上游收到真实凭据");
    assert!(!seen.headers.iter().any(|(_, v)| v.contains(&dummy)) && !seen.target.contains(&dummy), "占位值没有转发");
    assert_eq!(
        (h("x-test").as_deref(), h("content-type").as_deref(), h("accept-encoding").as_deref()),
        (Some("abc 123"), Some("application/json"), Some("identity"))
    );
    assert_eq!(seen.body, body.as_bytes(), "请求体逐字节相同");
    assert_eq!(seen.target, "/api/v1/echo?mode=plain&keep=1");

    // (e) 回显：原文、base64、base64url、百分号、JSON 转义，响应头里也有；压缩与 SSE 每个切点：都不见凭据
    assert!(!has_secret(&resp.all()), "plain: {}", resp.all());
    assert!(resp.text().contains("[REDACTED:or]") && resp.text().contains(REQ_MARKER), "{}", resp.text());
    assert!(resp.header("x-echo").is_none() && resp.header("set-cookie").is_none(), "不在白名单的响应头被丢弃");
    assert!(
        resp.header("x-request-id").is_some_and(|v| v.contains("[REDACTED:or]")),
        "白名单里的响应头也脱敏：{:?}",
        resp.header("x-request-id")
    );
    let gz = request(&format!("{jw}/echo?mode=gzip"), "GET", &[], b"");
    assert!(gz.status == 200 && gz.text().contains("B64:") && gz.header("content-encoding").is_none(), "{}", gz.all());
    assert!(!has_secret(&gz.all()) && gz.text().contains("[REDACTED:or]"), "gzip: {}", gz.all());
    let sse = request(&format!("{oa}/echo?mode=sse-split"), "GET", &[], b"");
    let events = sse.text().matches("data: ").count();
    assert!(sse.status == 200 && events == format!("Bearer {SECRET}").len() + 1, "{events}: {}", sse.text());
    assert!(!has_secret(&sse.all()), "sse: {}", sse.text());
    assert_eq!(sse.text().matches("[REDACTED:or]").count(), events, "每个事件都替换了");

    // (b) 流式：20 个事件间隔 200 ms，逐个到达
    let (status, _, mut rd) = send(&format!("{jw}/stream"), "GET", &[], b"");
    assert_eq!(status, 200);
    let t0 = Instant::now();
    let mut times = Vec::new();
    let mut buf = Vec::new();
    while let Some(c) = read_chunk(&mut rd) {
        buf.extend(c);
        while let Some(i) = buf.windows(2).position(|w| w == b"\n\n") {
            buf.drain(..i + 2);
            times.push(t0.elapsed());
        }
    }
    assert_eq!(times.len(), 20, "{times:?}");
    assert!(times[0] < Duration::from_millis(500), "第一个事件立刻到达：{times:?}");
    let gaps: Vec<u128> = times.windows(2).map(|w| (w[1] - w[0]).as_millis()).collect();
    assert!(gaps.iter().all(|g| (60..=600).contains(g)), "事件间隔：{gaps:?}");
    let total = (times[19] - times[0]).as_millis();
    assert!((3400..=5500).contains(&total), "19 个间隔合计约 3800 ms：{total}");

    // (c) 令牌不对或缺少：403，服务器收不到请求
    let before = (log.lock().unwrap().len(), env.service_log().matches("relay").count());
    for p in [format!("/{}/api/v1/models", "0".repeat(32)), "/api/v1/models".to_string(), format!("/{token}x/api/v1/models")] {
        let resp = request(&format!("http://127.0.0.1:{relay_port}{p}"), "GET", &[], b"");
        assert_eq!(resp.status, 403, "{p}");
    }
    assert_eq!((log.lock().unwrap().len(), env.service_log().matches("relay").count()), before, "没有发出任何请求");

    // (f) 策略：之外的路径与管理接口 403，上游收不到；跨源重定向不跟随；同源、在策略内的重定向跟随
    for (m, p) in [("POST", "/models"), ("GET", "/keys"), ("GET", "/models/%6Beys"), ("DELETE", "/echo"), ("GET", "/../v2/x")] {
        let resp = request(&format!("{jw}{p}"), m, &[], b"");
        assert_eq!(resp.status, 403, "{m} {p}: {}", resp.all());
    }
    assert_eq!(seen_count(&log, "/api/v1/keys") + seen_count(&log, "/api/v1/models/keys"), 0);
    let resp = request(&format!("{jw}/redirect-out"), "GET", &[], b"");
    assert!(resp.status == 502 && resp.text().contains("another origin"), "{}", resp.all());
    let resp = request(&format!("{jw}/redirect-in"), "GET", &[], b"");
    assert!(resp.status == 200 && resp.text().contains(RESP_MARKER), "{}", resp.all());
    // 本机程序断开：服务器在下一个心跳（10 秒）之内取消上游请求
    {
        let (hp, path) = split_url(&format!("{jw}/slow"));
        let mut s = TcpStream::connect(&hp).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: {hp}\r\nContent-Length: 0\r\n\r\n").unwrap();
        let t_wait = Instant::now();
        while seen_count(&log, "/api/v1/slow") == 0 {
            assert!(t_wait.elapsed() < Duration::from_secs(10), "请求没有到达上游");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(500));
        drop(s);
        let gone = Instant::now();
        let closed = loop {
            if let Some(t) = *SLOW_CLOSED.lock().unwrap() {
                break t;
            }
            assert!(gone.elapsed() < Duration::from_secs(20), "上游请求没有被取消");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(closed.duration_since(gone) < Duration::from_secs(15), "取消用了 {:?}", closed.duration_since(gone));
    }
    let o = r.finish();
    assert!(o.status.success(), "{}", stderr(&o));
    // 命令结束：端口关闭
    assert!(TcpStream::connect(("127.0.0.1", relay_port)).is_err(), "中继在命令结束后关闭");
    let run_out = format!("{}{}", stdout(&o), stderr(&o));

    // (f) 请求体规则 与 (g) 上限：--require 与 --max-requests 只收窄策略
    let r =
        start(&env, "limits", &["--http", &origin, "--env-url", "U=/api/v1", "--max-requests", "2", "--require", "json:model=m1"], &["U"]);
    let u = r.var("U");
    let n_echo = seen_count(&log, "/api/v1/echo");
    let bad = request(&format!("{u}/echo"), "POST", &[], br#"{"model":"m2"}"#);
    assert!(bad.status == 403 && bad.text().contains("json:model"), "{}", bad.all());
    let dup = request(&format!("{u}/echo"), "POST", &[], br#"{"model":"m1","model":"m2"}"#);
    assert_eq!(dup.status, 403, "重复的键");
    assert_eq!(seen_count(&log, "/api/v1/echo"), n_echo, "违反规则的请求没有到达上游");
    assert_eq!(request(&format!("{u}/echo"), "POST", &[], br#"{"model":"m1"}"#).status, 200);
    assert_eq!(request(&format!("{u}/models"), "GET", &[], b"").status, 200);
    let third = request(&format!("{u}/models"), "GET", &[], b"");
    assert!(third.status == 429 && third.text().contains("per-run request limit"), "{}", third.all());
    let o2 = r.finish();
    assert!(o2.status.success());

    // (d) 凭据不在本机任何进程的环境变量、命令行里，也不在任何文件里
    assert!(found_on_client(SECRET, &env.base).is_empty(), "{:?}", found_on_client(SECRET, &env.base));

    // (h) 日志里没有凭据、令牌与请求体；替换次数记了下来
    let slog = env.service_log();
    let all_logs = format!("{slog}{run_out}{}{}", stdout(&o2), stderr(&o2));
    assert!(
        !has_secret(&all_logs) && !all_logs.contains(&token) && !all_logs.contains(REQ_MARKER) && !all_logs.contains(RESP_MARKER),
        "{all_logs}"
    );
    assert!(slog.contains("relay: open entry=or") && slog.contains("last=echo status=200"), "{slog}");
    assert!(slog.lines().any(|l| l.contains("last=echo") && !l.contains("redactions=0")), "回显的替换次数：{slog}");
    assert!(slog.contains("relay refused") && slog.contains("code=FORBIDDEN"), "被拒绝的请求也记一行：{slog}");
}

#[test]
fn run_http_refuses_without_policy_or_enrollment() {
    let env = Env::setup("relay-nopolicy");
    let (port, _log) = upstream();
    let origin = format!("https://127.0.0.1:{port}");
    let o =
        env.run_stdin(&["import", "--name", "plain", "--domain", "127.0.0.1", "--ops", "http", "--self-signed"], b"plain-secret-value-123");
    assert!(o.status.success());
    // 没有策略：打不开，命令不运行
    let o = env
        .agent_cmd(&["run", "--http", &origin, "--env-url", "U=/v1", "sh", "-c", "echo RAN"])
        .env("XDG_RUNTIME_DIR", env.base.join("rt"))
        .output()
        .unwrap();
    assert!(!o.status.success() && stderr(&o).contains("NO_RELAY_POLICY") && !stdout(&o).contains("RAN"), "{}{}", stdout(&o), stderr(&o));
    // 选项写错：什么都不打开
    for bad in [
        vec!["--env-url", "U=/v1"],
        vec!["--http", "http://127.0.0.1", "--env-url", "U=/v1"],
        vec!["--http", &origin, "--env-url", "PATH=/v1"],
    ] {
        let mut a = vec!["run"];
        a.extend(bad.iter().copied());
        a.extend(["sh", "-c", "echo RAN"]);
        let o = env.agent_cmd(&a).env("XDG_RUNTIME_DIR", env.base.join("rt")).output().unwrap();
        assert!(!o.status.success() && !stdout(&o).contains("RAN"), "{bad:?}: {}", stderr(&o));
    }
    // 删除条目时策略一起删除
    assert!(env.run(&["relay", "set", "--name", "plain", "--allow", "GET /v1/models"]).status.success());
    assert!(stdout(&env.run(&["relay", "list"])).contains("共 1 份"));
    assert!(env.run(&["relay", "remove", "--name", "plain"]).status.success());
    assert!(stdout(&env.run(&["relay", "list"])).contains("共 0 份"));
}

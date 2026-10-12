//! `passmanager git-proxy`：Agent 机器上的本地 git 凭据注入代理（只监听本机回环地址）。
//!
//! git 通过 `url.<代理前缀>.insteadOf` 把 `https://<主机>/…` 改写为
//! `http://127.0.0.1:<端口>/<路径令牌>/https/<主机>/…`。代理把每个 smart-HTTP 请求（请求体与响应体都是流式的）
//! 经双层加密通道交给服务器；服务器带上条目里的访问令牌（PAT）请求上游。本机从不接触 PAT。
//!
//! - 路径令牌：随机 128 位，持久保存在配置目录（0600；insteadOf 配置在重启后仍然有效），防止本机其他程序借用代理；
//! - 常驻服务与 git 配置见 `git_service`（`enroll` 与 `git-proxy --install` 自动完成）；
//! - 只接受回环地址的连接；只接受 `https` 目标；服务器端再检查主机是否属于条目的域名、请求是否是 smart-HTTP。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::ExitCode;

use pm_proto::{GitHead, Request};

pub const DEFAULT_LISTEN: &str = "127.0.0.1:7878";
const MAX_HEAD: usize = 64 * 1024;

/// 读取或生成路径令牌（配置目录下的 `git-proxy.token`，0600）。
pub fn path_token(dir: &Path) -> Result<String, String> {
    let p = dir.join("git-proxy.token");
    if let Ok(t) = std::fs::read_to_string(&p) {
        let t = t.trim().to_string();
        if t.len() == 32 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(t);
        }
    }
    let raw: [u8; 16] = pm_crypto::rng::random_array().map_err(|e| e.to_string())?;
    let t = hex::encode(raw);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    pm_platform::paths::write_atomic(&p, t.as_bytes(), 0o600).map_err(|e| e.to_string())?;
    Ok(t)
}

/// 请求行与请求头。
#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
}

pub fn read_head<R: BufRead>(r: &mut R) -> Result<Head, String> {
    let mut lines = Vec::new();
    let mut total = 0;
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed".into());
        }
        total += n;
        if total > MAX_HEAD {
            return Err("request head too large".into());
        }
        let l = line.trim_end_matches(['\r', '\n']).to_string();
        if l.is_empty() {
            break;
        }
        lines.push(l);
    }
    let first = lines.first().ok_or("empty request")?;
    let mut it = first.split(' ');
    let (method, target, ver) = (it.next().unwrap_or(""), it.next().unwrap_or(""), it.next().unwrap_or(""));
    if method.is_empty() || !target.starts_with('/') || !ver.starts_with("HTTP/1.") {
        return Err("bad request line".into());
    }
    let headers = lines[1..].iter().filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    Ok(Head { method: method.to_string(), target: target.to_string(), headers })
}

/// `/<令牌>/https/<主机[:端口]>/<路径>` → 上游 URL。令牌用常数时间比较。
pub fn upstream_url(target: &str, token: &str) -> Result<String, &'static str> {
    let rest = target.strip_prefix('/').ok_or("bad path")?;
    let (tok, rest) = rest.split_once('/').ok_or("bad path")?;
    if !pm_crypto::ct_eq(tok.as_bytes(), token.as_bytes()) {
        return Err("bad token");
    }
    let rest = rest.strip_prefix("https/").ok_or("only https upstreams are supported")?;
    let (host, path) = rest.split_once('/').ok_or("bad path")?;
    if host.is_empty() || host.contains(['@', '\\']) {
        return Err("bad host");
    }
    Ok(format!("https://{host}/{path}"))
}

/// HTTP/1.1 分块请求体的读取。
pub struct ChunkedReader<R: BufRead> {
    r: R,
    left: usize,
    done: bool,
}

impl<R: BufRead> ChunkedReader<R> {
    pub fn new(r: R) -> Self {
        Self { r, left: 0, done: false }
    }
}

impl<R: BufRead> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunked encoding");
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut line = String::new();
            self.r.read_line(&mut line)?;
            let size = line.trim().split(';').next().unwrap_or("");
            let n = usize::from_str_radix(size, 16).map_err(|_| bad())?;
            if n == 0 {
                // 跳过 trailer 直到空行。
                loop {
                    let mut t = String::new();
                    if self.r.read_line(&mut t)? == 0 || t.trim().is_empty() {
                        break;
                    }
                }
                self.done = true;
                return Ok(0);
            }
            self.left = n;
        }
        let want = buf.len().min(self.left);
        let n = self.r.read(&mut buf[..want])?;
        if n == 0 {
            return Err(bad());
        }
        self.left -= n;
        if self.left == 0 {
            let mut crlf = [0u8; 2];
            self.r.read_exact(&mut crlf)?;
            if &crlf != b"\r\n" {
                return Err(bad());
            }
        }
        Ok(n)
    }
}

/// HTTP/1.1 分块响应体的写入。
pub struct ChunkedWriter<W: Write>(pub W);

impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        write!(self.0, "{:x}\r\n", buf.len())?;
        self.0.write_all(buf)?;
        self.0.write_all(b"\r\n")?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

fn simple(s: &mut TcpStream, status: u16, msg: &str) {
    let body = format!("PassManager git-proxy: {msg}\n");
    let _ = write!(
        s,
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        reason(status),
        body.len()
    );
}

/// 处理一个连接（每个连接只处理一个请求）。
pub fn serve_conn(mut s: TcpStream, token: &str, connect: &dyn Fn() -> Option<Result<pm_proto::Client, pm_proto::ApiError>>) {
    if !s.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
        return;
    }
    let Ok(rd) = s.try_clone() else { return };
    let mut r = BufReader::new(rd);
    let head = match read_head(&mut r) {
        Ok(h) => h,
        Err(e) => return simple(&mut s, 400, e.as_str()),
    };
    let url = match upstream_url(&head.target, token) {
        Ok(u) => u,
        Err("bad token") => return simple(&mut s, 403, "forbidden"),
        Err(e) => return simple(&mut s, 400, e),
    };
    if head.header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        let _ = s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    let mut body: Box<dyn Read> = if head.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        Box::new(ChunkedReader::new(r))
    } else {
        let n: u64 = head.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        Box::new(r.take(n))
    };
    let mut client = match connect() {
        Some(Ok(c)) => c,
        Some(Err(e)) => return simple(&mut s, 502, &format!("{}: {}", e.code, e.message)),
        None => return simple(&mut s, 502, "no remote configuration (run passmanager enroll first)"),
    };
    // Authorization / Cookie 不转发（服务器也会丢弃）。
    let headers: Vec<(String, String)> = head
        .headers
        .iter()
        .filter(|(k, _)| !matches!(k.to_ascii_lowercase().as_str(), "authorization" | "cookie" | "proxy-authorization"))
        .cloned()
        .collect();
    let req = Request::GitProxy { method: head.method.clone(), url, headers };
    let mut out_stream = match s.try_clone() {
        Ok(o) => o,
        Err(_) => return,
    };
    let mut started = false;
    let mut on_head = |h: &GitHead| -> std::io::Result<()> {
        started = true;
        write!(out_stream, "HTTP/1.1 {} {}\r\n", h.status, reason(h.status))?;
        for (k, v) in &h.headers {
            write!(out_stream, "{k}: {v}\r\n")?;
        }
        out_stream.write_all(b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
    };
    let mut w = ChunkedWriter(match s.try_clone() {
        Ok(o) => o,
        Err(_) => return,
    });
    match client.git_proxy(&req, &mut body, &mut on_head, &mut w) {
        Ok(()) => {
            let _ = s.write_all(b"0\r\n\r\n");
        }
        Err(e) if !started => simple(
            &mut s,
            if e.code == "FORBIDDEN" || e.code == "DOMAIN_MISMATCH" || e.code == "NO_CREDENTIAL" { 403 } else { 502 },
            &format!("{}: {}", e.code, e.message),
        ),
        Err(e) => eprintln!("[PassManager git-proxy] stream aborted: {}", e.code),
    }
}

/// 配置错误（服务管理器不再重启）。
fn fail_config(msg: impl AsRef<str>) -> ExitCode {
    eprintln!("错误：{}", msg.as_ref());
    ExitCode::from(crate::git_service::EXIT_CONFIG)
}

/// 前台运行代理。`hosts` 为空时打印服务器上有 `git` 用途的所有条目的主机的 git 配置命令。
pub fn run(listen: Option<String>, hosts: Vec<String>) -> ExitCode {
    let addr: SocketAddr = match listen.as_deref().unwrap_or(DEFAULT_LISTEN).parse() {
        Ok(a) => a,
        Err(_) => return fail_config("--listen 必须是 IP:端口，例如 127.0.0.1:7878"),
    };
    if !addr.ip().is_loopback() {
        return fail_config("git-proxy 只能监听本机回环地址（127.0.0.1 / ::1）");
    }
    if crate::remote::load_in(&crate::remote::dir()).is_none() {
        return fail_config("没有远程配置：先运行 passmanager enroll '<注册码>'");
    }
    let token = match path_token(&crate::remote::dir()) {
        Ok(t) => t,
        Err(e) => return crate::install::fail(e),
    };
    let l = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            return crate::install::fail(format!(
                "监听 {addr} 失败：{e}（git-proxy 服务可能已在运行：systemctl --user status {}）",
                crate::git_service::UNIT
            ));
        }
    };
    let base = format!("http://{addr}/{token}/https");
    let (hosts, note) = if hosts.is_empty() {
        match crate::git_service::default_hosts() {
            Ok(h) if h.is_empty() => (h, Some("服务器上还没有 git 用途的条目".to_string())),
            Ok(h) => (h, None),
            Err(e) => (vec![], Some(format!("无法读取条目列表：{e}"))),
        }
    } else {
        (hosts, None)
    };
    println!("PassManager git-proxy 监听 {addr}。配置 git（每个主机一次；passmanager git-proxy --install 会自动写入）：");
    if let Some(n) = note {
        println!("  （{n}）");
        println!("  git config --global url.\"{base}/<主机>/\".insteadOf \"https://<主机>/\"");
    }
    for h in &hosts {
        println!("  git config --global url.\"{base}/{h}/\".insteadOf \"https://{h}/\"");
    }
    let _ = std::io::stdout().flush();
    for s in l.incoming() {
        let Ok(s) = s else { continue };
        let token = token.clone();
        std::thread::spawn(move || serve_conn(s, &token, &crate::remote::connect_if_configured));
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_mapping_and_token_check() {
        let t = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            upstream_url(&format!("/{t}/https/github.com/o/r.git/info/refs?service=git-upload-pack"), t).unwrap(),
            "https://github.com/o/r.git/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            upstream_url(&format!("/{t}/https/git.example.com:8121/r/x/git-receive-pack"), t).unwrap(),
            "https://git.example.com:8121/r/x/git-receive-pack"
        );
        assert_eq!(upstream_url("/wrongtoken0000000000000000000000/https/github.com/x", t), Err("bad token"));
        assert_eq!(upstream_url(&format!("/{t}/http/github.com/x"), t), Err("only https upstreams are supported"));
        assert!(upstream_url(&format!("/{t}/https/user@evil.com/x"), t).is_err());
        assert!(upstream_url(&format!("/{t}/https/"), t).is_err());
        assert!(upstream_url("nope", t).is_err());
    }

    #[test]
    fn head_and_chunked_codec() {
        let raw = b"POST /a/b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\nREST";
        let mut r = BufReader::new(&raw[..]);
        let h = read_head(&mut r).unwrap();
        assert_eq!((h.method.as_str(), h.target.as_str()), ("POST", "/a/b"));
        assert_eq!(h.header("transfer-encoding"), Some("chunked"));
        let mut body = String::new();
        ChunkedReader::new(&mut r).read_to_string(&mut body).unwrap();
        assert_eq!(body, "hello world");
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "REST");
        let mut bad = BufReader::new(&b"zz\r\nabc"[..]);
        assert!(ChunkedReader::new(&mut bad).read_to_string(&mut String::new()).is_err());
        let mut out = Vec::new();
        {
            let mut w = ChunkedWriter(&mut out);
            w.write_all(b"abc").unwrap();
            w.write_all(b"").unwrap();
        }
        assert_eq!(out, b"3\r\nabc\r\n");
        assert!(read_head(&mut BufReader::new(&b"GARBAGE\r\n\r\n"[..])).is_err());
        let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(70_000));
        assert!(read_head(&mut BufReader::new(huge.as_bytes())).is_err());
    }

    #[test]
    fn token_is_persistent_and_private() {
        let dir = std::env::temp_dir().join(format!("pm-gp-{}", std::process::id()));
        let a = path_token(&dir).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(path_token(&dir).unwrap(), a);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("git-proxy.token")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

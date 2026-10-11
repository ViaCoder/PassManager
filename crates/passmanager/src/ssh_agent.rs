//! `passmanager ssh-agent`：在已注册的 Agent 机器上提供 OpenSSH agent 协议（Unix 套接字，0600），
//! 让普通的 `ssh` / `scp` / `git`（经 SSH）直接使用服务器上保存的私钥——私钥从不离开服务器。
//!
//! - 列出公钥（REQUEST_IDENTITIES）：服务器上的 SSH 私钥条目；
//! - 签名（SIGN_REQUEST）：连同本连接最近一次的 `session-bind@openssh.com` 绑定，经双层加密通道转给服务器，
//!   由服务器检查绑定（主机密钥签名、主机是否绑定到该条目、非转发会话、待签数据属于同一会话）后签名；
//! - 添加 / 删除 / 锁定等操作一律拒绝；每个请求都重新连接服务器，令牌吊销后立即失效。

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pm_proto::{AgentBinding, AgentKeyView, Request};

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
const MAX_MSG: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub host_key: Vec<u8>,
    pub session_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub forwarding: bool,
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = u32::from_be_bytes(self.0.get(..4)?.try_into().ok()?) as usize;
        let v = self.0.get(4..4 + n)?;
        self.0 = &self.0[4 + n..];
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        let v = u32::from_be_bytes(self.0.get(..4)?.try_into().ok()?);
        self.0 = &self.0[4..];
        Some(v)
    }
    fn byte(&mut self) -> Option<u8> {
        let (b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*b)
    }
}

fn put_string(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u32).to_be_bytes());
    out.extend_from_slice(v);
}

/// 服务器端的操作（测试中可替换）。
pub trait Backend {
    fn keys(&self) -> Result<Vec<AgentKeyView>, String>;
    fn sign(&self, key: &[u8], data: &[u8], flags: u32, binding: Option<&Binding>) -> Result<Vec<u8>, String>;
}

/// 经远程配置连接服务器（每次新建连接）。
pub struct Remote;

impl Backend for Remote {
    fn keys(&self) -> Result<Vec<AgentKeyView>, String> {
        let mut c = crate::remote::connect_if_configured().ok_or("没有远程配置（先运行 passmanager enroll）")?.map_err(|e| e.code)?;
        c.call_as(&Request::AgentKeys).map_err(|e| e.code)
    }

    fn sign(&self, key: &[u8], data: &[u8], flags: u32, binding: Option<&Binding>) -> Result<Vec<u8>, String> {
        let mut c = crate::remote::connect_if_configured().ok_or("没有远程配置")?.map_err(|e| e.code)?;
        let req = Request::AgentSign {
            key: STANDARD.encode(key),
            data: STANDARD.encode(data),
            flags,
            binding: binding.map(|b| AgentBinding {
                host_key: STANDARD.encode(&b.host_key),
                session_id: STANDARD.encode(&b.session_id),
                signature: STANDARD.encode(&b.signature),
                forwarding: b.forwarding,
            }),
        };
        let sig: String = c.call_as(&req).map_err(|e| format!("{}: {}", e.code, e.message))?;
        STANDARD.decode(sig.as_bytes()).map_err(|e| e.to_string())
    }
}

/// 一条 agent 连接的状态：本连接上收到的会话绑定。
#[derive(Default)]
pub struct Conn {
    pub bindings: Vec<Binding>,
}

impl Conn {
    /// 处理一条消息（不含长度前缀），返回回复（不含长度前缀）。
    pub fn handle(&mut self, msg: &[u8], backend: &dyn Backend) -> Vec<u8> {
        let fail = vec![FAILURE];
        let Some((&t, body)) = msg.split_first() else { return fail };
        let mut r = R(body);
        match t {
            REQUEST_IDENTITIES => match backend.keys() {
                Ok(keys) => {
                    let mut out = vec![IDENTITIES_ANSWER];
                    let decoded: Vec<(Vec<u8>, String)> =
                        keys.into_iter().filter_map(|k| STANDARD.decode(k.blob.as_bytes()).ok().map(|b| (b, k.comment))).collect();
                    out.extend_from_slice(&(decoded.len() as u32).to_be_bytes());
                    for (b, c) in decoded {
                        put_string(&mut out, &b);
                        put_string(&mut out, c.as_bytes());
                    }
                    out
                }
                Err(e) => {
                    eprintln!("[PassManager ssh-agent] list keys failed: {e}");
                    fail
                }
            },
            SIGN_REQUEST => {
                let (Some(key), Some(data), Some(flags)) = (r.string(), r.string(), r.u32()) else { return fail };
                // 本连接上出现过转发会话的绑定：交给服务器拒绝（同时也在这里拒绝，省一次往返）。
                let binding = if self.bindings.iter().any(|b| b.forwarding) {
                    self.bindings.iter().find(|b| b.forwarding)
                } else {
                    self.bindings.last()
                };
                if binding.is_none_or(|b| b.forwarding) {
                    eprintln!(
                        "[PassManager ssh-agent] refused: {}",
                        if binding.is_none() { "no session-bind (OpenSSH >= 8.9 required)" } else { "forwarded session" }
                    );
                    return fail;
                }
                match backend.sign(key, data, flags, binding) {
                    Ok(sig) => {
                        let mut out = vec![SIGN_RESPONSE];
                        put_string(&mut out, &sig);
                        out
                    }
                    Err(e) => {
                        eprintln!("[PassManager ssh-agent] sign refused: {e}");
                        fail
                    }
                }
            }
            EXTENSION => {
                let Some(name) = r.string() else { return fail };
                if name != b"session-bind@openssh.com" {
                    return fail;
                }
                let (Some(h), Some(s), Some(sig), Some(fwd)) = (r.string(), r.string(), r.string(), r.byte()) else { return fail };
                if self.bindings.len() >= 16 {
                    return fail;
                }
                self.bindings.push(Binding { host_key: h.to_vec(), session_id: s.to_vec(), signature: sig.to_vec(), forwarding: fwd != 0 });
                vec![SUCCESS]
            }
            // 添加、删除、锁定、解锁等：一律拒绝。
            _ => fail,
        }
    }
}

fn serve_conn(mut s: UnixStream, backend: &dyn Backend) {
    let mut conn = Conn::default();
    loop {
        let mut len = [0u8; 4];
        if s.read_exact(&mut len).is_err() {
            return;
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_MSG {
            return;
        }
        let mut msg = vec![0u8; n];
        if s.read_exact(&mut msg).is_err() {
            return;
        }
        let reply = conn.handle(&msg, backend);
        let mut out = (reply.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&reply);
        if s.write_all(&out).is_err() {
            return;
        }
    }
}

pub fn default_socket() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d).join("passmanager-agent").join("agent.sock"),
        None => crate::remote::dir().join("agent").join("agent.sock"),
    }
}

/// 绑定 0600 的 Unix 套接字（目录 0700）；已存在的旧套接字文件被替换。
pub fn bind(path: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
    }
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if m.file_type().is_socket() {
            let _ = std::fs::remove_file(path);
        } else {
            return Err(format!("{} 已存在且不是套接字", path.display()));
        }
    }
    // SAFETY: umask 只影响本进程；绑定之后立即恢复。
    let old = unsafe { libc::umask(0o177) };
    let l = UnixListener::bind(path);
    // SAFETY: 同上。
    unsafe { libc::umask(old) };
    let l = l.map_err(|e| format!("监听 {} 失败：{e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    Ok(l)
}

pub fn run(socket: Option<PathBuf>) -> ExitCode {
    if crate::remote::load_in(&crate::remote::dir()).is_none() {
        return crate::install::fail("没有远程配置：先运行 passmanager enroll '<注册码>'");
    }
    let path = socket.unwrap_or_else(default_socket);
    let l = match bind(&path) {
        Ok(l) => l,
        Err(e) => return crate::install::fail(e),
    };
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", path.display());
    println!("echo PassManager ssh-agent pid {};", std::process::id());
    let _ = std::io::stdout().flush();
    for s in l.incoming() {
        let Ok(s) = s else { continue };
        std::thread::spawn(move || serve_conn(s, &Remote));
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        signed: Mutex<Vec<(Vec<u8>, Option<Binding>)>>,
    }

    impl Backend for Fake {
        fn keys(&self) -> Result<Vec<AgentKeyView>, String> {
            Ok(vec![AgentKeyView { blob: STANDARD.encode(b"KEYBLOB"), comment: "matrix".into() }])
        }
        fn sign(&self, key: &[u8], _data: &[u8], _flags: u32, binding: Option<&Binding>) -> Result<Vec<u8>, String> {
            self.signed.lock().unwrap().push((key.to_vec(), binding.cloned()));
            Ok(b"SIG".to_vec())
        }
    }

    fn sign_msg(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = vec![SIGN_REQUEST];
        put_string(&mut m, key);
        put_string(&mut m, data);
        m.extend_from_slice(&0u32.to_be_bytes());
        m
    }

    fn bind_msg(forwarding: bool) -> Vec<u8> {
        let mut m = vec![EXTENSION];
        put_string(&mut m, b"session-bind@openssh.com");
        put_string(&mut m, b"HOSTKEY");
        put_string(&mut m, b"SESSION");
        put_string(&mut m, b"HOSTSIG");
        m.push(forwarding as u8);
        m
    }

    #[test]
    fn protocol_rules() {
        let f = Fake::default();
        let mut c = Conn::default();
        // 列出公钥。
        let r = c.handle(&[REQUEST_IDENTITIES], &f);
        assert_eq!(r[0], IDENTITIES_ANSWER);
        assert_eq!(u32::from_be_bytes(r[1..5].try_into().unwrap()), 1);
        // 没有 session-bind：拒绝，不调用服务器。
        assert_eq!(c.handle(&sign_msg(b"KEYBLOB", b"data"), &f), vec![FAILURE]);
        assert!(f.signed.lock().unwrap().is_empty());
        // 绑定后签名：带上绑定。
        assert_eq!(c.handle(&bind_msg(false), &f), vec![SUCCESS]);
        let r = c.handle(&sign_msg(b"KEYBLOB", b"data"), &f);
        assert_eq!(r[0], SIGN_RESPONSE);
        assert_eq!(f.signed.lock().unwrap()[0].1.as_ref().unwrap().session_id, b"SESSION");
        // 转发会话：拒绝。
        let mut c2 = Conn::default();
        c2.handle(&bind_msg(true), &f);
        assert_eq!(c2.handle(&sign_msg(b"KEYBLOB", b"data"), &f), vec![FAILURE]);
        // 添加 / 删除 / 锁定 / 未知扩展 / 畸形消息：拒绝。
        for t in [17u8, 18, 19, 20, 22, 23, 25, 26, 99] {
            assert_eq!(c.handle(&[t, 0, 0, 0, 0], &f), vec![FAILURE], "{t}");
        }
        let mut other_ext = vec![EXTENSION];
        put_string(&mut other_ext, b"query");
        assert_eq!(c.handle(&other_ext, &f), vec![FAILURE]);
        assert_eq!(c.handle(&[SIGN_REQUEST, 0, 0], &f), vec![FAILURE]);
        assert_eq!(c.handle(&[], &f), vec![FAILURE]);
        // 绑定数量有上限。
        let mut c3 = Conn::default();
        for _ in 0..16 {
            assert_eq!(c3.handle(&bind_msg(false), &f), vec![SUCCESS]);
        }
        assert_eq!(c3.handle(&bind_msg(false), &f), vec![FAILURE]);
    }

    #[test]
    fn socket_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pm-agent-sock-{}", std::process::id()));
        let p = dir.join("a/agent.sock");
        let _l = bind(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(p.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        drop(_l);
        let _l2 = bind(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"not a socket").unwrap();
        assert!(bind(&p).is_err(), "不覆盖普通文件");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! 本地 IPC：Unix socket / Windows 命名管道。不监听任何 TCP 端口。
//!
//! 每条连接的第一帧必须是握手；失败时随机延迟后直接断开，不返回任何内容（防探测）。

use std::sync::Arc;
use std::time::Duration;

use pm_platform::Mode;
use pm_proto::{Hello, MAX_FRAME, PROTO_V, Request, Response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Session, Shared, log};

const HELLO_MAX: usize = 64 * 1024;

pub(crate) struct Peer {
    /// 是否以 root / 提权管理员身份运行。
    pub elevated: bool,
    /// 是否为允许的用户（系统模式下：安装用户或 root/管理员）。
    pub allowed: bool,
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> std::io::Result<Vec<u8>> {
    let len = s.read_u32().await? as usize;
    if len > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> std::io::Result<()> {
    s.write_u32(data.len() as u32).await?;
    s.write_all(data).await?;
    s.flush().await
}

/// 令牌会话拒绝提权客户端（root / 提权管理员）：提权的 Agent 本来就在安全边界之外。
/// 用户模式没有账户隔离；若服务自身也以提权身份运行（例如 CI 运行器），则不再额外拒绝。
fn token_allowed(shared: &Shared, peer: &Peer) -> bool {
    !peer.elevated || (shared.layout.mode == Mode::User && pm_platform::process::is_elevated())
}

async fn silent_reject() {
    let jitter: [u8; 1] = pm_crypto::rng::random_array().unwrap_or([128]);
    tokio::time::sleep(Duration::from_millis(200 + jitter[0] as u64 * 3)).await;
}

pub(crate) async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin>(shared: Arc<Shared>, mut s: S, peer: Peer) {
    if !peer.allowed {
        silent_reject().await;
        return;
    }
    let hello = match tokio::time::timeout(Duration::from_secs(10), read_frame(&mut s, HELLO_MAX)).await {
        Ok(Ok(b)) => serde_json::from_slice::<Hello>(&b).ok(),
        _ => None,
    };
    let session = match hello {
        Some(Hello::Token { v, token }) if v == PROTO_V && token_allowed(&shared, &peer) && shared.verify_token(&token) => {
            Some(Session::Agent)
        }
        Some(Hello::Password { v, password }) if v == PROTO_V => shared.password_login(password).await,
        Some(Hello::Setup { v, password }) if v == PROTO_V && (shared.layout.mode == Mode::User || peer.elevated) => {
            shared.setup(password).await
        }
        _ => None,
    };
    let Some(session) = session else {
        silent_reject().await;
        return;
    };
    if write_frame(&mut s, br#"{"ok":true}"#).await.is_err() {
        return;
    }
    loop {
        let frame = match read_frame(&mut s, MAX_FRAME).await {
            Ok(f) => f,
            Err(_) => break,
        };
        let resp = match serde_json::from_slice::<Request>(&frame) {
            Ok(req) => shared.dispatch(&session, req).await,
            Err(e) => Response::err("BAD_REQUEST", format!("invalid request: {e}")),
        };
        let bytes = serde_json::to_vec(&resp).unwrap_or_default();
        if write_frame(&mut s, &bytes).await.is_err() {
            break;
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            _ = crate::SHUTDOWN.notified() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = crate::SHUTDOWN.notified() => {}
        }
    }
}

#[cfg(unix)]
pub(crate) async fn serve(shared: Arc<Shared>) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let layout = shared.layout.clone();
    let path = layout.socket.clone();
    if layout.mode == Mode::User {
        std::fs::create_dir_all(&layout.run_dir).map_err(|e| e.to_string())?;
        let _ = std::fs::set_permissions(&layout.run_dir, std::fs::Permissions::from_mode(0o700));
    } else if !layout.run_dir.exists() {
        return Err(format!("{} 不存在（应由 service-prepare 创建）", layout.run_dir.display()));
    }
    if let Ok(m) = std::fs::symlink_metadata(&path) {
        if m.file_type().is_socket() {
            let _ = std::fs::remove_file(&path);
        } else {
            return Err(format!("{} 已存在且不是 socket", path.display()));
        }
    }
    let listener = tokio::net::UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    // 系统模式：目录（0750，属组为安装用户的组）负责访问控制；用户模式：仅本人。
    let mode = if layout.mode == Mode::System { 0o666 } else { 0o600 };
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
    log(&format!("listening on {}", path.display()));
    let client_uid = shared.info.client_uid;
    let my_uid = unsafe { libc::geteuid() };
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => {
                let Ok((stream, _)) = r else { continue };
                let uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
                let allowed = match layout.mode {
                    Mode::System => uid == 0 || client_uid.is_none_or(|c| c == uid),
                    Mode::User => uid == my_uid,
                };
                let peer = Peer { elevated: uid == 0, allowed };
                tokio::spawn(handle_conn(shared.clone(), stream, peer));
            }
        }
    }
    log("shutting down");
    shared.lock().await;
    shared.tokens.lock().unwrap().flush_if_dirty();
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[cfg(windows)]
pub(crate) async fn serve(shared: Arc<Shared>) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;

    use pm_platform::process::win::{SecAttrs, pipe_client};
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows::Win32::Foundation::HANDLE;

    let name = shared.layout.socket.to_string_lossy().to_string();
    // 只允许 SYSTEM、管道所有者（服务账户）与安装用户访问。
    let client = shared.info.client_sid.clone().or_else(pm_platform::process::current_user_sid).unwrap_or_default();
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GRGW;;;{client})");
    let make = |first: bool| -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        let mut sa = SecAttrs::from_sddl(&sddl)?;
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: 安全属性在调用期间有效。
        unsafe { opts.create_with_security_attributes_raw(&name, sa.as_ptr()) }
    };
    let mut server = make(true).map_err(|e| format!("create pipe {name}: {e}"))?;
    log(&format!("listening on {name}"));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            r = server.connect() => {
                if r.is_err() { continue; }
                let connected = server;
                server = make(false).map_err(|e| format!("create pipe: {e}"))?;
                let info = pipe_client(HANDLE(connected.as_raw_handle()));
                let (elevated, sid) = info.unwrap_or((true, String::new()));
                let allowed = shared.layout.mode == Mode::User || sid == client || elevated;
                tokio::spawn(handle_conn(shared.clone(), connected, Peer { elevated, allowed }));
            }
        }
    }
    shared.lock().await;
    shared.tokens.lock().unwrap().flush_if_dirty();
    Ok(())
}

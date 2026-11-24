//! 本地 IPC：Unix socket / Windows 命名管道；服务器模式下另有网络通道（见 `online`），
//! 网络连接经双层加密后同样交给这里的 `handle_conn`。
//!
//! 每条连接的第一帧必须是握手；失败时随机延迟后直接断开，不返回任何内容（防探测）。
//!
//! 经客户端网络连接 SSH 主机（见 `dial.rs`）：声明了 `dial` 的网络 Agent 连接上，SSH 类请求处理期间服务器可以
//! 往这条连接写 `{"dial": ...}` 帧；客户端另开一条 `Hello::Dial` 连接送来转发的字节。

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
    /// 来自网络（服务器模式的 Agent 通道）：只接受令牌与注册握手。
    pub network: bool,
    /// 网络连接的来源地址（审计与注册失败的限速）；本地连接为 None。
    pub addr: Option<std::net::IpAddr>,
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

pub(crate) async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(shared: Arc<Shared>, mut s: S, peer: Peer) {
    if !peer.allowed {
        silent_reject().await;
        return;
    }
    let hello = match tokio::time::timeout(Duration::from_secs(10), read_frame(&mut s, HELLO_MAX)).await {
        Ok(Ok(b)) => serde_json::from_slice::<Hello>(&b).ok(),
        _ => None,
    };
    let server_mode = shared.online.is_some();
    // 能替服务器连 SSH 主机的连接：网络上的 Agent，握手时声明了 dial（记下令牌 id，票据只认它）
    let mut dial_id: Option<String> = None;
    let session = match hello {
        Some(Hello::Token { v, token, dial }) if v == PROTO_V && token_allowed(&shared, &peer) && shared.verify_token(&token) => {
            if dial && peer.network {
                dial_id = shared.token_id(&token);
            }
            Some(Session::Agent)
        }
        // 转发连接：只在网络上、令牌有效、票据属于同一个令牌时接受
        Some(Hello::Dial { v, token, ticket, error }) if v == PROTO_V && peer.network && token_allowed(&shared, &peer) => {
            let Some(id) = shared.token_id(&token) else {
                silent_reject().await;
                return;
            };
            if !error.is_empty() {
                // 客户端没连上目标：把原因交给等待方，连接关闭
                let _ = shared.dials.deliver(&ticket, &id, Err(crate::dial::clean_reason(&error)));
                return;
            }
            // 先确认（客户端收到后才开始转发），再把这条连接交给等待中的 SSH 连接
            if shared.dials.has(&ticket, &id) && write_frame(&mut s, br#"{"ok":true}"#).await.is_ok() {
                let _ = shared.dials.deliver(&ticket, &id, Ok(Box::new(s)));
                return;
            }
            silent_reject().await;
            return;
        }
        // 网络上只接受令牌与注册；口令、首次设置、root 会话一律静默拒绝。
        Some(Hello::Password { .. } | Hello::Setup { .. } | Hello::Root { .. }) if peer.network => None,
        // 服务器模式没有口令（无口令库由 root 的 `passmanager init` 创建）。
        Some(Hello::Password { .. } | Hello::Setup { .. }) if server_mode => None,
        Some(Hello::Password { v, password }) if v == PROTO_V => shared.password_login(password).await,
        Some(Hello::Setup { v, password }) if v == PROTO_V && (shared.layout.mode == Mode::User || peer.elevated) => {
            shared.setup(password).await
        }
        // root 管理会话：只在本地 socket、对端为 root（用户模式下为同一用户，本来就没有隔离）。
        Some(Hello::Root { v }) if v == PROTO_V && server_mode && (peer.elevated || shared.layout.mode == Mode::User) => {
            Some(Session::Root)
        }
        Some(Hello::Enroll { v, code, .. }) if v == PROTO_V && peer.network => match shared.enroll(&code, peer.addr) {
            Some(token) => {
                let ack = serde_json::json!({"ok": true, "token": token.as_str()});
                let _ = write_frame(&mut s, ack.to_string().as_bytes()).await;
                return;
            }
            None => None,
        },
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
            // git 代理是流式的：这条连接交给代理处理，结束后关闭。
            Ok(Request::GitProxy { method, url, headers }) => match shared.git_prepare(&session, &method, &url).await {
                Ok((svc, u, plan)) => {
                    if write_frame(&mut s, &serde_json::to_vec(&Response::ok("continue")).unwrap_or_default()).await.is_err() {
                        return;
                    }
                    let out = crate::git::proxy(s, method, u, headers, svc, plan).await;
                    shared.git_finish(&url, out).await;
                    return;
                }
                Err(e) => Response::err(&e.code, e.message),
            },
            // 中继同样是流式的：这条连接交给中继处理，结束后关闭。
            Ok(Request::Relay { run, method, path, headers }) => match shared.relay_prepare(&session, &run, &method, &path, &headers).await
            {
                Ok(plan) => {
                    if write_frame(&mut s, &serde_json::to_vec(&Response::ok("continue")).unwrap_or_default()).await.is_err() {
                        return;
                    }
                    let out = crate::relay::serve(s, plan).await;
                    shared.relay_finish(out).await;
                    return;
                }
                Err(e) => {
                    let red = shared.agent_redactor().await;
                    Response::err(&e.code, red.redact_str(&e.message))
                }
            },
            // 上游 HTTP 不限时：等待期间同时读这条连接。Agent 断开（或按一问一答本不该来的新帧）时
            // 丢弃这个请求，上游连接随之关闭，服务器上不会留下没人等的请求。
            // 能转发的连接上的 SSH 类请求：处理期间把转发要求写回这条连接（只写不读，不打乱一问一答）
            Ok(req) if dial_id.is_some() && req.ssh_target().is_some() => {
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                let ctx = crate::dial::DialCtx { token_id: dial_id.clone().unwrap_or_default(), asks: tx };
                let work = crate::dial::DIALER.scope(ctx, shared.dispatch(&session, req));
                tokio::pin!(work);
                loop {
                    tokio::select! {
                        r = &mut work => break r,
                        Some(ask) = rx.recv() => {
                            let frame = serde_json::to_vec(&pm_proto::DialFrame { dial: ask }).unwrap_or_default();
                            if write_frame(&mut s, &frame).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            Ok(req) if req.waits_unbounded() => {
                tokio::select! {
                    r = shared.dispatch(&session, req) => r,
                    _ = read_frame(&mut s, MAX_FRAME) => {
                        log("http request cancelled: the agent disconnected");
                        return;
                    }
                }
            }
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
                let peer = Peer { elevated: uid == 0, allowed, network: false, addr: None };
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
                tokio::spawn(handle_conn(shared.clone(), connected, Peer { elevated, allowed, network: false, addr: None }));
            }
        }
    }
    shared.lock().await;
    shared.tokens.lock().unwrap().flush_if_dirty();
    Ok(())
}

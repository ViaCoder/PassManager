//! 客户端（TUI / MCP / CLI）与 PassManager 服务之间的本地协议。
//!
//! 帧格式：`u32 BE 长度 ‖ JSON`。每条连接的第一帧必须是 [`Hello`] 握手；
//! 握手失败时服务端直接断开，不返回任何错误或特征信息（防探测）。

use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use pm_platform::harden::Report;

pub const PROTO_V: u32 = 1;
pub const MAX_FRAME: usize = 96 * 1024 * 1024;
pub const ENV_TOKEN: &str = "PASSMANAGER_TOKEN";
pub const TOKEN_PREFIX: &str = "pm_";
/// 上传/下载文件的大小上限。
pub const MAX_FILE: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "auth", rename_all = "snake_case")]
pub enum Hello {
    /// Agent（MCP / CLI）：访问令牌，只能执行"使用类"操作。
    Token { v: u32, token: String },
    /// TUI：口令，可执行管理操作；库处于锁定状态时同时完成解锁。
    Password { v: u32, password: String },
    /// 首次设置口令（仅当库尚不存在时有效；系统模式下仅接受 root/管理员）。
    Setup { v: u32, password: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct EntryInput {
    /// 引用名；留空时按第一个域名自动生成（编辑时留空表示不改）。
    #[serde(default)]
    pub name: String,
    /// None 表示保留原密钥（编辑时）。
    pub secret: Option<String>,
    pub domains: Vec<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub self_signed: bool,
    #[serde(default)]
    pub auto_accept_host_key: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    // ---- 使用类（令牌即可） ----
    List,
    Http {
        method: String,
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
        #[serde(default)]
        body: Option<String>,
    },
    /// `target` 写成 `user@host[:port]`（可选前缀 `<引用名>/` 指定凭据）；命令以 `sudo ` 开头时自动提供 sudo 密码。
    Ssh {
        target: String,
        command: String,
    },
    /// 上传到 `target` 上的 `path`。
    Upload {
        target: String,
        path: String,
        data_base64: String,
    },
    /// 下载 `target` 上的 `path`（内容会脱敏）。
    Download {
        target: String,
        path: String,
    },
    Lock,
    Status,
    // ---- 管理类（口令会话） ----
    Entries,
    AddEntry {
        entry: EntryInput,
    },
    UpdateEntry {
        original: String,
        entry: EntryInput,
    },
    DeleteEntry {
        name: String,
    },
    Reveal {
        name: String,
        password: String,
    },
    Pins,
    PendingPins,
    TrustPins {
        pattern: String,
    },
    Tokens,
    CreateToken {
        label: String,
    },
    RevokeToken {
        id: String,
    },
    GetSettings,
    SetSettings {
        auto_lock_hours: u32,
    },
    ChangePassword {
        old: String,
        new: String,
    },
    Security,
}

impl Request {
    /// 是否允许令牌会话（Agent）执行。
    pub fn is_usage(&self) -> bool {
        matches!(
            self,
            Request::List
                | Request::Http { .. }
                | Request::Ssh { .. }
                | Request::Upload { .. }
                | Request::Download { .. }
                | Request::Lock
                | Request::Status
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Response {
    pub fn ok(data: impl Serialize) -> Self {
        Self { ok: true, data: Some(serde_json::to_value(data).unwrap_or(Value::Null)), code: None, message: None }
    }

    pub fn err(code: &str, message: impl Into<String>) -> Self {
        Self { ok: false, data: None, code: Some(code.into()), message: Some(message.into()) }
    }
}

// ---- 返回数据类型 ----

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialView {
    pub name: String,
    pub domains: Vec<String>,
    pub note: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntryView {
    pub name: String,
    pub domains: Vec<String>,
    pub note: String,
    pub self_signed: bool,
    pub auto_accept_host_key: bool,
    pub private_key: bool,
    pub created: u64,
    pub updated: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpResult {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    #[serde(default)]
    pub body_base64: bool,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SshResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DownloadResult {
    pub data_base64: String,
    pub size: usize,
    /// 内容中命中脱敏的次数（>0 表示文件已被改写）。
    pub redactions: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PinView {
    pub kind: String,
    pub host_port: String,
    pub algo: String,
    pub fingerprint: String,
    pub first_seen: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingPinView {
    pub kind: String,
    pub host_port: String,
    pub old_fingerprint: String,
    pub new_fingerprint: String,
    pub seen_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenView {
    pub id: String,
    pub label: String,
    pub created: u64,
    pub last_used: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewToken {
    pub id: String,
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatusView {
    pub initialized: bool,
    pub locked: bool,
    pub level: u8,
    pub mode: String,
    /// 安全检查是否全部通过。
    pub ready: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityView {
    pub level: u8,
    pub method: String,
    pub description: String,
    /// L1 时的原因说明。
    pub l1_reason: Option<String>,
    pub mode: String,
    pub report: Report,
    /// 运行时发现的问题（例如设备密钥无法解封、等级不一致）。
    pub runtime_issues: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SettingsView {
    pub auto_lock_hours: u32,
}

// ---- 帧读写 ----

pub fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    if data.len() > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"));
    }
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}

pub fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// ---- 阻塞式客户端 ----

#[derive(Debug, thiserror::Error, Clone, Serialize, Deserialize)]
#[error("{code}: {message}")]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}

trait Rw: Read + Write + Send {}
impl<T: Read + Write + Send> Rw for T {}

pub struct Client {
    stream: Box<dyn Rw>,
}

fn open_stream(path: &Path) -> std::io::Result<Box<dyn Rw>> {
    #[cfg(unix)]
    {
        Ok(Box::new(std::os::unix::net::UnixStream::connect(path)?))
    }
    #[cfg(windows)]
    {
        // 服务每接受一个连接后才创建下一个管道实例；期间打开会得到 ERROR_PIPE_BUSY(231)，稍后重试。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::fs::OpenOptions::new().read(true).write(true).open(path) {
                Ok(f) => return Ok(Box::new(f)),
                Err(e) if e.raw_os_error() == Some(231) && std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Client {
    /// 连接到当前布局的服务并完成握手。
    pub fn connect(hello: &Hello) -> Result<Self, ApiError> {
        let layout = pm_platform::Layout::detect_client();
        Self::connect_at(&layout.socket, hello)
    }

    pub fn connect_at(path: &Path, hello: &Hello) -> Result<Self, ApiError> {
        let mut stream = open_stream(path).map_err(|_| {
            ApiError::new(
                "NOT_RUNNING",
                "PassManager service is not running or not installed. Ask the user to run: sudo PassManager install",
            )
        })?;
        let hello_bytes = serde_json::to_vec(hello).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        let ack = write_frame(&mut stream, &hello_bytes).and_then(|_| read_frame(&mut stream));
        match ack {
            Ok(_) => Ok(Self { stream }),
            Err(_) => Err(match hello {
                Hello::Token { .. } => ApiError::new(
                    "AUTH_FAILED",
                    "Connection rejected: the access token is missing or invalid (or the agent runs as root/administrator). Ask the user to check PassManager → Agent 接入.",
                ),
                Hello::Password { .. } => ApiError::new(
                    "AUTH_FAILED",
                    "口令错误、尝试过于频繁，或服务未就绪（尚未初始化 / 设备密钥无法解封）。口令确认无误时请查看服务日志，或运行 sudo PassManager harden --check。",
                ),
                Hello::Setup { .. } => ApiError::new("AUTH_FAILED", "无法完成初始化（库已存在，或需要以管理员身份运行）。"),
            }),
        }
    }

    pub fn call(&mut self, req: &Request) -> Result<Value, ApiError> {
        let bytes = serde_json::to_vec(req).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        write_frame(&mut self.stream, &bytes).map_err(|e| ApiError::new("DISCONNECTED", e.to_string()))?;
        let resp = read_frame(&mut self.stream).map_err(|e| ApiError::new("DISCONNECTED", e.to_string()))?;
        let resp: Response = serde_json::from_slice(&resp).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        if resp.ok {
            Ok(resp.data.unwrap_or(Value::Null))
        } else {
            Err(ApiError::new(resp.code.as_deref().unwrap_or("ERROR"), resp.message.unwrap_or_default()))
        }
    }

    /// 调用并反序列化为具体类型。
    pub fn call_as<T: for<'de> Deserialize<'de>>(&mut self, req: &Request) -> Result<T, ApiError> {
        let v = self.call(req)?;
        serde_json::from_value(v).map_err(|e| ApiError::new("INTERNAL", e.to_string()))
    }
}

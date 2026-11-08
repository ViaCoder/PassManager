//! 客户端（TUI / MCP / CLI）与 PassManager 服务之间的本地协议。
//!
//! 帧格式：`u32 BE 长度 ‖ JSON`。每条连接的第一帧必须是 [`Hello`] 握手；
//! 握手失败时服务端直接断开，不返回任何错误或特征信息（防探测）。

pub mod agent_text;

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
    /// 服务器模式的 root 管理会话（`passmanager login|token|status|lock`）：只在本地 socket 上、
    /// 且对端 uid 为 0 时接受；经网络一律静默拒绝。
    Root { v: u32 },
    /// 服务器模式的 Agent 注册：一次性注册码换取访问令牌。只在网络通道（双层加密）上接受。
    Enroll {
        v: u32,
        code: String,
        #[serde(default)]
        host: String,
    },
}

/// 多字段条目的一个字段。`value` 为 None 或空串表示保留原值（编辑时）。
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FieldInput {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
}

pub const KIND_PASSWORD: &str = "password";
pub const KIND_SSH_KEY: &str = "ssh-key";
pub const KIND_FIELDS: &str = "fields";

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
    /// 多字段条目：按顺序给出全部字段（未列出的字段被删除）。None 表示不改变条目的字段结构。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<FieldInput>>,
    /// 声明的类型（`password` / `ssh-key`）。`ssh-key` 时服务端校验私钥能被解析（不接受加密私钥）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// SSH 私钥条目：允许 ssh-agent 桥签名的主机密钥指纹（`SHA256:…`）。None 表示不改。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_keys: Option<Vec<String>>,
    /// URL 别名：None 表示不改，空字符串表示取消，其他值表示设置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// 允许的用途（`http` / `ssh` / `git`，至少一种）。None 表示不改。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ops: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    // ---- 使用类（令牌即可） ----
    /// 已废弃：不再返回条目，只返回 `USE_LOOKUP` 错误（0.3.8 及更早的客户端仍会发送）。
    List,
    /// 按目标查询可用的凭据：只返回能用于这一个目标的条目名、字段名与现成的写法（[`LookupView`]）。
    /// `target`：URL、`[名称/]user@host[:port]`、主机名，或条目名（`{{名称}}` / `{{名称.base_url}}`）。
    /// `use_`：`http`、`ssh`、`scp`、`git`；省略时按 `target` 推断（URL → http，user@host → ssh）。
    Lookup {
        target: String,
        #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
        use_: Option<String>,
    },
    /// git-proxy 的主机发现：只返回有 `git` 用途条目绑定的域名（不含其他任何信息）。
    GitHosts,
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
    /// ssh-agent 桥：可用于签名的公钥（SSH 私钥条目）。
    AgentKeys,
    /// ssh-agent 桥：代为签名（只签与 `binding` 同一会话的 publickey 认证请求）。返回签名（base64）。
    AgentSign {
        key: String,
        data: String,
        #[serde(default)]
        flags: u32,
        #[serde(default)]
        binding: Option<AgentBinding>,
    },
    /// git 凭据注入代理（流式）：见 `Client::git_proxy`。
    GitProxy {
        method: String,
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    /// `passmanager run --http`：为这次运行打开一个中继。服务器按 `origin` 找到凭据和它的策略，返回运行编号；
    /// 三个上限只能收窄策略（0 表示沿用策略），`require` 是额外的请求体规则（`json:键=值`）。
    RelayOpen {
        origin: String,
        #[serde(default)]
        max_requests: u64,
        #[serde(default)]
        max_bytes: u64,
        #[serde(default)]
        require: Vec<String>,
    },
    /// 中继一个请求（流式，见 `Client::relay`）。`path` 是 origin 之后的路径，含查询串。
    Relay {
        run: String,
        method: String,
        path: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    /// 运行结束：作废运行编号。
    RelayClose {
        run: String,
    },
    // ---- 管理类（口令会话） ----
    Entries,
    /// 中继策略（root）。
    RelayPolicies,
    /// 新增或替换一个条目的中继策略。
    PutRelayPolicy {
        policy: RelayPolicyView,
    },
    DeleteRelayPolicy {
        entry: String,
    },
    /// URL 别名（只给管理员：Agent 看不到真实地址，也不能列出别名）。
    Aliases,
    /// 新增或替换别名。
    PutAlias {
        name: String,
        url: String,
        note: String,
    },
    DeleteAlias {
        name: String,
    },
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
    /// 网页管理的"全部显示"：返回一个条目的全部值（单值或全部字段）。只有网页会话能用，每次都记日志（只记名称）。
    ShowEntry {
        name: String,
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
    // ---- 服务器模式（局域网在线版） ----
    /// 解锁无口令库（管理会话）。
    Unlock,
    /// 新建一次性注册码（10 分钟有效、只能用一次），返回 [`EnrollView`]。
    EnrollCreate {
        label: String,
    },
    /// 新建注册码并生成给 AI Agent 的接入说明（`passmanager show --label`、网页令牌页），返回 [`AgentSetupView`]。
    AgentSetup {
        label: String,
        #[serde(default)]
        lang: String,
    },
    /// 网页的 `/a/<注册码>`：查询注册码是否有效（**不消耗**），返回 [`EnrollPeekView`]；`what` 用于审计记录。
    EnrollPeek {
        code: String,
        #[serde(default)]
        what: String,
        #[serde(default)]
        peer: String,
    },
    /// 尚未使用的注册码。
    Enrollments,
    /// 作废一个尚未使用的注册码。
    EnrollCancel {
        id: String,
    },
    /// 生成网页的一次性登录链接（只限 root 会话），返回 URL 字符串。
    LoginLink,
    /// 打开后直接进入管理界面的一次性链接（`passmanager login --auto`，只给 root）。
    AutoLoginLink,
    /// 服务器状态（封存等级、证书、监听端口、令牌数量），返回 [`ServerStatusView`]。
    ServerStatus,
}

impl Request {
    /// 是否允许令牌会话（Agent）执行。
    pub fn is_usage(&self) -> bool {
        matches!(
            self,
            Request::List
                | Request::Lookup { .. }
                | Request::GitHosts
                | Request::Http { .. }
                | Request::Ssh { .. }
                | Request::Upload { .. }
                | Request::Download { .. }
                | Request::Lock
                | Request::Status
                | Request::AgentKeys
                | Request::AgentSign { .. }
                | Request::GitProxy { .. }
                | Request::RelayOpen { .. }
                | Request::Relay { .. }
                | Request::RelayClose { .. }
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

/// `lookup` 的结果：只描述这一个目标可用的凭据——不含其他条目、该条目绑定的其他域名、备注或用途清单。
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LookupView {
    /// 规范化后的目标：`host:port`，按条目名查询时为占位符（例如 `{{ai.base_url}}`）。
    pub target: String,
    /// 用途：`http`、`ssh`、`scp` 或 `git`。
    #[serde(rename = "use")]
    pub use_: String,
    /// 会被使用的条目名（SSH 可能是私钥与口令两个）。
    pub credentials: Vec<String>,
    /// 多字段条目的字段名（只有名字）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// 现成的写法（照抄即可）。
    pub how: String,
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
    /// `password` / `ssh-key` / `fields`。
    #[serde(default)]
    pub kind: String,
    /// 多字段条目的字段名。
    #[serde(default)]
    pub fields: Vec<String>,
    /// SSH 私钥条目的公钥指纹（`算法 SHA256:…`），其他条目为 None。
    #[serde(default)]
    pub public_key: Option<String>,
    /// 允许 ssh-agent 桥签名的主机密钥指纹。
    #[serde(default)]
    pub host_keys: Vec<String>,
    /// 限定的用途。
    #[serde(default)]
    pub ops: Vec<String>,
    /// URL 别名（没有时为空）。
    #[serde(default)]
    pub alias: String,
}

/// `ShowEntry` 的结果：单值条目的值，或多字段条目的全部字段（名称，值）。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ShownEntry {
    pub secret: Option<String>,
    pub fields: Vec<(String, String)>,
}

/// git 代理的响应头（经白名单过滤）。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

/// git 代理的帧大小（请求体与响应体都按这个大小分帧）。
pub const GIT_CHUNK: usize = 64 * 1024;

/// 中继策略（root 查看与设置；`require` 每条写成 `json:键=值`）。上限为 0 表示不限。
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayPolicyView {
    pub entry: String,
    pub allow: Vec<String>,
    pub auth: String,
    #[serde(default)]
    pub require: Vec<String>,
    #[serde(default)]
    pub response_headers: Vec<String>,
    #[serde(default)]
    pub max_requests_run: u64,
    #[serde(default)]
    pub max_bytes_run: u64,
    #[serde(default)]
    pub max_requests_day: u64,
    #[serde(default)]
    pub max_bytes_day: u64,
}

/// 打开的中继：运行编号（只在这次运行有效），以及给日志用的 origin 写法（别名时是 `alias://名称`）。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RelayRunView {
    pub run: String,
    pub origin: String,
}

/// 中继响应的帧类型（每帧第一个字节）：响应头（JSON 的 `GitHead`）、数据、心跳、错误（JSON 的 `Response`）、结束。
pub const RELAY_HEAD: u8 = b'H';
pub const RELAY_DATA: u8 = b'D';
pub const RELAY_KEEPALIVE: u8 = b'K';
pub const RELAY_ERROR: u8 = b'E';
pub const RELAY_END: u8 = b'Z';

/// ssh-agent 桥：OpenSSH 的 `session-bind@openssh.com` 绑定信息（base64）。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AgentBinding {
    pub host_key: String,
    pub session_id: String,
    pub signature: String,
    pub forwarding: bool,
}

/// ssh-agent 桥列出的公钥。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentKeyView {
    /// 公钥（SSH 线上格式，base64）。
    pub blob: String,
    pub comment: String,
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
    /// 值得复查的宽绑定（只提示，不影响是否就绪；只有条目名与绑定，不含秘密）。
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// 管理员看到的别名。
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct AliasView {
    pub name: String,
    pub url: String,
    pub note: String,
}

/// 新建的注册码。`url` 只显示这一次。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnrollView {
    pub id: String,
    pub label: String,
    pub url: String,
    pub expires_in_secs: u64,
}

/// `show --label` 的结果：一段给 AI Agent 的文字（含一次性注册码）。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentSetupView {
    pub id: String,
    pub label: String,
    pub text: String,
    pub expires_in_secs: u64,
}

/// 有效注册码对应的完整 `pm-enroll://` URL。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnrollPeekView {
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingEnrollView {
    pub id: String,
    pub label: String,
    pub expires_in_secs: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ServerStatusView {
    pub domain: String,
    pub web_port: u16,
    pub agent_port: u16,
    pub lan: Vec<String>,
    /// 额外允许访问服务端口的地址或网段。
    #[serde(default)]
    pub allow: Vec<String>,
    /// 只有这些来源能打开管理界面；None 表示不额外限制。
    #[serde(default)]
    pub admin_allow: Option<Vec<String>>,
    pub locked: bool,
    pub initialized: bool,
    pub vault_mode: String,
    pub level: u8,
    pub seal_method: String,
    pub tpm_device: bool,
    pub tpm_rng: String,
    pub cert_not_after: Option<i64>,
    pub cert_error: Option<String>,
    pub tokens: usize,
    pub pending_enrollments: usize,
    pub server_key_fingerprint: String,
    pub vault_recovered_from_backup: bool,
    /// 安全检查是否全部通过（不通过时库保持锁定，Agent 得到 NOT_READY）。
    #[serde(default)]
    pub ready: bool,
    /// 未通过的检查项与运行时问题（部署时排查用）。
    #[serde(default)]
    pub issues: Vec<String>,
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

/// 注册握手的回复。
#[derive(Deserialize)]
struct EnrollAck {
    ok: bool,
    #[serde(default)]
    token: String,
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
        let stream = open_stream(path).map_err(|_| {
            ApiError::new(
                "NOT_RUNNING",
                "PassManager service is not running or not installed. Ask the user to run: sudo PassManager install",
            )
        })?;
        Self::handshake(stream, hello)
    }

    /// 在任意已建立的流上握手（远程模式：双层加密的网络流）。
    pub fn connect_stream<S: Read + Write + Send + 'static>(stream: S, hello: &Hello) -> Result<Self, ApiError> {
        Self::handshake(Box::new(stream), hello)
    }

    /// 注册：用一次性注册码换取访问令牌（只返回这一次）。
    pub fn enroll_stream<S: Read + Write + Send + 'static>(stream: S, code: &str, host: &str) -> Result<String, ApiError> {
        let mut stream: Box<dyn Rw> = Box::new(stream);
        let hello = Hello::Enroll { v: PROTO_V, code: code.into(), host: host.into() };
        let hello_bytes = serde_json::to_vec(&hello).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        let ack = write_frame(&mut stream, &hello_bytes).and_then(|_| read_frame(&mut stream));
        let fail = || {
            ApiError::new(
                "ENROLL_FAILED",
                "注册码无效、已使用或已过期（有效期 10 分钟，只能使用一次）。请在服务器上重新运行：passmanager show --label <名称>",
            )
        };
        let ack: EnrollAck = serde_json::from_slice(&ack.map_err(|_| fail())?).map_err(|_| fail())?;
        if ack.ok && ack.token.starts_with(TOKEN_PREFIX) { Ok(ack.token) } else { Err(fail()) }
    }

    fn handshake(mut stream: Box<dyn Rw>, hello: &Hello) -> Result<Self, ApiError> {
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
                Hello::Root { .. } => ApiError::new(
                    "AUTH_FAILED",
                    "服务拒绝了 root 管理会话：需要以 root 在服务器本机运行，且服务处于服务器模式（passmanager init）。",
                ),
                Hello::Enroll { .. } => ApiError::new("ENROLL_FAILED", "注册失败。"),
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

    /// git 代理（流式）：发送请求 → 等服务端确认 → 发送请求体（分帧，空帧结束）→ 收到响应头 → 把响应体写入 `out`。
    pub fn git_proxy(
        &mut self,
        req: &Request,
        body: &mut dyn Read,
        on_head: &mut dyn FnMut(&GitHead) -> std::io::Result<()>,
        out: &mut dyn Write,
    ) -> Result<(), ApiError> {
        let dis = |e: std::io::Error| ApiError::new("DISCONNECTED", e.to_string());
        let bytes = serde_json::to_vec(req).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        write_frame(&mut self.stream, &bytes).map_err(dis)?;
        let first: Response =
            serde_json::from_slice(&read_frame(&mut self.stream).map_err(dis)?).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        if !first.ok {
            return Err(ApiError::new(first.code.as_deref().unwrap_or("ERROR"), first.message.unwrap_or_default()));
        }
        let mut buf = vec![0u8; GIT_CHUNK];
        loop {
            let n = body.read(&mut buf).map_err(|e| ApiError::new("BAD_REQUEST", format!("reading request body: {e}")))?;
            if n == 0 {
                break;
            }
            write_frame(&mut self.stream, &buf[..n]).map_err(dis)?;
        }
        write_frame(&mut self.stream, &[]).map_err(dis)?;
        let head: Response =
            serde_json::from_slice(&read_frame(&mut self.stream).map_err(dis)?).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        if !head.ok {
            return Err(ApiError::new(head.code.as_deref().unwrap_or("ERROR"), head.message.unwrap_or_default()));
        }
        let head: GitHead = serde_json::from_value(head.data.unwrap_or_default()).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        on_head(&head).map_err(dis)?;
        loop {
            let f = read_frame(&mut self.stream).map_err(dis)?;
            if f.is_empty() {
                return Ok(());
            }
            out.write_all(&f).map_err(dis)?;
        }
    }

    /// 中继（流式）：发送请求 → 等服务端确认 → 发送请求体（分帧，空帧结束）→ 读带类型的帧：
    /// 响应头交给 `on_head`，数据写入 `out` 并立即 flush（SSE 事件不在这里积压），心跳时问一次 `cancelled`
    /// （本机程序已断开就返回 CANCELLED：连接随之关闭，服务器取消上游请求），错误帧与结束帧结束。
    pub fn relay(
        &mut self,
        req: &Request,
        body: &mut dyn Read,
        on_head: &mut dyn FnMut(&GitHead) -> std::io::Result<()>,
        out: &mut dyn Write,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ApiError> {
        let dis = |e: std::io::Error| ApiError::new("DISCONNECTED", e.to_string());
        let parse = |b: &[u8]| serde_json::from_slice::<Response>(b).map_err(|e| ApiError::new("INTERNAL", e.to_string()));
        let fail = |r: Response| ApiError::new(r.code.as_deref().unwrap_or("ERROR"), r.message.unwrap_or_default());
        let bytes = serde_json::to_vec(req).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
        write_frame(&mut self.stream, &bytes).map_err(dis)?;
        let first = parse(&read_frame(&mut self.stream).map_err(dis)?)?;
        if !first.ok {
            return Err(fail(first));
        }
        let mut buf = vec![0u8; GIT_CHUNK];
        loop {
            let n = body.read(&mut buf).map_err(|e| ApiError::new("BAD_REQUEST", format!("reading request body: {e}")))?;
            if n == 0 {
                break;
            }
            write_frame(&mut self.stream, &buf[..n]).map_err(dis)?;
        }
        write_frame(&mut self.stream, &[]).map_err(dis)?;
        loop {
            let f = read_frame(&mut self.stream).map_err(dis)?;
            if cancelled() {
                return Err(ApiError::new("CANCELLED", "the local program disconnected"));
            }
            let (kind, rest) = f.split_first().ok_or_else(|| ApiError::new("INTERNAL", "empty relay frame"))?;
            match *kind {
                RELAY_KEEPALIVE => {}
                RELAY_HEAD => {
                    let head: GitHead = serde_json::from_slice(rest).map_err(|e| ApiError::new("INTERNAL", e.to_string()))?;
                    on_head(&head).map_err(dis)?;
                }
                RELAY_DATA => {
                    out.write_all(rest).map_err(dis)?;
                    out.flush().map_err(dis)?;
                }
                RELAY_ERROR => return Err(fail(parse(rest)?)),
                RELAY_END => return Ok(()),
                _ => return Err(ApiError::new("INTERNAL", "unknown relay frame")),
            }
        }
    }

    /// 调用并反序列化为具体类型。
    pub fn call_as<T: for<'de> Deserialize<'de>>(&mut self, req: &Request) -> Result<T, ApiError> {
        let v = self.call(req)?;
        serde_json::from_value(v).map_err(|e| ApiError::new("INTERNAL", e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_wire_format() {
        assert_eq!(serde_json::to_string(&Hello::Root { v: 1 }).unwrap(), r#"{"auth":"root","v":1}"#);
        let e: Hello = serde_json::from_str(r#"{"auth":"enroll","v":1,"code":"abc"}"#).unwrap();
        assert!(matches!(e, Hello::Enroll { ref code, ref host, .. } if code == "abc" && host.is_empty()));
        let t: Hello = serde_json::from_str(r#"{"auth":"token","v":1,"token":"pm_x"}"#).unwrap();
        assert!(matches!(t, Hello::Token { .. }));
        assert!(serde_json::from_str::<Hello>(r#"{"auth":"admin","v":1}"#).is_err());
    }

    #[test]
    fn server_requests_are_not_usage_operations() {
        for r in [
            Request::Unlock,
            Request::EnrollCreate { label: "x".into() },
            Request::AgentSetup { label: "x".into(), lang: String::new() },
            Request::EnrollPeek { code: "x".into(), what: String::new(), peer: String::new() },
            Request::Enrollments,
            Request::EnrollCancel { id: "x".into() },
            Request::LoginLink,
            Request::ServerStatus,
        ] {
            assert!(!r.is_usage(), "{r:?}");
        }
        let r: Request = serde_json::from_str(r#"{"op":"login_link"}"#).unwrap();
        assert!(matches!(r, Request::LoginLink));
    }

    /// 内存中的双向管道，模拟服务端行为。
    struct Pipe {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Pipe {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Pipe {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn framed(json: &str) -> Vec<u8> {
        let mut v = (json.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(json.as_bytes());
        v
    }

    #[test]
    fn enroll_ack_parsing() {
        let ok = Pipe { input: std::io::Cursor::new(framed(r#"{"ok":true,"token":"pm_abc"}"#)), output: vec![] };
        assert_eq!(Client::enroll_stream(ok, "code", "pm.example.com").unwrap(), "pm_abc");
        for bad in [r#"{"ok":true}"#, r#"{"ok":true,"token":"nope"}"#, r#"{"ok":false,"token":"pm_x"}"#, "garbage"] {
            let p = Pipe { input: std::io::Cursor::new(framed(bad)), output: vec![] };
            assert_eq!(Client::enroll_stream(p, "code", "h").unwrap_err().code, "ENROLL_FAILED", "{bad}");
        }
        // 服务端静默断开（读到 EOF）。
        let p = Pipe { input: std::io::Cursor::new(vec![]), output: vec![] };
        assert!(Client::enroll_stream(p, "code", "h").is_err());
    }

    /// 一帧：类型字节 + 内容。
    fn typed(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = ((body.len() + 1) as u32).to_be_bytes().to_vec();
        v.push(kind);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn relay_frames() {
        // 服务端脚本：握手确认、继续、心跳、响应头、两块数据、结束。
        let script = |tail: Vec<u8>| {
            let mut v = framed(r#"{"ok":true}"#);
            v.extend(framed(r#"{"ok":true,"data":"continue"}"#));
            v.extend(tail);
            v
        };
        let mut tail = typed(RELAY_KEEPALIVE, b"");
        tail.extend(typed(RELAY_HEAD, br#"{"status":200,"headers":[["content-type","text/event-stream"]]}"#));
        tail.extend(typed(RELAY_DATA, b"data: 1\n\n"));
        tail.extend(typed(RELAY_DATA, b"data: 2\n\n"));
        tail.extend(typed(RELAY_END, b""));
        let pipe = Pipe { input: std::io::Cursor::new(script(tail)), output: vec![] };
        let mut c = Client::connect_stream(pipe, &Hello::Root { v: 1 }).unwrap();
        let req = Request::Relay { run: "r".into(), method: "POST".into(), path: "/v1/x".into(), headers: vec![] };
        let (mut status, mut out) = (0u16, Vec::new());
        c.relay(
            &req,
            &mut &b"{}"[..],
            &mut |h| {
                status = h.status;
                Ok(())
            },
            &mut out,
            &|| false,
        )
        .unwrap();
        assert_eq!((status, out.as_slice()), (200, &b"data: 1\n\ndata: 2\n\n"[..]));

        // 响应头之前的错误帧：返回服务器的错误码。
        let tail = typed(RELAY_ERROR, br#"{"ok":false,"code":"RATE_LIMIT","message":"max requests"}"#);
        let pipe = Pipe { input: std::io::Cursor::new(script(tail)), output: vec![] };
        let mut c = Client::connect_stream(pipe, &Hello::Root { v: 1 }).unwrap();
        let e = c.relay(&req, &mut &b""[..], &mut |_| Ok(()), &mut Vec::new(), &|| false).unwrap_err();
        assert_eq!(e.code, "RATE_LIMIT");

        // 本机程序已断开：下一帧（心跳）时返回 CANCELLED。
        let mut tail = typed(RELAY_KEEPALIVE, b"");
        tail.extend(typed(RELAY_END, b""));
        let pipe = Pipe { input: std::io::Cursor::new(script(tail)), output: vec![] };
        let mut c = Client::connect_stream(pipe, &Hello::Root { v: 1 }).unwrap();
        assert_eq!(c.relay(&req, &mut &b""[..], &mut |_| Ok(()), &mut Vec::new(), &|| true).unwrap_err().code, "CANCELLED");

        // 服务端拒绝请求本身（第一帧就是错误）。
        let mut v = framed(r#"{"ok":true}"#);
        v.extend(framed(r#"{"ok":false,"code":"FORBIDDEN","message":"no"}"#));
        let mut c = Client::connect_stream(Pipe { input: std::io::Cursor::new(v), output: vec![] }, &Hello::Root { v: 1 }).unwrap();
        assert_eq!(c.relay(&req, &mut &b""[..], &mut |_| Ok(()), &mut Vec::new(), &|| false).unwrap_err().code, "FORBIDDEN");
        assert!(req.is_usage() && Request::RelayClose { run: "r".into() }.is_usage() && !Request::RelayPolicies.is_usage());
    }
}

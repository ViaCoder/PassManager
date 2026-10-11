//! PassManager 服务：持有已解锁的库，代 Agent 使用凭据，返回脱敏结果。

pub mod agent;
pub mod git;
pub mod http;
pub mod online;
pub mod redact;
mod server;
pub mod server_files;
pub mod ssh;
pub mod template;
mod tokens;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pm_platform::harden::{self, Report};
use pm_platform::seal::{self, Sealer};
use pm_platform::{InstallInfo, Layout, Mode};
use pm_proto::*;
use pm_vault::{Entry, Pin, PinKind, Vault, VaultError, domain, validate_entry};
use serde_json::Value;
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

use crate::redact::Redactor;
use crate::tokens::TokenStore;

#[derive(Debug, Clone)]
pub struct ApiErr {
    pub code: String,
    pub message: String,
}

pub fn err(code: &str, message: impl Into<String>) -> ApiErr {
    ApiErr { code: code.into(), message: message.into() }
}

type R = Result<Value, ApiErr>;

fn ok(v: impl serde::Serialize) -> R {
    Ok(serde_json::to_value(v).unwrap_or(Value::Null))
}

/// 本服务的构建信息（见 build.rs）：只有从发布标签构建时才有标签与提交。
pub fn build_info() -> pm_proto::agent_text::BuildInfo {
    let s = |v: &str| (!v.is_empty()).then(|| v.to_string());
    pm_proto::agent_text::BuildInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        tag: s(env!("PM_BUILD_TAG")),
        commit: s(env!("PM_BUILD_COMMIT")),
    }
}

pub(crate) fn log(msg: &str) {
    eprintln!("[PassManager] {msg}");
}

struct Inner {
    vault: Option<Vault>,
    redactor: Arc<Redactor>,
    last_activity: Instant,
    pending: Vec<PendingPinView>,
    failures: u32,
    blocked_until: Option<Instant>,
}

pub struct Shared {
    pub layout: Layout,
    pub info: InstallInfo,
    sealer: Box<dyn Sealer>,
    l1_reason: Option<String>,
    device: Result<Zeroizing<[u8; 32]>, String>,
    inner: Mutex<Inner>,
    argon: Semaphore,
    tokens: std::sync::Mutex<TokenStore>,
    /// 就绪状态缓存（时间, 是否就绪），避免每个请求都读取报告与库文件头。
    ready_cache: std::sync::Mutex<Option<(Instant, bool)>>,
    /// 服务器模式（局域网在线版）的运行时状态。
    pub(crate) online: Option<online::Online>,
    /// 无口令库是否是从 .bak 恢复的（安全状态页显示）。
    recovered: std::sync::atomic::AtomicBool,
    /// ssh-agent 桥的签名速率限制（全局：每分钟 30 次）。
    sign_limiter: std::sync::Mutex<agent::SignLimiter>,
}

/// 会话类型。
pub(crate) enum Session {
    Agent,
    Admin {
        ready: bool,
    },
    /// 服务器模式：本机 root（`passmanager login|token|status|lock`）。
    Root,
    /// 服务器模式：网页管理（一次性链接登录）。
    Web,
}

/// 服务启动失败。`config` 为真表示配置错误（服务器模式以退出码 78 退出，systemd 不再重启）；
/// 否则是暂时性故障（退出码 75，有限次重试）。
#[derive(Debug)]
pub struct RunError {
    pub config: bool,
    pub message: String,
}

impl RunError {
    fn config(m: impl Into<String>) -> Self {
        Self { config: true, message: m.into() }
    }
    fn transient(m: impl Into<String>) -> Self {
        Self { config: false, message: m.into() }
    }
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Shared {
    /// 构造服务状态：自检、加载安装信息、解封设备密钥。
    pub fn init(layout: Layout) -> Result<Self, String> {
        pm_crypto::selftest::run_all().map_err(|e| format!("启动自检失败：{e}"))?;
        let info = match InstallInfo::load(&layout) {
            Ok(i) => i,
            Err(_) if layout.mode == Mode::User => {
                let i = default_user_info();
                std::fs::create_dir_all(&layout.data_dir).map_err(|e| e.to_string())?;
                set_private_dir(&layout.data_dir);
                i.store(&layout).map_err(|e| e.to_string())?;
                i
            }
            Err(e) => return Err(format!("读取安装信息失败（请运行 sudo PassManager install）：{e}")),
        };
        let sealer = seal::by_method(&info.seal_method, &layout).ok_or_else(|| format!("未知的封存方式 {}", info.seal_method))?;
        let l1_reason = if sealer.level() == 1 {
            Some(match layout.mode {
                Mode::User => "用户模式：服务与 Agent 运行在同一个系统用户下，设备密钥只能以文件形式保存。".to_string(),
                Mode::System => "当前环境没有可用的系统级封存方式（例如容器或非 systemd 的 Linux）。".to_string(),
            })
        } else {
            None
        };
        // 设备密钥：已封存则解封；用户模式 / Windows / 文件方式在首次启动时生成并封存。
        #[cfg(target_os = "macos")]
        let root_key = ROOT_PHASE_KEY.lock().unwrap().take();
        #[cfg(not(target_os = "macos"))]
        let root_key: Option<Zeroizing<[u8; 32]>> = None;
        let device = if let Some(k) = root_key {
            Ok(k)
        } else if sealer.is_provisioned() {
            sealer.unseal().map_err(|e| format!("无法解封设备密钥：{e}"))
        } else if layout.mode == Mode::User || cfg!(windows) || info.seal_method == seal::file::METHOD {
            let mut rand = |b: &mut [u8]| pm_crypto::rng::fill(b).map_err(std::io::Error::other);
            let key: Zeroizing<[u8; 32]> = Zeroizing::new(pm_crypto::rng::random_array().map_err(|e| e.to_string())?);
            sealer.seal(&key, &mut rand).map_err(|e| format!("封存设备密钥失败：{e}"))?;
            sealer.unseal().map_err(|e| format!("无法解封设备密钥：{e}"))
        } else {
            Err("设备密钥不存在。如果系统重装或硬件发生变化，库已无法恢复；请重新运行 sudo PassManager install。".into())
        };
        let tokens = TokenStore::load(layout.data_dir.join("tokens.json"));
        Ok(Self {
            layout,
            info,
            sealer,
            l1_reason,
            device,
            inner: Mutex::new(Inner {
                vault: None,
                redactor: Arc::new(Redactor::empty()),
                last_activity: Instant::now(),
                pending: vec![],
                failures: 0,
                blocked_until: None,
            }),
            argon: Semaphore::new(1),
            tokens: std::sync::Mutex::new(tokens),
            ready_cache: std::sync::Mutex::new(None),
            online: None,
            recovered: std::sync::atomic::AtomicBool::new(false),
            sign_limiter: std::sync::Mutex::new(agent::SignLimiter::new(30, Duration::from_secs(60))),
        })
    }

    /// 服务器模式：在 `init` 的基础上加载内层通道密钥与证书，并自动解锁无口令库。
    /// 返回的错误都是配置错误（设备密钥解不开、密钥文件缺失、库被降级等），重启也不会好。
    pub fn init_server(layout: Layout) -> Result<Self, RunError> {
        #[cfg(target_os = "linux")]
        if let Ok(i) = InstallInfo::load(&layout)
            && let Some(s) = &i.server
        {
            pm_platform::seal::linux::set_tpm_socket(s.tpm_socket.clone().map(Into::into));
        }
        let mut me = Self::init(layout).map_err(RunError::config)?;
        let Some(cfg) = me.info.server.clone() else { return Err(RunError::config("install.json 没有 server 配置")) };
        cfg.validate().map_err(RunError::config)?;
        let dk = *me.device_key().map_err(|e| RunError::config(e.message))?;
        let dk = Zeroizing::new(dk);
        let keys = server_files::load_server_keys(&me.layout, &dk)
            .map_err(RunError::config)?
            .ok_or_else(|| RunError::config("内层通道密钥不存在：请以 root 运行 passmanager init"))?;
        me.online = Some(online::Online::new(cfg, keys));
        online::load_stored_cert(&me, me.online.as_ref().unwrap());
        if me.vault_exists() {
            let mut v = Vault::open_device_only(&me.layout.vault_path(), &dk, me.sealer.level())
                .map_err(|e| RunError::config(format!("无法打开密码库：{e}")))?;
            if v.recovered_from_backup() {
                log("WARNING: vault.pmv was missing or damaged; opened vault.pmv.bak");
                me.recovered.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // reseal 把 L2 升级为 L3 后：文件头记录的等级随之升级（只允许升级）。
            if v.header().seal_level < me.sealer.level() {
                v.upgrade_seal_level(me.sealer.level()).map_err(|e| RunError::config(format!("更新封存等级失败：{e}")))?;
                log("vault seal level upgraded");
            }
            if me.ready() {
                let inner = me.inner.get_mut();
                inner.vault = Some(v);
                inner.last_activity = Instant::now();
                Self::rebuild_redactor(inner);
                log("vault unlocked (device-only mode)");
            } else {
                log("security check failed; vault stays locked");
            }
        }
        Ok(me)
    }

    /// 无口令库：用设备密钥解锁（网页"解锁"、root 命令）。
    async fn unlock_device_only(&self) -> Result<(), ApiErr> {
        if self.online.is_none() {
            return Err(err("BAD_REQUEST", "只有服务器模式（无口令库）可以这样解锁"));
        }
        if self.inner.lock().await.vault.is_some() {
            return Ok(());
        }
        if !self.vault_exists() {
            return Err(self.locked_err());
        }
        if !self.ready() {
            return Err(err("NOT_READY", "安全检查未通过，库保持锁定。"));
        }
        let dk = Zeroizing::new(*self.device_key()?);
        let path = self.layout.vault_path();
        let level = self.sealer.level();
        let v = tokio::task::spawn_blocking(move || Vault::open_device_only(&path, &dk, level))
            .await
            .map_err(|e| err("INTERNAL", e.to_string()))?
            .map_err(|e| err("INTERNAL", format!("无法打开密码库：{e}")))?;
        let mut inner = self.inner.lock().await;
        inner.vault = Some(v);
        inner.last_activity = Instant::now();
        Self::rebuild_redactor(&mut inner);
        log("vault unlocked");
        Ok(())
    }

    /// 消耗注册码并为该 Agent 生成访问令牌（只经双层加密通道返回这一次）。
    pub(crate) fn enroll(&self, code: &str) -> Option<Zeroizing<String>> {
        let on = self.online.as_ref()?;
        let label = on.enroll_consume(code)?;
        let (id, token) = self.tokens.lock().unwrap().create(&label).ok()?;
        log(&format!("agent enrolled: token {id} ({label})"));
        Some(Zeroizing::new(token))
    }

    fn server_status(&self, locked: bool) -> ServerStatusView {
        let (report, runtime) = self.security_state();
        let ready = report.passed() && runtime.is_empty();
        let mut issues: Vec<String> = report.failing().map(|f| format!("{}：{}", f.title, f.detail.lines().next().unwrap_or(""))).collect();
        issues.extend(runtime);
        let on = self.online.as_ref();
        let cs = on.map(|o| o.cert_state.lock().unwrap());
        ServerStatusView {
            domain: on.map(|o| o.cfg.domain.clone()).unwrap_or_default(),
            web_port: on.map(|o| o.cfg.web_port).unwrap_or(0),
            agent_port: on.map(|o| o.cfg.agent_port).unwrap_or(0),
            lan: on.map(|o| o.cfg.lan.clone()).unwrap_or_default(),
            allow: on.map(|o| o.cfg.allow.clone()).unwrap_or_default(),
            locked,
            initialized: self.vault_exists(),
            vault_mode: if on.is_some() { "无口令（设备密钥）".into() } else { "口令".into() },
            level: self.sealer.level(),
            seal_method: self.sealer.method().into(),
            tpm_device: tpm_present(),
            tpm_rng: match pm_crypto::rng::tpm_status() {
                pm_crypto::rng::TpmStatus::Active => "已启用（第三个熵源）".into(),
                pm_crypto::rng::TpmStatus::Absent | pm_crypto::rng::TpmStatus::NotProbed => "没有 TPM 设备".into(),
                pm_crypto::rng::TpmStatus::Disabled(w) => format!("已停用：{w}"),
            },
            cert_not_after: cs.as_ref().and_then(|c| c.not_after),
            cert_error: cs.as_ref().and_then(|c| c.error.clone()),
            tokens: self.tokens.lock().unwrap().list().len(),
            pending_enrollments: on.map(|o| o.pending_count()).unwrap_or(0),
            server_key_fingerprint: on.map(|o| pm_net::enroll::fpr_text(&o.keys.fingerprint())).unwrap_or_default(),
            vault_recovered_from_backup: self.recovered.load(std::sync::atomic::Ordering::SeqCst),
            ready,
            issues,
        }
    }

    fn device_key(&self) -> Result<&[u8; 32], ApiErr> {
        self.device.as_ref().map(|k| &**k).map_err(|e| err("NOT_READY", e.clone()))
    }

    fn vault_exists(&self) -> bool {
        self.layout.vault_path().exists() || pm_vault::store::backup_path(&self.layout.vault_path()).exists()
    }

    /// 安全检查报告 + 运行时问题。
    pub fn security_state(&self) -> (Report, Vec<String>) {
        let report = match self.layout.mode {
            Mode::User => harden::check(&harden::Ctx { layout: &self.layout, info: &self.info }),
            Mode::System => match Report::load(&self.layout) {
                Ok(r) => r,
                Err(e) => Report {
                    findings: vec![harden::Finding::manual(
                        "report",
                        "安全检查报告",
                        format!("无法读取安全检查报告：{e}"),
                        "重启服务（服务启动时会以管理员权限自动生成报告），或运行 sudo PassManager harden。",
                    )],
                    ..Default::default()
                },
            },
        };
        let mut issues = Vec::new();
        match &self.device {
            Err(e) => issues.push(e.clone()),
            Ok(dk) => {
                if self.vault_exists() {
                    match Vault::read_header(&self.layout.vault_path()) {
                        Ok(h) => {
                            if let Err(e) = Vault::check_device(&h, dk, self.sealer.level()) {
                                issues.push(e.to_string());
                            }
                        }
                        Err(e) => issues.push(format!("无法读取库文件：{e}")),
                    }
                }
            }
        }
        (report, issues)
    }

    pub fn ready(&self) -> bool {
        let (r, issues) = self.security_state();
        let ok = r.passed() && issues.is_empty();
        *self.ready_cache.lock().unwrap() = Some((Instant::now(), ok));
        ok
    }

    /// 带 10 秒缓存的就绪状态（用于 Agent 的每个请求）。
    fn ready_cached(&self) -> bool {
        if let Some((t, ok)) = *self.ready_cache.lock().unwrap()
            && t.elapsed() < Duration::from_secs(10)
        {
            return ok;
        }
        self.ready()
    }

    async fn touch(&self) {
        self.inner.lock().await.last_activity = Instant::now();
    }

    fn rebuild_redactor(inner: &mut Inner) {
        inner.redactor = Arc::new(match &inner.vault {
            Some(v) => {
                let values: Vec<(String, &str)> = v.payload.entries.iter().flat_map(|e| e.secret_values()).collect();
                Redactor::build(values.iter().map(|(l, s)| (l.as_str(), *s)))
            }
            None => Redactor::empty(),
        });
    }

    /// 锁定：丢弃内存中的全部密钥。
    pub async fn lock(&self) {
        let mut inner = self.inner.lock().await;
        if inner.vault.take().is_some() {
            log("vault locked");
        }
        Self::rebuild_redactor(&mut inner);
    }

    // ---- 握手 ----

    async fn backoff_ok(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.blocked_until.is_none_or(|t| Instant::now() >= t)
    }

    async fn record_failure(&self) {
        let mut inner = self.inner.lock().await;
        inner.failures += 1;
        if inner.failures >= 3 {
            let secs = 2u64.saturating_pow(inner.failures - 3).min(3600);
            inner.blocked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    async fn record_success(&self) {
        let mut inner = self.inner.lock().await;
        inner.failures = 0;
        inner.blocked_until = None;
    }

    pub(crate) fn verify_token(&self, token: &str) -> bool {
        self.tokens.lock().unwrap().verify(token).is_some()
    }

    /// 口令握手：校验口令；库锁定且安全检查通过时同时解锁。
    pub(crate) async fn password_login(self: &Arc<Self>, password: String) -> Option<Session> {
        let password = Zeroizing::new(password);
        if !self.backoff_ok().await || !self.vault_exists() {
            return None;
        }
        let dk = *self.device_key().ok()?;
        let dk = Zeroizing::new(dk);
        let ready = self.ready();
        let _permit = self.argon.acquire().await.ok()?;
        let header = self.inner.lock().await.vault.as_ref().map(|v| v.header().clone());
        let me = self.clone();
        let pw = password.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<Option<Vault>, VaultError> {
            if let Some(h) = header {
                if Vault::check_password(&h, &pw, &dk) { Ok(None) } else { Err(VaultError::WrongPassword) }
            } else {
                Vault::open(&me.layout.vault_path(), &pw, &dk, me.sealer.level()).map(Some)
            }
        })
        .await
        .ok()?;
        match result {
            Ok(v) => {
                self.record_success().await;
                if let Some(v) = v
                    && ready
                {
                    let mut inner = self.inner.lock().await;
                    inner.vault = Some(v);
                    inner.last_activity = Instant::now();
                    Self::rebuild_redactor(&mut inner);
                    log("vault unlocked");
                }
                Some(Session::Admin { ready })
            }
            Err(VaultError::WrongPassword) => {
                self.record_failure().await;
                None
            }
            Err(e) => {
                log(&format!("unlock failed: {e}"));
                self.record_failure().await;
                None
            }
        }
    }

    /// 首次设置口令并创建库。
    pub(crate) async fn setup(self: &Arc<Self>, password: String) -> Option<Session> {
        let password = Zeroizing::new(password);
        if self.vault_exists() || password.chars().count() < 8 {
            return None;
        }
        let dk = Zeroizing::new(*self.device_key().ok()?);
        let _permit = self.argon.acquire().await.ok()?;
        let me = self.clone();
        let level = self.sealer.level();
        let v = tokio::task::spawn_blocking(move || -> Result<Vault, String> {
            let (params, _) = pm_crypto::kdf::calibrate().map_err(|e| e.to_string())?;
            Vault::create(&me.layout.vault_path(), &password, &dk, level, params).map_err(|e| e.to_string())
        })
        .await
        .ok()?;
        match v {
            Ok(v) => {
                log("vault created");
                let ready = self.ready();
                if ready {
                    let mut inner = self.inner.lock().await;
                    inner.vault = Some(v);
                    inner.last_activity = Instant::now();
                    Self::rebuild_redactor(&mut inner);
                }
                Some(Session::Admin { ready })
            }
            Err(e) => {
                log(&format!("setup failed: {e}"));
                None
            }
        }
    }

    // ---- 请求分发 ----

    pub(crate) async fn dispatch(self: &Arc<Self>, session: &Session, req: Request) -> Response {
        // 解锁后如果安全检查变为不通过（例如有人重新开启了免口令提权），立即锁定并拒绝使用。
        if matches!(session, Session::Agent) && !matches!(req, Request::Status | Request::Lock) && !self.ready_cached() {
            if self.inner.lock().await.vault.is_some() {
                log("security check no longer passes; locking vault");
                self.lock().await;
            }
            return Response::err(
                "NOT_READY",
                "PassManager security check failed, the vault stays locked. Ask the user to run: PassManager",
            );
        }
        let server = self.online.is_some();
        let r = match session {
            Session::Agent if !req.is_usage() => Err(err("FORBIDDEN", "this operation is only available in the PassManager TUI")),
            Session::Admin { ready: false } if !matches!(req, Request::Status | Request::Security | Request::Lock) => {
                Err(err("NOT_READY", "安全检查未通过，库保持锁定。请在\"诊断\"页处理问题后重新打开 PassManager。"))
            }
            // 一次性登录链接只能由服务器上的 root 生成。
            Session::Admin { .. } | Session::Web | Session::Agent if matches!(req, Request::LoginLink) => {
                Err(err("FORBIDDEN", "login links can only be created by root on the server"))
            }
            // 服务器模式：密钥只写不读；没有口令；令牌只能通过注册码经双层加密通道发放。
            _ if server && matches!(req, Request::Reveal { .. }) => Err(err("FORBIDDEN", "secrets are write-only in server mode")),
            _ if server && matches!(req, Request::ChangePassword { .. }) => Err(err("BAD_REQUEST", "server mode has no password")),
            _ if server && matches!(req, Request::CreateToken { .. }) => {
                Err(err("FORBIDDEN", "use an enrollment code (passmanager token add <label>) to create tokens in server mode"))
            }
            _ if !server
                && matches!(
                    req,
                    Request::EnrollCreate { .. }
                        | Request::AgentSetup { .. }
                        | Request::EnrollPeek { .. }
                        | Request::Enrollments
                        | Request::EnrollCancel { .. }
                        | Request::LoginLink
                        | Request::Unlock
                ) =>
            {
                Err(err("BAD_REQUEST", "only available in server mode"))
            }
            Session::Root | Session::Web
                if !matches!(
                    req,
                    Request::Status
                        | Request::Security
                        | Request::ServerStatus
                        | Request::Lock
                        | Request::LoginLink
                        | Request::Tokens
                        | Request::RevokeToken { .. }
                        | Request::Enrollments
                        | Request::EnrollCancel { .. }
                ) && !self.ready_cached() =>
            {
                Err(err("NOT_READY", "安全检查未通过，库保持锁定。请查看\"安全状态\"（passmanager status）。"))
            }
            _ => self.handle(req).await,
        };
        match r {
            Ok(v) => Response { ok: true, data: Some(v), code: None, message: None },
            Err(e) => Response::err(&e.code, e.message),
        }
    }

    fn locked_err(&self) -> ApiErr {
        let server = self.online.is_some();
        if !self.vault_exists() {
            if server {
                err(
                    "NOT_INITIALIZED",
                    "PassManager server is not initialized. Ask the administrator to run on the server: passmanager init",
                )
            } else {
                err("NOT_INITIALIZED", "PassManager has not been set up yet. Ask the user to run: sudo PassManager install")
            }
        } else if !self.ready() {
            if server {
                err(
                    "NOT_READY",
                    "PassManager security check failed on the server, the vault stays locked. Ask the administrator to run on the server: passmanager status",
                )
            } else {
                err("NOT_READY", "PassManager security check failed, the vault stays locked. Ask the user to run: PassManager")
            }
        } else if server {
            err(
                "LOCKED",
                "The vault is locked. Ask the administrator to unlock it in the PassManager web UI or run on the server: passmanager unlock",
            )
        } else {
            err("LOCKED", "The vault is locked. Ask the user to run: PassManager unlock")
        }
    }

    async fn handle(self: &Arc<Self>, req: Request) -> R {
        self.touch().await;
        match req {
            Request::Status => {
                let locked = self.inner.lock().await.vault.is_none();
                ok(StatusView {
                    initialized: self.vault_exists(),
                    locked,
                    level: self.sealer.level(),
                    mode: format!("{:?}", self.layout.mode).to_lowercase(),
                    ready: self.ready(),
                })
            }
            Request::Lock => {
                self.lock().await;
                ok("locked")
            }
            Request::Security => {
                let (report, runtime_issues) = self.security_state();
                ok(SecurityView {
                    level: self.sealer.level(),
                    method: self.sealer.method().into(),
                    description: self.sealer.describe(),
                    l1_reason: self.l1_reason.clone(),
                    mode: format!("{:?}", self.layout.mode).to_lowercase(),
                    report,
                    runtime_issues,
                })
            }
            Request::List => {
                let inner = self.inner.lock().await;
                let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
                ok(v.payload
                    .entries
                    .iter()
                    .map(|e| CredentialView {
                        name: e.name.clone(),
                        domains: e.domains.clone(),
                        note: e.note.clone(),
                        fields: e.fields.iter().map(|f| f.name.clone()).collect(),
                        status: e.domains.is_empty().then(|| format!("{UNBOUND} (unbound: add domains in the web UI before use)")),
                        ops: e.ops.clone(),
                    })
                    .collect::<Vec<_>>())
            }
            Request::Http { method, url, headers, body } => self.do_http(&method, &url, &headers, body.as_deref()).await,
            Request::AgentKeys => {
                let inner = self.inner.lock().await;
                let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
                ok(v.payload
                    .entries
                    .iter()
                    .filter(|e| e.is_private_key() && e.allows(pm_vault::OP_SSH))
                    .filter_map(|e| {
                        agent::public_blob(&e.secret).ok().map(|b| AgentKeyView { blob: STANDARD.encode(b), comment: e.name.clone() })
                    })
                    .collect::<Vec<_>>())
            }
            Request::AgentSign { key, data, flags, binding } => self.agent_sign(&key, &data, flags, binding).await,
            Request::GitProxy { .. } => Err(err("BAD_REQUEST", "git proxy requests must be the streaming form")),
            Request::Ssh { target, command } => {
                let dest = ssh::parse_target(&target)?;
                // 命令中的占位符（{{name.field}} 等）按目标主机代入，例如把口令经管道交给远端程序。
                let command = {
                    let inner = self.inner.lock().await;
                    let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
                    http::substitute_all(&v.payload, &command, &dest.host, dest.port, pm_vault::OP_SSH)?.0
                };
                let (handle, t, redactor) = self.ssh_session(&target).await?;
                // 命令以 `sudo ` 开头且有口令条目时，由服务通过 stdin 提供 sudo 密码；只有私钥时原样执行。
                let (cmd, sudo) = match command.trim_start().strip_prefix("sudo ") {
                    Some(rest) if !t.secret.is_empty() => (Zeroizing::new(rest.trim_start().to_string()), true),
                    _ => (command.clone(), false),
                };
                let r = ssh::exec(&handle, &t, &cmd, sudo, &redactor).await;
                ssh::close(handle).await;
                ok(r?)
            }
            Request::Upload { target, path, data_base64 } => {
                let data = STANDARD.decode(data_base64.as_bytes()).map_err(|_| err("BAD_REQUEST", "data_base64 is not valid base64"))?;
                if data.len() > MAX_FILE {
                    return Err(err("TOO_LARGE", "file exceeds 64 MiB"));
                }
                let (handle, _t, _) = self.ssh_session(&target).await?;
                let r = ssh::upload(&handle, &path, &data).await;
                ssh::close(handle).await;
                r?;
                ok(serde_json::json!({ "uploaded": path, "size": data.len() }))
            }
            Request::Download { target, path } => {
                let (handle, _t, redactor) = self.ssh_session(&target).await?;
                let r = ssh::download(&handle, &path).await;
                ssh::close(handle).await;
                let data = r?;
                let (red, n) = redactor.redact(&data);
                ok(DownloadResult { size: red.len(), data_base64: STANDARD.encode(&red), redactions: n })
            }
            Request::Entries => {
                let inner = self.inner.lock().await;
                let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
                let mut list: Vec<EntryView> = v.payload.entries.iter().map(entry_view).collect();
                list.sort_by(|a, b| a.name.cmp(&b.name));
                ok(list)
            }
            Request::AddEntry { entry } => {
                let mut e = Entry {
                    name: entry.name.trim().to_string(),
                    secret: Zeroizing::new(String::new()),
                    domains: entry.domains.clone(),
                    note: entry.note.clone(),
                    self_signed: entry.self_signed,
                    auto_accept_host_key: entry.auto_accept_host_key,
                    created: pm_vault::now(),
                    updated: pm_vault::now(),
                    fields: vec![],
                    host_keys: entry.host_keys.clone().unwrap_or_default(),
                    ops: entry.ops.clone().unwrap_or_default(),
                };
                apply_secret(&mut e, None, &entry)?;
                // 名称可以留空：按第一个域名自动生成引用名。
                let auto = e.name.is_empty();
                if auto {
                    e.name = "pending".into();
                }
                validate_entry(&mut e).map_err(|m| err("BAD_REQUEST", m))?;
                let fp = check_kind(&e, entry.kind.as_deref())?;
                let mut name = String::new();
                self.mutate(|v| {
                    if auto {
                        let taken: Vec<&str> = v.payload.entries.iter().map(|x| x.name.as_str()).collect();
                        e.name = pm_vault::auto_name(&e.domains, &taken);
                    }
                    if v.payload.entry(&e.name).is_some() {
                        return Err(err("BAD_REQUEST", format!("名称 {} 已存在", e.name)));
                    }
                    name = e.name.clone();
                    v.payload.entries.push(e);
                    Ok(())
                })
                .await?;
                ok(serde_json::json!({"name": name, "public_key": fp}))
            }
            Request::UpdateEntry { original, entry } => {
                let mut fp = None;
                self.mutate(|v| {
                    let idx =
                        v.payload.entries.iter().position(|x| x.name == original).ok_or_else(|| err("UNKNOWN_CREDENTIAL", "条目不存在"))?;
                    let old = v.payload.entries[idx].clone();
                    let name = entry.name.trim();
                    let mut e = Entry {
                        // 编辑时名称留空表示不改。
                        name: if name.is_empty() { old.name.clone() } else { name.to_string() },
                        secret: Zeroizing::new(String::new()),
                        domains: entry.domains.clone(),
                        note: entry.note.clone(),
                        self_signed: entry.self_signed,
                        auto_accept_host_key: entry.auto_accept_host_key,
                        created: old.created,
                        updated: pm_vault::now(),
                        fields: vec![],
                        host_keys: entry.host_keys.clone().unwrap_or_else(|| old.host_keys.clone()),
                        ops: entry.ops.clone().unwrap_or_else(|| old.ops.clone()),
                    };
                    apply_secret(&mut e, Some(&old), &entry)?;
                    validate_entry(&mut e).map_err(|m| err("BAD_REQUEST", m))?;
                    fp = check_kind(&e, entry.kind.as_deref())?;
                    if e.name != original && v.payload.entry(&e.name).is_some() {
                        return Err(err("BAD_REQUEST", format!("名称 {} 已存在", e.name)));
                    }
                    v.payload.entries[idx] = e;
                    Ok(())
                })
                .await?;
                ok(serde_json::json!({"name": entry.name.trim(), "public_key": fp}))
            }
            Request::DeleteEntry { name } => {
                self.mutate(|v| {
                    let before = v.payload.entries.len();
                    v.payload.entries.retain(|e| e.name != name);
                    if v.payload.entries.len() == before {
                        return Err(err("UNKNOWN_CREDENTIAL", "条目不存在"));
                    }
                    Ok(())
                })
                .await?;
                ok("deleted")
            }
            Request::Reveal { name, password } => {
                self.verify_password(password).await?;
                let inner = self.inner.lock().await;
                let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
                let e = v.payload.entry(&name).ok_or_else(|| err("UNKNOWN_CREDENTIAL", "条目不存在"))?;
                if e.fields.is_empty() {
                    ok(e.secret.as_str())
                } else {
                    ok(e.fields.iter().map(|f| format!("{}: {}", f.name, f.value.as_str())).collect::<Vec<_>>().join("\n"))
                }
            }
            Request::Pins => {
                let inner = self.inner.lock().await;
                let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
                ok(v.payload.pins.iter().map(pin_view).collect::<Vec<_>>())
            }
            Request::PendingPins => ok(self.inner.lock().await.pending.clone()),
            Request::TrustPins { pattern } => {
                let pat = pattern.trim().to_ascii_lowercase();
                let mut removed = Vec::new();
                self.mutate(|v| {
                    v.payload.pins.retain(|p| {
                        let m = pin_matches(&pat, &p.host_port);
                        if m {
                            removed.push(pin_view(p));
                        }
                        !m
                    });
                    Ok(())
                })
                .await?;
                self.inner.lock().await.pending.retain(|p| !pin_matches(&pat, &p.host_port));
                ok(removed)
            }
            Request::Tokens => {
                let t = self.tokens.lock().unwrap();
                ok(t.list()
                    .iter()
                    .map(|t| TokenView { id: t.id.clone(), label: t.label.clone(), created: t.created, last_used: t.last_used })
                    .collect::<Vec<_>>())
            }
            Request::CreateToken { label } => {
                let (id, token) = self.tokens.lock().unwrap().create(&label).map_err(|e| err("INTERNAL", e.to_string()))?;
                ok(NewToken { id, token })
            }
            Request::RevokeToken { id } => {
                if self.tokens.lock().unwrap().revoke(&id) {
                    ok("revoked")
                } else {
                    Err(err("BAD_REQUEST", "令牌不存在"))
                }
            }
            Request::GetSettings => {
                let inner = self.inner.lock().await;
                let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
                ok(SettingsView { auto_lock_hours: v.payload.settings.auto_lock_hours })
            }
            Request::SetSettings { auto_lock_hours } => {
                self.mutate(|v| {
                    v.payload.settings.auto_lock_hours = auto_lock_hours.min(24 * 30);
                    Ok(())
                })
                .await?;
                ok("saved")
            }
            Request::Unlock => {
                self.unlock_device_only().await?;
                ok("unlocked")
            }
            Request::EnrollCreate { label } => {
                let on = self.online.as_ref().ok_or_else(|| err("BAD_REQUEST", "only available in server mode"))?;
                ok(on.enroll_create(&label).map_err(|m| err("BAD_REQUEST", m))?)
            }
            Request::AgentSetup { label, lang } => {
                let on = self.online.as_ref().ok_or_else(|| err("BAD_REQUEST", "only available in server mode"))?;
                let lang = pm_proto::agent_text::Lang::parse(&lang).map_err(|m| err("BAD_REQUEST", m))?;
                let label = if label.trim().is_empty() { "agent".to_string() } else { label };
                let v = on.enroll_create(&label).map_err(|m| err("BAD_REQUEST", m))?;
                let code = pm_net::enroll::EnrollUrl::parse(&v.url).map_err(|m| err("INTERNAL", m))?.code;
                let text = pm_proto::agent_text::setup_text(lang, &on.web_origin(), &code, &v.url, &build_info(), v.expires_in_secs / 60);
                log(&format!("agent-setup: enrollment code {} created for \"{}\"", v.id, v.label));
                ok(pm_proto::AgentSetupView { id: v.id, label: v.label, text, expires_in_secs: v.expires_in_secs })
            }
            Request::EnrollPeek { code, what, peer } => {
                let on = self.online.as_ref().ok_or_else(|| err("BAD_REQUEST", "only available in server mode"))?;
                let clean = |s: &str| s.chars().filter(|c| c.is_ascii_graphic()).take(64).collect::<String>();
                match on.enroll_peek(&code) {
                    Some((id, url)) => {
                        log(&format!("bootstrap: {} for enrollment code {id} from {}", clean(&what), clean(&peer)));
                        ok(pm_proto::EnrollPeekView { url })
                    }
                    None => {
                        log(&format!("bootstrap: unknown or expired code ({}) from {}", clean(&what), clean(&peer)));
                        Err(err("NOT_FOUND", "not found"))
                    }
                }
            }
            Request::Enrollments => ok(self.online.as_ref().map(|o| o.enroll_list()).unwrap_or_default()),
            Request::EnrollCancel { id } => {
                if self.online.as_ref().is_some_and(|o| o.enroll_cancel(&id)) {
                    ok("cancelled")
                } else {
                    Err(err("BAD_REQUEST", "注册码不存在或已过期"))
                }
            }
            Request::LoginLink => {
                let on = self.online.as_ref().ok_or_else(|| err("BAD_REQUEST", "only available in server mode"))?;
                let t = on.links.create();
                log("web login link created");
                ok(format!("{}/l/{t}", on.web_origin()))
            }
            Request::ServerStatus => {
                let locked = self.inner.lock().await.vault.is_none();
                ok(self.server_status(locked))
            }
            Request::ChangePassword { old, new } => {
                if new.chars().count() < 8 {
                    return Err(err("BAD_REQUEST", "新口令至少需要 8 个字符"));
                }
                self.verify_password(old).await?;
                let dk = Zeroizing::new(*self.device_key()?);
                let _permit = self.argon.acquire().await.map_err(|_| err("INTERNAL", "semaphore"))?;
                let mut inner = self.inner.lock().await;
                let v = inner.vault.as_mut().ok_or_else(|| self.locked_err())?;
                let kdf = v.header().kdf;
                let new = Zeroizing::new(new);
                tokio::task::block_in_place(|| v.change_password(&new, &dk, kdf)).map_err(|e| err("INTERNAL", e.to_string()))?;
                ok("changed")
            }
        }
    }

    /// git 代理：检查会话与请求，选好条目。
    pub(crate) async fn git_prepare(
        &self,
        session: &Session,
        method: &str,
        url: &str,
    ) -> Result<(git::Service, url::Url, git::Plan), ApiErr> {
        if !matches!(session, Session::Agent | Session::Root) {
            return Err(err("FORBIDDEN", "git proxy is only available to agents"));
        }
        if !self.ready_cached() {
            return Err(err("NOT_READY", "PassManager security check failed, the vault stays locked."));
        }
        let (svc, u, host, port) = git::check_url(method, url)?;
        let inner = self.inner.lock().await;
        let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
        let plan = git::plan(&v.payload, &host, port, inner.redactor.clone())?;
        Ok((svc, u, plan))
    }

    /// git 代理结束：记录审计与首次看到的自签证书指纹。
    pub(crate) async fn git_finish(&self, url: &str, out: git::Outcome) {
        if let Some(a) = out.audit {
            log(&a);
        }
        if let (Some(fp), Ok(u)) = (out.observed_pin, url::Url::parse(url))
            && let Some(h) = http::host_string(&u)
        {
            let hp = format!("{h}:{}", u.port_or_known_default().unwrap_or(443));
            self.record_pin(PinKind::Https, &hp, "x509-spki", &fp).await;
        }
    }

    /// ssh-agent 桥的签名（条件见 `agent` 模块说明）。失败一律返回 FORBIDDEN / BAD_REQUEST，不签任何东西。
    async fn agent_sign(&self, key: &str, data: &str, flags: u32, binding: Option<AgentBinding>) -> R {
        let dec = |s: &str| STANDARD.decode(s.as_bytes()).map_err(|_| err("BAD_REQUEST", "invalid base64"));
        let key_blob = dec(key)?;
        let data = Zeroizing::new(dec(data)?);
        let Some(b) = binding else {
            return Err(err("FORBIDDEN", "refusing to sign: no session-bind@openssh.com binding (OpenSSH >= 8.9 required)"));
        };
        if b.forwarding {
            return Err(err("FORBIDDEN", "refusing to sign for a forwarded agent session"));
        }
        let host_blob = dec(&b.host_key)?;
        let session_id = dec(&b.session_id)?;
        let host_fp = agent::verify_binding(&host_blob, &session_id, &dec(&b.signature)?).map_err(|m| err("FORBIDDEN", m))?;
        let req = agent::parse_userauth(&data).map_err(|m| err("FORBIDDEN", format!("refusing to sign: {m}")))?;
        if req.session_id != session_id || req.key_blob != key_blob || req.host_key.as_ref().is_some_and(|h| *h != host_blob) {
            return Err(err("FORBIDDEN", "refusing to sign: request does not belong to the bound session"));
        }
        let (name, pem, allowed) = {
            let inner = self.inner.lock().await;
            let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
            let e = v
                .payload
                .entries
                .iter()
                .find(|e| {
                    e.is_private_key()
                        && e.allows(pm_vault::OP_SSH)
                        && agent::public_blob(&e.secret).ok().as_deref() == Some(key_blob.as_slice())
                })
                .ok_or_else(|| err("UNKNOWN_CREDENTIAL", "no stored key matches"))?;
            (e.name.clone(), e.secret.clone(), agent_allowed_host_keys(e, &v.payload.pins))
        };
        if !allowed.contains(&host_fp) {
            log(&format!("ssh-agent sign refused: entry={name} host={host_fp} (host key not bound to this entry)"));
            return Err(err(
                "FORBIDDEN",
                format!(
                    "refusing to sign: host key {host_fp} is not bound to \"{name}\". Ask the user to add it in the PassManager web UI."
                ),
            ));
        }
        if !self.sign_limiter.lock().unwrap().allow_at(Instant::now()) {
            return Err(err("RATE_LIMITED", "too many signature requests; try again in a minute"));
        }
        let sig = agent::sign(&pem, &data, flags).map_err(|m| err("INTERNAL", m))?;
        let key_fp = ssh::key_fingerprint(&pem).unwrap_or_default();
        log(&format!("ssh-agent sign: entry={name} key={key_fp} host={host_fp} at={}", pm_vault::now()));
        ok(STANDARD.encode(sig))
    }

    async fn verify_password(&self, password: String) -> Result<(), ApiErr> {
        let password = Zeroizing::new(password);
        if !self.backoff_ok().await {
            return Err(err("WRONG_PASSWORD", "尝试过于频繁，请稍后再试"));
        }
        let dk = Zeroizing::new(*self.device_key()?);
        let _permit = self.argon.acquire().await.map_err(|_| err("INTERNAL", "semaphore"))?;
        let header = {
            let inner = self.inner.lock().await;
            inner.vault.as_ref().ok_or_else(|| self.locked_err())?.header().clone()
        };
        let ok = tokio::task::spawn_blocking(move || Vault::check_password(&header, &password, &dk)).await.unwrap_or(false);
        if ok {
            self.record_success().await;
            Ok(())
        } else {
            self.record_failure().await;
            Err(err("WRONG_PASSWORD", "口令错误"))
        }
    }

    /// 修改载荷并写盘，然后重建脱敏器。
    async fn mutate(&self, f: impl FnOnce(&mut Vault) -> Result<(), ApiErr>) -> Result<(), ApiErr> {
        let mut inner = self.inner.lock().await;
        let v = inner.vault.as_mut().ok_or_else(|| self.locked_err())?;
        f(v)?;
        v.save().map_err(|e| err("INTERNAL", format!("保存失败：{e}")))?;
        Self::rebuild_redactor(&mut inner);
        Ok(())
    }

    async fn record_pin(&self, kind: PinKind, host_port: &str, algo: &str, fp: &str) {
        let _ = self
            .mutate(|v| {
                v.payload.pins.retain(|p| !(p.kind == kind && p.host_port == host_port));
                v.payload.pins.push(Pin {
                    kind,
                    host_port: host_port.into(),
                    algo: algo.into(),
                    fingerprint: fp.into(),
                    first_seen: pm_vault::now(),
                });
                Ok(())
            })
            .await;
    }

    /// `display`：对 Agent 的消息与日志中使用的名称（通常就是 host_port；URL 来自条目里的基础地址时是占位符）。
    async fn pin_mismatch(&self, kind: PinKind, host_port: &str, display: &str, old: &str, new: &str) -> ApiErr {
        let mut inner = self.inner.lock().await;
        inner.pending.retain(|p| p.host_port != host_port);
        inner.pending.push(PendingPinView {
            kind: pin_kind_str(kind).into(),
            host_port: host_port.into(),
            old_fingerprint: old.into(),
            new_fingerprint: new.into(),
            seen_at: pm_vault::now(),
        });
        log(&format!("host key changed for {display}"));
        let what = if kind == PinKind::Ssh { "SSH host key" } else { "TLS certificate" };
        if display != host_port {
            return err(
                "HOST_KEY_CHANGED",
                format!(
                    "The {what} fingerprint of the host in {display} changed. Nothing was sent. Ask the user to check and trust the new fingerprint in the PassManager web UI."
                ),
            );
        }
        let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
        err(
            "HOST_KEY_CHANGED",
            format!(
                "The {what} fingerprint of {host_port} changed (old {old}, new {new}). Nothing was sent. If the host was reinstalled, ask the user to run: PassManager trust {host}"
            ),
        )
    }

    async fn do_http(&self, method: &str, url: &str, headers: &[(String, String)], body: Option<&str>) -> R {
        let (prepared, expected, redactor) = {
            let inner = self.inner.lock().await;
            let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
            let p = http::prepare(&v.payload, method, url, headers, body)?;
            let expected = if p.self_signed { v.payload.pin(PinKind::Https, &p.host_port()).map(|p| p.fingerprint.clone()) } else { None };
            (p, expected, inner.redactor.clone())
        };
        let host_port = prepared.host_port();
        // URL 来自条目里的基础地址时，对 Agent 的消息与日志只提占位符，不提真实主机。
        let display = prepared.label.clone().unwrap_or_else(|| host_port.clone());
        let self_signed = prepared.self_signed;
        match http::execute(prepared, expected.clone(), &redactor).await? {
            http::Outcome::Done { result, observed_pin } => {
                if self_signed
                    && expected.is_none()
                    && let Some(fp) = observed_pin
                {
                    self.record_pin(PinKind::Https, &host_port, "x509-spki", &fp).await;
                }
                ok(result)
            }
            http::Outcome::PinMismatch { observed } => {
                Err(self.pin_mismatch(PinKind::Https, &host_port, &display, expected.as_deref().unwrap_or("?"), &observed).await)
            }
        }
    }

    async fn ssh_session(&self, target: &str) -> Result<(russh::client::Handle<ssh::Checker>, ssh::Target, Arc<Redactor>), ApiErr> {
        let dest = ssh::parse_target(target)?;
        let (target, expected, redactor) = {
            let inner = self.inner.lock().await;
            let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
            let (key, pw) = http::ssh_credentials(&v.payload, dest.name.as_deref(), &dest.host, dest.port)?;
            let t = ssh::Target::from_entries(key.as_ref(), pw.as_ref(), &dest.host, dest.port, &dest.user);
            let expected = v.payload.pin(PinKind::Ssh, &t.host_port()).map(|p| p.fingerprint.clone());
            (t, expected, inner.redactor.clone())
        };
        match ssh::connect(&target, expected.clone()).await? {
            ssh::Connected::PinMismatch { observed } => Err(self
                .pin_mismatch(PinKind::Ssh, &target.host_port(), &target.host_port(), expected.as_deref().unwrap_or("?"), &observed)
                .await),
            ssh::Connected::Session { handle, observed } => {
                if let Some((algo, fp)) = observed
                    && expected.as_deref() != Some(fp.as_str())
                {
                    self.record_pin(PinKind::Ssh, &target.host_port(), &algo, &fp).await;
                }
                Ok((handle, target, redactor))
            }
        }
    }

    /// 后台任务：空闲自动锁定、刷新令牌使用时间。
    async fn housekeeping(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            self.tokens.lock().unwrap().flush_if_dirty();
            let expired = {
                let inner = self.inner.lock().await;
                match &inner.vault {
                    Some(v) => {
                        let h = v.payload.settings.auto_lock_hours as u64;
                        h > 0 && inner.last_activity.elapsed() > Duration::from_secs(h * 3600)
                    }
                    None => false,
                }
            };
            if expired {
                log("auto-lock after idle timeout");
                self.lock().await;
            }
        }
    }
}

/// 新建或编辑条目时设置密钥 / 字段。
/// - `entry.fields` 为 Some：按给出的顺序设置全部字段，值为空时沿用原条目同名字段（不存在则报错），未列出的字段删除；
/// - 否则单值：`secret` 非空时替换；为空时沿用原值（原条目是多字段时保留原字段）。
fn apply_secret(e: &mut Entry, old: Option<&Entry>, input: &EntryInput) -> Result<(), ApiErr> {
    match &input.fields {
        Some(list) if !list.is_empty() => {
            if input.secret.as_deref().is_some_and(|s| !s.is_empty()) {
                return Err(err("BAD_REQUEST", "多字段条目不能同时提供单独的密钥"));
            }
            let mut fields = Vec::new();
            for f in list {
                let name = f.name.trim().to_string();
                let value = match f.value.as_deref() {
                    Some(v) if !v.is_empty() => Zeroizing::new(v.to_string()),
                    _ => old
                        .and_then(|o| o.field(&name))
                        .map(|x| x.value.clone())
                        .ok_or_else(|| err("BAD_REQUEST", format!("字段 {name} 没有值")))?,
                };
                fields.push(pm_vault::Field { name, value });
            }
            e.fields = fields;
            e.secret = Zeroizing::new(String::new());
        }
        _ => match (input.secret.as_deref(), old) {
            (Some(s), _) if !s.is_empty() => {
                if old.is_some_and(|o| !o.fields.is_empty()) && input.fields.is_none() {
                    return Err(err("BAD_REQUEST", "这是多字段条目，请按字段编辑"));
                }
                e.secret = Zeroizing::new(s.to_string());
            }
            (_, Some(o)) => {
                e.secret = o.secret.clone();
                e.fields = o.fields.clone();
            }
            (_, None) => {}
        },
    }
    Ok(())
}

/// 校验声明的类型。`ssh-key`：必须是能解析的（未加密）SSH 私钥，返回公钥指纹。
fn check_kind(e: &Entry, kind: Option<&str>) -> Result<Option<String>, ApiErr> {
    match kind.unwrap_or("") {
        "" => Ok(e.is_private_key().then(|| ssh::key_fingerprint(&e.secret).ok()).flatten()),
        KIND_PASSWORD => Ok(None),
        KIND_SSH_KEY => {
            if !e.fields.is_empty() {
                return Err(err("BAD_REQUEST", "ssh-key 条目是单个私钥，不能有字段"));
            }
            if !e.is_private_key() {
                return Err(err("BAD_REQUEST", "内容不是 PEM / OpenSSH 私钥（应以 -----BEGIN … PRIVATE KEY----- 开头）"));
            }
            ssh::key_fingerprint(&e.secret).map(Some).map_err(|m| err("BAD_REQUEST", m))
        }
        other => Err(err("BAD_REQUEST", format!("未知的条目类型 {other}（password / ssh-key）"))),
    }
}

fn entry_view(e: &Entry) -> EntryView {
    let public_key = if e.is_private_key() { ssh::key_fingerprint(&e.secret).ok() } else { None };
    EntryView {
        kind: if !e.fields.is_empty() {
            KIND_FIELDS.into()
        } else if e.is_private_key() {
            KIND_SSH_KEY.into()
        } else {
            KIND_PASSWORD.into()
        },
        fields: e.fields.iter().map(|f| f.name.clone()).collect(),
        host_keys: e.host_keys.clone(),
        ops: e.ops.clone(),
        public_key,
        name: e.name.clone(),
        domains: e.domains.clone(),
        note: e.note.clone(),
        self_signed: e.self_signed,
        auto_accept_host_key: e.auto_accept_host_key,
        private_key: e.is_private_key(),
        created: e.created,
        updated: e.updated,
    }
}

fn pin_kind_str(k: PinKind) -> &'static str {
    match k {
        PinKind::Ssh => "ssh",
        PinKind::Https => "https",
    }
}

fn pin_view(p: &Pin) -> PinView {
    PinView {
        kind: pin_kind_str(p.kind).into(),
        host_port: p.host_port.clone(),
        algo: p.algo.clone(),
        fingerprint: p.fingerprint.clone(),
        first_seen: p.first_seen,
    }
}

/// ssh-agent 桥允许的主机密钥：条目上显式绑定的指纹，加上指纹库里主机与条目域名匹配的 SSH 主机密钥（TOFU）。
/// 匹配规则与其他用途相同（通配符、网段只匹配字面 IP、host:port）。
fn agent_allowed_host_keys(e: &Entry, pins: &[pm_vault::Pin]) -> Vec<String> {
    let mut allowed = e.host_keys.clone();
    for p in pins.iter().filter(|p| p.kind == PinKind::Ssh) {
        let (h, port) = p.host_port.rsplit_once(':').map(|(h, port)| (h, port.parse().unwrap_or(22))).unwrap_or((p.host_port.as_str(), 22));
        if domain::matches_any_port(&e.domains, h, port) {
            allowed.push(p.fingerprint.clone());
        }
    }
    allowed
}

/// `pattern` 可为 `host:port`、`host` 或 `*.domain`（任意端口）。
fn pin_matches(pattern: &str, host_port: &str) -> bool {
    if pattern == host_port {
        return true;
    }
    let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    if pattern.contains(':') && !pattern.starts_with("*.") && pattern.parse::<std::net::IpAddr>().is_err() {
        return false;
    }
    domain::matches(pattern, host)
}

fn default_user_info() -> InstallInfo {
    let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "user".into());
    InstallInfo {
        mode: Mode::User,
        client_user: user.clone(),
        client_uid: current_uid(),
        client_gid: None,
        client_sid: None,
        service_user: user,
        seal_method: seal::file::METHOD.into(),
        seal_level: 1,
        binary: std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default(),
        server: None,
    }
}

fn current_uid() -> Option<u32> {
    #[cfg(unix)]
    // SAFETY: getuid 无副作用。
    unsafe {
        Some(libc::getuid())
    }
    #[cfg(not(unix))]
    None
}

fn set_private_dir(p: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = p;
}

/// 是否发现了 TPM（swtpm 套接字或 /dev/tpmrm0）。
fn tpm_present() -> bool {
    #[cfg(target_os = "linux")]
    {
        pm_platform::seal::linux::discover_tpm().is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::path::Path::new(pm_platform::seal::TPM_DEVICE).exists()
    }
}

pub(crate) static SHUTDOWN: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// 请求服务退出（Windows 服务管理器的停止命令等）。
pub fn request_shutdown() {
    SHUTDOWN.notify_one();
}

/// 运行服务（阻塞直到收到退出信号）。install.json 有 server 配置时以服务器模式运行。
pub fn run(layout: Layout) -> Result<(), RunError> {
    pm_platform::process::harden_process();
    let server = InstallInfo::load(&layout).ok().is_some_and(|i| i.server.is_some());
    if server {
        return run_server(layout);
    }
    let shared = Arc::new(Shared::init(layout).map_err(RunError::transient)?);
    if let Err(e) = &shared.device {
        log(&format!("WARNING: {e}"));
    }
    if shared.sealer.level() == 1 {
        log(&format!("WARNING: {}", seal::L1_WARNING));
    }
    if shared.layout.mode == Mode::User {
        let _ = std::fs::write(shared.layout.data_dir.join("service.pid"), std::process::id().to_string());
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| RunError::transient(e.to_string()))?;
    rt.block_on(async move {
        tokio::spawn(shared.clone().housekeeping());
        server::serve(shared).await
    })
    .map_err(RunError::transient)
}

/// 服务器模式：本地 socket（root 管理命令）+ 443 网页 + 8443 Agent 通道 + 证书续期。
fn run_server(layout: Layout) -> Result<(), RunError> {
    let shared = Arc::new(Shared::init_server(layout)?);
    if shared.sealer.level() == 1 {
        log(&format!("WARNING: {}", seal::L1_WARNING));
    }
    let cfg = shared.online.as_ref().expect("server mode").cfg.clone();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| RunError::transient(e.to_string()))?;
    rt.block_on(async move {
        let bind = |port: u16| {
            let addr = format!("{}:{port}", cfg.bind);
            async move {
                tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
                    let msg = format!("监听 {addr} 失败：{e}");
                    // 没有绑定特权端口的权限是配置问题；端口被占用、地址暂时不可用等按暂时性故障重试。
                    if e.kind() == std::io::ErrorKind::PermissionDenied { RunError::config(msg) } else { RunError::transient(msg) }
                })
            }
        };
        let allowed =
            format!("LAN {} ; allow {}", cfg.lan.join(", "), if cfg.allow.is_empty() { "-".into() } else { cfg.allow.join(", ") });
        if cfg.single_port() {
            let one = bind(cfg.web_port).await?;
            log(&format!("server mode (single port): https://{}:{} for web and agents ({allowed})", cfg.domain, cfg.web_port));
            tokio::spawn(online::serve_single(shared.clone(), one));
        } else {
            let web = bind(cfg.web_port).await?;
            let agents = bind(cfg.agent_port).await?;
            log(&format!("server mode: web https://{}:{} , agents :{} ({allowed})", cfg.domain, cfg.web_port, cfg.agent_port));
            tokio::spawn(online::serve_web(shared.clone(), web));
            tokio::spawn(online::serve_agents(shared.clone(), agents));
        }
        tokio::spawn(shared.clone().housekeeping());
        tokio::spawn(online::cert_loop(shared.clone()));
        server::serve(shared).await.map_err(RunError::transient)
    })
}

/// 仅 macOS 系统模式：在 root 阶段解封设备密钥并准备目录，然后降权。
/// 返回值由 `run_with_layout` 使用。
#[cfg(target_os = "macos")]
pub fn macos_root_phase(layout: &Layout) -> Result<(), String> {
    use pm_platform::harden::Ctx;
    if !pm_platform::process::is_elevated() || layout.mode != Mode::System {
        return Ok(());
    }
    let info = InstallInfo::load(layout).map_err(|e| e.to_string())?;
    // socket 目录：服务账户所有，安装用户的组可进入（先于安全检查创建，检查才能看到它）。
    if let (Ok(svc), Some(gid)) = (nix_user(&info.service_user), info.client_gid) {
        let _ = std::fs::create_dir_all(&layout.run_dir);
        let _ = std::os::unix::fs::chown(&layout.run_dir, Some(svc), Some(gid));
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&layout.run_dir, std::fs::Permissions::from_mode(0o750));
    }
    // 安全检查（root 权限，只检查不修改）。
    let report = harden::check(&Ctx { layout, info: &info });
    let _ = report.store(layout);
    // 预先在 root 阶段读出设备密钥，通过环境以外的方式传递：写入进程内静态变量。
    if let Some(s) = seal::by_method(&info.seal_method, layout)
        && let Ok(k) = s.unseal()
    {
        ROOT_PHASE_KEY.lock().unwrap().replace(k);
    }
    pm_platform::process::drop_privileges(&info.service_user).map_err(|e| format!("降权失败：{e}"))
}

#[cfg(target_os = "macos")]
fn nix_user(name: &str) -> Result<u32, ()> {
    let c = std::ffi::CString::new(name).map_err(|_| ())?;
    // SAFETY: getpwnam 返回静态缓冲区，只读取 uid。
    unsafe {
        let p = libc::getpwnam(c.as_ptr());
        if p.is_null() { Err(()) } else { Ok((*p).pw_uid) }
    }
}

#[cfg(target_os = "macos")]
pub static ROOT_PHASE_KEY: std::sync::Mutex<Option<Zeroizing<[u8; 32]>>> = std::sync::Mutex::new(None);

#[cfg(test)]
mod tests {
    use super::*;

    /// ssh-agent 桥的主机绑定与其他用途使用同一套匹配规则：通配符（不含顶点）、网段（只匹配字面 IP）、host:port。
    #[test]
    fn agent_host_binding_uses_domain_matcher() {
        let pin = |hp: &str, fp: &str| pm_vault::Pin {
            kind: PinKind::Ssh,
            host_port: hp.into(),
            algo: "ecdsa-sha2-nistp384".into(),
            fingerprint: fp.into(),
            first_seen: 0,
        };
        let pins = vec![
            pin("db1.example.com:22", "FP-db1"),
            pin("example.com:22", "FP-apex"),
            pin("198.51.100.9:22", "FP-lan"),
            pin("198.51.101.9:22", "FP-other-net"),
            pin("db2.example.com:2222", "FP-db2-2222"),
            pin("[2001:db8::5]:22", "FP-v6"),
        ];
        let mut https_pin = pin("db3.example.com:22", "FP-https");
        https_pin.kind = PinKind::Https;
        let mut all = pins.clone();
        all.push(https_pin);
        let e = Entry {
            name: "k".into(),
            secret: Zeroizing::new(String::new()),
            domains: vec!["*.example.com:22".into(), "198.51.100.0/24".into(), "2001:db8::/48".into()],
            note: String::new(),
            self_signed: false,
            auto_accept_host_key: false,
            created: 0,
            updated: 0,
            fields: vec![],
            host_keys: vec!["SHA256:explicit".into()],
            ops: vec![],
        };
        let got = agent_allowed_host_keys(&e, &all);
        assert_eq!(got, vec!["SHA256:explicit", "FP-db1", "FP-lan", "FP-v6"]);
    }
}

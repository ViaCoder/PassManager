//! PassManager 服务：持有已解锁的库，代 Agent 使用凭据，返回脱敏结果。

pub mod http;
pub mod redact;
mod server;
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
}

/// 会话类型。
pub(crate) enum Session {
    Agent,
    Admin { ready: bool },
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
        })
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
            Some(v) => Redactor::build(v.payload.entries.iter().map(|e| (e.name.as_str(), e.secret.as_str()))),
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
        let r = match session {
            Session::Agent if !req.is_usage() => Err(err("FORBIDDEN", "this operation is only available in the PassManager TUI")),
            Session::Admin { ready: false } if !matches!(req, Request::Status | Request::Security | Request::Lock) => {
                Err(err("NOT_READY", "安全检查未通过，库保持锁定。请在\"诊断\"页处理问题后重新打开 PassManager。"))
            }
            _ => self.handle(req).await,
        };
        match r {
            Ok(v) => Response { ok: true, data: Some(v), code: None, message: None },
            Err(e) => Response::err(&e.code, e.message),
        }
    }

    fn locked_err(&self) -> ApiErr {
        if !self.vault_exists() {
            err("NOT_INITIALIZED", "PassManager has not been set up yet. Ask the user to run: sudo PassManager install")
        } else if !self.ready() {
            err("NOT_READY", "PassManager security check failed, the vault stays locked. Ask the user to run: PassManager")
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
                    .map(|e| CredentialView { name: e.name.clone(), domains: e.domains.clone(), note: e.note.clone() })
                    .collect::<Vec<_>>())
            }
            Request::Http { method, url, headers, body } => self.do_http(&method, &url, &headers, body.as_deref()).await,
            Request::Ssh { target, command } => {
                // 命令以 `sudo ` 开头时，由服务通过 stdin 提供 sudo 密码。
                let (cmd, sudo) = match command.trim_start().strip_prefix("sudo ") {
                    Some(rest) => (rest.trim_start().to_string(), true),
                    None => (command.clone(), false),
                };
                let (handle, t, redactor) = self.ssh_session(&target).await?;
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
                    secret: Zeroizing::new(entry.secret.clone().unwrap_or_default()),
                    domains: entry.domains.clone(),
                    note: entry.note.clone(),
                    self_signed: entry.self_signed,
                    auto_accept_host_key: entry.auto_accept_host_key,
                    created: pm_vault::now(),
                    updated: pm_vault::now(),
                };
                // 名称可以留空：按第一个域名自动生成引用名。
                let auto = e.name.is_empty();
                if auto {
                    e.name = "pending".into();
                }
                validate_entry(&mut e).map_err(|m| err("BAD_REQUEST", m))?;
                self.mutate(|v| {
                    if auto {
                        let taken: Vec<&str> = v.payload.entries.iter().map(|x| x.name.as_str()).collect();
                        e.name = pm_vault::auto_name(&e.domains, &taken);
                    }
                    if v.payload.entry(&e.name).is_some() {
                        return Err(err("BAD_REQUEST", format!("名称 {} 已存在", e.name)));
                    }
                    v.payload.entries.push(e);
                    Ok(())
                })
                .await?;
                ok("added")
            }
            Request::UpdateEntry { original, entry } => {
                self.mutate(|v| {
                    let idx =
                        v.payload.entries.iter().position(|x| x.name == original).ok_or_else(|| err("UNKNOWN_CREDENTIAL", "条目不存在"))?;
                    let old = &v.payload.entries[idx];
                    let name = entry.name.trim();
                    let mut e = Entry {
                        // 编辑时名称留空表示不改。
                        name: if name.is_empty() { old.name.clone() } else { name.to_string() },
                        secret: match &entry.secret {
                            Some(s) if !s.is_empty() => Zeroizing::new(s.clone()),
                            _ => old.secret.clone(),
                        },
                        domains: entry.domains.clone(),
                        note: entry.note.clone(),
                        self_signed: entry.self_signed,
                        auto_accept_host_key: entry.auto_accept_host_key,
                        created: old.created,
                        updated: pm_vault::now(),
                    };
                    validate_entry(&mut e).map_err(|m| err("BAD_REQUEST", m))?;
                    if e.name != original && v.payload.entry(&e.name).is_some() {
                        return Err(err("BAD_REQUEST", format!("名称 {} 已存在", e.name)));
                    }
                    v.payload.entries[idx] = e;
                    Ok(())
                })
                .await?;
                ok("updated")
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
                ok(e.secret.as_str())
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

    async fn pin_mismatch(&self, kind: PinKind, host_port: &str, old: &str, new: &str) -> ApiErr {
        let mut inner = self.inner.lock().await;
        inner.pending.retain(|p| p.host_port != host_port);
        inner.pending.push(PendingPinView {
            kind: pin_kind_str(kind).into(),
            host_port: host_port.into(),
            old_fingerprint: old.into(),
            new_fingerprint: new.into(),
            seen_at: pm_vault::now(),
        });
        log(&format!("host key changed for {host_port}"));
        let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
        err(
            "HOST_KEY_CHANGED",
            format!(
                "The {} fingerprint of {host_port} changed (old {old}, new {new}). Nothing was sent. If the host was reinstalled, ask the user to run: PassManager trust {host}",
                if kind == PinKind::Ssh { "SSH host key" } else { "TLS certificate" }
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
                Err(self.pin_mismatch(PinKind::Https, &host_port, expected.as_deref().unwrap_or("?"), &observed).await)
            }
        }
    }

    async fn ssh_session(&self, target: &str) -> Result<(russh::client::Handle<ssh::Checker>, ssh::Target, Arc<Redactor>), ApiErr> {
        let dest = ssh::parse_target(target)?;
        let (target, expected, redactor) = {
            let inner = self.inner.lock().await;
            let v = inner.vault.as_ref().ok_or_else(|| self.locked_err())?;
            let e = http::select(&v.payload, dest.name.as_deref(), &dest.host)?;
            let t = ssh::Target::from_entry(&e, &dest.host, dest.port, &dest.user);
            let expected = v.payload.pin(PinKind::Ssh, &t.host_port()).map(|p| p.fingerprint.clone());
            (t, expected, inner.redactor.clone())
        };
        match ssh::connect(&target, expected.clone()).await? {
            ssh::Connected::PinMismatch { observed } => {
                Err(self.pin_mismatch(PinKind::Ssh, &target.host_port(), expected.as_deref().unwrap_or("?"), &observed).await)
            }
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

fn entry_view(e: &Entry) -> EntryView {
    EntryView {
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

pub(crate) static SHUTDOWN: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// 请求服务退出（Windows 服务管理器的停止命令等）。
pub fn request_shutdown() {
    SHUTDOWN.notify_one();
}

/// 运行服务（阻塞直到收到退出信号）。
pub fn run(layout: Layout) -> Result<(), String> {
    pm_platform::process::harden_process();
    let shared = Arc::new(Shared::init(layout)?);
    if let Err(e) = &shared.device {
        log(&format!("WARNING: {e}"));
    }
    if shared.sealer.level() == 1 {
        log(&format!("WARNING: {}", seal::L1_WARNING));
    }
    if shared.layout.mode == Mode::User {
        let _ = std::fs::write(shared.layout.data_dir.join("service.pid"), std::process::id().to_string());
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        tokio::spawn(shared.clone().housekeeping());
        server::serve(shared).await
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

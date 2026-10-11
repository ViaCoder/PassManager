//! SSH 执行器（内置 russh，取代 sshpass）。
//!
//! - 首次连接记录主机密钥；之后主机密钥变化时**在认证之前**中止，不发送任何认证数据。
//! - 认证：同一主机同时匹配私钥条目与口令条目时，先用私钥（公钥认证，ecdsa-sha2-nistp384 / ed25519 / rsa 等）；
//!   失败且服务器仍提供 password / keyboard-interactive 时，才用口令条目（先 password，再 keyboard-interactive）。
//!   多字段条目使用名为 `password` 的字段。
//! - `sudo=true`：只在有口令条目时生效，以 `sudo -k -S -p ''` 执行并从 stdin 提供该口令；只有私钥时 `sudo` 命令原样执行。
//! - 算法偏好：密钥交换优先 mlkem768x25519-sha256（后量子混合），其次 ecdh-sha2-nistp384，再兼容 curve25519；
//!   加密优先 aes256-gcm@openssh.com；主机密钥与公钥认证支持 ecdsa-sha2-nistp384。
//!   （russh 不支持 sntrup761x25519-sha512，对只提供它与 nistp384 的旧主机会协商 ecdh-sha2-nistp384。）
//! - 输出与下载内容全部脱敏。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pm_proto::SshResult;
use pm_vault::Entry;
use russh::ChannelMsg;
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::PublicKeyOrCertificate;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
use zeroize::Zeroizing;

use crate::redact::Redactor;
use crate::{ApiErr, err};

const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const EXEC_TIMEOUT: Duration = Duration::from_secs(600);

/// 解析后的 SSH 目标。
#[derive(Debug, PartialEq, Eq)]
pub struct Dest {
    /// 可选的凭据引用名（同一主机有多个凭据时使用）。
    pub name: Option<String>,
    pub user: String,
    pub host: String,
    pub port: u16,
}

/// 解析 `[<引用名>/]user@host[:port]`；IPv6 写成 `user@[::1]:22`。省略 user 时为 root，省略端口时为 22。
pub fn parse_target(t: &str) -> Result<Dest, ApiErr> {
    let bad = || err("BAD_REQUEST", format!("invalid target \"{t}\"; use user@host or user@host:port"));
    let t = t.trim();
    let (name, rest) = match t.split_once('/') {
        Some((n, r)) if !n.is_empty() && !n.contains('@') => (Some(n.to_string()), r),
        Some(_) => return Err(bad()),
        None => (None, t),
    };
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) if !u.is_empty() => (u.to_string(), h),
        Some(_) => return Err(bad()),
        None => ("root".to_string(), rest),
    };
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(bad)?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| bad())?,
            None if after.is_empty() => 22,
            None => return Err(bad()),
        };
        (h.to_string(), port)
    } else if hostport.matches(':').count() == 1 {
        let (h, p) = hostport.split_once(':').unwrap();
        (h.to_string(), p.parse().map_err(|_| bad())?)
    } else {
        (hostport.to_string(), 22)
    };
    let host = pm_vault::domain::normalize_host(&host);
    if host.is_empty() || host.contains(['/', ' ', '@']) || user.contains([' ', '/']) {
        return Err(bad());
    }
    Ok(Dest { name, user, host, port })
}

pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// 私钥条目的私钥 PEM（先用它认证）。
    pub key: Option<Zeroizing<String>>,
    /// 口令条目的口令（多字段条目为 `password` 字段）；没有口令条目时为空。用于口令认证与 sudo。
    pub secret: Zeroizing<String>,
    pub auto_accept: bool,
}

impl Target {
    /// `key`：私钥条目；`pw`：口令条目（两者可以都有：先私钥，后口令）。
    pub fn from_entries(key: Option<&Entry>, pw: Option<&Entry>, host: &str, port: u16, user: &str) -> Self {
        Self {
            host: host.to_string(),
            port,
            user: user.to_string(),
            key: key.map(|k| k.secret.clone()),
            secret: Zeroizing::new(pw.and_then(|e| e.password()).unwrap_or("").to_string()),
            auto_accept: key.is_some_and(|k| k.auto_accept_host_key),
        }
    }

    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub struct Checker {
    expected: Option<String>,
    accept_change: bool,
    observed: Arc<Mutex<Option<(String, String)>>>,
}

fn fingerprint(k: &PublicKey) -> (String, String) {
    (k.algorithm().to_string(), k.fingerprint(HashAlg::Sha256).to_string())
}

impl client::Handler for Checker {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let (algo, fp) = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => fingerprint(key),
            PublicKeyOrCertificate::Certificate(c) => fingerprint(&PublicKey::from(c.public_key().clone())),
        };
        let ok = match &self.expected {
            None => true,
            Some(e) => *e == fp || self.accept_change,
        };
        *self.observed.lock().unwrap() = Some((algo, fp));
        Ok(ok)
    }
}

pub enum Connected {
    Session { handle: Handle<Checker>, observed: Option<(String, String)> },
    PinMismatch { observed: String },
}

/// 连接并认证。`expected_pin` 为已记录的主机密钥指纹。
pub async fn connect(t: &Target, expected_pin: Option<String>) -> Result<Connected, ApiErr> {
    let observed = Arc::new(Mutex::new(None));
    let checker = Checker { expected: expected_pin.clone(), accept_change: t.auto_accept, observed: observed.clone() };
    let config = Arc::new(client_config());
    let conn = tokio::time::timeout(CONNECT_TIMEOUT, client::connect(config, (t.host.as_str(), t.port), checker)).await;
    let mut handle = match conn {
        Err(_) => return Err(err("UPSTREAM_ERROR", format!("SSH connection to {} timed out", t.host_port()))),
        Ok(Err(e)) => {
            let obs = observed.lock().unwrap().clone();
            if let (Some((_, fp)), Some(exp)) = (&obs, &expected_pin)
                && fp != exp
                && !t.auto_accept
            {
                return Ok(Connected::PinMismatch { observed: fp.clone() });
            }
            return Err(err("UPSTREAM_ERROR", format!("SSH connection to {} failed: {e}", t.host_port())));
        }
        Ok(Ok(h)) => h,
    };
    // 先私钥；失败后只有服务器仍提供口令方式时才回退到口令条目。
    let mut authed = false;
    let mut password_offered = true;
    if let Some(pem) = &t.key {
        let key = russh::keys::decode_secret_key(pem, None)
            .map_err(|_| err("BAD_CREDENTIAL", "the stored private key could not be parsed (encrypted keys are not supported)"))?;
        let hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
        match handle.authenticate_publickey(t.user.clone(), PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await {
            Ok(client::AuthResult::Success) => authed = true,
            Ok(client::AuthResult::Failure { remaining_methods, .. }) => {
                password_offered =
                    remaining_methods.iter().any(|m| matches!(m, russh::MethodKind::Password | russh::MethodKind::KeyboardInteractive));
            }
            Err(_) => password_offered = false,
        }
    }
    if !authed && password_offered && !t.secret.is_empty() {
        let pw_ok = handle.authenticate_password(t.user.clone(), t.secret.to_string()).await.map(|r| r.success()).unwrap_or(false);
        authed = pw_ok || keyboard_interactive(&mut handle, &t.user, &t.secret).await;
    }
    if !authed {
        let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "").await;
        return Err(err("AUTH_REJECTED", format!("SSH authentication as {} on {} was rejected", t.user, t.host_port())));
    }
    let obs = observed.lock().unwrap().clone();
    Ok(Connected::Session { handle, observed: obs })
}

/// 客户端算法偏好（见模块说明）。
pub fn client_config() -> client::Config {
    use std::borrow::Cow;
    let mut preferred = russh::Preferred::DEFAULT.clone();
    preferred.kex = Cow::Owned(vec![
        russh::kex::MLKEM768X25519_SHA256,
        russh::kex::ECDH_SHA2_NISTP384,
        russh::kex::CURVE25519,
        russh::kex::CURVE25519_PRE_RFC_8731,
        russh::kex::ECDH_SHA2_NISTP521,
        russh::kex::ECDH_SHA2_NISTP256,
        russh::kex::DH_G16_SHA512,
        russh::kex::DH_G14_SHA256,
        russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
        russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    ]);
    let mut ciphers = vec![russh::cipher::AES_256_GCM];
    ciphers.extend(preferred.cipher.iter().filter(|c| **c != russh::cipher::AES_256_GCM).cloned());
    preferred.cipher = Cow::Owned(ciphers);
    let mut macs = vec![russh::mac::HMAC_SHA512_ETM];
    macs.extend(preferred.mac.iter().filter(|m| **m != russh::mac::HMAC_SHA512_ETM).cloned());
    preferred.mac = Cow::Owned(macs);
    client::Config { inactivity_timeout: Some(Duration::from_secs(120)), preferred, ..Default::default() }
}

/// 解析 OpenSSH 私钥并返回公钥指纹（`算法 SHA256:…`）。加密的私钥不接受。错误信息不包含私钥内容。
pub fn key_fingerprint(pem: &str) -> Result<String, String> {
    let key = russh::keys::decode_secret_key(pem, None)
        .map_err(|_| "无法解析 SSH 私钥（需要未加密的 OpenSSH / PEM 私钥；加密私钥请先用 ssh-keygen -p 去掉口令）".to_string())?;
    let pubk = key.public_key();
    Ok(format!("{} {}", pubk.algorithm(), pubk.fingerprint(HashAlg::Sha256)))
}

async fn keyboard_interactive(handle: &mut Handle<Checker>, user: &str, secret: &str) -> bool {
    let Ok(mut resp) = handle.authenticate_keyboard_interactive_start(user.to_string(), None).await else { return false };
    for _ in 0..4 {
        match resp {
            KeyboardInteractiveAuthResponse::Success => return true,
            KeyboardInteractiveAuthResponse::Failure { .. } => return false,
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = prompts.iter().map(|_| secret.to_string()).collect();
                match handle.authenticate_keyboard_interactive_respond(answers).await {
                    Ok(r) => resp = r,
                    Err(_) => return false,
                }
            }
        }
    }
    false
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// 执行命令。
pub async fn exec(handle: &Handle<Checker>, t: &Target, command: &str, sudo: bool, redactor: &Redactor) -> Result<SshResult, ApiErr> {
    let mut ch = handle.channel_open_session().await.map_err(|e| err("UPSTREAM_ERROR", format!("open channel: {e}")))?;
    let cmd = if sudo { format!("sudo -k -S -p '' -- sh -c {}", shell_quote(command)) } else { command.to_string() };
    ch.exec(true, cmd.as_bytes()).await.map_err(|e| err("UPSTREAM_ERROR", format!("exec: {e}")))?;
    if sudo {
        let line = Zeroizing::new(format!("{}\n", t.secret.as_str()));
        let _ = ch.data_bytes(line.as_bytes().to_vec()).await;
    }
    let _ = ch.eof().await;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = None;
    let mut truncated = false;
    let read = async {
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } => append(&mut stdout, &data, &mut truncated),
                ChannelMsg::ExtendedData { data, ext: 1 } => append(&mut stderr, &data, &mut truncated),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status as i32),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    if tokio::time::timeout(EXEC_TIMEOUT, read).await.is_err() {
        truncated = true;
    }
    let (o, _) = redactor.redact(&stdout);
    let (e, _) = redactor.redact(&stderr);
    Ok(SshResult { exit_code: code, stdout: String::from_utf8_lossy(&o).into(), stderr: String::from_utf8_lossy(&e).into(), truncated })
}

fn append(buf: &mut Vec<u8>, data: &[u8], truncated: &mut bool) {
    if buf.len() + data.len() > MAX_OUTPUT {
        let room = MAX_OUTPUT.saturating_sub(buf.len());
        buf.extend_from_slice(&data[..room]);
        *truncated = true;
    } else {
        buf.extend_from_slice(data);
    }
}

async fn sftp(handle: &Handle<Checker>) -> Result<russh_sftp::client::SftpSession, ApiErr> {
    let ch = handle.channel_open_session().await.map_err(|e| err("UPSTREAM_ERROR", format!("open channel: {e}")))?;
    ch.request_subsystem(true, "sftp").await.map_err(|e| err("UPSTREAM_ERROR", format!("sftp subsystem: {e}")))?;
    russh_sftp::client::SftpSession::new(ch.into_stream()).await.map_err(|e| err("UPSTREAM_ERROR", format!("sftp: {e}")))
}

pub async fn upload(handle: &Handle<Checker>, remote_path: &str, data: &[u8]) -> Result<(), ApiErr> {
    use russh_sftp::protocol::OpenFlags;
    use tokio::io::AsyncWriteExt;
    let s = sftp(handle).await?;
    let e = |x: russh_sftp::client::error::Error| err("UPSTREAM_ERROR", format!("upload {remote_path}: {x}"));
    // 创建或截断目标文件（SftpSession::write 只用 WRITE 标志，不会创建/截断）。
    let mut f = s.open_with_flags(remote_path, OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE).await.map_err(e)?;
    f.write_all(data).await.map_err(|x| err("UPSTREAM_ERROR", format!("upload {remote_path}: {x}")))?;
    f.shutdown().await.map_err(|x| err("UPSTREAM_ERROR", format!("upload {remote_path}: {x}")))?;
    let _ = s.close().await;
    Ok(())
}

pub async fn download(handle: &Handle<Checker>, remote_path: &str) -> Result<Vec<u8>, ApiErr> {
    let s = sftp(handle).await?;
    // 先检查大小，避免读入超大文件。
    if let Ok(m) = s.metadata(remote_path).await
        && m.size.unwrap_or(0) > pm_proto::MAX_FILE as u64
    {
        return Err(err("TOO_LARGE", "remote file exceeds 64 MiB"));
    }
    let data = s.read(remote_path).await.map_err(|e| err("UPSTREAM_ERROR", format!("download {remote_path}: {e}")))?;
    let _ = s.close().await;
    if data.len() > pm_proto::MAX_FILE {
        return Err(err("TOO_LARGE", "remote file exceeds 64 MiB"));
    }
    Ok(data)
}

pub async fn close(handle: Handle<Checker>) {
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "").await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let d = |n: Option<&str>, u: &str, h: &str, p: u16| Dest { name: n.map(str::to_string), user: u.into(), host: h.into(), port: p };
        assert_eq!(parse_target("deploy@db1.example.com").unwrap(), d(None, "deploy", "db1.example.com", 22));
        assert_eq!(parse_target("deploy@db1.example.com:2222").unwrap(), d(None, "deploy", "db1.example.com", 2222));
        assert_eq!(parse_target("db1.example.com").unwrap(), d(None, "root", "db1.example.com", 22));
        assert_eq!(parse_target("ops/deploy@DB1.example.com").unwrap(), d(Some("ops"), "deploy", "db1.example.com", 22));
        assert_eq!(parse_target("u@[::1]:2200").unwrap(), d(None, "u", "::1", 2200));
        assert_eq!(parse_target("u@::1").unwrap(), d(None, "u", "::1", 22));
        assert!(parse_target("@host").is_err());
        assert!(parse_target("u@host:abc").is_err());
        assert!(parse_target("u@").is_err());
    }
}

//! SSH 执行器（内置 russh，取代 sshpass）。
//!
//! - 首次连接记录主机密钥；之后主机密钥变化时**在认证之前**中止，不发送任何认证数据。
//! - 认证：私钥条目用公钥认证；否则先试 password，再试 keyboard-interactive。
//! - `sudo=true`：以 `sudo -k -S -p ''` 执行，从 stdin 提供密码。
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
    pub secret: Zeroizing<String>,
    pub private_key: bool,
    pub auto_accept: bool,
}

impl Target {
    pub fn from_entry(e: &Entry, host: &str, port: u16, user: &str) -> Self {
        Self {
            host: host.to_string(),
            port,
            user: user.to_string(),
            secret: e.secret.clone(),
            private_key: e.is_private_key(),
            auto_accept: e.auto_accept_host_key && e.is_private_key(),
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
    let config = Arc::new(client::Config { inactivity_timeout: Some(Duration::from_secs(120)), ..Default::default() });
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
    let authed = if t.private_key {
        let key = russh::keys::decode_secret_key(&t.secret, None)
            .map_err(|_| err("BAD_CREDENTIAL", "the stored private key could not be parsed (encrypted keys are not supported)"))?;
        let hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
        handle
            .authenticate_publickey(t.user.clone(), PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await
            .map(|r| r.success())
            .unwrap_or(false)
    } else {
        let pw_ok = handle.authenticate_password(t.user.clone(), t.secret.to_string()).await.map(|r| r.success()).unwrap_or(false);
        pw_ok || keyboard_interactive(&mut handle, &t.user, &t.secret).await
    };
    if !authed {
        let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "").await;
        return Err(err("AUTH_REJECTED", format!("SSH authentication as {} on {} was rejected", t.user, t.host_port())));
    }
    let obs = observed.lock().unwrap().clone();
    Ok(Connected::Session { handle, observed: obs })
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

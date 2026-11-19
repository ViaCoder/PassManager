//! 托管证书：服务器用自己的 ACME 账号与 Cloudflare 令牌为别的主机签发证书，用设备密钥封存在本机，
//! 再经服务端的 SSH 会话（库里绑定该主机的凭据）上传到远端临时目录、执行安装命令、删掉临时文件。
//! 远端主机既拿不到 Cloudflare 令牌，也不需要 PassManager 客户端；配置存在加密库里（`passmanager cert add`）。

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use pm_platform::ServerConfig;
use pm_proto::ManagedCertView;
use pm_vault::ManagedCert;
use zeroize::Zeroizing;

use crate::server_files as sf;
use crate::{Shared, log, ssh};

/// 立即续期的请求与唤醒：`cert renew` 把域名放进 `force`，再唤醒证书循环。
#[derive(Default)]
pub(crate) struct Control {
    pub wake: tokio::sync::Notify,
    pub force: std::sync::Mutex<HashSet<String>>,
}

impl Control {
    /// 排队一张证书的立即续期并唤醒循环。
    pub fn request(&self, domain: &str) {
        self.force.lock().unwrap_or_else(|e| e.into_inner()).insert(domain.to_string());
        self.wake.notify_one();
    }
    /// 取走全部排队的域名（循环开始一轮时调用）。
    fn take(&self) -> HashSet<String> {
        std::mem::take(&mut *self.force.lock().unwrap_or_else(|e| e.into_inner()))
    }
    fn is_pending(&self, domain: &str) -> bool {
        self.force.lock().unwrap_or_else(|e| e.into_inner()).contains(domain)
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// DNS-01 的写入方式：与服务器自己的证书相同（Cloudflare 令牌从封存文件读；测试用 challtest）。
pub(crate) fn dns_for(layout: &pm_platform::Layout, cfg: &ServerConfig, dk: &[u8; 32]) -> Result<pm_net::acme::Dns, String> {
    if let Some(api) = cfg.dns.strip_prefix("challtest:") {
        return Ok(pm_net::acme::Dns::ChallTest { api: api.to_string() });
    }
    let token = sf::load_cf_token(layout, dk)?.ok_or("没有 Cloudflare token（安装时经 stdin 传入：passmanager init --cf-token-stdin）")?;
    Ok(pm_net::acme::Dns::cloudflare(token))
}

/// 某个域名的 ACME 参数：目录、测试根证书、传播等待都沿用服务器配置。
pub(crate) fn acme_cfg(cfg: &ServerConfig, domain: &str) -> pm_net::acme::AcmeCfg {
    pm_net::acme::AcmeCfg {
        directory: cfg.acme_directory.clone(),
        root_pem: cfg.acme_root_pem.clone(),
        domain: domain.to_string(),
        propagation: if cfg.dns == "cloudflare" { Duration::from_secs(20) } else { Duration::ZERO },
    }
}

/// 这一轮要不要签发：强制、没有证书、或进入续期窗口；失败后按退避等待（强制时不等）。
pub(crate) fn should_issue(chain: Option<&str>, st: &sf::ManagedState, force: bool, renew_days: u32, now: i64) -> bool {
    if force {
        return true;
    }
    if !pm_net::acme::needs_renewal(chain, now, renew_days) {
        return false;
    }
    st.failures == 0 || now - st.last_attempt >= pm_net::acme::backoff_secs(st.failures - 1) as i64
}

/// 这一轮要不要投递：有证书，且它的到期时间与上次成功投递的不同（新证书），或者强制。
pub(crate) fn should_deliver(not_after: Option<i64>, st: &sf::ManagedState, force: bool) -> bool {
    not_after.is_some() && (force || st.delivered_not_after != not_after)
}

/// 远端建目录的命令（0700，只有属主能进）。
pub(crate) fn mkdir_command(dir: &str) -> String {
    format!("mkdir -p -m 700 {}", ssh::shell_quote(dir))
}

/// 命令输出的最后几行（错误信息用；已经脱敏）。
fn tail(s: &str, lines: usize) -> String {
    let v: Vec<&str> = s.lines().collect();
    v[v.len().saturating_sub(lines)..].join(" | ")
}

/// 投递一张证书：建目录 → 上传 pem/key（0600）→ 执行安装命令 → 删掉两个文件（无论成败）。
async fn deliver(shared: &Shared, c: &ManagedCert, chain: &str, key: &str) -> Result<(), String> {
    let (session, t, redactor) = shared.ssh_session(&c.target).await.map_err(|e| format!("连接 {}：{}", c.target, e.message))?;
    let (pem_path, key_path) = pm_vault::managed_cert::remote_paths(c);
    let run = async {
        let r = ssh::exec(&session.handle, &t, &mkdir_command(&c.dir), false, &redactor).await.map_err(|e| e.message)?;
        if r.exit_code != Some(0) {
            return Err(format!("建目录失败（退出码 {:?}）：{}", r.exit_code, tail(&r.stderr, 2)));
        }
        ssh::upload_mode(&session.handle, &pem_path, chain.as_bytes(), 0o600).await.map_err(|e| e.message)?;
        ssh::upload_mode(&session.handle, &key_path, key.as_bytes(), 0o600).await.map_err(|e| e.message)?;
        let r = ssh::exec(&session.handle, &t, &c.after, false, &redactor).await.map_err(|e| e.message)?;
        if r.exit_code != Some(0) {
            return Err(format!("安装命令退出码 {:?}：{}", r.exit_code, tail(&format!("{}\n{}", r.stdout, r.stderr), 3)));
        }
        Ok(())
    }
    .await;
    // 私钥与证书的临时副本无论成败都删掉；删不掉只记日志
    for p in [&key_path, &pem_path] {
        if let Err(e) = ssh::remove(&session.handle, p).await {
            log(&format!("managed cert {}: cleanup {} failed: {}", c.domain, p, e.message));
        }
    }
    ssh::close(session).await;
    run
}

/// 一轮：对每张托管证书，需要时签发（同一个 ACME 账号），需要时投递；状态写回文件。返回是否有失败（循环据此缩短等待）。
pub(crate) async fn tick(shared: &Arc<Shared>) -> bool {
    let Some(on) = shared.online.as_ref() else { return false };
    let Ok(dk) = shared.device_key() else { return false };
    if on.cfg.acme_directory.is_empty() {
        return false;
    }
    let certs: Vec<ManagedCert> = {
        let inner = shared.inner.lock().await;
        match inner.vault.as_ref() {
            Some(v) => v.payload.managed_certs.clone(),
            None => return false,
        }
    };
    let forced = shared.managed.take();
    if certs.is_empty() {
        return false;
    }
    let layout = &shared.layout;
    let mut states = sf::load_managed_states(layout);
    // 配置里已经没有的域名：状态一起清掉
    states.retain(|d, _| certs.iter().any(|c| &c.domain == d));
    let mut any_error = false;
    for c in &certs {
        let force = forced.contains(&c.domain);
        let st = states.entry(c.domain.clone()).or_default();
        // 1. 签发
        let stored = match sf::load_managed_cert(layout, dk, &c.domain) {
            Ok(s) => s,
            Err(e) => {
                st.last_error = Some(format!("读取已保存的证书失败：{e}"));
                any_error = true;
                continue;
            }
        };
        if should_issue(stored.as_ref().map(|(ch, _)| ch.as_str()), st, force, on.cfg.renew_days, now()) {
            st.last_attempt = now();
            st.attempts += 1;
            let result = async {
                let dns = dns_for(layout, &on.cfg, dk)?;
                let saved = sf::load_acme_account(layout, dk);
                let issued = pm_net::acme::issue(&acme_cfg(&on.cfg, &c.domain), &dns, saved.as_deref().map(|s| s.as_str()))
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(a) = &issued.new_account {
                    sf::store_acme_account(layout, dk, a)?;
                }
                sf::store_managed_cert(layout, dk, &c.domain, &issued.chain_pem, &issued.key_pem)
            }
            .await;
            match result {
                Ok(()) => {
                    st.failures = 0;
                    st.last_error = None;
                    log(&format!("managed cert {} issued", c.domain));
                }
                Err(e) => {
                    st.failures = st.failures.saturating_add(1);
                    st.last_error = Some(format!("签发失败：{e}"));
                    any_error = true;
                    log(&format!("managed cert {} issue failed: {e}", c.domain));
                }
            }
            sf::store_managed_states(layout, &states);
            // 重新取 st（上面的闭包借用结束后再拿一次，避免同时可变借用）
        }
        let st = states.entry(c.domain.clone()).or_default();
        // 2. 投递
        let Ok(Some((chain, key))) = sf::load_managed_cert(layout, dk, &c.domain) else { continue };
        let not_after = pm_net::tls::cert_not_after(&chain);
        if should_deliver(not_after, st, force) {
            st.last_attempt = now();
            st.attempts += 1;
            let key: Zeroizing<String> = key;
            match deliver(shared, c, &chain, &key).await {
                Ok(()) => {
                    st.delivered_not_after = not_after;
                    st.last_error = None;
                    log(&format!("managed cert {} delivered to {}", c.domain, c.target));
                }
                Err(e) => {
                    st.last_error = Some(format!("投递失败：{e}"));
                    any_error = true;
                    log(&format!("managed cert {} delivery failed: {e}", c.domain));
                }
            }
            sf::store_managed_states(layout, &states);
        }
    }
    sf::store_managed_states(layout, &states);
    any_error
}

/// 全部托管证书的配置与状态（root 的 `cert list` 与 `status`）。
pub(crate) async fn views(shared: &Shared) -> Vec<ManagedCertView> {
    let certs: Vec<ManagedCert> = {
        let inner = shared.inner.lock().await;
        inner.vault.as_ref().map(|v| v.payload.managed_certs.clone()).unwrap_or_default()
    };
    let states = sf::load_managed_states(&shared.layout);
    let mut out: Vec<ManagedCertView> = certs.iter().map(|c| view(shared, c, states.get(&c.domain))).collect();
    out.sort_by(|a, b| a.domain.cmp(&b.domain));
    out
}

pub(crate) fn view(shared: &Shared, c: &ManagedCert, st: Option<&sf::ManagedState>) -> ManagedCertView {
    let st = st.cloned().unwrap_or_default();
    ManagedCertView {
        domain: c.domain.clone(),
        target: c.target.clone(),
        dir: c.dir.clone(),
        after: c.after.clone(),
        not_after: sf::managed_chain(&shared.layout, &c.domain).as_deref().and_then(pm_net::tls::cert_not_after),
        delivered_not_after: st.delivered_not_after,
        last_attempt: st.last_attempt,
        attempts: st.attempts,
        failures: st.failures,
        last_error: st.last_error,
        pending: shared.managed.is_pending(&c.domain),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_deliver_decisions() {
        let (chain, _) = pm_net::tls::self_signed(&["lab.example.com"]);
        let na = pm_net::tls::cert_not_after(&chain).unwrap();
        let fresh = sf::ManagedState::default();
        // 没有证书：签发；证书还新：不签；强制：签。
        assert!(should_issue(None, &fresh, false, 30, 0));
        assert!(!should_issue(Some(&chain), &fresh, false, 30, na - 60 * 86400));
        assert!(should_issue(Some(&chain), &fresh, true, 30, na - 60 * 86400));
        // 进入续期窗口：签；刚失败过：按退避等待（10 分钟），过了再签；强制不等。
        let t = na - 10 * 86400;
        assert!(should_issue(Some(&chain), &fresh, false, 30, t));
        let failed = sf::ManagedState { failures: 1, last_attempt: t - 100, ..Default::default() };
        assert!(!should_issue(Some(&chain), &failed, false, 30, t));
        assert!(should_issue(Some(&chain), &failed, false, 30, t + 600));
        assert!(should_issue(Some(&chain), &failed, true, 30, t));
        // 投递：没有证书不投；新证书投；已投过同一张不投；强制再投。
        assert!(!should_deliver(None, &fresh, true));
        assert!(should_deliver(Some(na), &fresh, false));
        let delivered = sf::ManagedState { delivered_not_after: Some(na), ..Default::default() };
        assert!(!should_deliver(Some(na), &delivered, false));
        assert!(should_deliver(Some(na + 1), &delivered, false));
        assert!(should_deliver(Some(na), &delivered, true));
    }

    #[test]
    fn mkdir_command_quotes_and_tail_keeps_last_lines() {
        assert_eq!(mkdir_command("/root/pm-cert"), "mkdir -p -m 700 '/root/pm-cert'");
        assert_eq!(tail("a\nb\nc\nd", 2), "c | d");
        assert_eq!(tail("", 3), "");
    }

    #[test]
    fn control_queues_and_takes() {
        let c = Control::default();
        assert!(!c.is_pending("a.example.com"));
        c.request("a.example.com");
        c.request("a.example.com");
        assert!(c.is_pending("a.example.com"));
        let taken = c.take();
        assert_eq!(taken.len(), 1);
        assert!(!c.is_pending("a.example.com") && c.take().is_empty());
    }

    #[test]
    fn acme_cfg_follows_server_config() {
        let cfg = ServerConfig { domain: "pm.example.com".into(), ..Default::default() };
        let a = acme_cfg(&cfg, "lab.example.com");
        assert_eq!(
            (a.domain.as_str(), a.propagation, a.directory.as_str()),
            ("lab.example.com", Duration::from_secs(20), pm_platform::paths::LETS_ENCRYPT)
        );
        let cfg = ServerConfig { dns: "challtest:http://x".into(), ..Default::default() };
        assert_eq!(acme_cfg(&cfg, "x.test").propagation, Duration::ZERO);
    }
}

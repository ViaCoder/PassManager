//! Agent 访问令牌存储（库外的 `tokens.json`，只保存 SHA-256）。

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pm_vault::Token;
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
struct File {
    tokens: Vec<Token>,
}

pub struct TokenStore {
    path: PathBuf,
    tokens: Vec<Token>,
    dirty: bool,
    /// 主文件缺失或损坏、从 `.bak` 读出：下一次保存不把坏主文件复制为 `.bak`。
    from_backup: bool,
}

impl TokenStore {
    /// 读取令牌表。主文件缺失或损坏（例如断电时被截断）时回退到 `.bak`。
    pub fn load(path: PathBuf) -> Self {
        let parse = |d: Vec<u8>| serde_json::from_slice::<File>(&d).ok().map(|f| f.tokens);
        if let Some(t) = pm_vault::store::read_main(&path).ok().and_then(parse) {
            return Self { path, tokens: t, dirty: false, from_backup: false };
        }
        match pm_vault::store::read_backup(&path).ok().and_then(parse) {
            Some(t) => {
                crate::log("WARNING: tokens.json missing or damaged; using tokens.json.bak");
                Self { path, tokens: t, dirty: false, from_backup: true }
            }
            None => Self { path, tokens: Vec::new(), dirty: false, from_backup: false },
        }
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        let data = serde_json::to_vec_pretty(&File { tokens: self.tokens.clone() }).map_err(std::io::Error::other)?;
        pm_vault::store::write_atomic_opts(&self.path, &data, !self.from_backup)?;
        self.from_backup = false;
        self.dirty = false;
        Ok(())
    }

    pub fn flush_if_dirty(&mut self) {
        if self.dirty {
            let _ = self.save();
        }
    }

    /// 校验令牌，成功时返回令牌 id（常数时间比较全部令牌）。
    pub fn verify(&mut self, token: &str) -> Option<String> {
        let h = pm_crypto::sha256(token.as_bytes());
        let mut found = None;
        for t in &self.tokens {
            if pm_crypto::ct_eq(&t.hash, &h) {
                found = Some(t.id.clone());
            }
        }
        if let Some(id) = &found
            && let Some(t) = self.tokens.iter_mut().find(|t| &t.id == id)
        {
            let now = pm_vault::now();
            if t.last_used.is_none_or(|l| now.saturating_sub(l) > 60) {
                t.last_used = Some(now);
                self.dirty = true;
            }
        }
        found
    }

    pub fn list(&self) -> &[Token] {
        &self.tokens
    }

    /// 新建令牌，返回 (id, 明文令牌)。明文只返回这一次。
    pub fn create(&mut self, label: &str) -> Result<(String, String), pm_crypto::CryptoError> {
        let raw: [u8; 32] = pm_crypto::rng::random_array()?;
        let token = format!("{}{}", pm_proto::TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(raw));
        let id_raw: [u8; 4] = pm_crypto::rng::random_array()?;
        let id = hex::encode(id_raw);
        self.tokens.push(Token {
            id: id.clone(),
            label: label.chars().take(64).collect(),
            hash: pm_crypto::sha256(token.as_bytes()),
            created: pm_vault::now(),
            last_used: None,
        });
        if let Err(e) = self.save() {
            crate::log(&format!("WARNING: saving tokens.json failed: {e}"));
        }
        Ok((id, token))
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        let before = self.tokens.len();
        self.tokens.retain(|t| t.id != id);
        let changed = self.tokens.len() != before;
        if changed {
            let _ = self.save();
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 断电 / kill -9：写入过程中的每个崩溃点之后令牌表都完整（旧或新）；
    /// 主文件被截断或损坏时回退到 .bak，且恢复后的第一次保存不覆盖 .bak。
    #[test]
    fn tokens_survive_crashes_and_fall_back_to_backup() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tokens.json");
        let mut s = TokenStore::load(p.clone());
        assert!(s.list().is_empty());
        let (_, t1) = s.create("a").unwrap();
        let (_, t2) = s.create("b").unwrap();
        for point in [
            pm_vault::store::CrashPoint::HalfWrittenTemp,
            pm_vault::store::CrashPoint::BeforeBackup,
            pm_vault::store::CrashPoint::BeforeRename,
        ] {
            pm_vault::store::CRASH_AT.with(|c| c.set(Some(point)));
            let _ = s.create("crash");
            let r = TokenStore::load(p.clone());
            assert_eq!(r.list().len(), s.list().len() - 1, "{point:?}");
            s.save().unwrap();
        }
        let n = s.list().len();
        // 截断的主文件：用 .bak（上一版）。
        let good = std::fs::read(&p).unwrap();
        std::fs::write(&p, &good[..good.len() / 2]).unwrap();
        let mut r = TokenStore::load(p.clone());
        assert_eq!(r.list().len(), n - 1);
        assert!(r.verify(&t1).is_some() && r.verify(&t2).is_some());
        let bak = pm_vault::store::read_backup(&p).unwrap();
        r.save().unwrap();
        assert_eq!(pm_vault::store::read_backup(&p).unwrap(), bak, "恢复后的第一次保存不覆盖 .bak");
        assert_eq!(TokenStore::load(p.clone()).list().len(), n - 1);
        // 主文件与 .bak 都坏：空表（所有令牌失效，需要重新注册），而不是 panic。
        std::fs::write(&p, b"{").unwrap();
        std::fs::write(pm_vault::store::backup_path(&p), b"[").unwrap();
        assert!(TokenStore::load(p.clone()).list().is_empty());
        // 吊销立即持久化。
        let mut s = TokenStore::load(dir.path().join("t2.json"));
        let (id, tok) = s.create("x").unwrap();
        assert!(s.revoke(&id));
        assert!(TokenStore::load(dir.path().join("t2.json")).verify(&tok).is_none());
        assert!(!s.revoke(&id));
    }
}

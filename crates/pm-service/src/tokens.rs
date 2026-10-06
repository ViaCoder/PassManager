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
}

impl TokenStore {
    pub fn load(path: PathBuf) -> Self {
        let tokens = std::fs::read(&path).ok().and_then(|d| serde_json::from_slice::<File>(&d).ok()).map(|f| f.tokens).unwrap_or_default();
        Self { path, tokens, dirty: false }
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        let data = serde_json::to_vec_pretty(&File { tokens: self.tokens.clone() }).map_err(std::io::Error::other)?;
        pm_vault::store::write_atomic(&self.path, &data)?;
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
        let _ = self.save();
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

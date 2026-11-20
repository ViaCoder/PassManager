//! 客户端自动更新：服务器把自己正在运行的那个正式发布，经已经固定指纹的双层加密通道交给版本更旧的客户端。
//!
//! "确认过的正式发布"指同时满足三条：
//! 1. 服务器自己是从发布标签构建的（`build-info` 有标签和提交）；
//! 2. agent-bin 目录里有 `agent-bundle.sh` 写下的发布记录 [`RELEASE_FILE`]：它先按 GitHub 发布页的 SHA256SUMS
//!    校验每个平台包，再记下包里 PassManager 程序的 SHA-256，版本就是服务器自己的版本；
//! 3. 程序文件此刻的 SHA-256 与记录一致。
//!
//! 客户端只在提供的版本比自己新时才替换自己（从不降级），并再核对一遍 SHA-256 和新程序报告的版本。

use serde::{Deserialize, Serialize};

/// agent-bin 目录里的发布记录（每行：`<版本> <目标> <程序的 SHA-256>`）。
pub const RELEASE_FILE: &str = "RELEASE";
/// 发布记录的大小上限（一个发布只有几行）。
pub const MAX_RELEASE_FILE: u64 = 64 << 10;
/// 程序的大小上限（编码后仍在一帧之内）。
pub const MAX_BINARY: u64 = 64 << 20;

/// 能自动更新的平台（与一键接入相同，只有 Linux 与 macOS）。
pub const TARGETS: &[&str] =
    &["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "universal-apple-darwin", "aarch64-apple-darwin", "x86_64-apple-darwin"];

/// 这台机器按优先顺序可以用的平台包（macOS 先要通用二进制，再要本架构的）。其他系统为空：不自动更新。
pub fn client_targets() -> Vec<&'static str> {
    // 编译时就确定：操作系统与 CPU 架构
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        vec!["x86_64-unknown-linux-gnu"]
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        vec!["aarch64-unknown-linux-gnu"]
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        vec!["universal-apple-darwin", "aarch64-apple-darwin"]
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        vec!["universal-apple-darwin", "x86_64-apple-darwin"]
    } else {
        Vec::new()
    }
}

/// `offered` 是否比 `have` 新（按语义化版本比较，预发布版本比正式版本旧）。任一方解析不了都算"不新"。
pub fn newer(offered: &str, have: &str) -> bool {
    match (semver::Version::parse(offered), semver::Version::parse(have)) {
        (Ok(o), Ok(h)) => o > h,
        _ => false,
    }
}

/// 发布记录里的一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseBin {
    pub version: String,
    pub target: String,
    /// 程序的 SHA-256（64 位小写十六进制）。
    pub sha256: String,
}

/// 解析发布记录：每行 `<版本> <目标> <SHA-256>`，`#` 开头的是注释；格式不对的行忽略。
pub fn parse_release(text: &str) -> Vec<ReleaseBin> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // 正好三段，用空白分开
        let f: Vec<&str> = line.split_whitespace().collect();
        let [version, target, sha] = f.as_slice() else { continue };
        // 版本必须是语义化版本，目标必须是已知平台，SHA-256 必须是 64 位十六进制
        let sha_ok = sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit());
        if semver::Version::parse(version).is_ok() && TARGETS.contains(target) && sha_ok {
            out.push(ReleaseBin { version: version.to_string(), target: target.to_string(), sha256: sha.to_ascii_lowercase() });
        }
    }
    out
}

/// `ClientUpdate` 的回复（有更新时）：版本、平台、SHA-256 与程序本身（base64）。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ClientUpdateView {
    pub version: String,
    pub target: String,
    pub sha256: String,
    /// 程序（标准 base64）。
    pub data: String,
}

impl std::fmt::Debug for ClientUpdateView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 程序本身太长，只显示长度
        f.debug_struct("ClientUpdateView")
            .field("version", &self.version)
            .field("target", &self.target)
            .field("sha256", &self.sha256)
            .field("data", &format_args!("<{} base64 chars>", self.data.len()))
            .finish()
    }
}

impl ClientUpdateView {
    /// 打包：程序编码成 base64。
    pub fn new(version: &str, target: &str, sha256: &str, bin: &[u8]) -> Self {
        use base64::Engine;
        Self {
            version: version.into(),
            target: target.into(),
            sha256: sha256.into(),
            data: base64::engine::general_purpose::STANDARD.encode(bin),
        }
    }

    /// 解出程序（只检查编码和大小；SHA-256 由调用方用 pm-crypto 核对）。
    pub fn binary(&self) -> Result<Vec<u8>, String> {
        use base64::Engine;
        let bin = base64::engine::general_purpose::STANDARD.decode(&self.data).map_err(|_| "更新包的编码不对".to_string())?;
        if bin.is_empty() || bin.len() as u64 > MAX_BINARY {
            return Err("更新包的大小不对".into());
        }
        Ok(bin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_follows_semver() {
        // 预发布按序号比较，正式版本比它的预发布新
        assert!(newer("0.3.11-rc.23", "0.3.11-rc.22"));
        assert!(newer("0.3.11-rc.10", "0.3.11-rc.9"));
        assert!(newer("0.3.11", "0.3.11-rc.23"));
        assert!(newer("0.4.0", "0.3.11"));
        // 相同、更旧、解析不了：都不算新（从不降级）
        assert!(!newer("0.3.11-rc.22", "0.3.11-rc.22"));
        assert!(!newer("0.3.11-rc.21", "0.3.11-rc.22"));
        assert!(!newer("0.3.11-rc.22", "0.3.11"));
        assert!(!newer("latest", "0.3.11"));
        assert!(!newer("0.3.12", "dev"));
        assert!(!newer("v0.3.12", "0.3.11"));
    }

    #[test]
    fn parse_release_keeps_only_valid_lines() {
        let a = "ab".repeat(32);
        let text = format!(
            "# 由 agent-bundle.sh 生成\n\n0.3.11-rc.23 x86_64-unknown-linux-gnu {a}\n0.3.11-rc.23 universal-apple-darwin {}\n\
             0.3.11-rc.23 x86_64-pc-windows-msvc {a}\nbad x86_64-unknown-linux-gnu {a}\n0.3.11-rc.23 aarch64-unknown-linux-gnu abc\n\
             0.3.11-rc.23 aarch64-unknown-linux-gnu {a} extra\n",
            a.to_uppercase()
        );
        let r = parse_release(&text);
        assert_eq!(r.len(), 2, "{r:?}");
        assert_eq!(r[0], ReleaseBin { version: "0.3.11-rc.23".into(), target: "x86_64-unknown-linux-gnu".into(), sha256: a.clone() });
        // 大写的 SHA-256 统一成小写
        assert_eq!(r[1].sha256, a);
        assert!(parse_release("").is_empty());
    }

    #[test]
    fn client_targets_are_known() {
        let t = client_targets();
        assert!(t.iter().all(|x| TARGETS.contains(x)));
        if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
            assert_eq!(t, ["x86_64-unknown-linux-gnu"]);
        }
        if cfg!(windows) {
            assert!(t.is_empty(), "Windows 不自动更新");
        }
    }

    #[test]
    fn view_round_trips_and_checks_size() {
        let v = ClientUpdateView::new("0.3.11-rc.23", "x86_64-unknown-linux-gnu", &"00".repeat(32), b"\x7fELF-binary");
        let j = serde_json::to_string(&v).unwrap();
        let back: ClientUpdateView = serde_json::from_str(&j).unwrap();
        assert_eq!(back.binary().unwrap(), b"\x7fELF-binary");
        // Debug 不打印程序内容
        assert!(!format!("{v:?}").contains(&v.data));
        let mut bad = back.clone();
        bad.data = "%%%".into();
        assert!(bad.binary().is_err());
        bad.data = String::new();
        assert!(bad.binary().is_err(), "空程序");
    }
}

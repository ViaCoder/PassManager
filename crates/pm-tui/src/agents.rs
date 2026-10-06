//! Agent 接入适配器（表驱动）。
//!
//! 每个适配器描述：检测方式、配置文件位置与格式。接入时为该 Agent 新建专用令牌，
//! 把 MCP 配置合并写入其配置文件（先备份原文件，只增加 `passmanager` 一项）。

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

pub const SERVER_KEY: &str = "passmanager";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// JSON，服务器表位于 `key` 下，`stdio_type` 表示是否需要写 `"type": "stdio"`。
    Json { key: &'static str, stdio_type: bool },
    /// TOML（Codex：`[mcp_servers.<name>]`）。
    Toml { key: &'static str },
}

pub struct Adapter {
    pub id: &'static str,
    pub name: &'static str,
    /// 优先使用的命令行（如 `claude mcp add`）。
    pub cli: Option<&'static str>,
    pub format: Format,
    /// 相对用户主目录的配置文件路径（按平台）。
    pub path: fn(&Path) -> PathBuf,
}

fn home() -> PathBuf {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

fn vscode_user_dir(h: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        h.join("Library/Application Support/Code/User")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| h.join("AppData/Roaming")).join("Code/User")
    } else {
        h.join(".config/Code/User")
    }
}

pub const ADAPTERS: &[Adapter] = &[
    Adapter {
        id: "claude",
        name: "Claude Code",
        cli: Some("claude"),
        format: Format::Json { key: "mcpServers", stdio_type: true },
        path: |h| h.join(".claude.json"),
    },
    Adapter {
        id: "codex",
        name: "Codex CLI",
        cli: None,
        format: Format::Toml { key: "mcp_servers" },
        path: |h| h.join(".codex/config.toml"),
    },
    Adapter {
        id: "cursor",
        name: "Cursor",
        cli: None,
        format: Format::Json { key: "mcpServers", stdio_type: false },
        path: |h| h.join(".cursor/mcp.json"),
    },
    Adapter {
        id: "gemini",
        name: "Gemini CLI",
        cli: None,
        format: Format::Json { key: "mcpServers", stdio_type: false },
        path: |h| h.join(".gemini/settings.json"),
    },
    Adapter {
        id: "vscode",
        name: "VS Code",
        cli: None,
        format: Format::Json { key: "servers", stdio_type: true },
        path: |h| vscode_user_dir(h).join("mcp.json"),
    },
    Adapter {
        id: "windsurf",
        name: "Windsurf",
        cli: None,
        format: Format::Json { key: "mcpServers", stdio_type: false },
        path: |h| h.join(".codeium/windsurf/mcp_config.json"),
    },
];

fn in_path(cmd: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&paths).any(|d| {
        d.join(cmd).is_file() || (cfg!(windows) && (d.join(format!("{cmd}.exe")).is_file() || d.join(format!("{cmd}.cmd")).is_file()))
    })
}

impl Adapter {
    pub fn config_path(&self) -> PathBuf {
        (self.path)(&home())
    }

    /// 是否检测到该 Agent（配置文件或其目录存在，或命令行在 PATH 中）。
    pub fn detected(&self) -> bool {
        let p = self.config_path();
        p.exists() || p.parent().is_some_and(|d| d.exists() && d != home()) || self.cli.is_some_and(in_path)
    }

    /// 配置文件中是否已有 passmanager 项。
    pub fn configured(&self) -> bool {
        let Ok(text) = std::fs::read_to_string(self.config_path()) else { return false };
        match self.format {
            Format::Json { key, .. } => {
                serde_json::from_str::<Value>(&text).ok().is_some_and(|v| v.get(key).and_then(|m| m.get(SERVER_KEY)).is_some())
            }
            Format::Toml { key } => {
                text.parse::<toml_edit::DocumentMut>().ok().is_some_and(|d| d.get(key).and_then(|t| t.get(SERVER_KEY)).is_some())
            }
        }
    }

    /// 写入 MCP 配置。
    pub fn connect(&self, bin: &str, token: &str) -> Result<String, String> {
        if let Some(cli) = self.cli
            && in_path(cli)
            && self.id == "claude"
        {
            let _ = Command::new(cli).args(["mcp", "remove", "--scope", "user", SERVER_KEY]).output();
            let out = Command::new(cli)
                .args(["mcp", "add", "--scope", "user", SERVER_KEY, "-e", &format!("{}={token}", pm_proto::ENV_TOKEN), "--", bin, "mcp"])
                .output()
                .map_err(|e| e.to_string())?;
            if out.status.success() {
                return Ok("已通过 claude mcp add 接入".into());
            }
        }
        let path = self.config_path();
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let old = std::fs::read_to_string(&path).ok();
        if let Some(o) = &old {
            let _ = std::fs::write(
                path.with_extension(format!("{}.bak-passmanager", path.extension().and_then(|e| e.to_str()).unwrap_or("cfg"))),
                o,
            );
        }
        let new = match self.format {
            Format::Json { key, stdio_type } => {
                let mut v: Value = old
                    .as_deref()
                    .map(|t| serde_json::from_str(t).map_err(|e| format!("无法解析 {}：{e}", path.display())))
                    .transpose()?
                    .unwrap_or(json!({}));
                if !v.is_object() {
                    return Err(format!("{} 不是 JSON 对象", path.display()));
                }
                let mut server = json!({ "command": bin, "args": ["mcp"], "env": { pm_proto::ENV_TOKEN: token } });
                if stdio_type {
                    server["type"] = json!("stdio");
                }
                let obj = v.as_object_mut().unwrap();
                let servers = obj.entry(key).or_insert_with(|| json!({}));
                if !servers.is_object() {
                    *servers = json!({});
                }
                servers.as_object_mut().unwrap().insert(SERVER_KEY.into(), server);
                serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
            }
            Format::Toml { key } => {
                let mut doc: toml_edit::DocumentMut =
                    old.as_deref().unwrap_or("").parse().map_err(|e| format!("无法解析 {}：{e}", path.display()))?;
                let mut t = toml_edit::Table::new();
                t["command"] = toml_edit::value(bin);
                let mut args = toml_edit::Array::new();
                args.push("mcp");
                t["args"] = toml_edit::value(args);
                let mut env = toml_edit::InlineTable::new();
                env.insert(pm_proto::ENV_TOKEN, token.into());
                t["env"] = toml_edit::value(env);
                if !doc.contains_key(key) {
                    let mut parent = toml_edit::Table::new();
                    parent.set_implicit(true);
                    doc[key] = toml_edit::Item::Table(parent);
                }
                doc[key][SERVER_KEY] = toml_edit::Item::Table(t);
                doc.to_string()
            }
        };
        write_private(&path, &new)?;
        Ok(format!("已写入 {}", path.display()))
    }

    /// 移除 MCP 配置。
    pub fn disconnect(&self) -> Result<(), String> {
        if self.id == "claude" && in_path("claude") {
            let _ = Command::new("claude").args(["mcp", "remove", "--scope", "user", SERVER_KEY]).output();
        }
        let path = self.config_path();
        let Ok(text) = std::fs::read_to_string(&path) else { return Ok(()) };
        let new = match self.format {
            Format::Json { key, .. } => {
                let mut v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
                if let Some(m) = v.get_mut(key).and_then(|m| m.as_object_mut()) {
                    m.remove(SERVER_KEY);
                }
                serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
            }
            Format::Toml { key } => {
                let mut doc: toml_edit::DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| e.to_string())?;
                if let Some(t) = doc.get_mut(key).and_then(|t| t.as_table_like_mut()) {
                    t.remove(SERVER_KEY);
                }
                doc.to_string()
            }
        };
        write_private(&path, &new)
    }
}

fn write_private(path: &Path, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("写入 {} 失败：{e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// "其他 Agent"：可复制的配置片段。
pub fn snippet(bin: &str, token: &str) -> String {
    let j = json!({ "mcpServers": { SERVER_KEY: { "command": bin, "args": ["mcp"], "env": { pm_proto::ENV_TOKEN: token } } } });
    format!(
        "MCP 配置：\n{}\n\nCLI 用法（在 Agent 的环境中设置）：\nexport {}={token}\n{bin} list",
        serde_json::to_string_pretty(&j).unwrap_or_default(),
        pm_proto::ENV_TOKEN
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_and_toml_merge() {
        let dir = std::env::temp_dir().join(format!("pm-agents-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: 测试中修改 HOME。
        unsafe { std::env::set_var("HOME", &dir) };
        std::fs::create_dir_all(dir.join(".cursor")).unwrap();
        std::fs::write(dir.join(".cursor/mcp.json"), r#"{"mcpServers":{"other":{"command":"x"}},"keep":1}"#).unwrap();
        let cursor = ADAPTERS.iter().find(|a| a.id == "cursor").unwrap();
        cursor.connect("/usr/local/bin/PassManager", "pm_abc").unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(dir.join(".cursor/mcp.json")).unwrap()).unwrap();
        assert_eq!(v["keep"], 1);
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(v["mcpServers"]["passmanager"]["env"]["PASSMANAGER_TOKEN"], "pm_abc");
        assert!(cursor.configured());
        cursor.disconnect().unwrap();
        assert!(!cursor.configured());

        std::fs::create_dir_all(dir.join(".codex")).unwrap();
        std::fs::write(dir.join(".codex/config.toml"), "model = \"o3\"\n").unwrap();
        let codex = ADAPTERS.iter().find(|a| a.id == "codex").unwrap();
        codex.connect("/usr/local/bin/PassManager", "pm_xyz").unwrap();
        let t = std::fs::read_to_string(dir.join(".codex/config.toml")).unwrap();
        assert!(t.contains("model = \"o3\""));
        assert!(t.contains("[mcp_servers.passmanager]"));
        assert!(t.contains("PASSMANAGER_TOKEN = \"pm_xyz\""));
        assert!(codex.configured());
        codex.disconnect().unwrap();
        assert!(!codex.configured());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! 检测是否在"真实终端、且不在 Agent 会话中"运行。
//!
//! 管理入口（解锁、信任指纹、查看明文、录入密钥）必须由人在真实终端里操作，
//! 防止屏幕内容经由 Agent 的 shell 回传到 LLM 上下文。

use std::io::IsTerminal;

/// 已知 AI Agent 会在子进程中设置的环境变量。
pub const AGENT_ENV_VARS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "CODEX_MANAGED_BY_NPM",
    "GEMINI_CLI",
    "CURSOR_AGENT",
    "AIDER_CHAT_HISTORY_FILE",
    "OPENCODE",
    "CLINE_ACTIVE",
];

/// 返回检测到的 Agent 环境变量名。
pub fn agent_session() -> Option<&'static str> {
    AGENT_ENV_VARS.iter().copied().find(|v| std::env::var_os(v).is_some())
}

pub fn is_real_tty() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// 管理入口的前置检查。返回 Err 时附带给用户看的原因。
pub fn require_human_terminal() -> Result<(), String> {
    if !is_real_tty() {
        return Err("必须在真实终端中运行（stdin/stdout 不是 TTY）。".into());
    }
    if let Some(v) = agent_session() {
        return Err(format!("检测到 AI Agent 会话（环境变量 {v}），请在你自己的终端窗口中运行，而不是让 Agent 运行。"));
    }
    Ok(())
}

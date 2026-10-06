# 更新日志

[English](CHANGELOG.md) | 简体中文

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-10-06

首个版本。

### 新增

- 面向 AI Agent 的密码管理：Agent 通过 MCP 或 CLI 让 PassManager 代为使用密钥（HTTPS 请求、SSH 命令、SCP 传输），全程看不到明文，返回结果自动脱敏。
- 条目只有"密钥 + 域名"（说明可选）；HTTP 请求中写 `{{secret}}`，按目标主机自动选择密钥。
- 抗量子双层加密：ML-KEM-1024（aws-lc-rs）+ Classic McEliece（liboqs），AES-256-GCM + ChaCha20-Poly1305，Argon2id；双源随机数与健康检测。
- 设备密钥封存：Linux systemd-creds（有 TPM 时 L3）、Windows DPAPI（有 TPM 时叠加 TPM）、macOS 系统钥匙串。
- 一键安装、账户安全检查与自动加固、TUI（键盘 + 鼠标）、Agent 一键接入（Claude Code、Codex、Cursor、Gemini CLI、VS Code、Windsurf）。
- Linux、macOS、Windows 的 x64 与 arm64 发布包。
- 许可证：PolyForm Strict License 1.0.0 + PassManager Contribution Terms（仅限非商业使用；禁止分发与修改版；欢迎通过 PR 贡献）。

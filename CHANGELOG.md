# Changelog

English | [简体中文](CHANGELOG.zh-CN.md)

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-06

First release.

### Added

- Password management for AI agents: agents ask PassManager over MCP or the CLI to use secrets on their behalf (HTTPS requests, SSH commands, SCP transfers). They never see the plaintext, and results are redacted automatically.
- Entries are just "secret + domains" (with an optional note). Write `{{secret}}` in an HTTP request and the secret for the target host is selected automatically.
- Two post-quantum layers: ML-KEM-1024 (aws-lc-rs) + Classic McEliece (liboqs), with AES-256-GCM + ChaCha20-Poly1305 and Argon2id; two random sources with health tests.
- Device key sealing: Linux systemd-creds (L3 with a TPM), Windows DPAPI (combined with the TPM when present), macOS System keychain.
- One-step install, account security checks with automatic hardening, a TUI (keyboard + mouse), and one-click agent setup (Claude Code, Codex, Cursor, Gemini CLI, VS Code, Windsurf).
- Release packages for Linux, macOS, and Windows on x64 and arm64.
- License: PolyForm Strict License 1.0.0 + PassManager Contribution Terms (noncommercial use only; no distribution or changed versions; contributions welcome through pull requests).

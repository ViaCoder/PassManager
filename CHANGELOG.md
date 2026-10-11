# Changelog

English | [简体中文](CHANGELOG.zh-CN.md)

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-11

### Added

- **LAN server mode (online edition)**: run one PassManager server on your LAN and let agents on other machines use its credentials. MCP and CLI usage on the agent side is unchanged; `PassManager enroll` connects an agent with a one-time code (10 minutes, single use).
- **Double post-quantum agent channel**: TLS 1.3 restricted to X25519MLKEM768 / SecP256r1MLKEM768 + TLS_AES_256_GCM_SHA384 (no 0-RTT), plus an inner layer keyed by the server's static ML-KEM-1024 **and** Classic McEliece 6688128 keys, bound to the TLS exporter (relaying through another TLS connection fails), with per-direction ChaCha20-Poly1305 frames and counters (replay/reorder rejected). Agents pin the server key fingerprint (SHA-384) from the enrollment code. Over the network only token and enrollment handshakes are accepted, and only from the configured client CIDRs (IPv4).
- **Web admin UI**: server-rendered, no JavaScript, CSP `default-src 'none'`; entries (secrets are write-only), agent tokens and enrollment codes, host key pins, settings, lock/unlock, security status. No passwords: login only through a one-time link printed by `passmanager login` (root on the server, 2 minutes, GET confirms / POST consumes); sessions expire after 2 h idle / 12 h absolute; Host / Fetch Metadata / Origin / CSRF checks, `__Host-` cookie, rate limits.
- **Root commands** on the server: `passmanager init`, `login`, `token add|list|revoke`, `status`, `lock`, `unlock`, `reseal`, with Linux-style help and examples.
- **Passwordless vault mode** (device key only, no Argon2 — fits 1 GiB servers), with the mode in the authenticated header and in the KEK derivation (downgrade protection). The service unlocks automatically at start. Password (v1) vaults are unchanged.
- **TPM sealing and entropy**: `systemd-creds --with-key=host+tpm2` (L3) when a TPM works — `/dev/tpmrm0` or an optional swtpm Unix socket — otherwise host key (L2); `passmanager reseal` upgrades L2 → L3; no PCR binding. A health-tested `TPM2_GetRandom` source is mixed into the RNG when available.
- **Let's Encrypt DNS-01 via Cloudflare** (token supplied on stdin and sealed with the device key), automatic renewal with back-off; a stored certificate keeps being used while valid.
- **Robustness**: atomic writes with fsync for the vault, tokens, keys and certificates; `.bak` fallback for corrupt or truncated files; crash-injection tests; systemd unit with network-online ordering, a bounded TPM wait, `Restart=on-failure` with start limits, and exit code 78 only for real configuration errors.
- **One-step installers**: `scripts/install-server.sh` (no site defaults — `--domain` and `--lan-cidr` are required; nftables rules, IPv6 off, hardened unit) and `scripts/install-agent.sh`, both with a `DRY_RUN` test mode.
- **`passmanager import`** (root, server): import a secret from stdin — verbatim, one trailing newline stripped, 64 KiB limit, never echoed or logged; refuses a terminal unless `--interactive` (no echo); `--domain` (host or host:port, repeatable), `--note`, `--self-signed`, `--replace`. Entries without domains are allowed and shown as "未绑定域名" (unbound) until a domain is added.
- **SSH private-key entries** (`--kind ssh-key`): unencrypted OpenSSH / PEM keys (ECDSA P-384, Ed25519, RSA), encrypted keys rejected; only the public fingerprint is displayed; public-key auth is used for key entries; works with hardened sshd profiles (`mlkem768x25519-sha256` or `ecdh-sha2-nistp384`, AES-256-GCM, HMAC-SHA2-512-ETM, `AuthenticationMethods publickey`); host keys can be bound to an entry (`--host-key`).
- **Multi-field entries** (`--fields username,password`, one value per line, CRLF accepted): placeholders `{{name.field}}`, `{{field}}` (when exactly one entry matches the host) and `{{secret}}` (single-value entries) in HTTP URL / headers / body and SSH commands; `sudo` uses the `password` field; every field is redacted (all encodings, also line by line); MCP `list` shows field names only. Vaults from 0.1.0 are read and migrated transparently.
- **`PassManager ssh-agent`**: OpenSSH agent bridge on the agent machine; private keys stay on the server, which signs only `publickey` userauth requests bound (session-bind) to an allowed host key; rate-limited and audited.
- **`PassManager git-proxy`**: loopback git smart-HTTP proxy on the agent machine (path token, `insteadOf` config); the server injects the stored PAT for the entry's domains only (HTTPS only, no redirects, client `Authorization` dropped, token never returned); request and response bodies are streamed (packs larger than 64 MiB work).
- **Wildcard and CIDR bindings, specificity, op restriction**: `*.example.com` (subdomains only), CIDR ranges (`198.51.100.0/24`, IPv6 prefixes; literal IP targets only), IDNA-normalized names; the most specific matching entry wins (exact > longer wildcard > longer prefix); `--ops http,ssh,git` restricts what an entry may be used for (e.g. an initial SSH password that can never be injected into HTTP); for SSH a matching key entry is tried before a matching password entry, which is used only if the server still offers password authentication. The ssh-agent bridge uses the same matcher.
- The agent-side remote client, `enroll`, `ssh-agent` (Unix) and `git-proxy` build on Linux, macOS and Windows; server-only commands are Linux-only.
- `scripts/release_scan.py`: whitelist-based pre-release scan (tracked file types, high-entropy strings, PEM blocks, private IPv4 literals).

### Changed

- Workspace version 0.2.0; new crates `pm-net` and `pm-web`.
- **Behavior change**: `*.example.com` no longer matches `example.com` itself; add the apex as a separate domain where needed. Several entries matching the same target are no longer always ambiguous — the most specific one is used.

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

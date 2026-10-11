# Changelog

English | [简体中文](CHANGELOG.zh-CN.md)

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.3.5] - 2026-10-11

### Added

- **Single-port mode**: `install-server.sh --port N` (site file `PORT`, `passmanager init --port N`) serves the web UI and the agent channel on one TLS port and dispatches on the negotiated ALPN — only clients asking for `pm-inner/1` alone reach the agent channel (same inner handshake and TLS-exporter binding); `h2`, `http/1.1`, no ALPN and browser-style offers get the web UI. Every generated address carries the port (web origin, login link, agent-setup one-liner, bootstrap downloads, `pm-enroll://` codes) and the web Host/Origin checks require it. Equal web and agent ports now mean single-port mode. Two-port mode (443/8443) is unchanged and remains the default.
- **IP allowlist**: `--allow` (repeatable, several space-separated entries per value; site file `ALLOW_IPS`) adds IPv4/IPv6 addresses or CIDRs that may reach the service port(s) but not SSH; `--lan-cidr` keeps access to SSH and the service. nftables and the service's own source check (web and agent channel) use the same list; `127.0.0.1`/`::1` are always allowed by the service. Entries are validated by the service's parser before the installer changes anything (host bits must be zero); an invalid list in the configuration is a configuration error (exit 78). IPv6 entries are written before the IPv6 drop rule and the installer warns that they have no effect while IPv6 is disabled. Re-running the installer replaces the old rules and listeners.
- **Base-URL placeholders**: an http URL may start with `{{entry}}` / `{{entry.field}}` (for example `{{ai.base_url}}/models`): the stored value is used raw as the base URL (absolute https, no user info), the rest is appended, and the resulting host must be bound to that entry and to every other placeholder. The URL never appears in messages, logs or responses; URL values are also redacted by path. MCP tool description and agent rules (version 2) mention it.

### Fixed

- `passmanager init` rewrote the systemd unit with only the `tss` group, dropping the swtpm socket/directory groups the installer had added; it now computes the same groups.

## [0.3.4] - 2026-10-11

### Fixed

- **Agent setup one-liner in zsh**: the printed command used `curl --proto =https …`; zsh (the macOS default shell) expands an unquoted `=https` as a command path (`zsh: https not found`) and nothing ran. It is now `sh -c "$(curl --proto '=https' --tlsv1.3 -fsSL https://<domain>/a/<code> || echo "exit $?")"` everywhere (agent-setup text EN/ZH, web page, README, deployment guide).
- **Failures are no longer silent**: with `curl … | sh` a failed download gave `sh` empty input and exit status 0. The new form prints curl's error and exits with curl's exit code; the setup text tells the AI that exit code 35 (TLS handshake failure — the client's curl lacks X25519MLKEM768) means "use step 2 (build from the pinned source)", and that other errors (22 = code expired or used, 6/7 = server unreachable) must be reported to the user.
- Tests run the exact printed command through `sh -c`, `bash -c` and `zsh -c` against a local test server, check the failure exit codes (22 for a used code, 35 for a TLS handshake against the post-quantum-only server), and CI installs zsh.

## [0.3.3] - 2026-10-11

### Fixed

- **swtpm socket access from root without supplementary groups**: `service-prepare` (run by systemd as `ExecStartPre=+…`, i.e. root without supplementary groups) could not see a swtpm socket that is only accessible through its group (for example `nobody:tss 0660` in a `0750` directory in an unprivileged LXC, where root has no DAC override for the unmapped owner) and kept waiting ("TPM did not appear"), restarting forever. When running as root, PassManager now joins the group of the socket's directory and of the socket (and `tss`) before any TPM access — service-prepare, reseal, init/status probes — and `systemd-creds` children inherit them. File permissions are never changed.
- The wait now requires the socket to accept a connection and reports what actually failed: missing (ENOENT), permission denied (EACCES — reported as a permission problem, not as a missing TPM) or connection refused (swtpm not listening).
- `install-server.sh` adds the socket's and its directory's group to the service's `SupplementaryGroups` when they are only group-accessible (the service uses the socket for TPM randomness); `server-unit --tpm-group` accepts a space-separated list of validated group names.

## [0.3.2] - 2026-10-11

### Fixed

- `install-server.sh --agent-bundle`: the server's own binary now always serves its own target (for example `aarch64-unknown-linux-gnu` on arm64 servers) and a release archive for the same target no longer replaces it, so agents get exactly the server's version. Archives that do not match `SHA256SUMS` are still skipped with a warning. Previously an archive for the native target could overwrite the server's binary.
- The installer tests assumed an x86_64 host (they failed on arm64 CI runners); they now run the bundle logic for every simulated `uname -m` (`x86_64`, `amd64`, `aarch64`, `arm64`, and an unknown architecture) on any machine.

## [0.3.1] - 2026-10-11

### Fixed

- **Agent configuration location**: `enroll` now always writes the agent's remote configuration to `~/.config/passmanager` (Windows: `%APPDATA%\PassManager`) instead of following `XDG_CONFIG_HOME`, and later use looks there first (then in the `XDG_CONFIG_HOME` location used by 0.3.0 and earlier). Before, an agent enrolled from one environment (for example the `curl … | sh` terminal) could not find its configuration when started with a different `XDG_CONFIG_HOME` (for example as an MCP server, or on CI runners) and fell back to local mode (`NO_TOKEN`). `unenroll` cleans up both locations. `PASSMANAGER_CONFIG_DIR` still overrides everything.
- **CI / release on Windows arm64**: the LLVM installer is awaited (exit code checked) and its removal from `RUNNER_TEMP` is best-effort, so the setup no longer fails with "access denied" (v0.3.0 had no GitHub Release because of this).

## [0.3.0] - 2026-10-11

### Added

- **One-step agent onboarding**: `passmanager agent-setup [--label NAME] [--lang zh]` (root on the server; also on the web "Agent 令牌" page) creates a one-time enrollment code and prints one block of text for an AI agent: the command `curl --proto =https --tlsv1.3 -fsSL https://<domain>/a/<code> | sh` (a server-generated POSIX sh bootstrap that installs the matching client from the server, verifies its SHA-256, enrolls and configures MCP), a source-build fallback pinned to the server's release tag and commit (for clients without ML-KEM TLS and Windows; development builds print a note instead), and the usage rules. Fetching the script does not consume the code; unknown/expired codes return 404; `/a/` is GET/HEAD only, rate-limited, audited and CIDR-restricted.
- **Agent usage rules**: `passmanager agent-instructions [--lang zh]`; `enroll` writes them idempotently between `<!-- passmanager:begin -->` / `<!-- passmanager:end -->` into the global instruction files of detected agents (Claude Code, Codex, Gemini CLI, Windsurf) with a backup (`--no-instructions` skips); `passmanager unenroll` and `uninstall` remove them.
- `passmanager unenroll` removes the remote configuration, the MCP entries and the rules from an agent machine.
- `install-server.sh --agent-bundle DIR` provides client binaries for other platforms from release archives (checked against `SHA256SUMS`).

### Changed

- Workspace version 0.3.0. `passmanager token add` stays available but the documented way is `agent-setup`; the web token page shows the agent setup text.

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

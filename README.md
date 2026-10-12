# PassManager

English | [简体中文](README.zh-CN.md)

A post-quantum password manager for AI agents.

- You store **secret + domain** entries in a **TUI** (keyboard and mouse).
- Any AI agent (Claude Code, Codex, Cursor, Gemini CLI, …) asks PassManager over **MCP** or the **CLI** to **use** a secret on its behalf: send an HTTPS request, run a command over SSH, or copy a file with SCP.
- The agent **never sees the plaintext**. Results are redacted automatically, and a secret is only ever sent to the domains it is bound to.
- The vault is encrypted in two post-quantum layers, **ML-KEM-1024 (aws-lc-rs) + Classic McEliece (liboqs)**. The device key is sealed by the **TPM / operating system** where possible, and randomness comes from two independent sources with health tests.

See [docs/DESIGN.md](docs/DESIGN.md) for the full design and [CHANGELOG.md](CHANGELOG.md) for release notes.

> The TUI, installer, and CLI messages are currently in Chinese. Agent-facing text (MCP tool descriptions and error codes) is in English.

## Install

Download the package for your platform from [Releases](../../releases) (Linux / macOS / Windows, x64 and arm64), unpack it, then run:

```sh
sudo ./PassManager install        # Linux / macOS (needs administrator rights once)
PassManager.exe install           # Windows: double-click or run in a terminal (one UAC prompt)
```

The installer copies the program to a path only administrators can write → creates a dedicated service account → generates and seals the device key → starts the service → checks and hardens the account setup → sets your password → opens the management UI.

- Security levels: **L3** hardware sealing (TPM) / **L2** operating-system sealing / **L1** file permissions only (a warning stays visible).
- **There is no recovery mechanism.** After moving to another machine, reinstalling the OS, or clearing the TPM, the vault cannot be opened and secrets must be entered again.
- Without administrator rights, use `PassManager install --user` (L1, no account isolation).
- Recommended account setup (the installer checks it and fixes what is safe to fix automatically): disable the built-in administrator; require a password for every elevation from your daily account; never run AI agents as administrator; do not run sudo in an agent's terminal. The vault stays locked until all required checks pass.
- The macOS package is not signed with an Apple Developer ID. After downloading it in a browser, run `xattr -d com.apple.quarantine PassManager` first.
- Verify downloads with `sha256sum -c SHA256SUMS`, or check build provenance with `gh attestation verify <file> --repo ViaCoder/PassManager`.

## Daily use

```sh
PassManager                         # management UI: entries / hosts / agents / diagnostics / settings
PassManager unlock                  # unlock once after boot
PassManager trust db1.example.com   # trust a new fingerprint after a host reinstall or certificate change (*.example.com works too)
```

Each entry needs only a **secret** (API key, password, or SSH private key) and **domains** (such as `api.github.com`, `*.example.com`, `10.0.0.5`).

On the "Agent 接入" (Agents) tab, select your agent and press Enter to connect it: PassManager creates a dedicated token and writes the MCP configuration. For other agents, copy:

```json
{ "mcpServers": { "passmanager": { "command": "/usr/local/bin/PassManager", "args": ["mcp"], "env": { "PASSMANAGER_TOKEN": "pm_…" } } } }
```

## How agents use it

| MCP tool | CLI | Description |
|---|---|---|
| `list` | `PassManager list` | Hosts that have stored secrets |
| `http` | `PassManager http https://api.github.com/user -H 'Authorization: Bearer {{secret}}'` | Write `{{secret}}` where the secret goes; the secret for the URL's host is filled in. HTTPS only |
| `ssh` | `PassManager ssh deploy@db1.example.com 'sudo systemctl restart nginx'` | Logs in with the stored password or private key; commands starting with `sudo` get the sudo password automatically |
| `scp` | `PassManager scp ./app.conf deploy@db1.example.com:/etc/app.conf` | Write the remote side as `user@host:/path`; downloaded content is redacted |

- The CLI accepts common forms: `http` supports curl's `-X`, `-H`, `-d`/`--data-raw`, `-d @file`, `--json`; `ssh` supports `-p`, `-l`, `ssh://user@host:port`; `scp` supports `-P`.
- If a host has several stored secrets, pick one by the reference name shown in the list: `{{name}}` in HTTP, `name/user@host` for SSH/SCP.
- The CLI reads the token from the `PASSMANAGER_TOKEN` environment variable and prints JSON. Errors that need the user tell the agent exactly what to ask for, e.g. `LOCKED: Ask the user to run: PassManager unlock`.

## LAN server (online edition)

Since 0.2.0 one Linux server on your LAN can hold the vault for agents on other machines (Linux, macOS, Windows).
Agents talk to it over TLS 1.3 with hybrid post-quantum key exchange plus an inner ML-KEM-1024 + Classic McEliece layer;
the server has a password-free web admin UI (one-time login links printed by root). There are no site defaults:
the domain and the allowed client CIDRs must be given at install time.

```sh
# server (root; Debian 13 or another systemd ≥ 250 distribution)
./install-server.sh --domain pm.example.com --lan-cidr 198.51.100.0/24 < cloudflare-token
passmanager import --name github --domain api.github.com < token.txt     # secrets come from stdin, never echoed
passmanager import --name forge --ops git --domain github.com < pat.txt  # git entries: git over HTTPS just works
passmanager show --label laptop --lang en                                  # prints one block of text for an AI agent
```

Give the printed block to the AI agent on the machine that should use PassManager. It contains a one-time enrollment code
(10 minutes, single use) and tells the agent to run one command —
`sh -c "$(curl --proto '=https' --tlsv1.3 -fsSL https://pm.example.com/a/<code> || echo "exit $?")"` (works in sh, bash and zsh,
and fails loudly with curl's exit code) — which installs the client (SHA-256 verified),
enrolls it, configures the MCP server for the detected agents (Claude Code, Codex, Cursor, Gemini CLI, VS Code, Windsurf) and
adds the usage rules to their global instruction files (`~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, …), and sets up git over
HTTPS: `git-proxy` becomes a per-user service that starts at boot or login (systemd user unit; LaunchAgent on macOS; manual steps
on Windows) and every host of an entry with the `git` op (GitHub, a self-hosted forge, …) gets an `insteadOf` line, so plain
`git clone https://…` works while the token stays on the server. If the agent's curl cannot do post-quantum TLS (exit code 35),
the block tells it to build the client from the pinned release source and run `enroll` instead, which does the same.

`passmanager show` is the one onboarding command: `show --label NAME` (root on the server) prints the full guide with a fresh code,
`show --label NAME --url` only the `pm-enroll://` code, `show --rules` only the rules, and plain `show` (or any non-root user) the
public guide without a code — on an enrolled machine it also names the server. `passmanager token list|revoke` manage tokens and
pending codes; `passmanager unenroll` removes everything again (including the git-proxy service and the `insteadOf` lines).

What else 0.2.0 adds on top of `http` / `ssh` / `scp`:

- **Multi-field entries**: `passmanager import --name mail --fields username,password` (one value per line). Use `{{mail.username}}`,
  `{{mail.password}}`, or `{{password}}` when only one entry matches the host; `{{secret}}` keeps meaning the single value of a
  single-value entry. `sudo` uses the `password` field. Agents only ever see field *names*.
- **SSH keys**: `--kind ssh-key` stores an unencrypted OpenSSH/PEM private key (ECDSA P-384, Ed25519, RSA). Only the public
  fingerprint is shown. Public-key login is used for key entries and works with hardened sshd profiles
  (`mlkem768x25519-sha256` / `ecdh-sha2-nistp384`, `aes256-gcm@openssh.com`, `hmac-sha2-512-etm@openssh.com`, `AuthenticationMethods publickey`).
- **`PassManager ssh-agent`** (agent machine): an OpenSSH agent socket so plain `ssh`, `scp` and `git` can use keys stored on the
  server. Keys never leave the server; it only signs `publickey` userauth requests bound (OpenSSH ≥ 8.9 `session-bind`) to a host key
  that belongs to the entry, rate-limited and audited.
- **`PassManager git-proxy`** (agent machine): a loopback git smart-HTTP proxy. Enrollment installs it as a user service and writes
  `url."http://127.0.0.1:7878/<path-token>/https/<host>/".insteadOf "https://<host>/"` for every git entry's host (re-run
  `passmanager git-proxy --install` after adding git entries; `--uninstall` removes it), so git clones and pushes through the
  server, which adds the stored token (`Authorization: Basic x-access-token:<PAT>`). The path token is persistent (0600).
  The agent machine never receives the token; only HTTPS, only the entry's domains, no redirects.

- **Single-port mode and IP allowlist**: `install-server.sh --port 8121` serves the web UI and the agent channel on one port
  (split by TLS ALPN), and `--allow "203.0.113.7 2001:db8::/32"` lets extra addresses reach that port (but not SSH); the firewall
  and the service enforce the same list.
- **Base-URL placeholders**: an entry can store a confidential base URL (for example an AI gateway endpoint) in a `base_url`
  field; agents call `{{ai.base_url}}/models` and the URL is substituted on the server, checked against the entry's domains and
  redacted from results.

Full walkthrough: [docs/DEPLOY-LAN.md](docs/DEPLOY-LAN.md). Design: [docs/DESIGN.md](docs/DESIGN.md) §10.

## Uninstall

```sh
sudo PassManager uninstall [--restore-hardening]   # permanently removes the service, service account, and all data
```

## Development

Requires Rust ≥ 1.88, CMake, a C compiler, and libclang (for liboqs bindgen).

```sh
cargo build --release
cargo test --workspace --features pm-crypto/test-hooks
python3 -I tests/tui_pty_smoke.py target/debug/PassManager "$(mktemp -d)"   # TUI pseudo-terminal test (Linux/macOS)
python3 -I tests/release_smoke.py target/release/PassManager                # release package functional test
```

- If you have `libclang` but not `clang`, set `BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/<version>/include"`.
- In debug builds, `PASSMANAGER_INSECURE_TEST_KDF=1` uses tiny Argon2 parameters (tests only; ignored in release builds). `PASSMANAGER_HOME=<dir>` puts all files under that directory.
- Local cross-builds (Linux x64/arm64 and Windows x64 from Linux; needs zig ≥ 0.14 and `cargo install cargo-zigbuild`): `scripts/cross-build.sh`. macOS builds need a Mac.

## Testing and releases

- **CI** (every push, `.github/workflows/ci.yml`): on native Linux / macOS / Windows runners for both x64 and arm64, runs formatting and lint checks, all tests (including end-to-end tests with a real service + HTTPS + SSH/SFTP + MCP + CLI), and the TUI pseudo-terminal test; installs, probes, and uninstalls in system mode; runs the full agent flow on a hardened Linux runner; and checks the supply chain with `cargo deny`.
- **Releases**:
  1. Bump `version` in `Cargo.toml` and add a matching `## [x.y.z]` section to `CHANGELOG.md` (English, used as the release notes) and `CHANGELOG.zh-CN.md`.
  2. Commit.
  3. `git tag vx.y.z && git push origin vx.y.z`.

  `.github/workflows/release.yml` checks that the tag matches the version, builds on each platform's native runner, and **runs the packaged binary as a functional test** (the macOS universal binary runs both natively on arm64 and as x86_64 under Rosetta). When everything passes it publishes the release with `SHA256SUMS`, build provenance attestations, and notes taken from the CHANGELOG. Tags containing `-` (such as `v0.2.0-rc.1`) are marked as pre-releases.

## License

[PolyForm Strict License 1.0.0](LICENSE) + [PassManager Contribution Terms](LICENSE-CONTRIBUTING.md). Licensor: ViaCoder.

- You may use the official releases for noncommercial purposes (personal use, education, charities, government, and so on). Commercial use is not permitted.
- You may not distribute the software or make or publish changed versions.
- Contributions are welcome: you may fork this repository and change the code, but only to prepare contributions to it. See [CONTRIBUTING.md](CONTRIBUTING.md). Opening a pull request means you agree to the Contribution Terms.

This is a summary; the license texts govern.

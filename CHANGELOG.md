# Changelog

English | [简体中文](CHANGELOG.zh-CN.md)

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.3.11-rc.5] - 2026-10-18

### Added

- **Network-bound encryption (Clevis + Tang).** After `passmanager init --tang 127.0.0.1:<port>`, the web port forwards the two Clevis requests under `/tang/` (`GET /tang/adv[/<thp>]`, `POST /tang/rec/<kid>`) unchanged to tangd (Debian's `tang` package) on the loopback interface. Other machines bind a key to this server with `clevis encrypt tang '{"url":"https://pm.example.com:8120/tang","thp":"<thumbprint>"}'`: a disk image cannot be unlocked away from a network that reaches the server, without a TPM.
  - **Only mature implementations.** tangd holds the keys and does the exchange (McCallum-Relyea, so the server never sees the client's key); PassManager is only the HTTPS front.
  - **The same access rules as the web pages:** the source must be in the LAN ranges or the allowlist and the Host must be this site; the transport is TLS 1.3 with the hybrid post-quantum group.
  - **Only what belongs to Tang is forwarded:** thumbprints and key IDs must use tangd's own character set, an exchange request must be `application/jwk+json` and at most 8 KiB, and only tangd's two reply types are passed back (anything else is a 502). The tangd address must be a loopback address (otherwise a configuration error, exit code 78).
  - **Known limit:** Tang's exchange uses the P-521 elliptic curve and is not post-quantum by itself; the transport to the server is.

### Changed

- **`passmanager init --allow` says that the firewall does not change with it.** The allowlist firewall rules are written by `install-server.sh`; running only `init` updates the service's own source check, while the firewall keeps the old list (new sources time out).

## [0.3.11-rc.4] - 2026-10-18

### Added

- **Enrolling macOS, Windows and older Linux machines without building from source.** Their built-in curl and PowerShell cannot do the post-quantum TLS (X25519MLKEM768) that the server requires, so the one-line installer fails there with exit code 35 and the setup text used to send them to a source build. When the server has the `SHA256SUMS` of its own release in the agent-bin directory, `passmanager show --label <name>` now adds a step 2 with ready commands for each platform: download the release package from the GitHub release page pinned to the server's tag, check its SHA-256 (written into the command), unpack it and enroll. The source build moves to step 3. The server's TLS policy is unchanged; the SHA-256 reaches the agent machine through the setup text that the administrator copies from the server.
- **`scripts/agent-bundle.sh`** puts the release packages into the agent-bin directory of a running server without re-running the installer: it checks every package against `SHA256SUMS`, unpacks the Linux and macOS binaries, never replaces the server's own binary and copies `SHA256SUMS` for the setup text. `install-server.sh --agent-bundle` uses it.

### Changed

- **`--agent-bundle` requires `SHA256SUMS`.** A bundle directory without it (or with a symbolic link instead of a file) is refused before anything is installed.

## [0.3.11-rc.3] - 2026-10-17

### Added

- **SSH through a jump host.** Write the target as `jumpuser@jumphost>user@host` in the `ssh` and `scp` tools (for scp: `jumpuser@jumphost>user@host:/path`), or use `-J jumpuser@jumphost` with `passmanager ssh` / `passmanager scp`, as with OpenSSH. One jump host is supported.
  - **Each hop uses only its own stored credential.** The server logs in to the jump host with the credential bound to it, opens a `direct-tcpip` channel to the target, and runs the full SSH handshake and login with the target inside that channel. The jump host only relays ciphertext; it never sees the target's credential, and the target never sees the jump host's.
  - **Host keys are checked on both hops.** A changed key on either hop stops with `HOST_KEY_CHANGED` before any login data is sent to that hop; if the jump host's key changed, no forwarding is requested at all.
  - **`lookup` understands routes** and lists the credentials for both hops; its `how` contains the full route.
  - **Compatibility:** the route is part of the target string, so only the server needs the upgrade. Older clients pass it through unchanged, except for scp when the jump host has an explicit port (`jump:2222>…`), which needs this client.
- **`lookup` fills in a non-default port.** When the target has no port and nothing is bound to the default port, but the host is bound on exactly one other port (for example `git.example.com:8121`), `lookup` answers with that port. An explicit port is never changed, and two bound ports for the same host stay ambiguous.

### Changed

- Code adjusted for the lints of Rust 1.99 (`collapsible_match`, `needless_borrows_for_generic_args`); behaviour is unchanged.

## [0.3.11-rc.2] - 2026-10-16

### Fixed

- **`lookup` for git now matches agent rules v5.** Its `how` said to run plain git and, if git asked for credentials, to run `passmanager git-proxy --install`. It now says `passmanager run git <clone|fetch|pull|push|ls-remote> https://<host>/<owner>/<repo>.git`. Only the server needs the upgrade; clients are unchanged.

## [0.3.11-rc.1] - 2026-10-15

### Added

- **`passmanager run <command>`** forwards authentication for a single command, with nothing installed or configured (Unix).
  Examples: `passmanager run git push`, `passmanager run ssh user@host`, `passmanager run rsync …`.
  - **git over HTTPS:** a loopback relay on a random port with a one-time path token. The relay is handed to git only through `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`, so no git config file is written. Requests still go through the server, which adds the token.
  - **ssh, scp, rsync and git over SSH:** a temporary agent socket in a private directory, passed as `SSH_AUTH_SOCK`. The server still signs.
  - **Lifetime:** both are removed when the command exits. Ctrl-C goes to the command, and the exit code is the command's. Directories left behind by a crashed run are removed on the next run.

### Changed

- **Agent rules v5:** shell commands that need a login use `passmanager run` instead of `git-proxy --install` and `ssh-agent`. Run `passmanager show --rules --write` after upgrading.

### Security

- **`passmanager git-proxy` no longer prints its path token.** The configuration commands it prints read the token file with `$(cat …)`, so the token stays out of terminal output and out of the service journal.

## [0.3.10] - 2026-10-15

### Security

- **rustls 0.23.45 → 0.23.46** for RUSTSEC-2026-0349, RUSTSEC-2026-0346, RUSTSEC-2026-0347 and RUSTSEC-2026-0348, published after 0.3.9 was released.
  - The relevant one is RUSTSEC-2026-0349: an unauthenticated ServerHello could make later client connections fall back from the hybrid post-quantum key exchange to a classical one. PassManager's agent channel stayed confidential through its inner ML-KEM-1024 + Classic McEliece layer, but the outer TLS guarantee is restored.
  - RUSTSEC-2026-0346 is about `Debug` output of client session values. PassManager never prints them.
  - ECH (0347) and Brotli certificate decompression (0348) are not used.
- No other dependency changed.

### Maintenance

- A daily scheduled check of the RustSec advisories (`.github/workflows/advisories.yml`) reports new advisories before the next release instead of after it. Releases now go through a `release/X.Y.Z` branch that must pass CI before the tag is pushed.

## [0.3.9] - 2026-10-15

### Changed (breaking for agents)

- **Need-to-know discovery: `lookup` replaces `list`.** Agents no longer receive every entry with all domains, notes, fields and operations. `lookup` (MCP tool and `passmanager lookup TARGET [--use http|ssh|scp|git]`) takes the URL, `user@host` or host the agent is about to use (or `{{name}}` when a base URL is itself secret) and returns only the reference name(s), field names and `how`, a ready-to-copy `http` / `ssh` / `scp` call. It picks the entry with exactly the same rules as the real request. Notes are never shown to agents. `list` (MCP alias and CLI) and the protocol's `List` request now return `USE_LOOKUP` and disclose nothing.
- **Progressive, compact usage guidance** for weaker models, following Anthropic's tool-writing guidance and the MCP specification. `instructions` is at most five lines: lookup first, copy `how`, never reveal secrets, follow `Next:`. Each of the four tools has two or three sentences, one minimal JSON example and `readOnlyHint` / `destructiveHint` / `openWorldHint` annotations. A test caps the size of the tool list.
- **Every error ends with `Next:`** (CLI: a `next` field) saying exactly what to do, e.g. `NO_CREDENTIAL` → import it on the server without displaying it: `<command that prints the secret> | ssh root@<server> passmanager import …`; `DOMAIN_MISMATCH` → `passmanager update --name … --domain …`; `AMBIGUOUS` → ask the user which named credential to use. The texts live in `pm_proto::agent_text::next_step`.
- **Usage rules v4** (written to the agents' global instruction files): the lookup workflow, git and ssh-agent, the `Next:` rule, and how an agent with root SSH on the server adds or changes credentials. `passmanager show --rules --write` refreshes the block in place after an upgrade, without enrolling again.
- git-proxy host discovery uses the new token-only `git_hosts` request, which returns only the domains of entries with the `git` op.

### Added

- `passmanager update --name N [--domain D]… [--remove-domain D]… [--add-op OP]… [--remove-op OP]… [--note TEXT]` (root on the server): changes bindings, operations and the note without touching the secret. `--add-op` on an unrestricted entry changes nothing; `--remove-op` on an unrestricted entry keeps all other operations.
- `import` and `update` warn when a note looks like it contains a path, URL, account or token. A note should be one short purpose.

### Security

- Error messages no longer list the domains an entry is bound to (`DOMAIN_MISMATCH` now says only that the entry is not bound to the requested host) or the operations it allows (`OP_NOT_ALLOWED`), and `AMBIGUOUS` lists only the tied reference names.

### Upgrade

- Upgrade the server first, then each client (`passmanager show --rules --write` on each client).
- Clients up to 0.3.8 still work for `http`, `ssh`, `scp` and git, but their `list` returns `USE_LOOKUP`, and `git-proxy --install` cannot discover hosts until the client is upgraded. Existing `insteadOf` lines keep working.

## [0.3.8] - 2026-10-12

### Changed

- **One onboarding command: `passmanager show`.** `show --label NAME` (root on the server) creates the 10-minute single-use enrollment code and prints the complete guide for the AI agent — the one-liner `sh -c "$(curl --proto '=https' --tlsv1.3 -fsSL https://<origin>/a/<code> || echo "exit $?")"`, the fallback for machines whose curl lacks post-quantum TLS (exit code 35: build from the release source pinned to tag and commit, then `PassManager enroll '<pm-enroll://…>'`) and the rules. `show --label NAME --url` prints only the `pm-enroll://` code, `show --rules` only the rules block. Plain `show`, or any user who is not root on the server, gets the public guide without a code (on an enrolled machine it names the server). Chinese is the default; `--lang en` for English. The text still has a single source (`pm_proto::agent_text`).
- **Removed** `passmanager agent-setup`, `passmanager agent-instructions`, `passmanager token add` and `scripts/install-agent.sh`; use `show --label`, `show --rules`, `show --label --url` and the one-liner. `token list` / `token revoke`, `enroll` and `import` are unchanged.
- **Usage rules v3**: git over HTTPS uses plain `https://` URLs through the resident `git-proxy` service; `passmanager git-proxy --install` refreshes it.

### Added

- **git works after enrollment**, for every entry with the `git` op (GitHub, self-hosted forges, … treated identically): `enroll` — used by the one-liner and by the source-build fallback — installs `git-proxy` as a per-user service that starts at boot or login (systemd user unit `passmanager-git-proxy.service` with `loginctl enable-linger` attempted without prompting and documented when not permitted; LaunchAgent `com.passmanager.git-proxy` on macOS; printed `schtasks` steps on Windows) and writes one global `url."http://127.0.0.1:7878/<path-token>/https/<host>/".insteadOf "https://<host>/"` per git host. The path token is persistent (0600), so the lines survive restarts; re-running replaces and never duplicates; the lines are only written once the service runs, so a machine without a user service manager keeps a working git. The PAT never touches the agent machine. New options: `enroll --no-git-proxy`, `enroll --git-proxy-listen ADDR`, `git-proxy --install`, `git-proxy --uninstall`; `unenroll` removes the service and the lines.
- `git-proxy` without `--host` prints the configuration for the hosts of all entries with the `git` op (from the `list` call). Configuration errors (no remote configuration, non-loopback `--listen`) exit with 78 so the service manager does not restart it.

### Security

- **Enrollment codes**: failed redeems on the agent channel are now rate-limited per source address (10 failures in 10 minutes → 15 minutes lockout; during the lockout even a valid code is refused and not consumed). The audit log records label, source address and result of every redeem (`enroll: ok …`, `enroll: rejected …`), never the code. Verified unchanged: 256-bit random codes, only the SHA-256 kept in memory, 10-minute expiry, single use with take-out and invalidation in one atomic step.

### Tests

- clap parsing of every `show` form and the new `enroll` / `git-proxy` options, the removed commands are rejected; the public guide (no `--label`, not root) contains no `pm-enroll://` code and no `/a/<code>`; code strength and hash-only storage, expiry, reuse, 16 threads redeeming the same code (exactly one wins), per-source lockout; `agent_setup_e2e` switched to `show` (including concurrent `enroll` with one code and the lockout over the network); a new end-to-end test runs `show` → the bootstrap script in a temporary HOME with fake `systemctl` / `loginctl` → checks the unit file, the calls and the `insteadOf` lines (idempotent `git-proxy --install`), starts the proxy with the unit's `ExecStart`, `git push` / `git ls-remote` against a local git HTTP server succeed, no PAT anywhere in the temporary HOME or outputs, and after `token revoke` git fails; systemd unit / LaunchAgent generation and install sequences with fake service managers, `systemd-analyze verify`; real-git `insteadOf` replacement that keeps user entries; `shellcheck` on the generated bootstrap script; `install_scripts_test.sh` covers `git-proxy --install/--uninstall` with fake service managers.

## [0.3.7] - 2026-10-11

### Fixed

- **Stale cached stylesheet after upgrades**: pages referenced `/static/style.css` (and the favicon) under a fixed URL with `max-age=3600`, so after an upgrade the browser combined the new HTML with the old cached stylesheet (huge unstyled icons, visible skip link) until a hard reload. Static assets are now referenced as `/static/style.css?v=<hash>` / `/static/icon.svg?v=<hash>`, where the hash is the first 10 hex characters of the SHA-256 of the compiled-in file; a new build with different bytes gets a new URL. Requests with the current hash are served with `max-age=31536000, immutable`; requests without `v` or with an old/unknown `v` still get the current file with `max-age=3600` (stale pages never 404). Pages themselves stay `no-store`, so they always reference the current hash. Other headers (CSP, `nosniff`, CORP, Referrer-Policy) and the Host check are unchanged.

### Tests

- Hash function (known value, one changed byte changes the URL), `Cache-Control` selection, rendered pages contain the exact current hash for each asset, the static routes work with and without (current, old, malformed) `?v` and keep all security headers and the Host check.

## [0.3.6] - 2026-10-11

### Changed

- **Web admin UI redesign** (still server-rendered, no JavaScript, no external resources): consistent spacing and type scale; page headers with icon, description and primary action; navigation highlights the current page (`aria-current`) and wraps on narrow screens; status tiles and badges for vault lock state, seal level (L1/L2/L3), certificate expiry (days left; amber at ≤ 21 days, red at ≤ 7 days or expired), security-check result (failing checks are listed on the status page), token state (used / never used) and enrollment-code countdown; forms with separate labels, hints (`aria-describedby`), `:user-invalid` styling and an explicit "re-enter the secret" hint after a failed save; the entry form hides inputs that do not apply to the selected type via CSS `:has()` (everything stays visible without it; the server still ignores them); delete and revoke ask for confirmation through `<details>` (no script); empty states for entries, tokens, enrollment codes, pins and checks; tables become stacked cards below 720 px; skip link, `:focus-visible` outlines, `prefers-reduced-motion` and `forced-colors` support; light and dark palettes checked against WCAG AA (every text/background pair ≥ 5.8:1).
- **Icons**: a small stroke icon set (shield, key, lock/unlock, server, token, link, settings, warning, check, copy, trash, …) as an inline SVG sprite in the page; templates call `icon("name")`, which only accepts names from a fixed list. New same-origin favicon `/static/icon.svg`.
- **CSP tightened**: `img-src 'self' data:` → `img-src 'self'` (`data:` was never used; the favicon is same-origin). Other CSP directives unchanged.

### Fixed

- **Web forms were rejected in real browsers** (since the web UI was introduced): with `Referrer-Policy: no-referrer` browsers send `Origin: null` on form POSTs, which the request guard (correctly) rejects with 403 — login confirmation, saving entries, locking, etc. all failed. The policy is now `same-origin` (response header and `<meta>`): same-origin requests carry the real Origin/Referer, cross-origin requests still get no Referer. The guard is unchanged and still rejects `Origin: null`, foreign origins, wrong Host and cross-site Fetch Metadata. Verified end-to-end in Chrome (one-time-link login, entry create/edit/delete, token create/revoke, lock/unlock); the login-link token is only ever sent back to the same origin and is consumed by the POST.

### Tests

- Offline guarantee: templates, stylesheet and favicon must not reference external URLs (http/https, protocol-relative, `@import`, fonts, `data:`), contain `<script>`, event-handler attributes, `javascript:` URLs, embedding elements or inline styles; links, form actions and resources must be same-site paths or fragments.
- Favicon/CSP test: exact CSP string, favicon headers (`image/svg+xml`, `nosniff`, CORP `same-origin`, CSP), Host check also applies to static files, navigation highlight.
- Icon test (every used name is defined, unknown or injected names render nothing); the XSS injection test covers the new template variables (`nav`, `st.ready`, `st.issues`, `st.allow`) and the new branches (empty states, certificate expiry, seal levels).
- Referrer-Policy test: header and `<meta>` pinned to `same-origin`; the guard still rejects `Origin: null` and foreign origins; same-origin browser POSTs (`Origin: https://pm.test:8121`, `Sec-Fetch-Site: same-origin`, valid CSRF) succeed for login confirmation, entry save and lock, while the same requests with `Origin: null` are rejected without consuming the link.

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

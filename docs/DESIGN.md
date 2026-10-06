# PassManager Design

English | [简体中文](DESIGN.zh-CN.md)

A post-quantum password manager for AI agents. A human manages "secret + domains" entries in a TUI; any AI agent asks PassManager over MCP or the CLI to **use** a credential on its behalf (HTTPS requests, SSH commands, SFTP transfers). The agent **never sees the plaintext**, and results are redacted automatically.

---

## 1. Goals and threat model

| ID | Threat | Mitigation |
|---|---|---|
| T1 | The AI provider extracts secrets from the conversation context | Secrets never enter the agent process or the LLM context; every result is redacted; secrets can only be entered in the TUI; the TUI refuses to show plaintext outside a TTY or inside an agent session |
| T2 | Prompt injection makes the agent do something unintended | Every entry is bound to domains and its secret is only sent to matching hosts; HTTPS only; no cross-host redirects; SSH host keys and self-signed certificate fingerprints are pinned |
| T3 | The agent scans the whole disk and uploads it | The vault and device key belong to a dedicated system user and live outside $HOME; the device key is sealed by the TPM / OS; the vault file has two post-quantum encryption layers |
| — | The service is discovered or probed | No TCP listener; the first frame on the local socket must be a valid handshake, otherwise the connection is silently closed after a random delay with no identifying response |

**The only security boundary is the operating-system user.** Agents run as a normal user; the service runs as the dedicated user `passmanager` (macOS: `_passmanager`; Windows: `NT SERVICE\PassManager`). If an agent has root/administrator rights, no design can help — this is the one assumption of the design, and `PassManager harden` checks and enforces it (§6).

**Residual risks** (stated plainly):

- An injected agent can still misuse a credential **within that entry's own domains** (for example, delete repositories with a GitHub token). Use least-privilege tokens / accounts for each entry, and do not use wildcards on domains with user-controlled subdomains.
- If the agent can modify the user's shell configuration, it can fake `sudo` and capture the administrator password. Do not run sudo in an agent's terminal.
- Fingerprints are recorded on first connection (TOFU): if the very first connection is intercepted, the attacker's fingerprint is recorded.
- An access token is only a "door key": whoever holds a leaked token can only **use** credentials (still without seeing the plaintext), and it can be revoked in the TUI with one click.

---

## 2. Architecture

```
 Current user                                          Service user (isolated)
 PassManager (TUI) ──(password handshake)──┐          ┌────────────────────────────┐
                                           ├─ local ─►│ PassManager service         │──► HTTPS sites
 Any agent ─ PassManager mcp/CLI ──────────┘  socket  │  unlocked keys (memory only)│──► SSH / SFTP hosts
                     (token handshake)                │  vault.pmv + sealed dev key │◄── TPM / DPAPI / keychain
                                                      └────────────────────────────┘
```

- A single executable, `PassManager`: service, TUI, MCP server, CLI, installer.
- Local IPC: a Unix socket on Linux/macOS (directory 0750, group = the installing user's group); a named pipe with a DACL on Windows (only SYSTEM, the service account, and the installing user). Frame format: `u32 BE length ‖ JSON`.
- Handshake (first frame):
  - `{"auth":"token","v":1,"token":"pm_…"}`: agent session, limited to "use" operations (list / http / ssh / upload / download / lock / status). Clients running as root or with an elevated token are always rejected.
  - `{"auth":"password","v":1,"password":"…"}`: TUI admin session; also unlocks the vault if it is locked and the security checks pass.
  - `{"auth":"setup","v":1,"password":"…"}`: first-time password setup (only when no vault exists; in system mode only root/administrator).
  - Every failure is followed by a random delay (200–1000 ms) and a silent disconnect. After 3 consecutive password failures, exponential backoff applies (up to 1 hour).
- Access tokens are stored outside the vault in `tokens.json`, as SHA-256 only (tokens carry 256 bits of entropy, so the hash cannot be reversed). This lets the service recognize valid tokens while the vault is locked and reply "please unlock".

### 2.1 Crates

| Crate | Contents | C libraries |
|---|---|---|
| `pm-crypto` | Two-source RNG with health tests, Argon2id, ML-KEM-1024, Classic McEliece, two-layer envelope, startup self-tests | aws-lc, liboqs |
| `pm-vault` | Data model, domain rules, file format, atomic writes | via pm-crypto |
| `pm-platform` | Directory layout, TTY / agent-session detection, device-key sealing, security checks and account hardening, process hardening, service configuration templates | none (can be `cargo check`ed for Windows/macOS on its own) |
| `pm-proto` | Protocol types, frame I/O, blocking client | none |
| `pm-service` | Service: sessions, request dispatch, HTTPS / SSH / SFTP executors, redaction, tokens | via pm-crypto |
| `pm-tui` | Management UI (ratatui, keyboard + mouse), agent setup adapters | via pm-crypto (random key generation) |
| `passmanager` | The `PassManager` binary: CLI, MCP server, install / uninstall / harden / service entry points | — |

---

## 3. Cryptography

### 3.1 Libraries and algorithms

| Purpose | Library | Algorithm |
|---|---|---|
| Post-quantum #1 (lattice) | aws-lc-rs 1.18.1 (FIPS 140-3 validated module) | ML-KEM-1024 (FIPS 203) |
| Post-quantum #2 (code-based) | liboqs 0.13 (`oqs` crate, Classic McEliece only) | Classic-McEliece-6688128 (NIST level 5) |
| Symmetric / HKDF / RNG | aws-lc-rs | AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA-512, SystemRandom |
| Password KDF | RustCrypto `argon2` 0.5.3 | Argon2id |

Cryptographic dependencies are pinned exactly with `=`; everything else is locked by the committed `Cargo.lock`. `deny.toml` and `cargo deny` / `cargo audit` in CI handle supply-chain review.

### 3.2 Randomness (two sources)

```
out = HKDF-SHA512(salt = "pm/rng/v1" ‖ counter, ikm = getrandom(64) ‖ aws-lc SystemRandom(64))
```

- The output is secure as long as either source is sound. Both sources are read on every call and no state is cached, so it is fork-safe by construction.
- Startup health tests: 4 KiB is sampled from each source and checked with the SP 800-90B repetition count test (cutoff 6) and adaptive proportion test (window 512, cutoff 20); all-zero/all-one output and identical output from both sources are rejected.
- Continuous tests: every call compares the first 16 bytes of each source's output with its previous output, and the two sources with each other. Any failure is **fail-closed**: every later call returns an error.
- liboqs randomness is routed to the combined RNG through `OQS_randombytes_custom_algorithm`; if the RNG fails inside that callback, the process aborts.
- Startup self-tests (any failure refuses to run): known-answer tests for SHA-512 (FIPS 180-2), HKDF (RFC 5869), AES-256-GCM (GCM spec test case 14), ChaCha20-Poly1305 (RFC 8439 §2.8.2), and Argon2id (RFC 9106 §5.3); an ML-KEM round trip; liboqs availability; and a pairwise consistency test after each KEM key generation.

### 3.3 Key hierarchy

```
IKM    = Argon2id(NFKC(password), salt) ‖ device_key            # zeroized after use
KEK_A  = HKDF(salt=vault_id, IKM, "pm/v1/kek/A")
KEK_B  = HKDF(salt=vault_id, IKM, "pm/v1/kek/B")
wrap_A = AES-256-GCM(KEK_A, VK_A ‖ dk_mlkem)          aad = vault_id ‖ "pm/v1/wrap/A"
wrap_B = ChaCha20-Poly1305(KEK_B, VK_B ‖ sk_mceliece)  aad = vault_id ‖ "pm/v1/wrap/B"
kcv    = HKDF(salt=vault_id, device_key, "pm/v1/kcv")[..16]   # device key check value
```

### 3.4 Two-layer encryption on every save (fresh DEKs and nonces)

```
P = postcard(payload), padded to a multiple of 4 KiB; H = SHA-512(header)
Inner: (ct_M, ss_M) = McEliece.Encaps(pk_M)
       DEK_B = HKDF(VK_B ‖ ss_M, "pm/v1/dek/B" ‖ H ‖ ct_M)
       C1    = ChaCha20-Poly1305(DEK_B, nonce_B, P, aad = H)
Outer: (ct_K, ss_K) = ML-KEM-1024.Encaps(ek_K)
       DEK_A = HKDF(VK_A ‖ ss_K, "pm/v1/dek/A" ‖ H ‖ ct_K)
       C2    = AES-256-GCM(DEK_A, nonce_A, C1, aad = H ‖ ct_M)
```

An attacker must break the symmetric "password + device key" chain, ML-KEM, **and** McEliece to decrypt; a flaw in any single algorithm or library does not reduce overall security.

### 3.5 File format `vault.pmv`

```
"PMVAULT\0" | u32 LE header length | header (postcard) | SealedPayload (postcard)
header = { version, vault_id, seal_level, kcv, kdf{m_kib,t,p}, salt, ek_mlkem, pk_mce, wrap_a, wrap_b }
SealedPayload = { ct_mlkem, ct_mce, nonce_a, nonce_b, c2 }
```

- The header's SHA-512 is associated data for both AEAD layers, so tampering with any field makes decryption fail; the seal level is recorded in the header and downgrades are rejected.
- Hard KDF floors: memory ≥ 256 MiB, iterations ≥ 2. The default is 1 GiB / t=3 / p=4; memory is chosen from the machine's physical RAM, then iterations are increased until one run takes ≥ 1 second.
- Atomic writes: write a temp file → fsync → keep the old file as `.bak` → rename → fsync the directory. If the main file is missing, `.bak` is read.
- Changing the password only re-wraps `wrap_A` / `wrap_B`.

---

## 4. Device key sealing

| Level | Meaning |
|---|---|
| L3 | Hardware sealing (TPM): copying the data directory, a VM snapshot, or the whole disk to another machine does not allow unsealing |
| L2 | OS sealing: unsealing requires root / system rights on this machine |
| L1 | File permissions only (fallback; warned about in four places: end of install, TUI title bar, every unlock, diagnostics tab) |

| Platform | L3 | L2 | L1 |
|---|---|---|---|
| Linux (systemd ≥ 250) | `systemd-creds encrypt --with-key=host+tpm2 --tpm2-pcrs=` (not bound to PCRs, so firmware/kernel updates still unseal); loaded by the unit's `LoadCredentialEncrypted=`, plaintext only appears in the service's private `$CREDENTIALS_DIRECTORY` | Same with `--with-key=host` (`/var/lib/systemd/credential.secret`, root 0400) | Containers / no systemd: `device.key` owned by the service account (0600) |
| Windows | DPAPI (service account, user scope) seals `k_os`; the TPM (Platform Crypto Provider, non-exportable RSA) seals `k_hw`; `device_key = k_os ⊕ k_hw` | DPAPI only | — |
| macOS (unsigned) | **Not possible**: Apple DTS states that launchd daemons cannot use the Secure Enclave, and a LaunchAgent would run as the agent's user, breaking isolation | System keychain: launchd starts the service as root; it reads the item and then irreversibly drops privileges to `_passmanager`. The item is created by the installed binary, so the default ACL trusts only that binary; on upgrade the old binary exports the device key and the new binary re-creates the item (ACL rebinding). Fallback: a root-only file `/var/db/passmanager/device.key` (0400), likewise read in the root phase before dropping privileges | — |

- Post-quantum note: TPM2 sealing, DPAPI, and the system keychain are all symmetric constructions; the Windows TPM RSA key only provides "hardware binding", and the combination always keeps the symmetric `k_os`.
- **There is no recovery mechanism**: after a hardware failure, a TPM clear, an OS reinstall, or a move to another machine, the vault can never be opened again and credentials must be re-entered. The installer requires the user to confirm this explicitly.

---

## 5. Using credentials

### 5.1 Entries

`secret + domains (+ optional note)`. Advanced options: self-signed certificate (enables fingerprint pinning, for public and internal hosts alike), and auto-accepting host-key changes for private-key entries.

- No name is required: each entry gets an **automatic reference name** (from its first domain, e.g. `*.github.com` → `github.com`, with `-2` added on collisions). Agents normally do not need it — write `{{secret}}` in HTTP and `user@host` for SSH/SCP, and the service picks the entry by host. The reference name is only needed when one host has several secrets (`{{name}}` / `name/user@host`); in that case `AMBIGUOUS` is returned with the choices.
- Domains: `example.com` matches only itself; `*.example.com` matches itself and subdomains at any depth; IPs match exactly. A wildcard base cannot be a public suffix (including private sections), so `*`, `*.com`, `*.co.uk`, and `*.github.io` are rejected. An exact match names a single host, so only ICANN suffixes themselves (`com`, `co.uk`) are rejected and hostnames in private sections such as `github.io` or `httpbin.org` are allowed.
- The SSH authentication method is chosen from the secret's content: `-----BEGIN … PRIVATE KEY-----` is a private key, anything else is a password.

### 5.2 Tools (MCP and CLI correspond one to one)

| MCP tool | CLI | Behavior |
|---|---|---|
| `list` | `PassManager list` | Hosts with stored secrets (reference name, domains, note) |
| `http(method, url, headers?, body?)` | `PassManager http [METHOD] URL [-X] [-H 'K: V'] [-d BODY \| -d @file \| --json BODY]` | Write `{{secret}}` in headers / body / URL query and the secret for the URL's host is selected; HTTPS only; no cross-host redirects; `Set-Cookie` and auth-related response headers are removed; body and headers are redacted |
| `ssh(target, command)` | `PassManager ssh [-p port] [-l user] user@host[:port] command…` | Built-in russh; falls back to keyboard-interactive if password auth fails; commands starting with `sudo ` become `sudo -k -S -p ''` with the password supplied on stdin; output is redacted |
| `scp(source, destination)` | `PassManager scp [-P port] source destination` | Write the remote side as `user@host:/path`; SFTP upload (create/truncate) or download (content redacted, 64 MiB limit); local files are read and written by the client as the current user |

Compatibility: the MCP tools also accept older names (`list_credentials`, `http_request`, `ssh_exec`, `ssh_upload`/`ssh_download`) and common argument shapes (headers as an object / array / `"K: V"` text, body as a JSON object, ssh with separate `host`/`user`/`port`, scp with `from`/`to`), but the tool list only advertises the four above. The CLI accepts common curl, OpenSSH, and scp options and ignores unrelated ones such as `-s`, `-L`, `-t`, `-o …`. Clients locate the local service without environment variables (Linux uses `/run/user/<uid>`, Windows derives the pipe name from the user SID), so it also works in MCP child processes with a minimal environment.

The MCP server speaks newline-delimited JSON-RPC 2.0 over stdio, supports protocol versions 2025-11-25 / 2025-06-18 / 2025-03-26 / 2024-11-05, and includes three sentences of usage guidance in `instructions`. Error messages tell the agent what to do next:

| Code | Meaning |
|---|---|
| `LOCKED` | The vault is locked: `Ask the user to run: PassManager unlock` |
| `NOT_READY` | Security checks failed: `Ask the user to run: PassManager` |
| `NOT_INITIALIZED` / `NOT_RUNNING` | Not installed yet: `sudo PassManager install` |
| `DOMAIN_MISMATCH` | `"github" only works with *.github.com` |
| `USE_HTTPS` | Plain HTTP is not supported (not even on internal networks) |
| `NO_CREDENTIAL` | No secret is stored for this host |
| `AMBIGUOUS` | This host has several secrets; their reference names are listed |
| `UNKNOWN_CREDENTIAL` | The given reference name does not exist |
| `HOST_KEY_CHANGED` | SSH host key / self-signed certificate fingerprint changed, **nothing was sent**: `Ask the user to run: PassManager trust <host>` |
| `AUTH_FAILED` / `AUTH_REJECTED` / `UPSTREAM_ERROR` / `BAD_REQUEST` / `FORBIDDEN` | Other errors |

### 5.3 Output redaction

For each secret, variants are generated: the raw value, the value with whitespace removed, Base64 (standard / URL-safe, each at 3 byte-alignment offsets, keeping only the characters fully determined by the secret, which also covers `user:pass` Basic encoding), hex in both cases, percent-encoding (everything encoded / RFC 3986 unreserved kept / form encoding, each with upper- and lowercase escapes), JSON escaping, HTML escaping, and every line of length ≥ 16 in multi-line secrets (PEM). A single Aho-Corasick pass (leftmost-longest) replaces matches with `[REDACTED:name]`. Upstream errors included in error messages are redacted too, with URLs removed.

### 5.4 Fingerprint changes

- Recorded automatically on first connection (per `host:port`): the SSH host key (`SHA256:…`), or the SHA-256 of a self-signed certificate's SubjectPublicKeyInfo.
- When a fingerprint changes, the connection is aborted **before authentication / during the TLS handshake**, no credentials are sent, the change is added to a "pending" list, and `HOST_KEY_CHANGED` is returned.
- The user runs `PassManager trust db1.example.com` (no port needed; it clears the records for all ports of that host; `*.example.com` works in bulk; `host:port` clears just one port). A single-purpose dialog shows the old and new fingerprints, the user enters the password and confirms, and the program exits. The command requires a real TTY and refuses to run inside an agent session.

---

## 6. Security checks and account hardening (`PassManager harden`)

Recommended setup: disable the built-in administrator (root / Administrator); use a normal account with administrator rights day to day, where **every elevation requires a password**; never run agents elevated.

Flow: checks at install → two groups are listed, "will be fixed automatically" and "needs your action" → after one confirmation the automatic fixes are applied (backed up first to `hardening-backup/` under the data directory; `--restore-hardening` on uninstall restores them) → re-check. **The vault can only be unlocked when every required check passes** (items marked "recommended" only warn; currently just FileVault on macOS). If a check starts failing after unlock, the agent's next request locks the vault immediately (readiness is cached for 10 seconds). The service re-checks on every start (Linux: `ExecStartPre=+PassManager service-prepare`; macOS: in the root phase; Windows: a boot-time scheduled task running as SYSTEM), and the report must be owned by root and not writable by others. The TUI's diagnostics tab offers `[Re-check]` and `[Fix]` (one sudo / UAC prompt).

| Platform | Fixed automatically (after checking the safety preconditions) | Needs user action |
|---|---|---|
| Linux | Lock root (if the current user can sudo and has a password); change `NOPASSWD:` to `PASSWD:` and comment out `!authenticate` (if the user has a password; written only after `visudo -c` passes); write `/etc/sudoers.d/zz-passmanager-hardening` (`timestamp_type=tty`, 5 minutes); lock other accounts with empty passwords; service account set to nologin, locked, and removed from admin groups; fix owner and permissions of the data directory, vault, device key, socket directory, program file, and service unit | The current user has no password; membership in docker / lxd / incus / disk; programs on PATH with `cap_dac_*` / `cap_setuid` / `cap_sys_ptrace` / `cap_sys_admin` |
| macOS | Disable root; sudoers as above; turn off automatic login; service account shell set to `/usr/bin/false`; file permissions | Empty user password; SIP disabled; (recommended) enable FileVault |
| Windows | Disable the built-in Administrator (if another enabled administrator with a password exists); UAC `EnableLUA=1`, `ConsentPromptBehaviorAdmin=1` (elevation asks for a password), `PromptOnSecureDesktop=1`; disable Guest; data directory ACL limited to SYSTEM and the service SID; reset the program file ACL | Membership in Backup Operators; `SeDebugPrivilege` / `SeBackupPrivilege` granted directly; administrator accounts without a password |

User mode (`install --user`, the fallback without administrator rights) has no account isolation, skips account hardening, and shows the L1 warning permanently.

---

## 7. Usability

- One-step install: Linux/macOS `sudo ./PassManager install`; Windows: double-click `PassManager.exe` (one UAC prompt). The installer copies the program to a path only root can write (Linux `/usr/local/bin`; macOS `/Library/PassManager`, linked into `/usr/local/bin`, because `/usr/local/bin` belongs to the user on many Macs; Windows `C:\Program Files\PassManager`), creates the service account, generates the device key and seals it at the highest available level, registers and starts the service, hardens the account, sets the password (confirming "no recovery", showing strength), and finally opens the TUI.
- The TUI runs on demand and exits when done (the service keeps the unlocked state; the TUI exits after 15 idle minutes): `PassManager` (full UI), `PassManager unlock`, `PassManager trust <host>`. Keyboard and mouse both work: click to select, double-click to edit, scroll with the wheel, click tabs / button bars / dialog buttons, and paste (multi-line private keys).
- Five tabs: entries, hosts, agents, diagnostics, settings (idle auto-lock, 12 hours by default; change password; lock now).
- The agents tab detects Claude Code (preferring `claude mcp add`), Codex CLI, Cursor, Gemini CLI, VS Code, and Windsurf and connects them in one step: it creates a dedicated token for that agent and merges it into the agent's MCP configuration (backing up the original file first and adding only the `passmanager` entry). For other agents it shows a configuration snippet to copy (the token is shown only once).

---

## 8. Differences from the original plan

| Plan | Implementation | Reason |
|---|---|---|
| MCP via the official `rmcp` SDK | Hand-written stdio JSON-RPC (about 250 lines, `crates/passmanager/src/mcp.rs`) | Only initialize / tools/list / tools/call / ping are needed; fewer dependencies and less attack surface, unaffected by frequent SDK API changes |
| Token hashes stored inside the vault | Stored outside the vault in `tokens.json` (SHA-256 only) | Valid tokens must be recognized while the vault is locked to reply "please unlock", while invalid tokens still get silence |
| — | HTTPS requests must contain at least one `{{secret}}` placeholder | Prevents the service from being used as a general HTTP proxy |
| `mlock` for in-memory secrets | Linux: the unit sets `MemorySwapMax=0`, so the whole service process is never swapped out; other platforms rely on OS-encrypted swap (macOS encrypts swap by default; Windows can encrypt the page file). Secrets are zeroized with `zeroize`, and core dumps are disabled (plus `PR_SET_DUMPABLE=0` on Linux) | Argon2id needs 1 GiB of memory, and `mlockall` would hit the locked-memory limit and fail allocations; disabling swap per cgroup is more thorough |
| Socket directory group = the installing user's primary group | True on Linux; macOS uses a dedicated group `_passmanager_clients` (the installing user is added to it) | On macOS the primary group `staff` is shared by all local users |

---

## 9. Verification status

CI runs on 6 native GitHub runners: Linux (ubuntu-latest, ubuntu-24.04-arm), macOS (macos-latest = Apple silicon, macos-15-intel), Windows (windows-latest, windows-11-arm).

| Item | Coverage | Status |
|---|---|---|
| Unit tests: KATs, RNG health tests and stuck-source fail-closed, KEM tampering, two-layer envelope, bit-flip / wrong password / wrong device key / level downgrade, domain rules, sudoers rule matching, every redaction encoding, placeholders, HTTP request rules, MCP protocol and argument compatibility, CLI arguments (curl / ssh / scp forms), agent config merging (JSON/TOML), TUI rendering and mouse hit-testing | 6 runners | Pass |
| End-to-end tests (`crates/passmanager/tests/e2e.rs`): a real service process + a local self-signed HTTPS echo server + a russh test SSH/SFTP server, covering anti-probing, tokens, entry management, automatic `{{secret}}` selection by host, filling and redaction (including base64 / hex / URL-encoded echoes), domain restrictions, HTTPS only, no cross-host redirects, self-signed certificate pinning and rotation, SSH exec and host-key changes, SFTP upload and redacted download, revealing plaintext, token revocation, locking, MCP and CLI | 6 runners | Pass |
| Pseudo-terminal TUI smoke test (`tests/tui_pty_smoke.py`) | Linux, macOS (Windows has no pty; unit tests only) | Pass |
| System mode: install (service account, device-key sealing, service start) → security checks → set password → probe (invalid token silently rejected) → uninstall | 6 runners | Pass. Actual sealing: Linux systemd-creds host key (L2, runners have no TPM), macOS System keychain (L2, read in the root phase before dropping privileges, no prompt), Windows DPAPI (L2, runners have no TPM). The runner account can elevate without a password, so the security checks fail as expected and the vault stays locked |
| Full flow after hardening: set the user password, leave the docker group, `install --yes` hardens automatically → all checks pass → unlock → run the agent flow as a normal user with a token (HTTPS filling and redaction) | Linux x64 / arm64 | Pass |
| Release packages: built on each platform's native runner, then unpacked and run directly (real Argon2id parameters); the macOS universal binary also runs its x86_64 part under Rosetta | Linux x64 / arm64, macOS, Windows x64 / arm64 | Pass |
| Local cross-builds (`scripts/cross-build.sh`, Zig) | Linux x64 / arm64, Windows x64 | Pass |
| Not yet verified | Real Linux / Windows machines with a TPM (L3), macOS keychain ACL rebinding on upgrade, the full flow on hardened Windows, the L1 warning in an Alpine container | — |

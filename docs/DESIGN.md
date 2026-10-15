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
- Optional third source (server mode): the TPM (`TPM2_GetRandom` over `/dev/tpmrm0` or a configured swtpm socket) is mixed into the IKM when it passes a 1 KiB startup health test; any later failure disables only that source (§10.4).
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
- Version 2 headers (passwordless server mode) add a mode byte; see §10.3. Reads fall back to `.bak` only when the main file is missing or corrupt.
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
- Domains: `example.com` matches only itself; `*.example.com` matches subdomains at any depth but **not** `example.com` itself (since 0.2.0 — list the apex separately), nor lookalikes such as `badexample.com` or `example.com.evil.net`; IPs match exactly; CIDR ranges (`198.51.100.0/24`, `2001:db8::/48`, host bits zero, at least /8 resp. /32) match literal IP targets only — a name that resolves into the range does not match. Names are compared lowercased, without a trailing dot, and IDNA-normalized (punycode). Any form can carry `:port`. When several entries match one target, the most specific wins (exact host or IP > longer wildcard > longer CIDR prefix; with a port beats without); equal candidates are an `AMBIGUOUS` error that lists only reference names. Entries can be restricted to operations (`ops`: `http`, `ssh` — including scp and the ssh-agent bridge —, `git`). `*` must be the whole leftmost label and be followed by at least two labels. A wildcard base cannot be a public suffix (including private sections), so `*`, `*.com`, `*.co.uk`, and `*.github.io` are rejected. An exact match names a single host, so only ICANN suffixes themselves (`com`, `co.uk`) are rejected and hostnames in private sections such as `github.io` or `httpbin.org` are allowed.
- The SSH authentication method is chosen from the secret's content: `-----BEGIN … PRIVATE KEY-----` is a private key, anything else is a password.

### 5.2 Tools (MCP and CLI correspond one to one)

| MCP tool | CLI | Behavior |
|---|---|---|
| `lookup(target, use?)` | `PassManager lookup TARGET [--use http\|ssh\|scp\|git]` | Need-to-know discovery: for one URL, `user@host` or host (or `{{name}}` when the base URL itself is secret) it returns only the reference name(s), field names and a ready-to-copy call (`how`), chosen by exactly the same rules as the real request. Never other entries, other domains of the entry, notes or the `ops` list |
| `http(method, url, headers?, body?)` | `PassManager http [METHOD] URL [-X] [-H 'K: V'] [-d BODY \| -d @file \| --json BODY]` | Write `{{secret}}` in headers / body / URL query and the secret for the URL's host is selected; HTTPS only; no cross-host redirects; `Set-Cookie` and auth-related response headers are removed; body and headers are redacted |
| `ssh(target, command)` | `PassManager ssh [-p port] [-l user] user@host[:port] command…` | Built-in russh; falls back to keyboard-interactive if password auth fails; commands starting with `sudo ` become `sudo -k -S -p ''` with the password supplied on stdin; output is redacted |
| `scp(source, destination)` | `PassManager scp [-P port] source destination` | Write the remote side as `user@host:/path`; SFTP upload (create/truncate) or download (content redacted, 64 MiB limit); local files are read and written by the client as the current user |

Compatibility: `list` (and `list_credentials`) no longer lists anything; it returns `USE_LOOKUP`. The MCP tools also accept older names (`http_request`, `ssh_exec`, `ssh_upload`/`ssh_download`) and common argument shapes (headers as an object / array / `"K: V"` text, body as a JSON object, ssh with separate `host`/`user`/`port`, scp with `from`/`to`), but the tool list only advertises the four above. The CLI accepts common curl, OpenSSH, and scp options and ignores unrelated ones such as `-s`, `-L`, `-t`, `-o …`. Clients locate the local service without environment variables (Linux uses `/run/user/<uid>`, Windows derives the pipe name from the user SID), so it also works in MCP child processes with a minimal environment.

The MCP server speaks newline-delimited JSON-RPC 2.0 over stdio, supports protocol versions 2025-11-25 / 2025-06-18 / 2025-03-26 / 2024-11-05, and discloses usage progressively: `instructions` (at most five lines: lookup first, copy `how`, never reveal secrets, follow `Next:`) → tool descriptions (two or three sentences plus one minimal example each, with `readOnlyHint`/`destructiveHint`/`openWorldHint` annotations; a test caps the whole tool list in size) → `lookup`'s `how` → a `Next:` line appended to every error by code (`pm_proto::agent_text::next_step`). Error messages do not list an entry's domains or allowed operations:

| Code | Meaning |
|---|---|
| `LOCKED` | The vault is locked: `Ask the user to run: PassManager unlock` |
| `NOT_READY` | Security checks failed: `Ask the user to run: PassManager` |
| `NOT_INITIALIZED` / `NOT_RUNNING` | Not installed yet: `sudo PassManager install` |
| `DOMAIN_MISMATCH` | `"github" is not bound to evil.example` (the bound domains are not listed); Next: `ssh root@<server> passmanager update --name … --domain …` |
| `OP_NOT_ALLOWED` | The entry may not be used for this operation; Next: `passmanager update --add-op …` |
| `USE_LOOKUP` | The removed `list` was called; Next: call `lookup` |
| `USE_HTTPS` | Plain HTTP is not supported (not even on internal networks) |
| `NO_CREDENTIAL` | No secret is stored for this host; Next: import it on the server without displaying it (`… \| ssh root@<server> passmanager import …`) |
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

---

## 10. LAN server mode (online edition)

The single-machine design above is unchanged. Server mode is a second deployment shape: one PassManager server on the LAN (for example `pm.example.com` resolving to a private address), agents on other machines, a web admin UI, and root commands on the server. It is enabled by `passmanager init` (the `server` section in the root-owned `install.json`).

### 10.1 Network threat model

| ID | Threat | Mitigation |
|---|---|---|
| N1 | Someone outside the LAN reaches the service | Ports 443 (web) and 8443 (agents) only; IPv4 only; the source address is checked in the application against the configured CIDRs (`--lan-cidr`, required, no default: without it the network listeners refuse to start) before any TLS handshake; `install-server.sh` adds an nftables table that drops everything except those CIDRs → 22/web/agent ports and drops all IPv6; IPv6 is disabled with `/etc/sysctl.d/99-disable-ipv6.conf`. The DNS name resolves to a private address, so the certificate is the only public artifact. |
| N2 | A passive attacker records traffic now and breaks it later (quantum) | Outer TLS 1.3 accepts only the hybrid groups X25519MLKEM768 / SecP256r1MLKEM768 and only TLS_AES_256_GCM_SHA384, no 0-RTT; the agent channel adds an inner layer keyed by ML-KEM-1024 **and** Classic McEliece 6688128 (two families, two libraries). |
| N3 | Active MITM with a mis-issued certificate | The agent pins the SHA-384 fingerprint of the server's inner static keys from the enrollment code (not TOFU). The inner key confirmation is bound to the TLS exporter, so terminating TLS and relaying the inner bytes fails. |
| N4 | A LAN device probes the agent port | Only `Hello::Token` and `Hello::Enroll` are accepted over the network; `Password`, `Setup` and `Root` are silently rejected; every failure gets the same random delay and silent close. |
| N5 | Web UI attacks (CSRF, XSS, DNS rebinding, clickjacking) | Server-rendered pages with no JavaScript, CSP `default-src 'none'`; Host check; Fetch Metadata + Origin checks; CSRF token on every POST; `__Host-` cookie (HttpOnly, Secure, SameSite=Strict); 64 KiB body limit; per-source limits on invalid login links; every template has an XSS injection test. |
| N6 | Web login credentials are stolen | There are none: login only via a one-time link printed by `passmanager login` (root on the server, i.e. whoever holds the SSH key). The link lives 2 minutes, GET shows a confirmation page, POST consumes it. Sessions expire after 2 h idle / 12 h absolute and live only in memory. |
| N7 | Secrets leak through the web UI | Secrets are write-only: no page or response contains them (tested), forms never echo them back, and `Reveal` is refused in server mode. |
| N8 | A stolen agent token | It can only *use* credentials (never see them) and only from the LAN; revocation is immediate (web or `passmanager token revoke`). Tokens are delivered only once, through the double-encrypted channel during enrollment, and stored on the agent in a 0600 file (never written into MCP configs). |

### 10.2 Agent channel construction

```
TCP (IPv4, LAN source only) → TLS 1.3 [X25519MLKEM768 + AES-256-GCM, ALPN pm-inner/1] → inner layer → existing local protocol (handle_conn)

server static keys:   ML-KEM-1024 (aws-lc-rs) + Classic McEliece 6688128 (liboqs), private parts sealed with the device key
bundle   = "PMK1" ‖ len‖ek_mlkem ‖ len‖pk_mceliece           (~1 MB, downloaded once at enrollment and cached)
fpr      = SHA-384("pm/inner/v1/fpr\0" ‖ bundle)             (in the enrollment code, pinned in remote.toml)

C → S  "PMIN" ‖ 0x01 ‖ 0x02 ‖ nonce_c ‖ fpr ‖ ct_K ‖ ct_M     (ct_K/ss_K = ML-KEM.Encaps, ct_M/ss_M = McEliece.Encaps)
S → C  nonce_s ‖ tag_s ;  C → S  tag_c
E    = TLS exporter("EXPORTER-PassManager-inner-v1", 64)
th   = SHA-512("pm/inner/v1/transcript" ‖ client message ‖ nonce_s)
okm  = HKDF-SHA512(salt = nonce_c ‖ nonce_s, ikm = ss_K ‖ ss_M ‖ E, info = "pm/inner/v1/keys" ‖ th)
k_c2s, k_s2c, k_fin = okm[0..32], okm[32..64], okm[64..112]
tag_s = HMAC-SHA384(k_fin, "…server-finished" ‖ th);  tag_c = HMAC-SHA384(k_fin, "…client-finished" ‖ th)
frame = u32 len ‖ ChaCha20-Poly1305(k_dir, nonce = dir ‖ 0³ ‖ counter_u64, aad = "pm/inner/v1/frame" ‖ len, ≤64 KiB)
```

- Only a server holding both private keys can produce `tag_s`; a relay through another TLS connection has a different `E` and fails.
- The version and operation bytes are part of the transcript; the server only accepts version 1 (downgrade attempts fail).
- Each direction has its own key and an implicit counter (not transmitted): replayed, reordered, dropped or reflected frames fail authentication and close the connection. The outer layer is AES-GCM and the inner layer ChaCha20-Poly1305 (different algorithms).
- The server wraps the inner session as an `AsyncRead + AsyncWrite` (a duplex pipe with two pumps) and hands it to the unchanged `handle_conn`; the agent side wraps it as `Read + Write` for the existing blocking client, so MCP and CLI usage are unchanged.

Enrollment: `passmanager show --label <label> --url` (root) prints `pm-enroll://<domain>:<port>/<code>#<fpr>` (32 random bytes, 10 minutes, single use — taken out and invalidated atomically, so of concurrent redeems exactly one succeeds — only its SHA-256 is kept, in memory; failed redeems are rate-limited per source address, 10 per 10 minutes → 15 minutes lockout; the audit log records label, source address and result, never the code). `show --label <label>` prints the full agent guide around such a code (§10.10). `passmanager enroll <code>` fetches the bundle, verifies `fpr`, opens an inner session, exchanges the code for a fresh token, and writes `remote.toml`, `token` (0600) and `server-keys.bin` under `~/.config/passmanager` plus the MCP config of detected agents (without the token).

### 10.3 Passwordless vault mode — and its trade-offs

```
KEK_A = HKDF(salt = vault_id, ikm = device_key, info = "pm/v2/kek/A" ‖ "device-only" ‖ salt)   (KEK_B likewise)
header v2 = v1 fields + mode byte (device-only); the header hash remains the AAD of both payload layers
```

- No Argon2 (small servers and containers, e.g. 1 GiB RAM, are fine); the service unlocks automatically at start. v1 (password) vaults are byte-for-byte unchanged.
- Downgrade protection: the mode is in the authenticated header **and** in the HKDF info; a device-only vault rewritten to look like a password vault (or the reverse) fails to open; the password APIs refuse device-only vaults and vice versa; the seal level may only go up (`reseal`), and the `.bak` fallback is used only for corrupt files, never to bypass a policy failure.
- **Trade-off, stated plainly:** whoever is root on the server — or, without a TPM, whoever has the disk, a snapshot or a backup — has the vault. The only administrative credential is therefore the SSH key that gives root on the server. There is **no recovery path**: no online sync, no backup, no export.

### 10.4 Device key, TPM and the boot sequence

- Sealing: `systemd-creds --with-key=host+tpm2 --tpm2-pcrs=` (L3) when a TPM works, otherwise `--with-key=host` (L2). The TPM is `/dev/tpmrm0` (auto-detected) or, optionally, a swtpm Unix socket configured with `--tpm-socket` (for example a software TPM that a hypervisor host provides to a container; preferred when configured); in socket mode every `systemd-creds` call gets `SYSTEMD_TPM2_DEVICE=swtpm:path=…` and, when run by root, the `tss` group (the socket is `nobody:tss 0660`, and `ExecStartPre=+` processes have no supplementary groups). Detection is an encrypt/decrypt round trip plus a check of the credential header ID (`has-tpm2` only looks at kernel devices).
- `passmanager reseal` upgrades L2 → L3: decrypt, re-encrypt to `.new`, verify header and round trip, stop the service, rename, update `install.json`, mark the vault header L3, start. Every step can be re-run after a crash.
- **What the TPM gives:** a stolen disk image, snapshot or backup cannot be decrypted without this TPM state; moving the container elsewhere does not work either. **What it does not give:** root inside the running container can still ask the TPM to unseal; the hypervisor host root can read container memory. **No PCR binding**, because an LXC container has no boot measurements of its own (PCRs reflect the host firmware/kernel, so binding would break on every host update). **Cost:** losing the swtpm state, clearing the TPM, or migrating to another node makes the vault permanently unreadable.
- Unprivileged LXC cannot use `LoadCredentialEncrypted=`, so `ExecStartPre=+PassManager service-prepare` (root) decrypts the device key into `/run/passmanager-key/device.key` (service account, 0400); the service reads and deletes it, `ExecStopPost` removes leftovers.
- The TPM is also a third, optional entropy source (`TPM2_GetRandom` over the swtpm socket or `/dev/tpmrm0`, 1 KiB SP 800-90B sample before use, continuous test; any failure permanently disables only that source).

### 10.5 Robustness (hard reset, kill -9, power loss)

- Unit: `After=/Wants=network-online.target`, bounded wait (60 s) for the TPM in `ExecStartPre`, `Restart=on-failure` with `StartLimitIntervalSec=900`/`StartLimitBurst=10`. Exit code **78** only for real configuration errors (bad `install.json`, missing keys, undecryptable device key, downgraded vault, no permission for privileged ports) together with `RestartPreventExitStatus=78`; transient failures (TPM not yet present, port busy) exit 75 and are retried.
- Every persistent file is written atomically (temp file → fsync → rename → fsync dir): vault, tokens, `install.json`, sealed keys, certificates, ACME state. Crash-injection tests cover a half-written temp file, a crash before the backup update and a crash before the rename. Reading falls back to `.bak` when the main file is missing, truncated or corrupt, and the first save after such a recovery does not overwrite the good `.bak`.
- Certificates: a stored certificate is used as long as it is valid; renewal (every 6 h, 30-day window) failing never blocks startup; failures back off from 10 minutes to 6 hours with the failure count persisted, so restart loops do not hammer Let's Encrypt.

### 10.6 Commands

| Where | Command | Purpose |
|---|---|---|
| server (root) | `passmanager init [--cf-token-stdin] [--skip-acme] …` | device key, inner keys, passwordless vault, certificate, systemd unit (idempotent) |
| server (root) | `passmanager login` | one-time web login link |
| server (root) | `passmanager token list` / `revoke <id>` | tokens and pending enrollment codes |
| server (root) | `passmanager status` / `lock` / `unlock` / `reseal` | status, lock, unlock, L2 → L3 |
| server (root) | `passmanager import --name <n> [--domain …] [--kind ssh-key] [--fields a,b] [--replace]` | import a secret from stdin |
| server (root) | `passmanager show --label N [--url] [--lang en]` | one-time code + the text block for an AI agent (`--url`: only the code) |
| anywhere | `passmanager show [--rules] [--lang en]` | public guide without a code (names the server when enrolled) / only the rules |
| agent | `passmanager enroll 'pm-enroll://…' [--no-instructions] [--no-git-proxy]` | join the server; configures MCP, the usage rules and the git-proxy service |
| agent | `passmanager unenroll` | remove the configuration, rules and git-proxy service |
| agent | `passmanager ssh-agent [--socket PATH]` | OpenSSH agent bridge (Unix) |
| agent | `passmanager git-proxy [--listen 127.0.0.1:PORT] [--install \| --uninstall]` | git credential-injecting proxy; `--install`: user service + `insteadOf` lines |
| server | `scripts/install-server.sh` | one-step server installer (`DRY_RUN=1` for tests) |

### 10.7 Entries: multi-field secrets and SSH keys

- An entry holds either one value (`secret`) or named fields (`username`, `password`, `token`, …). Field names are
  `[a-z0-9_-]`, unique, non-empty values. The 0.1.0 payload format is still read and is rewritten in the new format on the next save.
- Placeholders: `{{secret}}` = the single value of the entry selected by host (an error for multi-field entries, telling the agent to
  name a field); `{{name}}` = a named single-value entry; `{{name.field}}`; `{{field}}` only when exactly one entry matches the host.
  Errors never list other entries' fields. `sudo` uses the `password` field (or the single value of a password entry).
- A URL that starts with `{{entry}}` / `{{entry.field}}` (typically `{{ai.base_url}}`, optionally followed by a path or query) uses
  that value raw as the base: it must be an absolute https URL without user info, the text after it must not change scheme, host,
  port or user info, and the resulting host must be bound to that entry and to every other placeholder in the request. Messages and
  logs name the placeholder, never the URL. `{{secret}}` and bare field names cannot start a URL (they depend on the host).
- Redaction covers every field value in all encodings, also per line for multi-line values (≥ 8 characters per line); for URL values
  also the path and query on their own.
- SSH: when a key entry and a password entry both match the host, the key is tried first; the password entry is used only if the key is rejected and the server still offers `password` / `keyboard-interactive` (e.g. a default initial password bound to `*.example.com` and a LAN CIDR with `--ops ssh`). `sudo` uses the password entry.
- SSH key entries (`ssh-key`) hold an unencrypted private key; only the public key and its SHA-256 fingerprint are ever displayed.
  Host keys bound to the entry (`SHA256:…`) are checked in addition to the TOFU pin store.

### 10.8 ssh-agent bridge

`passmanager ssh-agent` serves the OpenSSH agent protocol on a 0600 Unix socket and forwards `REQUEST_IDENTITIES` / `SIGN_REQUEST`
over the agent channel. The server signs only if (1) the client sent `session-bind@openssh.com` for this connection and it is not a
forwarded session, (2) the host key's signature over the session identifier verifies, (3) that host key is allowed for the entry,
(4) the data is a `publickey` `SSH_MSG_USERAUTH_REQUEST` for the same session identifier and the same public key, and (5) the rate
limit (30/min) is not exceeded. Every signature and every refusal is written to the audit log (entry, key and host-key fingerprints only).
Residual risk: a compromised agent machine can still log in to the allowed hosts while the bridge runs — but cannot copy the key.

### 10.9 git credential proxy

`passmanager git-proxy` listens on loopback only, requires a random 128-bit path token (0600 file), and forwards one smart-HTTP
request per connection as a stream (request frames, then a response head, then response frames, 64 KiB each). The server accepts only
`GET …/info/refs?service=git-upload-pack|git-receive-pack` and `POST …/git-upload-pack|git-receive-pack` over HTTPS to hosts bound to
the entry, drops client `Authorization` / `Cookie`, forwards a small header whitelist, adds `Authorization: Basic base64(user:PAT)`,
refuses redirects, redacts non-pack responses, and aborts a pack stream if the raw token appears in it. Self-signed upstreams are pinned
like HTTPS entries. The audit log records entry, host, service, status and byte counts.

### 10.10 One-step agent onboarding

`passmanager show --label <name>` (root on the server) creates an ordinary enrollment code and prints one block of text for an AI
agent. Nothing in it is secret except that code (10 minutes, single use, only its SHA-256 is kept in memory). The text comes from a
single source (`pm_proto::agent_text`); without `--label`, or for anyone but root on the server, `show` prints the public variant
of the same guide with placeholders instead of a code.

- `GET /a/<code>` on the web port returns a POSIX sh script generated for that code: it embeds the full `pm-enroll://…#<fpr>` URL
  and the SHA-256 of every client binary in `/var/lib/passmanager/agent-bin/` (copied there by the installer; nothing is downloaded at
  request time). The script and the binaries travel over the same PQ-only TLS as the web UI; the SHA-256 check protects against a
  corrupted or swapped download, and `enroll` still pins the inner server key fingerprint, so a tampered binary or script would
  have to come from the server itself.
- Fetching `/a/<code>` or a binary does not consume the code; `enroll` does. Unknown/expired codes answer 404 without detail;
  only GET/HEAD; per-source limits (30 requests and 10 unknown codes per 10 minutes → 15 minutes lockout); every hit is audited
  (code id, what was fetched, source address); the CIDR check happens before the TLS handshake as for every web request.
- Fallback: clients whose TLS stack lacks X25519MLKEM768 cannot connect at all (by design). The block then tells the agent to build
  the client from source at the release tag and commit of the running server (embedded at build time from the tag build — `GITHUB_*`
  in CI, `PASSMANAGER_RELEASE_TAG`/`PASSMANAGER_RELEASE_COMMIT`, or a clean checkout at tag `v<version>`), and to refuse if
  `git rev-parse HEAD` differs. Development builds print a note instead of an unverifiable pin.
- `enroll` writes the usage rules between `<!-- passmanager:begin -->` and `<!-- passmanager:end -->` in the global instruction
  files of detected agents (Claude Code `~/.claude/CLAUDE.md`, Codex `~/.codex/AGENTS.md`, Gemini CLI `~/.gemini/GEMINI.md`,
  Windsurf `global_rules.md`): updated in place, never duplicated, previous content kept as `*.passmanager.bak`, refused when the
  markers are damaged, removed by `unenroll` / `uninstall`.
- `enroll` (both the one-liner and the source-build fallback) also makes git over HTTPS work for every entry the agent can use
  that has the `git` op — GitHub, self-hosted forges and others are treated identically: it installs `git-proxy` as a per-user
  service (systemd user unit with `Restart=on-failure` and `RestartPreventExitStatus=78`, `loginctl enable-linger` attempted with
  `--no-ask-password` and documented when not permitted; a LaunchAgent on macOS; printed `schtasks` steps on Windows) and replaces
  the PassManager-managed `url.<loopback proxy>/<path-token>/https/<host>/.insteadOf` lines in the global git configuration. The
  128-bit path token is stored persistently (0600) in the client configuration directory, so the lines survive restarts; managed
  lines are recognised by a loopback address plus a 32-hex path token, so re-running replaces and never duplicates. The host list
  comes from the token-only `git_hosts` request, which returns just the domains of entries whose `ops` include `git`; `git-proxy` without `--host` uses the same list. The
  PAT stays on the server.

# PassManager LAN server: deployment guide

English | [简体中文](DEPLOY-LAN.zh-CN.md)

All names and addresses below are examples (`example.com`, RFC 5737 documentation ranges); use your own values.
Design and threat model: [`DESIGN.md`](DESIGN.md) §10.

## 0. Prerequisites

- Server: Linux with systemd ≥ 250 (e.g. Debian 13). 1 GiB RAM is enough (passwordless mode runs no Argon2; the service uses about 20 MB).
- A domain such as `pm.example.com` with an A record pointing to the server's private IPv4 address (e.g. `198.51.100.10`).
- Certificates: Let's Encrypt DNS-01 via Cloudflare. Use an API token limited to Zone → DNS → Edit for that zone; it is passed on
  **stdin** (first line) and sealed with the device key. Without ACME use `--skip-acme` and later `passmanager import-cert`.
- The allowed client CIDR(s) — required, there is no default — e.g. `198.51.100.0/24`.
- The only admin credential is the SSH key that gives root on the server; the web UI has no password (one-time links printed by root).

## 1. Server (root)

```sh
tar xzf PassManager-0.2.0-lan-x86_64-linux.tar.gz && cd PassManager-0.2.0-lan-x86_64-linux
./install-server.sh --domain pm.example.com --lan-cidr 198.51.100.0/24 < /root/cf-token
# or keep the values in a local, never-committed file:
#   DOMAIN=pm.example.com / LAN_CIDRS="198.51.100.0/24 203.0.113.0/24" / TPM_SOCKET=… / WEB_PORT / AGENT_PORT
./install-server.sh --site-file site.local.env < /root/cf-token
```

The script is idempotent: it installs the binary (+ `passmanager` alias), creates the `passmanager` system account, adds root to
`tss` and installs tss2 libraries when a TPM is present, writes `/etc/sysctl.d/99-disable-ipv6.conf`, installs an
`inet passmanager` nftables table that only lets the given CIDRs reach 22 and the web/agent ports (all IPv6 dropped), writes the
systemd unit and runs `passmanager init` (device key at L3 with a TPM, else L2; inner channel keys; passwordless vault; certificate).

Check: `passmanager status`, `ss -tlnp`, `nft list table inet passmanager`, `systemd-analyze security passmanager`.

## 2. Web admin

`ssh root@pm.example.com passmanager login` prints a one-time link (2 minutes, single use). Open it and click the button.
Secrets are write-only. Sessions expire after 2 h idle / 12 h absolute.

## 3. Agents (any platform)

```sh
ssh root@pm.example.com passmanager agent-setup --label laptop      # --lang zh for Chinese
```

This prints one block of text; give it to the AI agent on the agent machine (the web UI's "Agent 令牌" page shows the same
block). The block contains a one-time enrollment code (10 minutes, single use) and:

1. the command `curl --proto =https --tlsv1.3 -fsSL https://pm.example.com/a/<code> | sh`. The server returns a small POSIX sh
   script generated for that code; it downloads the client for the machine's OS/CPU from the server itself
   (`/a/<code>/bin/<target>`), verifies its SHA-256, installs it to `~/.local/bin` (no root), and runs `enroll`;
2. if that fails at the TLS handshake (curl without ML-KEM, e.g. macOS or older distributions) or on Windows: build the client
   from the release tag and commit pinned in the block (`cargo build --release -p passmanager`; needs Rust, cmake, a C compiler,
   libclang) and run its `enroll`. A development build of the server prints a note instead of a pin;
3. the usage rules for the AI.

`enroll` verifies the pinned server key fingerprint, stores the token in a private file, writes the MCP config of detected
agents (without the token) and the usage rules between `<!-- passmanager:begin -->` / `<!-- passmanager:end -->` in their global
instruction files (backup `*.passmanager.bak`; `--no-instructions` skips this). Fetching the script does not consume the code;
`enroll` does. Unknown or expired codes return 404; `/a/` requests are rate-limited, audited and, like the whole web port, only
accepted from the configured CIDRs. `passmanager unenroll` removes the configuration, MCP entries and rules from the agent machine;
revoke the token in the web UI or with `passmanager token revoke <id>`.

The installer copies its own binary into `/var/lib/passmanager/agent-bin/`; for other platforms pass
`--agent-bundle <dir>` with the release archives (`PassManager-<version>-<target>.tar.gz`, optionally `SHA256SUMS`). The server
never downloads anything at request time.

### 3.1 Importing secrets (server, root)

```sh
passmanager import --name github --domain api.github.com < token.txt
passmanager import --name mail --fields username,password --domain mail.example.com < creds.txt   # one value per line
passmanager import --name deploy-key --kind ssh-key --domain db1.example.com:22 \
    --host-key "$(ssh-keyscan -t ecdsa db1.example.com 2>/dev/null)" < id_ecdsa       # unencrypted key
passmanager import --name github --replace --domain api.github.com < new-token.txt
passmanager import --name pin --interactive                                           # typed without echo
```

Content is stored verbatim (one trailing newline stripped, 64 KiB max), never echoed or logged; the command prints only the
name, byte count and domain count. Entries without `--domain` are shown as "未绑定域名" (unbound) and unusable until a domain is
added in the web UI. Placeholders: `{{secret}}` (single-value entries), `{{name.field}}`, `{{field}}` (when exactly one entry matches
the host); `sudo` uses the `password` field.

Bindings may be exact hosts, `*.example.com` (subdomains only, not the apex), IPs, or CIDR ranges such as `198.51.100.0/24`
(matched against literal IP targets only), each optionally with `:port`; the most specific matching entry wins. A default initial
SSH password for new machines, usable only for SSH and only after a stored key was rejected:

```sh
passmanager import --name init-pw --domain '*.example.com' --domain 198.51.100.0/24 --ops ssh < initial-password.txt
```

### 3.2 ssh-agent bridge (agent machine, Linux / macOS)

```sh
PassManager ssh-agent &                       # prints SSH_AUTH_SOCK=… (socket mode 0600)
export SSH_AUTH_SOCK=…; ssh deploy@db1.example.com
```

Private keys never leave the server. It signs only publickey userauth requests and requires OpenSSH ≥ 8.9
`session-bind@openssh.com` proving the session belongs to a host key allowed for the entry (bound with `--host-key` / the web UI,
or a pinned fingerprint matching the entry's domains); 30 signatures per minute, each one audited.

### 3.3 git credential proxy (agent machine, any platform)

```sh
PassManager git-proxy --host github.com &     # listens on 127.0.0.1:7878 by default and prints the git config command
git config --global url."http://127.0.0.1:7878/<path-token>/https/github.com/".insteadOf "https://github.com/"
git clone https://github.com/owner/repo.git
```

The server needs an entry bound to that host: a single-value PAT, or a multi-field entry with `username` and `token`/`password`
(user name defaults to `x-access-token`). Only smart-HTTP (`info/refs`, `git-upload-pack`, `git-receive-pack`) over HTTPS to the
entry's domains is forwarded, redirects are not followed, and the token is injected on the server only. The path token is stored in
the config directory (0600) so other local programs cannot borrow the proxy.

## 4. TPM (L3)

`/dev/tpmrm0` is auto-detected. A software TPM exposed as a swtpm Unix socket can be configured with `--tpm-socket <path>`.
Then run `./install-server.sh --site-file site.local.env --skip-acme` (libraries, tss group) and `passmanager reseal`.
Losing or clearing the TPM state, or moving to another host, makes the vault permanently unreadable — there is no recovery.

## 5. Failures

Exit code 78 = configuration error (no restart); 75 = transient (retried). All files are written atomically and a damaged vault
falls back to `vault.pmv.bak`. A failed certificate renewal never blocks startup while the stored certificate is valid.

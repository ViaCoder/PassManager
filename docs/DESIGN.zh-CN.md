# PassManager 设计文档

[English](DESIGN.md) | 简体中文

面向 AI Agent 的抗量子密码管理器。人类通过 TUI 管理"密钥 + 域名"条目；任意 AI Agent 通过 MCP 或 CLI 让 PassManager **代为使用**凭据（HTTPS 请求、SSH 命令、SFTP 传输），**全程看不到明文**，返回结果自动脱敏。

---

## 1. 目标与威胁模型

| 编号 | 威胁 | 应对 |
|---|---|---|
| T1 | AI 服务商从对话上下文中提取密钥 | 密钥永不进入 Agent 进程与 LLM 上下文；所有返回结果脱敏；密钥只能在 TUI 中录入；TUI 在非 TTY / Agent 会话中拒绝显示明文 |
| T2 | 提示注入诱导 Agent 执行非预期操作 | 每个条目必须绑定域名，密钥只会发往匹配的主机；只支持 HTTPS；不跟随跨主机重定向；SSH 主机密钥与自签证书指纹固定 |
| T3 | Agent 扫描全盘并上传 | 库与设备密钥归专用系统用户所有、放在 $HOME 之外；设备密钥由 TPM / 系统封存；库文件双层抗量子加密 |
| — | 服务被发现或探测 | 不监听 TCP；本地 socket 的第一帧必须是合法握手，否则随机延迟后静默断开，不返回任何特征信息 |

**唯一的安全边界是操作系统用户**：Agent 以普通用户运行，服务以专用用户 `passmanager`（macOS：`_passmanager`；Windows：`NT SERVICE\PassManager`）运行。如果 Agent 拥有 root/管理员权限，任何方案都会失效——这是本设计唯一的前提，`PassManager harden` 负责检查并加固它（§6）。

**残余风险**（如实说明）：

- 被注入的 Agent 仍可在**条目自己的域名范围内**滥用权限（例如用 GitHub token 删仓库）。请为每个条目使用最小权限的 token / 账户，不要把通配符用在有用户可控子域名的域上。
- 如果 Agent 能修改用户的 shell 配置，可以伪造 `sudo` 截获管理员口令。请不要在 Agent 的终端里执行 sudo。
- 首次连接时自动记录指纹（TOFU）：如果第一次连接就被中间人拦截，记录下来的会是攻击者的指纹。
- 访问令牌只是"门禁"：泄露后持有者只能**使用**凭据（仍看不到明文），在 TUI 中一键吊销即可。

---

## 2. 架构

```
 当前用户                                           服务用户（隔离）
 PassManager (TUI) ──(口令握手)───┐               ┌───────────────────────────┐
                                 ├─ 本地 socket ─►│ PassManager service        │──► HTTPS 网站
 任意 Agent ─ PassManager mcp/CLI ┘ (令牌握手)    │  已解锁的密钥（仅在内存中）│──► SSH / SFTP 主机
                                                  │  vault.pmv + 封存的设备密钥 │◄── TPM / DPAPI / 系统钥匙串
                                                  └───────────────────────────┘
```

- 单一可执行文件 `PassManager`：服务、TUI、MCP 服务器、CLI、安装程序。
- 本地 IPC：Linux/macOS 为 Unix socket（目录 0750，属组为安装用户的组），Windows 为带 DACL 的命名管道（只允许 SYSTEM、服务账户、安装用户）。帧格式：`u32 BE 长度 ‖ JSON`。
- 握手（第一帧）：
  - `{"auth":"token","v":1,"token":"pm_…"}`：Agent 会话，只能执行"使用类"操作（list / http / ssh / upload / download / lock / status）。以 root / 提权令牌运行的客户端一律拒绝。
  - `{"auth":"password","v":1,"password":"…"}`：TUI 管理会话；库锁定且安全检查通过时同时完成解锁。
  - `{"auth":"setup","v":1,"password":"…"}`：首次设置口令（库不存在时；系统模式只接受 root/管理员）。
  - 失败一律随机延迟（200–1000 ms）后静默断开。口令连续失败 3 次后进入指数退避（最长 1 小时）。
- 访问令牌保存在库外的 `tokens.json`，只存 SHA-256（令牌有 256 bit 熵，哈希不可逆）。这样库锁定时也能识别合法令牌，并给出"请解锁"的提示。

### 2.1 crate 划分

| crate | 内容 | 依赖 C 库 |
|---|---|---|
| `pm-crypto` | 双源 RNG 与健康检测、Argon2id、ML-KEM-1024、Classic McEliece、双层封装、启动自检 | aws-lc、liboqs |
| `pm-vault` | 数据模型、域名规则、文件格式、原子写入 | 经 pm-crypto |
| `pm-platform` | 目录布局、TTY / Agent 会话检测、设备密钥封存、安全检查与账户加固、进程加固、服务配置模板 | 无（可单独为 Windows/macOS 做 `cargo check`） |
| `pm-proto` | 协议类型、帧读写、阻塞式客户端 | 无 |
| `pm-service` | 服务：会话、请求分发、HTTPS / SSH / SFTP 执行器、脱敏、令牌 | 经 pm-crypto |
| `pm-tui` | 管理界面（ratatui，键盘 + 鼠标）、Agent 接入适配器 | 经 pm-crypto（随机密钥生成） |
| `passmanager` | 二进制 `PassManager`：命令行、MCP 服务器、安装/卸载/加固/服务入口 | — |

---

## 3. 密码学

### 3.1 库与算法

| 用途 | 库 | 算法 |
|---|---|---|
| 抗量子 #1（格密码） | aws-lc-rs 1.18.1（FIPS 140-3 认证模块） | ML-KEM-1024（FIPS 203） |
| 抗量子 #2（编码密码） | liboqs 0.13（`oqs` crate，只启用 Classic McEliece） | Classic-McEliece-6688128（NIST 5 级） |
| 对称 / HKDF / 随机数 | aws-lc-rs | AES-256-GCM、ChaCha20-Poly1305、HKDF-SHA-512、SystemRandom |
| 口令 KDF | RustCrypto `argon2` 0.5.3 | Argon2id |

加密相关依赖用 `=` 精确锁定版本，其余依赖由提交的 `Cargo.lock` 锁定；`deny.toml` 与 CI 中的 `cargo deny` / `cargo audit` 负责供应链审查。

### 3.2 随机数（两个来源）

```
out = HKDF-SHA512(salt = "pm/rng/v1" ‖ counter, ikm = getrandom(64) ‖ aws-lc SystemRandom(64))
```

- 只要任一来源可靠，输出就是安全的；每次调用都实时读取两个来源，不缓存状态，天然 fork 安全。
- 启动健康检测：对每个来源各采样 4 KiB，执行 SP 800-90B 重复计数测试（截断值 6）与自适应比例测试（窗口 512、截断值 20），拒绝全零/全一、两源相同的输出。
- 连续测试：每次调用比较各源本次与上次输出的前 16 字节、两源之间是否相同。任何失败都 **fail-closed**：此后所有调用都返回错误。
- liboqs 的随机数通过 `OQS_randombytes_custom_algorithm` 接入组合 RNG；若该回调中 RNG 失败，进程直接 abort。
- 启动自检（任何一项失败都拒绝运行）：SHA-512（FIPS 180-2）、HKDF（RFC 5869）、AES-256-GCM（GCM 规范用例 14）、ChaCha20-Poly1305（RFC 8439 §2.8.2）、Argon2id（RFC 9106 §5.3）的已知答案测试，ML-KEM 往返，liboqs 可用性；KEM 密钥生成后做成对一致性测试。

### 3.3 密钥层级

```
IKM    = Argon2id(NFKC(password), salt) ‖ device_key            # 用完即清零
KEK_A  = HKDF(salt=vault_id, IKM, "pm/v1/kek/A")
KEK_B  = HKDF(salt=vault_id, IKM, "pm/v1/kek/B")
wrap_A = AES-256-GCM(KEK_A, VK_A ‖ dk_mlkem)          aad = vault_id ‖ "pm/v1/wrap/A"
wrap_B = ChaCha20-Poly1305(KEK_B, VK_B ‖ sk_mceliece)  aad = vault_id ‖ "pm/v1/wrap/B"
kcv    = HKDF(salt=vault_id, device_key, "pm/v1/kcv")[..16]   # 设备密钥校验值
```

### 3.4 每次保存的双层加密（DEK 与 nonce 全新）

```
P = postcard(载荷)，填充到 4 KiB 的整数倍；H = SHA-512(文件头)
内层：(ct_M, ss_M) = McEliece.Encaps(pk_M)
      DEK_B = HKDF(VK_B ‖ ss_M, "pm/v1/dek/B" ‖ H ‖ ct_M)
      C1    = ChaCha20-Poly1305(DEK_B, nonce_B, P, aad = H)
外层：(ct_K, ss_K) = ML-KEM-1024.Encaps(ek_K)
      DEK_A = HKDF(VK_A ‖ ss_K, "pm/v1/dek/A" ‖ H ‖ ct_K)
      C2    = AES-256-GCM(DEK_A, nonce_A, C1, aad = H ‖ ct_M)
```

攻击者必须**同时**攻破"口令 + 设备密钥"这条对称链、ML-KEM 和 McEliece 才能解密；任何一个算法或库出了问题，都不会降低整体安全性。

### 3.5 文件格式 `vault.pmv`

```
"PMVAULT\0" | u32 LE 文件头长度 | 文件头（postcard） | SealedPayload（postcard）
文件头 = { version, vault_id, seal_level, kcv, kdf{m_kib,t,p}, salt, ek_mlkem, pk_mce, wrap_a, wrap_b }
SealedPayload = { ct_mlkem, ct_mce, nonce_a, nonce_b, c2 }
```

- 文件头的 SHA-512 作为两层 AEAD 的关联数据，任何字段被篡改都会导致解密失败；封存等级写在文件头里，降级会被拒绝。
- KDF 参数硬下限：内存 ≥ 256 MiB、迭代 ≥ 2；默认 1 GiB / t=3 / p=4，按本机物理内存选择内存大小，再增加迭代次数直到单次 ≥ 1 秒。
- 原子写入：写临时文件 → fsync → 备份旧文件为 `.bak` → rename → fsync 目录；主文件缺失时读取 `.bak`。
- 修改口令只重新包裹 `wrap_A` / `wrap_B`。

---

## 4. 设备密钥封存

| 等级 | 含义 |
|---|---|
| L3 | 硬件封存（TPM）：整个数据目录、虚拟机快照或整块磁盘被拷到别的机器上也解不开 |
| L2 | 系统封存：必须本机 root / 系统权限才能解开 |
| L1 | 仅文件权限保护（兜底；安装结束、TUI 标题栏、每次解锁、诊断页四处持续警告） |

| 平台 | L3 | L2 | L1 |
|---|---|---|---|
| Linux（systemd ≥ 250） | `systemd-creds encrypt --with-key=host+tpm2 --tpm2-pcrs=`（不绑定 PCR，固件/内核升级后仍可解开）；服务单元 `LoadCredentialEncrypted=` 加载，明文只出现在服务专属的 `$CREDENTIALS_DIRECTORY` | 同上，`--with-key=host`（`/var/lib/systemd/credential.secret`，root 0400） | 容器 / 非 systemd：服务账户所有的 `device.key`（0600） |
| Windows | DPAPI（服务账户用户范围）封存 `k_os`，TPM（Platform Crypto Provider 不可导出 RSA）封存 `k_hw`，`device_key = k_os ⊕ k_hw` | 只用 DPAPI | — |
| macOS（未签名） | **不可行**：Apple DTS 说明 launchd 守护进程无法使用 Secure Enclave；LaunchAgent 会以 Agent 所在用户运行，破坏隔离 | 系统钥匙串：服务由 launchd 以 root 启动，读取条目后立即不可逆地降权到 `_passmanager`；条目由已安装的二进制创建，默认 ACL 只信任它；升级时由旧程序导出设备密钥、新程序重新创建条目（ACL 换绑）。退回方案：root 专属文件 `/var/db/passmanager/device.key`（0400），同样 root 阶段读取后降权 | — |

- 抗量子说明：TPM2 封存、DPAPI、系统钥匙串都是对称结构；Windows 的 TPM RSA 只提供"硬件绑定"，组合中始终保留对称部分 `k_os`。
- **没有任何恢复机制**：硬件损坏、TPM 被清除、重装系统或换机器后库永久无法打开，凭据需要重新录入。安装向导要求用户明确确认。

---

## 5. 凭据使用

### 5.1 条目

`密钥 + 域名（+ 可选说明）`，高级选项：自签证书（启用指纹固定，公网和内网主机都适用）、私钥条目自动接受主机密钥变更。

- 不需要起名：每个条目有一个**自动生成的引用名**（取第一个域名，如 `*.github.com` → `github.com`，重名时加 `-2`）。Agent 平时不需要它——HTTP 中写 `{{secret}}`、SSH/SCP 写 `user@host`，服务按主机自动选择；只有同一主机保存了多个密钥时才用引用名指定（`{{引用名}}` / `引用名/user@host`），此时会返回 `AMBIGUOUS` 并列出可选项。
- 域名：`example.com` 只匹配自身；`*.example.com` 匹配自身及任意层级子域名；IP 精确匹配。通配符的基底不能是公共后缀（含私有段），因此 `*`、`*.com`、`*.co.uk`、`*.github.io` 都会被拒绝；精确匹配只对应一台主机，只拒绝 ICANN 顶级后缀本身（`com`、`co.uk`），允许 `github.io`、`httpbin.org` 这类私有段中的主机名。
- SSH 认证方式由密钥内容自动判断：`-----BEGIN … PRIVATE KEY-----` 为私钥，否则为密码。

### 5.2 工具（MCP 与 CLI 一一对应）

| MCP 工具 | CLI | 行为 |
|---|---|---|
| `list` | `PassManager list` | 已保存密钥的主机（引用名、域名、说明） |
| `http(method, url, headers?, body?)` | `PassManager http [METHOD] URL [-X] [-H 'K: V'] [-d BODY \| -d @file \| --json BODY]` | 在请求头 / 请求体 / URL 查询中写 `{{secret}}`，按 URL 主机自动选择密钥；只支持 HTTPS；不跟随跨主机重定向；删除 `Set-Cookie` 与认证类响应头；正文与响应头脱敏 |
| `ssh(target, command)` | `PassManager ssh [-p 端口] [-l 用户] user@host[:port] 命令…` | 内置 russh；password 失败时尝试 keyboard-interactive；命令以 `sudo ` 开头时改为 `sudo -k -S -p ''` 并从 stdin 提供密码；输出脱敏 |
| `scp(source, destination)` | `PassManager scp [-P 端口] 源 目标` | 远程一侧写成 `user@host:/path`；SFTP 上传（创建/截断）或下载（内容脱敏，上限 64 MiB）；本地文件由客户端以当前用户身份读写 |

兼容性：MCP 工具同时接受旧名称（`list_credentials`、`http_request`、`ssh_exec`、`ssh_upload`/`ssh_download`）和常见参数写法（headers 为对象 / 数组 / `"K: V"` 文本，body 为 JSON 对象，ssh 分开写 `host`/`user`/`port`，scp 用 `from`/`to`），但工具列表只公开上面 4 个；CLI 兼容 curl、OpenSSH、scp 的常用选项，并忽略 `-s`、`-L`、`-t`、`-o …` 等无关选项。客户端定位本地服务不依赖环境变量（Linux 用 `/run/user/<uid>`，Windows 用用户 SID 生成管道名），因此在环境变量很少的 MCP 子进程中同样可用。

MCP 服务器为 stdio、按行分隔的 JSON-RPC 2.0，支持协议版本 2025-11-25 / 2025-06-18 / 2025-03-26 / 2024-11-05，并在 `instructions` 中附带三句使用说明。错误信息可以直接指导下一步：

| 代码 | 含义 |
|---|---|
| `LOCKED` | 库已锁定：`Ask the user to run: PassManager unlock` |
| `NOT_READY` | 安全检查未通过：`Ask the user to run: PassManager` |
| `NOT_INITIALIZED` / `NOT_RUNNING` | 尚未安装：`sudo PassManager install` |
| `DOMAIN_MISMATCH` | `"github" only works with *.github.com` |
| `USE_HTTPS` | 不支持明文 HTTP（内网也不支持） |
| `NO_CREDENTIAL` | 该主机没有保存密钥 |
| `AMBIGUOUS` | 该主机有多个密钥，列出引用名供指定 |
| `UNKNOWN_CREDENTIAL` | 指定的引用名不存在 |
| `HOST_KEY_CHANGED` | SSH 主机密钥 / 自签证书指纹变化，**未发送任何数据**：`Ask the user to run: PassManager trust <主机>` |
| `AUTH_FAILED` / `AUTH_REJECTED` / `UPSTREAM_ERROR` / `BAD_REQUEST` / `FORBIDDEN` | 其他错误 |

### 5.3 输出脱敏

对每个密钥生成变体：原文、去空白的原文、Base64（标准 / URL 安全，各 3 种字节对齐偏移，只取完全由密钥决定的字符段，可覆盖 `user:pass` 的 Basic 编码）、hex 大小写、百分号编码（全部编码 / 保留 RFC 3986 unreserved / 表单编码，各含大小写转义）、JSON 转义、HTML 转义、多行密钥（PEM）中长度 ≥ 16 的每一行。用 Aho-Corasick（最左最长匹配）一次扫描，替换为 `[REDACTED:name]`。错误信息中的上游报错也经过脱敏，并去掉 URL。

### 5.4 指纹变更

- 首次连接自动记录（按 `host:port`）：SSH 记录主机密钥（`SHA256:…`），自签证书记录证书 SubjectPublicKeyInfo 的 SHA-256。
- 指纹变化时在**认证之前 / TLS 握手阶段**中止，不发送任何认证数据，记入"待确认"列表，返回 `HOST_KEY_CHANGED`。
- 用户运行 `PassManager trust db1.example.com`（不需要端口，清除该主机所有端口的记录；`*.example.com` 可批量；也可写 `host:port` 只清除一个端口）：弹出只做这一件事的对话框，显示新旧指纹，输入口令后确认，程序自动退出。该命令要求真实 TTY 且不在 Agent 会话中。

---

## 6. 安全检查与账户加固（`PassManager harden`）

推荐架构：禁用内置管理员（root / Administrator）；日常使用有管理员权限的普通账户，**每次提权都必须输入口令**；Agent 永远不以提权状态运行。

流程：安装时检查 → 列出"将自动修改"与"需要你处理"两组 → 确认一次后自动修改（修改前备份到数据目录下的 `hardening-backup/`，卸载时可用 `--restore-hardening` 还原）→ 复查。**只有全部必需项都通过才能解锁**（标为"建议"的项只提示、不阻止，目前只有 macOS 的 FileVault）。解锁之后如果检查变为不通过，Agent 的下一个请求会触发立即锁定（就绪状态缓存 10 秒）。服务每次启动时复查一次（Linux：`ExecStartPre=+PassManager service-prepare`；macOS：root 阶段；Windows：开机以 SYSTEM 运行的计划任务），报告必须由 root 所有且不可被他人修改。TUI"诊断"页提供 `[重新检查]` 与 `[一键修复]`（弹出一次 sudo / UAC 授权）。

| 平台 | 自动修改（先确认安全前提） | 需要用户处理 |
|---|---|---|
| Linux | 锁定 root（前提：当前用户能 sudo 且有口令）；`NOPASSWD:` 改为 `PASSWD:`、注释 `!authenticate`（前提：用户有口令；`visudo -c` 校验通过才写入）；写入 `/etc/sudoers.d/zz-passmanager-hardening`（`timestamp_type=tty`、5 分钟）；锁定其他空口令账户；服务账户 nologin + 锁定 + 移出管理员组；修正数据目录、库文件、设备密钥、socket 目录、程序文件、服务单元的属主与权限 | 当前用户没有口令；属于 docker / lxd / incus / disk 组；PATH 中有带 `cap_dac_*` / `cap_setuid` / `cap_sys_ptrace` / `cap_sys_admin` 的程序 |
| macOS | 禁用 root；sudoers 同上；关闭自动登录；服务账户 shell 设为 `/usr/bin/false`；文件权限 | 用户口令为空；SIP 关闭；（建议）开启 FileVault |
| Windows | 禁用内置 Administrator（前提：另有已启用、设有口令的管理员）；UAC `EnableLUA=1`、`ConsentPromptBehaviorAdmin=1`（提权要求输入口令）、`PromptOnSecureDesktop=1`；禁用 Guest；数据目录 ACL 只授权 SYSTEM 与服务 SID；重置程序文件 ACL | 属于 Backup Operators；被单独授予 `SeDebugPrivilege` / `SeBackupPrivilege`；管理员账户没有口令 |

用户模式（`install --user`，无管理员权限时的降级方案）不存在账户隔离，不执行账户加固，并持续显示 L1 警告。

---

## 7. 易用性

- 一键安装：Linux/macOS `sudo ./PassManager install`；Windows 双击 `PassManager.exe`（弹出一次 UAC）。安装程序复制程序到只有 root 可写的路径（Linux `/usr/local/bin`；macOS `/Library/PassManager`，再链接到 `/usr/local/bin`，因为很多 Mac 上 `/usr/local/bin` 归用户所有；Windows `C:\Program Files\PassManager`）、创建服务账户、生成并按最高可用等级封存设备密钥、注册并启动服务、执行账户加固、设置口令（确认"没有恢复机制"、显示强度）、最后打开 TUI。
- TUI 按需运行、用完即退（解锁状态由服务保持，空闲 15 分钟退出）：`PassManager`（完整界面）、`PassManager unlock`、`PassManager trust <主机>`。键盘与鼠标都可用：单击选中、双击编辑、滚轮滚动、标签页 / 按钮栏 / 对话框按钮可点击、支持粘贴（多行私钥）。
- 五个标签页：条目、主机、Agent 接入、诊断、设置（空闲自动锁定时长，默认 12 小时；修改口令；立即锁定）。
- Agent 接入页自动检测 Claude Code（优先 `claude mcp add`）、Codex CLI、Cursor、Gemini CLI、VS Code、Windsurf，一键接入：为该 Agent 新建专用令牌，合并写入其 MCP 配置（先备份原文件，只增加 `passmanager` 一项）。其他 Agent 显示可复制的配置片段（令牌只显示一次）。

---

## 8. 与计划的差异

| 计划 | 实现 | 原因 |
|---|---|---|
| MCP 使用官方 SDK `rmcp` | 手写的 stdio JSON-RPC（约 250 行，`crates/passmanager/src/mcp.rs`） | 只需要 initialize / tools/list / tools/call / ping 四个方法；减少依赖与攻击面，不受 SDK 接口频繁变动影响 |
| 令牌哈希保存在库内 | 保存在库外的 `tokens.json`（只有 SHA-256） | 库锁定时也要能识别合法令牌并返回"请解锁"，同时对非法令牌保持静默 |
| — | HTTPS 请求必须至少包含一个 `{{secret}}` 占位符 | 防止服务被当作通用 HTTP 代理 |
| 内存中的秘密 `mlock` 锁定 | Linux：服务单元 `MemorySwapMax=0`，整个服务进程不会被换出；其余平台依赖系统加密的交换空间（macOS 默认加密 swap；Windows 可开启页面文件加密）。秘密均用 `zeroize` 清零，并禁用 core dump（Linux 另设 `PR_SET_DUMPABLE=0`） | Argon2id 需要 1 GiB 内存，`mlockall` 会受锁定内存上限限制导致分配失败；按 cgroup 禁止换出更彻底 |
| socket 目录属组为安装用户的主组 | Linux 如此；macOS 改用专用组 `_passmanager_clients`（安装用户加入该组） | macOS 用户的主组 `staff` 由所有本地用户共享 |

---

## 9. 验证状态

CI 在 6 种 GitHub 原生运行器上执行：Linux（ubuntu-latest、ubuntu-24.04-arm）、macOS（macos-latest = Apple 芯片、macos-15-intel）、Windows（windows-latest、windows-11-arm）。

| 项目 | 覆盖范围 | 状态 |
|---|---|---|
| 单元测试：KAT、RNG 健康检测与卡死源 fail-closed、KEM 篡改、双层封装、逐位篡改 / 错误口令 / 错误设备密钥 / 等级降级、域名规则、sudoers 规则匹配、脱敏各编码、占位符、HTTP 请求规则、MCP 协议与参数兼容、CLI 参数（curl / ssh / scp 写法）、Agent 配置合并（JSON/TOML）、TUI 渲染与鼠标命中 | 6 种运行器 | 通过 |
| 端到端测试（`crates/passmanager/tests/e2e.rs`）：真实服务进程 + 本地自签 HTTPS 回显服务 + russh 测试 SSH/SFTP 服务器，覆盖防探测、令牌、条目管理、`{{secret}}` 按主机自动选择、代填与脱敏（含 base64 / hex / URL 编码回显）、域名限制、只允许 HTTPS、不跟随跨主机重定向、自签证书指纹固定与更换、SSH 执行与主机密钥更换、SFTP 上传与下载脱敏、查看明文、吊销令牌、锁定、MCP 与 CLI | 6 种运行器 | 通过 |
| 伪终端 TUI 冒烟测试（`tests/tui_pty_smoke.py`） | Linux、macOS（Windows 没有 pty，只做单元测试） | 通过 |
| 系统模式：安装（服务账户、设备密钥封存、服务启动）→ 安全检查 → 设置口令 → 探测（无效令牌被静默拒绝）→ 卸载 | 6 种运行器 | 通过。实际封存方式：Linux systemd-creds 主机密钥（L2，运行器没有 TPM）、macOS 系统钥匙串（L2，root 阶段读取后降权，无弹窗）、Windows DPAPI（L2，运行器没有 TPM）。运行器账户免口令提权，安全检查按预期不通过、库保持锁定 |
| 加固后的完整流程：设置用户口令、移出 docker 组、`install --yes` 自动加固 → 复查全部通过 → 解锁 → 以普通用户和令牌跑 Agent 流程（HTTPS 代填与脱敏） | Linux x64 / arm64 | 通过 |
| 发布包：在各平台原生运行器上构建后直接解包运行（真实 Argon2id 参数），macOS 通用二进制另以 Rosetta 运行 x86_64 部分 | Linux x64 / arm64、macOS、Windows x64 / arm64 | 通过 |
| 本地交叉构建（`scripts/cross-build.sh`，Zig） | Linux x64 / arm64、Windows x64 | 通过 |
| 尚未验证 | 有 TPM 的真实 Linux / Windows（L3）、macOS 升级时钥匙串 ACL 换绑、Windows 加固后的完整流程、在 Alpine 容器中显示 L1 警告 | — |

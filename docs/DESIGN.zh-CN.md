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
- 可选的第三个来源（服务器模式）：TPM（经 `/dev/tpmrm0` 或配置的 swtpm 套接字发送 `TPM2_GetRandom`）通过 1 KiB 启动健康检测后并入 IKM；之后任何失败只停用这个源（§10.4）。
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
- 第 2 版文件头（服务器模式的无口令库）多一个模式字节，见 §10.3。主文件缺失或损坏时才回退到 `.bak`。
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
- 域名：`example.com` 只匹配自身；`*.example.com` 匹配任意层级的子域名，但**不**匹配 `example.com` 本身（0.2.0 起，需要时单独列出），也不匹配 `badexample.com`、`example.com.evil.net` 这类形似名称；IP 精确匹配；网段（`198.51.100.0/24`、`2001:db8::/48`，主机位为 0，IPv4 至少 /8、IPv6 至少 /32）只匹配字面 IP 目标——域名即使解析到该网段也不匹配。名称比较前统一小写、去掉末尾的点并做 IDNA（punycode）规范化。任一形式都可以加 `:端口`。多个条目匹配同一目标时选最具体的（精确主机或 IP > 更长的通配符 > 前缀更长的网段；同级时带端口的更具体）；同样具体的报 `AMBIGUOUS`，只列出引用名。条目可以限定用途（`ops`：`http`、`ssh`——含 scp 与 ssh-agent 桥——、`git`）。`*` 只能是最左边的整个标签，其后至少两个标签。通配符的基底不能是公共后缀（含私有段），因此 `*`、`*.com`、`*.co.uk`、`*.github.io` 都会被拒绝；精确匹配只对应一台主机，只拒绝 ICANN 顶级后缀本身（`com`、`co.uk`），允许 `github.io`、`httpbin.org` 这类私有段中的主机名。
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

---

## 10. 局域网在线版（服务器模式）

前面的单机设计保持不变。服务器模式是另一种部署形态：局域网里一台 PassManager 服务器（例如解析到内网地址的 `pm.example.com`），其他机器上的 Agent 经网络使用凭据，另有网页管理界面与服务器上的 root 命令。由 `passmanager init` 开启（root 所有的 `install.json` 里的 `server` 配置）。

### 10.1 网络威胁模型

| 编号 | 威胁 | 应对 |
|---|---|---|
| N1 | 局域网以外的人连到服务 | 只开 443（网页）与 8443（Agent）；只用 IPv4；在任何 TLS 握手之前，程序内按配置的网段（`--lan-cidr`，必须指定、没有默认值；不指定时网络监听拒绝启动）检查来源地址；`install-server.sh` 加一张 nftables 表，只放行这些网段访问 22 与网页 / Agent 端口，丢弃其余入站与全部 IPv6；`/etc/sysctl.d/99-disable-ipv6.conf` 关闭 IPv6。域名解析到内网地址，公开的只有证书。 |
| N2 | 现在录下流量、将来用量子计算机破解 | 外层 TLS 1.3 只接受混合组 X25519MLKEM768 / SecP256r1MLKEM768 与 TLS_AES_256_GCM_SHA384，无 0-RTT；Agent 通道再加一层内层，由 ML-KEM-1024 **和** Classic McEliece 6688128（两个家族、两个库）共同决定密钥。 |
| N3 | 用误签发的证书做主动中间人 | Agent 固定注册码里服务端内层静态公钥的 SHA-384 指纹（不是 TOFU）；内层的密钥确认绑定 TLS exporter，终止 TLS 后再转发内层字节必然失败。 |
| N4 | 局域网设备探测 Agent 端口 | 网络上只接受 `Hello::Token` 与 `Hello::Enroll`；`Password`、`Setup`、`Root` 一律静默拒绝；所有失败都是同样的随机延迟后静默断开。 |
| N5 | 针对网页的攻击（CSRF、XSS、DNS 重绑定、点击劫持） | 服务端渲染、没有 JavaScript、CSP `default-src 'none'`；Host 校验；Fetch Metadata 与 Origin 校验；每个 POST 校验 CSRF 令牌；`__Host-` cookie（HttpOnly、Secure、SameSite=Strict）；请求体上限 64 KiB；无效登录链接按来源限速；每个模板都有 XSS 注入测试。 |
| N6 | 网页登录凭据被盗 | 没有凭据：只能用 `passmanager login`（服务器上的 root，也就是持有 SSH 密钥的人）打印的一次性链接登录。链接 2 分钟有效，GET 只显示确认页，POST 才消耗；会话空闲 2 小时、登录满 12 小时失效，只保存在内存里。 |
| N7 | 密钥经网页泄露 | 密钥只写不读：任何页面、任何响应都不包含密钥（有测试），表单从不回显，服务器模式拒绝 `Reveal`。 |
| N8 | Agent 令牌被盗 | 只能**使用**凭据（看不到明文），且只能从局域网使用；在网页或用 `passmanager token revoke` 吊销立即生效。令牌只在注册时经双层加密通道送达一次，在 Agent 上存为 0600 文件（不写进任何 MCP 配置）。 |

### 10.2 Agent 通道的构造

```
TCP（IPv4，只接受局域网来源）→ TLS 1.3 [X25519MLKEM768 + AES-256-GCM，ALPN pm-inner/1] → 内层 → 原有的本地协议（handle_conn）

服务端静态密钥：ML-KEM-1024（aws-lc-rs）+ Classic McEliece 6688128（liboqs），私钥用设备密钥封存
bundle = "PMK1" ‖ 长度‖ek_mlkem ‖ 长度‖pk_mceliece          （约 1 MB，注册时下载一次并缓存）
fpr    = SHA-384("pm/inner/v1/fpr\0" ‖ bundle)                （写在注册码里，固定在 remote.toml）

C → S  "PMIN" ‖ 0x01 ‖ 0x02 ‖ nonce_c ‖ fpr ‖ ct_K ‖ ct_M     （ct_K/ss_K = ML-KEM 封装，ct_M/ss_M = McEliece 封装）
S → C  nonce_s ‖ tag_s ；  C → S  tag_c
E    = TLS exporter("EXPORTER-PassManager-inner-v1", 64)
th   = SHA-512("pm/inner/v1/transcript" ‖ 客户端消息 ‖ nonce_s)
okm  = HKDF-SHA512(salt = nonce_c ‖ nonce_s, ikm = ss_K ‖ ss_M ‖ E, info = "pm/inner/v1/keys" ‖ th)
k_c2s, k_s2c, k_fin = okm[0..32], okm[32..64], okm[64..112]
tag_s = HMAC-SHA384(k_fin, "…server-finished" ‖ th)；tag_c = HMAC-SHA384(k_fin, "…client-finished" ‖ th)
帧    = u32 长度 ‖ ChaCha20-Poly1305(k_方向, nonce = 方向 ‖ 0³ ‖ 计数器 u64, aad = "pm/inner/v1/frame" ‖ 长度, ≤64 KiB)
```

- 只有同时持有两把私钥的服务端才能算出 `tag_s`；经另一条 TLS 连接转发时 `E` 不同，握手失败。
- 版本与操作码字节在 transcript 里；服务端只接受版本 1（降级尝试失败）。
- 两个方向各一把密钥、各一个不在线上传输的计数器：重放、重排、丢帧、反射都会认证失败并断开连接。外层 AES-GCM、内层 ChaCha20-Poly1305，算法不同。
- 服务端把内层会话包装成 `AsyncRead + AsyncWrite`（duplex 管道 + 两个加解密泵）交给原样不变的 `handle_conn`；Agent 端包装成 `Read + Write` 交给原有的阻塞客户端，所以 MCP 与 CLI 的用法不变。

注册：`passmanager show --label <标签> --url`（root）输出 `pm-enroll://<域名>:<端口>/<注册码>#<指纹>`（32 字节随机数，10 分钟有效，只能用一次——取出与作废是原子的，并发兑换时恰好一个成功——服务端只在内存里保存它的 SHA-256；兑换失败按来源地址限速，10 分钟内 10 次 → 锁定 15 分钟；审计日志只记录标签、来源地址与结果，从不记录注册码）。`show --label <标签>` 打印围绕这个注册码的完整接入说明（§10.10）。`passmanager enroll <注册码>` 下载公钥包、核对指纹、建立内层会话、用注册码换一个新令牌，然后在 `~/.config/passmanager` 下写入 `remote.toml`、`token`（0600）与 `server-keys.bin`，并为检测到的 Agent 写入 MCP 配置（不含令牌）。

### 10.3 无口令库模式及其代价

```
KEK_A = HKDF(salt = vault_id, ikm = device_key, info = "pm/v2/kek/A" ‖ "device-only" ‖ salt)   （KEK_B 同理）
v2 文件头 = v1 的字段 + 模式字节（device-only）；文件头哈希仍是两层载荷加密的 AAD
```

- 不运行 Argon2（1 GiB 内存的小服务器或容器也够用）；服务启动时自动解锁。v1（口令）库的格式逐字节不变。
- 防降级：模式写在受认证的文件头里，**同时**参与 HKDF 的 info；把无口令库改写成口令库（或反过来）都打不开；口令接口拒绝无口令库，反之亦然；封存等级只能升高（`reseal`）；`.bak` 回退只用于文件损坏，绝不用来绕过策略检查。
- **代价（直说）：** 拿到服务器 root 的人——或者在没有 TPM 时，拿到磁盘、快照或备份的人——就拿到了密码库。因此唯一的管理凭据就是能以 root 登录服务器的 SSH 密钥。**没有任何恢复途径**：不做在线同步、不做备份、不能导出。

### 10.4 设备密钥、TPM 与开机顺序

- 封存：TPM 可用时 `systemd-creds --with-key=host+tpm2 --tpm2-pcrs=`（L3），否则 `--with-key=host`（L2）。TPM 是自动检测的 `/dev/tpmrm0`，或用 `--tpm-socket` 配置的 swtpm Unix 套接字（例如虚拟化宿主机为容器提供的软件 TPM；配置后优先）；套接字模式下每次调用 `systemd-creds` 都带 `SYSTEMD_TPM2_DEVICE=swtpm:path=…`，root 调用时还会补上 `tss` 组（套接字为 `nobody:tss 0660`，而 `ExecStartPre=+` 的进程没有附加组）。判断 TPM 是否可用靠一次加密 / 解密往返并检查凭据文件头的类型 ID（`has-tpm2` 只看内核设备）。
- `passmanager reseal` 把 L2 升级为 L3：解密 → 重新加密到 `.new` → 检查文件头并解密比对 → 停止服务 → rename → 更新 `install.json` → 库文件头记为 L3 → 启动服务。任何一步之后断电，重新运行即可。
- **TPM 带来什么：** 偷走的磁盘镜像、快照或备份没有这份 TPM 状态就解不开；把容器搬到别处也解不开。**带不来什么：** 正在运行的容器里的 root 仍然可以让 TPM 解封；虚拟化宿主机的 root 能读容器内存。**不绑定 PCR**：LXC 没有自己的启动度量（PCR 反映宿主机的固件与内核，绑定后宿主机每次升级都会解不开）。**代价：** swtpm 状态丢失、TPM 被清除或迁移到别的节点后，密码库永久无法打开。
- 非特权 LXC 不支持 `LoadCredentialEncrypted=`，所以由 `ExecStartPre=+PassManager service-prepare`（root）把设备密钥解密到 `/run/passmanager-key/device.key`（服务账户 0400），服务读取后立即删除，`ExecStopPost` 清理残留。
- TPM 同时是随机数的第三个可选来源（经 swtpm 套接字或 `/dev/tpmrm0` 发送 `TPM2_GetRandom`；启用前 1 KiB 样本过 SP 800-90B 检测，运行中连续检测；任何失败只永久停用这个源）。

### 10.5 健壮性（硬重启、kill -9、断电）

- 单元：`After=/Wants=network-online.target`；`ExecStartPre` 里有限次（60 秒）等待 TPM；`Restart=on-failure` 加 `StartLimitIntervalSec=900`/`StartLimitBurst=10`。退出码 **78** 只用于真正的配置错误（`install.json` 损坏、密钥缺失、设备密钥解不开、库被降级、没有绑定特权端口的权限），配合 `RestartPreventExitStatus=78`；暂时性故障（TPM 还没出现、端口被占用）以 75 退出并重试。
- 所有持久文件都原子写入（临时文件 → fsync → rename → fsync 目录）：库、令牌表、`install.json`、封存的密钥、证书、ACME 状态。崩溃注入测试覆盖半写的临时文件、更新 .bak 之前崩溃、rename 之前崩溃。主文件缺失、截断或损坏时读取回退到 `.bak`，恢复后的第一次保存不会覆盖完好的 `.bak`。
- 证书：已保存的证书只要没过期就先用它启动；续期（每 6 小时检查，剩余 30 天内续期）失败从不阻塞启动；失败后按 10 分钟到 6 小时退避，失败次数持久化，服务反复重启也不会频繁请求 Let's Encrypt。

### 10.6 命令

| 位置 | 命令 | 作用 |
|---|---|---|
| 服务器（root） | `passmanager init [--cf-token-stdin] [--skip-acme] …` | 设备密钥、内层密钥、无口令库、证书、systemd 单元（可重复执行） |
| 服务器（root） | `passmanager login` | 网页一次性登录链接 |
| 服务器（root） | `passmanager token list` / `revoke <id>` | 令牌与未使用的注册码 |
| 服务器（root） | `passmanager status` / `lock` / `unlock` / `reseal` | 状态、锁定、解锁、L2 → L3 |
| 服务器（root） | `passmanager import --name <名称> [--domain …] [--kind ssh-key] [--fields a,b] [--replace]` | 从标准输入导入密钥 |
| 服务器（root） | `passmanager show --label 名称 [--url] [--lang en]` | 一次性注册码 + 给 AI Agent 的整段文字（`--url`：只有注册码） |
| 任何机器 | `passmanager show [--rules] [--lang en]` | 不含注册码的公开说明（已注册时写出服务器）/ 只打印使用规则 |
| Agent 机器 | `passmanager enroll 'pm-enroll://…' [--no-instructions] [--no-git-proxy]` | 接入服务器；配置 MCP、使用规则与 git-proxy 服务 |
| Agent 机器 | `passmanager unenroll` | 移除配置、使用规则与 git-proxy 服务 |
| Agent 机器 | `passmanager ssh-agent [--socket 路径]` | OpenSSH agent 桥（Unix） |
| Agent 机器 | `passmanager git-proxy [--listen 127.0.0.1:端口] [--install \| --uninstall]` | git 凭据注入代理；`--install`：用户服务 + `insteadOf` |
| 服务器 | `scripts/install-server.sh` | 服务器一键安装（`DRY_RUN=1` 用于测试） |

### 10.7 条目：多字段密钥与 SSH 私钥

- 条目要么是一个值（`secret`），要么是若干命名字段（`username`、`password`、`token`……）。字段名只能是 `[a-z0-9_-]`、不能重复、值不能为空。
  0.1.0 的载荷格式仍可读取，下次保存时改写为新格式。
- 占位符：`{{secret}}` = 按主机选出的条目的单值（多字段条目会报错并提示写字段名）；`{{名称}}` = 指定的单值条目；`{{名称.字段}}`；
  `{{字段}}` 只在恰好一个条目匹配该主机时可用。错误信息不会列出其他条目的字段。`sudo` 使用 `password` 字段（或密码条目的单值）。
- URL 以 `{{条目}}` / `{{条目.字段}}` 开头时（通常是 `{{ai.base_url}}`，后面可以接路径或查询），该值原样作为基础地址：必须是不带用户信息
  的绝对 https URL，后面的文本不能改变协议、主机、端口或用户信息，最终的主机必须属于该条目以及请求中其他每个占位符的绑定。
  消息与日志只提占位符，从不提地址。`{{secret}}` 与裸字段名不能放在 URL 开头（它们依赖主机）。
- 脱敏覆盖每个字段的值及其全部编码；多行值还逐行脱敏（每行 ≥ 8 个字符）；URL 值的路径与查询也单独脱敏。
- SSH：私钥条目与口令条目都匹配同一主机时先用私钥；只有私钥被拒且服务器仍提供 `password` / `keyboard-interactive` 时才用口令条目
  （例如绑定到 `*.example.com` 与局域网网段、`--ops ssh` 的默认初始口令）。`sudo` 使用口令条目的口令。
- SSH 私钥条目（`ssh-key`）保存未加密的私钥；任何地方只显示公钥与 SHA-256 指纹。条目上绑定的主机密钥（`SHA256:…`）与 TOFU 指纹库一起检查。

### 10.8 ssh-agent 桥

`passmanager ssh-agent` 在 0600 的 Unix 套接字上提供 OpenSSH agent 协议，把 `REQUEST_IDENTITIES` / `SIGN_REQUEST` 经 Agent 通道转给服务器。
服务器只在以下条件都满足时签名：(1) 客户端为这条连接发送了 `session-bind@openssh.com` 且不是转发会话；(2) 主机密钥对会话标识的签名有效；
(3) 该主机密钥被允许用于该条目；(4) 待签数据是针对同一会话标识、同一公钥的 `publickey` `SSH_MSG_USERAUTH_REQUEST`；(5) 未超过速率限制（30 次/分钟）。
每次签名与每次拒绝都写入审计日志（只记条目、公钥与主机密钥指纹）。剩余风险：桥运行期间，被攻破的 Agent 机器仍能登录允许的主机，但拿不走私钥。

### 10.9 git 凭据代理

`passmanager git-proxy` 只监听回环地址，要求随机 128 位路径令牌（0600 文件），每个连接转发一个 smart-HTTP 请求，以流的形式传输
（请求帧 → 响应头 → 响应帧，每帧 64 KiB）。服务器只接受经 HTTPS 发往条目绑定主机的 `GET …/info/refs?service=git-upload-pack|git-receive-pack`
与 `POST …/git-upload-pack|git-receive-pack`；丢弃客户端的 `Authorization` / `Cookie`，只转发少量白名单请求头，加上
`Authorization: Basic base64(用户名:PAT)`；拒绝重定向；非 pack 响应脱敏；pack 流中一旦出现令牌原文即中止。自签证书的上游与 HTTPS 条目一样按指纹固定。
审计日志记录条目、主机、服务、状态与字节数。

### 10.10 Agent 一键接入

`passmanager show --label <名称>`（服务器上的 root）生成一个普通的注册码，并打印一段给 AI Agent 的文字。除了这个注册码（10 分钟、
只能用一次、服务端只在内存里保存 SHA-256），文字里没有任何秘密。文字只有一个来源（`pm_proto::agent_text`）；不带 `--label`、或不是
服务器上的 root 时，`show` 打印同一份说明的公开版本，用占位符代替注册码。

- 网页端口上的 `GET /a/<注册码>` 返回为该注册码生成的 POSIX sh 脚本：内嵌完整的 `pm-enroll://…#<指纹>` 与
  `/var/lib/passmanager/agent-bin/` 中每个客户端程序的 SHA-256（由安装脚本复制；请求时从不联网下载）。脚本与程序都经过与网页相同的
  纯后量子 TLS；SHA-256 校验防止下载损坏或被替换，`enroll` 仍固定内层服务端公钥指纹，所以篡改的程序或脚本只能来自服务器本身。
- 获取 `/a/<注册码>` 或程序不消耗注册码，`enroll` 才消耗。未知或过期的注册码返回 404，不说明原因；只接受 GET/HEAD；按来源限速
  （10 分钟内 30 次请求、10 次未知注册码 → 锁定 15 分钟）；每次访问都记审计（注册码 ID、获取的内容、来源地址）；与所有网页请求一样，
  网段检查在 TLS 握手之前。
- 回退：TLS 不支持 X25519MLKEM768 的客户端根本连不上（有意如此）。这时文字让 Agent 按运行中的服务器的发布标签与提交从源码构建客户端
  （构建时嵌入：CI 的 `GITHUB_*`、`PASSMANAGER_RELEASE_TAG`/`PASSMANAGER_RELEASE_COMMIT`，或位于标签 `v<版本>` 的干净检出），
  `git rev-parse HEAD` 不一致时拒绝。开发构建只给出说明，不给无法核对的固定值。
- `enroll` 把使用规则写入检测到的 Agent 的全局指令文件（Claude Code `~/.claude/CLAUDE.md`、Codex `~/.codex/AGENTS.md`、
  Gemini CLI `~/.gemini/GEMINI.md`、Windsurf `global_rules.md`）中 `<!-- passmanager:begin -->` 与 `<!-- passmanager:end -->` 之间：
  原地更新、不重复，原内容保存为 `*.passmanager.bak`，标记损坏时拒绝修改，`unenroll` / `uninstall` 时移除。
- `enroll`（一行命令与源码构建的回退方式都一样）还让基于 HTTPS 的 git 对 Agent 能使用的每个有 `git` 用途的条目直接可用——GitHub、
  自建的 git 服务器等一视同仁：把 `git-proxy` 装成用户服务（systemd 用户单元，`Restart=on-failure`、`RestartPreventExitStatus=78`；
  以 `--no-ask-password` 尝试 `loginctl enable-linger`，没有权限时给出说明；macOS 上是 LaunchAgent；Windows 上打印 `schtasks` 步骤），
  并替换全局 git 配置里由 PassManager 写入的 `url.<回环代理>/<路径令牌>/https/<主机>/.insteadOf` 行。128 位路径令牌持久保存在客户端
  配置目录（0600），这些行在重启后仍然有效；由回环地址加 32 位十六进制路径令牌识别我们写入的行，所以重复运行只替换、不重复。主机列表
  来自普通的 `list` 调用（`ops` 含 `git` 的条目）；`git-proxy` 不带 `--host` 时使用同一份列表。PAT 留在服务器上。

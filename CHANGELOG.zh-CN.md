# 更新日志

[English](CHANGELOG.md) | 简体中文

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.3.1] - 2026-10-11

### 修复

- **Agent 配置的位置**：`enroll` 现在总是把远程配置写到 `~/.config/passmanager`（Windows：`%APPDATA%\PassManager`），不再跟随 `XDG_CONFIG_HOME`；之后使用时先找这里，再找 0.3.0 及更早版本按 `XDG_CONFIG_HOME` 写入的位置。此前在一种环境里注册（例如执行 `curl … | sh` 的终端），而在 `XDG_CONFIG_HOME` 不同的环境里启动（例如作为 MCP 服务，或在 CI 运行器上）时找不到配置，会退回单机模式（`NO_TOKEN`）。`unenroll` 清理两个位置。`PASSMANAGER_CONFIG_DIR` 仍然优先。
- **Windows arm64 的 CI 与发布**：等待 LLVM 安装程序结束并检查退出码，从 `RUNNER_TEMP` 删除安装包改为尽力而为，不再因"拒绝访问"失败（v0.3.0 因此没有生成 GitHub Release）。

## [0.3.0] - 2026-10-11

### 新增

- **Agent 一键接入**：`passmanager agent-setup [--label 名称] [--lang zh]`（服务器上的 root；网页"Agent 令牌"页也可以）生成一次性注册码，并打印一段给 AI Agent 的文字：命令 `curl --proto =https --tlsv1.3 -fsSL https://<域名>/a/<注册码> | sh`（服务器生成的 POSIX sh 引导脚本：从服务器安装匹配的客户端、校验 SHA-256、注册并配置 MCP）、固定到服务器发布标签与提交的源码构建回退（用于不支持 ML-KEM TLS 的客户端与 Windows；开发构建只给出说明），以及使用规则。获取脚本不消耗注册码；未知或过期的注册码返回 404；`/a/` 只接受 GET/HEAD，限速、记审计并受网段限制。
- **Agent 使用规则**：`passmanager agent-instructions [--lang zh]`；`enroll` 把它们幂等地写入检测到的 Agent（Claude Code、Codex、Gemini CLI、Windsurf）的全局指令文件中 `<!-- passmanager:begin -->` 与 `<!-- passmanager:end -->` 之间并保留备份（`--no-instructions` 跳过）；`passmanager unenroll` 与 `uninstall` 移除。
- `passmanager unenroll`：从 Agent 机器上移除远程配置、MCP 项与使用规则。
- `install-server.sh --agent-bundle 目录`：从发布包为其他平台提供客户端程序（按 `SHA256SUMS` 校验）。

### 变更

- 工作区版本 0.3.0。`passmanager token add` 仍然可用，但文档中的方式是 `agent-setup`；网页令牌页显示接入说明。

## [0.2.0] - 2026-10-11

### 新增

- **局域网在线版（服务器模式）**：在局域网里运行一台 PassManager 服务器，其他机器上的 Agent 使用它保存的凭据。Agent 端 MCP 与 CLI 的用法不变；`PassManager enroll` 用一次性注册码（10 分钟、只能用一次）接入。
- **双层后量子 Agent 通道**：TLS 1.3 只允许 X25519MLKEM768 / SecP256r1MLKEM768 + TLS_AES_256_GCM_SHA384（无 0-RTT），内层再由服务端的 ML-KEM-1024 **与** Classic McEliece 6688128 静态密钥决定会话密钥，并绑定 TLS exporter（换一条 TLS 连接转发即失败）；两个方向各用 ChaCha20-Poly1305 与帧计数器（拒绝重放与重排）。Agent 固定注册码里的服务端公钥指纹（SHA-384）。网络上只接受令牌与注册握手，且只接受配置的来源网段（IPv4）。
- **网页管理界面**：服务端渲染、没有 JavaScript、CSP `default-src 'none'`；条目（密钥只写不读）、Agent 令牌与注册码、主机指纹、设置、锁定 / 解锁、安全状态。没有密码：只能用服务器上 root 运行 `passmanager login` 打印的一次性链接登录（2 分钟，GET 确认、POST 消耗）；会话空闲 2 小时 / 绝对 12 小时失效；Host / Fetch Metadata / Origin / CSRF 校验、`__Host-` cookie、限速。
- **服务器上的 root 命令**：`passmanager init`、`login`、`token add|list|revoke`、`status`、`lock`、`unlock`、`reseal`，Linux 风格的帮助与示例。
- **无口令库模式**（只用设备密钥、不运行 Argon2，1 GiB 内存的服务器也够用）：模式写在受认证的文件头里并参与 KEK 派生（防降级）；服务启动时自动解锁。口令库（v1）格式不变。
- **TPM 封存与随机数**：TPM 可用时（`/dev/tpmrm0` 或可选的 swtpm Unix 套接字）用 `systemd-creds --with-key=host+tpm2`（L3），否则主机密钥（L2）；`passmanager reseal` 从 L2 升级到 L3；不绑定 PCR。可用时把经过健康检测的 `TPM2_GetRandom` 并入随机数。
- **Let's Encrypt DNS-01（Cloudflare）**：token 经标准输入传入并用设备密钥封存；自动续期并退避；已保存的证书在有效期内继续使用。
- **健壮性**：库、令牌、密钥与证书都原子写入并 fsync；文件损坏或截断时回退到 `.bak`；崩溃注入测试；systemd 单元按 network-online 排序、有限次等待 TPM、`Restart=on-failure` 加启动次数上限，退出码 78 只用于真正的配置错误。
- **一键安装脚本**：`scripts/install-server.sh`（没有站点默认值，必须给出 `--domain` 与 `--lan-cidr`；nftables 规则、关闭 IPv6、加固单元）与 `scripts/install-agent.sh`，都带 `DRY_RUN` 测试模式。
- **`passmanager import`**（服务器，root）：从标准输入导入密钥——原样保存、只去掉末尾一个换行、上限 64 KiB、不回显不记录；标准输入是终端时拒绝（除非 `--interactive`，不回显输入）；`--domain`（主机或 主机:端口，可重复）、`--note`、`--self-signed`、`--replace`。允许没有域名的条目，显示为"未绑定域名"，添加域名前不能使用。
- **SSH 私钥条目**（`--kind ssh-key`）：未加密的 OpenSSH / PEM 私钥（ECDSA P-384、Ed25519、RSA），拒绝加密私钥；只显示公钥指纹；私钥条目用公钥认证；兼容加固的 sshd 配置（`mlkem768x25519-sha256` 或 `ecdh-sha2-nistp384`、AES-256-GCM、HMAC-SHA2-512-ETM、`AuthenticationMethods publickey`）；可为条目绑定主机密钥（`--host-key`）。
- **多字段条目**（`--fields username,password`，每行一个值，接受 CRLF）：HTTP 的 URL / 请求头 / 请求体与 SSH 命令里可用 `{{名称.字段}}`、`{{字段}}`（只有一个条目匹配该主机时）与 `{{secret}}`（单值条目）；`sudo` 使用 `password` 字段；每个字段都脱敏（全部编码、也逐行）；MCP `list` 只显示字段名。0.1.0 的库透明读取并迁移。
- **`PassManager ssh-agent`**：Agent 机器上的 OpenSSH agent 桥；私钥留在服务器，服务器只为绑定（session-bind）到允许的主机密钥的 `publickey` 认证请求签名；限速并记审计。
- **`PassManager git-proxy`**：Agent 机器上只监听回环地址的 git smart-HTTP 代理（路径令牌、`insteadOf` 配置）；服务器只对条目的域名注入保存的 PAT（只允许 HTTPS、不跟随重定向、丢弃客户端的 `Authorization`、令牌从不返回）；请求体与响应体都流式传输（大于 64 MiB 的包也可以）。
- **通配符与网段绑定、具体程度、用途限定**：`*.example.com`（只匹配子域名）、网段（`198.51.100.0/24`、IPv6 前缀；只匹配字面 IP 目标）、IDNA 规范化；多个条目匹配时用最具体的（精确 > 更长的通配符 > 更长的前缀）；`--ops http,ssh,git` 限定用途（例如永远不会被代入 HTTP 请求的 SSH 初始口令）；SSH 时先用匹配的私钥条目，只有服务器仍提供口令认证时才回退到匹配的口令条目。ssh-agent 桥使用同一套匹配规则。
- Agent 端的远程客户端、`enroll`、`ssh-agent`（Unix）与 `git-proxy` 可在 Linux、macOS、Windows 上构建；服务器专用命令只在 Linux 上提供。
- `scripts/release_scan.py`：发布前的白名单式扫描（受跟踪文件类型、高熵字符串、PEM 块、私有 IPv4 字面量）。

### 变更

- 工作区版本 0.2.0；新增 crate `pm-net` 与 `pm-web`。
- **行为变化**：`*.example.com` 不再匹配 `example.com` 本身，需要时把顶点域名单独加上。多个条目匹配同一目标时不再一律报歧义，而是使用最具体的那个。

## [0.1.0] - 2026-10-06

首个版本。

### 新增

- 面向 AI Agent 的密码管理：Agent 通过 MCP 或 CLI 让 PassManager 代为使用密钥（HTTPS 请求、SSH 命令、SCP 传输），全程看不到明文，返回结果自动脱敏。
- 条目只有"密钥 + 域名"（说明可选）；HTTP 请求中写 `{{secret}}`，按目标主机自动选择密钥。
- 抗量子双层加密：ML-KEM-1024（aws-lc-rs）+ Classic McEliece（liboqs），AES-256-GCM + ChaCha20-Poly1305，Argon2id；双源随机数与健康检测。
- 设备密钥封存：Linux systemd-creds（有 TPM 时 L3）、Windows DPAPI（有 TPM 时叠加 TPM）、macOS 系统钥匙串。
- 一键安装、账户安全检查与自动加固、TUI（键盘 + 鼠标）、Agent 一键接入（Claude Code、Codex、Cursor、Gemini CLI、VS Code、Windsurf）。
- Linux、macOS、Windows 的 x64 与 arm64 发布包。
- 许可证：PolyForm Strict License 1.0.0 + PassManager Contribution Terms（仅限非商业使用；禁止分发与修改版；欢迎通过 PR 贡献）。

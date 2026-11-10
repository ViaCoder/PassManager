# 更新日志

[English](CHANGELOG.md) | 简体中文

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.3.11-rc.19] - 2026-11-10

### 变更

- **HTTP 请求不再限时。** 去掉了整个上游 HTTPS 请求 180 秒的上限，慢的 API（例如很长的模型回复）不再被中途切断；连接仍是 20 秒超时。
  等待回复期间 Agent 客户端不设读超时（其他请求仍是 600 秒），两端都用 TCP keepalive 发现对端宕机或断网。Agent 断开或被取消时，
  服务器丢弃这个请求并关闭到上游的连接，服务器上不会留下没人等的请求。

## [0.3.11-rc.18] - 2026-11-09

### 变更

- **多行的密钥每次只用一行。** 口令 / 令牌条目或某个字段存了几行（例如以两行添加的两把可互换的 API key）时，每次使用随机取其中一行
  （操作系统 CSPRNG），而不是把几行连同换行一起发出去。HTTP 请求里的 `{{...}}` 占位符、中继、git 令牌和 SSH 口令都是这样（SSH 每次
  连接取一行，登录与 sudo 共用）。空白行跳过；PEM 私钥始终整体使用。每一行（4 个字符及以上，原来是 8 个）都单独脱敏。

## [0.3.11-rc.17] - 2026-11-08

### 变更

- **新的密钥是新增，从不覆盖。** 口令 / 令牌条目按保存的行显示遮罩（两行就两个遮罩，不露任何内容），每一行可以单独删除，在密钥区
  输入的内容作为新的行追加。网页为此既不发送也不接收原值：删除与追加由服务端在原值上完成，期间行数变了就拒绝，并且至少要保留一行。
  多字段条目里，新增的字段与保留着的字段同名时报错而不是覆盖：先勾选删除旧的。SSH 私钥仍是一个遮罩：先勾选删除再新增。"全部显示"
  之后仍可以直接修改。

## [0.3.11-rc.16] - 2026-11-08

### 变更

- **密钥在你要求之前一直隐藏。** 条目列表里不再有任何密钥信息（没有摘要、字段名或指纹，也去掉了"更新"一列）。编辑页把这个条目的
  全部密钥放在同一个密钥区：已保存的显示为 `••••••••`（不露开头、结尾或长度），只能删除，不能修改；新的密钥写在同一个区里，保存前
  完整可见。"全部显示"把已保存的密钥放进可编辑的输入框，可以直接修改；"隐藏"恢复遮住。0.3.11-rc.12 加的摘要已经去掉。域名与别名的
  说明默认收起。

## [0.3.11-rc.15] - 2026-11-08

### 修复

- **网页在笔记本、平板与手机上的布局。** 条目表格把"说明"列压到只剩几个字母宽（页面允许文字在任意位置断开，表格把这当成可以把一
  列压到一个字符宽），在 720 到 1100 像素之间还会截掉"编辑 / 删除"按钮。现在说明放在引用名下面，长主机名不再在连字符处折断，
  1101 像素以下改为卡片，421 像素以下的手机上标签放在内容上方。在 320 到 1920 像素之间的 12 种宽度下检查过，页面与表格都没有溢出。
- **编辑条目时看得到存的是哪一把**：在"新的值"输入框上方显示摘要（SSH 私钥另有公钥指纹；SSH 私钥现在也有摘要）。说明改为两行的
  输入框，长说明能看全，换行会合并成空格。手机上已有字段的"删除"始终和字段在同一行。

## [0.3.11-rc.13] - 2026-11-08

### 变更

- Windows arm64 上的 CI 与发布构建缓存 LLVM 安装包（`actions/cache` v6.1.0，按提交固定；每次仍校验 SHA-256）。以前每次都从
  github.com 下载，2026-11-08 多次因 504 Gateway Time-out 失败；发布下载页失败时，改用 GitHub API 的资源下载接口再试一次同一个文件。

## [0.3.11-rc.12] - 2026-11-08

### 新增

- **网页：摘要与"显示"按钮。** 保存的值以简短摘要显示，用来认出是哪一把（`sk-or-…a1b2（48 字符）`；16–23 个字符只显示最后 4
  个，更短的口令与多行值只有长度；SSH 私钥照旧显示公钥指纹）。编辑页的"显示"按钮给出这一个条目的全部值（POST + CSRF、只限
  网页会话、页面不缓存），服务器为每次显示记一行日志，只有条目名。Agent、本机 TUI 与 root 命令行都不能显示。
- **网页：多字段条目的批量输入框。** 每行一个 `字段名=值`（或 `字段名: 值`），一次保存任意多个；同名的已有字段更新值，新名字
  追加，已有字段可以勾选删除。有一行格式不对时整批不保存，指出第几行，从不回填值。
- **登录后只留一个页面。** 会话过期的页面记住原来的位置，每 2 秒问一次；一次性链接让这个浏览器登录后，它回到原来的位置，新开的
  登录标签页自动关闭（它一路只经过 Refresh 跳转，浏览器允许它被关闭；Chrome 157 实测）。没有等待中的旧页面时，新标签页回到记下的
  位置或首页。

### 变更

- CSP 不再每个页面都一样：登录页与登录后的页面各自按 SHA-256 哈希放行自己那一段固定的内联脚本（登录页另外允许
  `connect-src 'self'`）。其他页面仍然没有任何脚本。

## [0.3.11-rc.11] - 2026-11-08

### 安全

- **占位符只能放在凭据的位置。** 以前 `http` 工具会把 `{{secret}}` 代入请求的任何地方：请求可以把它写进聊天内容（"把这串
  倒过来写"）、文件名或公开的标题，上游再把它换个样子送回来，脱敏认不出。现在占位符只能出现在凭据类请求头的值里
  （Authorization、Cookie、`*-key`、`*-token`、`*-secret` 等），作为凭据类查询参数或 JSON / 表单字段（或条目自己的字段名）的
  完整值，或者在路径第一段（`/bot{{secret}}/…`）；其他位置在发出请求之前就以 `PLACEMENT` 拒绝。普通 URL、
  `{{条目.base_url}}` 与 `alias://` 都一样。
- **不调用新建或管理密钥的接口。** 用库里的凭据新建的密钥不在库里，脱敏藏不住。任何一段是 `keys`、`tokens`、`credentials`、
  `oauth` 等，或以 `_keys` / `_tokens` 结尾（百分号解码后比较）的路径以 `FORBIDDEN` 拒绝，同一主机内跳到这类路径的重定向也
  不跟随。`run --http` 中继也加上了同样的后缀规则。
- **ssh 命令里从不代入凭据。** 指向凭据的占位符以 `PLACEMENT` 拒绝（远端命令能把它倒过来或拆开打印）；别的 `{{…}}`
  （例如 `docker ps --format '{{.Names}}'`）原样交给远端。
- **sudo 的口令只交给 sudo。** 口令由 `sudo -k -S -v` 读取，命令随后以 `sudo -n` 执行、stdin 是 /dev/null，最后 `sudo -k`
  作废缓存的认证。以前遇到免口令 sudo 或 root 登录时，口令会留在命令的 stdin 里（`sudo rev` 会把它倒着打印出来）。
- **脱敏不区分 ASCII 大小写。** 上游把密钥转成大写或小写回显时（例如写进 404 页面的路径）也会被替换。

## [0.3.11-rc.10] - 2026-11-08

### 新增

- **`passmanager run --http <origin>`：本机程序不经手凭据就能调用 HTTPS API。** SDK、CLI 或 curl 拿到一个带一次性令牌的本机地址
  （`--env-url NAME=/路径`）和一个占位密钥（`--env-key NAME`）；每个请求都经服务器，服务器按凭据的中继策略检查、加上凭据，再把回答
  流式送回。SSE 事件逐个到达，单个请求最长 30 分钟，程序断开时上游请求随之取消。
- **中继策略**（`passmanager relay set/list/remove`，root）：允许的 `方法 路径`（精确，或以 `/*` 结尾的前缀）、凭据怎样发出、JSON
  请求体规则、每次运行与每 24 小时的上限。管理密钥、登录、账号或计费的路径永远不放行。`--max-requests`、`--max-bytes`、`--require`
  只能收窄策略。有策略的凭据，`lookup` 会给出 `run --http` 的命令。
- **流式脱敏：** 回答按滑动窗口脱敏，结果与整段脱敏完全相同（所有编码形式），只扣住可能是匹配开头的几个字节。压缩的回答先解压。

### 变更

- 有中继策略的库用新格式（v4）写入；没有策略的库仍用原来的格式。
- CI 与发布构建改在 `ubuntu-24.04` 上运行，不再用 `ubuntu-latest`。GitHub 把 `ubuntu-latest` 换成了 26.04，那里 `oqs-sys` 用系统
  libclang 生成的绑定结构体大小不对，构建失败。

## [0.3.11-rc.9] - 2026-11-06

### 修复

- **在条目的域名框粘贴 `https://` 网址时被拒绝**，报 `invalid port`，看起来像是必须写端口。现在可以直接粘贴：只取其中的主机和端口。其他协议给出明确的错误，带用户名的网址被拒绝。`--domain` 同样修复。
- **条目设了别名后，只知道条目名的 Agent 走不下去：** `lookup {{名称}}` 只回 `ALIAS_ONLY`。现在返回 `alias://` 的写法；真实地址仍然不返回，原主机仍然不能直接访问。
- **ssh-agent 套接字不再修改进程的 umask。** 它在私有目录里创建，以 0600 改名到位，从不以更宽的权限出现，也不再影响其他线程新建的文件（曾让测试随机失败）。

## [0.3.11-rc.8] - 2026-11-06

### 变更

- **URL 别名改成条目表单上的一个输入框，** 不再是单独的页面。填写后，这个条目的主机只能经 `alias://<名称>` 访问；清空即恢复。限制说明写在输入框下面，条目列表显示别名。`passmanager alias` 命令保留给 root。

## [0.3.11-rc.7] - 2026-11-06

### 安全

- **升级有新公告的依赖：** rustls-webpki 0.103.16（RUSTSEC-2026-0382，已不受信任的 emSign 中间证书）、webpki-root-certs 1.0.11（RUSTSEC-2026-0383）、crypto-bigint 0.7.10（RUSTSEC-2026-0387）、ctutils 0.4.8（RUSTSEC-2026-0385）、tokio 1.53.3（RUSTSEC-2026-0386）。
- **压缩响应可以绕过脱敏。** Agent 可以要求 `Accept-Encoding: gzip`，压缩后的字节不会被脱敏发现，Agent 解压后就能读到密钥。现在请求一律要求 `identity`，服务器仍返回压缩内容时拒绝返回。
- **吸取 OpenSSH 通配符与 principals 修复的教训（10.3、10.4、CVE-2026-35414）：**
  - **空集合不再等于全部。** 没有用途的条目过去允许所有用途，现在什么都不允许，新条目至少要有一种用途。旧条目在解锁时改写一次，明确列出全部用途，原有功能不受影响。
  - **目标是数据，不是模式。** 目标里的 `*`、逗号、控制字符和过长的名称不再进入匹配，目标 `*.example.com` 不能匹配绑定 `*.example.com`。SSH 的用户名和主机按严格字符集检查，不能以 `-` 开头。
  - **检测：** `passmanager status` 和安全页提示允许全部用途的通配符绑定和很宽的网段。

### 新增

- **URL 别名。** 在网页或用 `passmanager alias add` 设置。Agent 使用 `alias://<名称>/<路径>`；整台主机不能被直接访问（`ALIAS_ONLY`，http、ssh、scp、git、lookup 和 ssh-agent 桥都一样），真实地址从发给 Agent 的所有内容里去掉，包括编码形式。限制见 `docs/DEPLOY-LAN.zh-CN.md` 3.1.1。
- **网页一键登录。** `passmanager web` 在你自己的电脑上打开管理页面：经 PassManager 登录服务器，取一次性链接后直接进入。`passmanager web --install` 注册 `passmanager-web://`，登录页的新按钮由它接管；处理程序收不到链接里的任何内容。
- **未登录时的页面更好用：** 登录页优先提供一键登录，会话过期时给出提示，已登录时直接回到首页。
- **`passmanager init --admin-allow`**：把网页管理页面限制到指定地址，不影响 `/tang/`、Agent 接入和 Agent 通道。空列表是配置错误。
- **Advisories 工作流自己提出修复。** 出现新公告时，`scripts/advisory_fix.py` 按漏洞库选出最小的兼容修复版本，测试后开 PR。不会合并，也不会发布。

### 变更

- **`passmanager import` 新条目必须写 `--ops`。** `--replace` 不写时保留原来的用途。
- **Agent 使用规则 v7：** 加一行说明 `alias://`。升级后运行 `passmanager show --rules --write`。
- 还在 Node 20 上的 GitHub Actions 升到 Node 24 版本；`mlugg/setup-zig` 还没有新版，暂时不动。

## [0.3.11-rc.6] - 2026-10-18

### 新增

- **`lookup tang`：Agent 从服务器本身得知本服务器的 Tang 用法。** 只能访问 PassManager、没有本地笔记的 Agent 调用 `lookup tang`（或本服务器的 `https://…/tang` 地址）。服务器当场读取 tangd 当前的签名密钥，计算指纹（RFC 7638，与 `tang-show-keys` 相同），返回 pin 与远程主机上经过实测的步骤：检查 OpenSSL 与连通、`clevis encrypt` 并用 SHA-256 核对、开机把文件解密到 `/run` 并等待服务器应答的 systemd 单元、把原路径换成指向该副本（保留属主与权限）、撤销。只需升级服务器，旧客户端得到同样的回答。
  - 指纹经已固定指纹的 Agent 通道送达，客户端不必信任首次下载。
  - 没有配置 `--tang` 时返回 `NO_TANG`；tangd 无应答时返回 `UPSTREAM_ERROR`。
- **Agent 使用规则 v6**：加一行指向 `lookup tang`，MCP 的 `lookup` 说明也提到它。升级后运行 `passmanager show --rules --write`。

### 文档

- `docs/DEPLOY-LAN.zh-CN.md` 4.1：在 `/tang/` 后面部署 tangd、允许与移除远程主机、Agent 从 `lookup tang` 得到什么。

## [0.3.11-rc.5] - 2026-10-18

### 新增

- **网络绑定加密（Clevis + Tang）。** `passmanager init --tang 127.0.0.1:<端口>` 之后，网页端口在 `/tang/` 上把 Clevis 的两种请求（`GET /tang/adv[/<thp>]`、`POST /tang/rec/<kid>`）原样转给本机回环上的 tangd（Debian 的 `tang` 包）。其他机器用 `clevis encrypt tang '{"url":"https://pm.example.com:8120/tang","thp":"<指纹>"}'` 把密钥绑定到这台服务器：磁盘镜像离开能访问服务器的网络就解不开，不需要 TPM。
  - **只用成熟的实现。** 密钥与交换由 tangd 完成（McCallum-Relyea 交换，服务器看不到客户端的密钥）；PassManager 只做 HTTPS 入口。
  - **访问限制与网页相同：** 来源必须在局域网网段或允许列表，Host 必须是本站；传输是 TLS 1.3 + 混合后量子组。
  - **只转发该转发的：** 指纹与密钥 ID 只接受 tangd 自己的字符集，交换请求必须是 `application/jwk+json` 且不超过 8 KiB，tangd 的回答只接受它的两种类型（其他一律 502）；tangd 地址只能是回环地址（否则配置错误，退出码 78）。
  - **已知限制：** Tang 的交换基于 P-521 椭圆曲线，本身不是后量子的；后量子的是到达服务器的传输。

### 变更

- **`passmanager init --allow` 会提醒防火墙不随之改变。** 允许列表的防火墙规则由 `install-server.sh` 生成；只运行 `init` 时，应用内的来源检查已经更新，防火墙仍是旧的列表（新加的来源连接超时）。

## [0.3.11-rc.4] - 2026-10-18

### 新增

- **macOS、Windows 和较旧的 Linux 不用再从源码构建就能接入。** 这些机器自带的 curl 和 PowerShell 不支持服务器要求的后量子 TLS（X25519MLKEM768），一行安装命令会以退出码 35 失败，以前的接入说明只能让它们从源码构建。现在只要服务器的 agent-bin 目录里有它自己那个发布的 `SHA256SUMS`，`passmanager show --label <名称>` 就会多出第 2 步：给出每个平台现成的命令——从固定到服务器标签的 GitHub 发布页下载发布包，校验写在命令里的 SHA-256，解压后注册。源码构建改为第 3 步。服务器的 TLS 策略不变；SHA-256 经管理员从服务器上复制的接入说明到达 Agent 机器。
- **`scripts/agent-bundle.sh`**：不重新运行安装脚本，就能把发布包放进运行中服务器的 agent-bin 目录。它逐个按 `SHA256SUMS` 校验，解出 Linux 与 macOS 的程序，从不替换服务器自己的程序，并复制 `SHA256SUMS` 供接入说明使用。`install-server.sh --agent-bundle` 也改为调用它。

### 变更

- **`--agent-bundle` 必须有 `SHA256SUMS`。** 目录里没有它（或者它是符号链接）时，在安装任何东西之前就拒绝。

## [0.3.11-rc.3] - 2026-10-17

### 新增

- **经跳板 SSH。** 在 `ssh`、`scp` 工具里把目标写成 `跳板用户@跳板主机>user@host`（scp 写成 `跳板用户@跳板主机>user@host:/path`），或者像 OpenSSH 一样给 `passmanager ssh` / `passmanager scp` 加 `-J 跳板用户@跳板主机`。只支持一级跳板。
  - **每一跳只用自己绑定的凭据。** 服务器先用跳板绑定的凭据登录跳板，再开一条到目标的 `direct-tcpip` 通道，在通道里与目标完成完整的 SSH 握手与登录。跳板只转发密文，看不到目标的凭据，目标也看不到跳板的凭据。
  - **两跳都核对主机密钥。** 任何一跳的主机密钥变化都以 `HOST_KEY_CHANGED` 中止，不向那一跳发送任何登录数据；跳板的主机密钥变化时，根本不会请求转发。
  - **`lookup` 支持路由写法**，列出两跳的凭据，`how` 写出完整路由。
  - **兼容性：** 路由写在目标字符串里，只需升级服务器，旧客户端原样转发。例外：scp 且跳板写了端口（`jump:2222>…`）时需要本版客户端。
- **`lookup` 自动补上非默认端口。** 目标没写端口、默认端口上没有绑定，而这台主机正好只在另一个端口上有绑定（例如 `git.example.com:8121`）时，`lookup` 按那个端口回答。显式写出的端口不会被改；同一主机绑定了两个端口时视为有歧义，不猜。

### 变更

- 按 Rust 1.99 的 lint（`collapsible_match`、`needless_borrows_for_generic_args`）调整代码，行为不变。

## [0.3.11-rc.2] - 2026-10-16

### 修复

- **`lookup` 对 git 给出的写法与 Agent 使用规则 v5 一致。** 原来的 `how` 叫 Agent 直接运行 git，git 要求输入凭据时再运行 `passmanager git-proxy --install`；现在给出 `passmanager run git <clone|fetch|pull|push|ls-remote> https://<主机>/<owner>/<repo>.git`。只需升级服务器，客户端不变。

## [0.3.11-rc.1] - 2026-10-15

### 新增

- **`passmanager run <命令>`**：只为一条命令提供经服务器转发的认证，不装服务、不改配置（Unix）。
  例如：`passmanager run git push`、`passmanager run ssh user@host`、`passmanager run rsync …`。
  - **基于 HTTPS 的 git**：在本机回环地址的随机端口开一个转发口，路径令牌是一次性的。转发口只通过 `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` 交给 git，所以不写任何 git 配置文件。请求照旧经过服务器，由服务器带上令牌。
  - **ssh、scp、rsync 与基于 SSH 的 git**：临时 agent 套接字放在只有本人能访问的目录里，经 `SSH_AUTH_SOCK` 交给命令。签名照旧由服务器完成。
  - **生命周期**：命令结束后两者都删除。Ctrl-C 交给命令本身，退出码与命令相同。异常退出留下的临时目录在下次运行时删除。

### 变更

- **Agent 使用规则 v5**：需要登录的终端命令改用 `passmanager run`，不再用 `git-proxy --install` 和 `ssh-agent`。升级后运行 `passmanager show --rules --write`。

### 安全

- **`passmanager git-proxy` 不再打印路径令牌。** 它打印的配置命令改为用 `$(cat …)` 读令牌文件，所以令牌不会出现在终端输出和服务日志里。

## [0.3.10] - 2026-10-15

### 安全

- **rustls 0.23.45 → 0.23.46**，修复 0.3.9 发布之后公布的 RUSTSEC-2026-0349、RUSTSEC-2026-0346、RUSTSEC-2026-0347、RUSTSEC-2026-0348。
  - 与本项目有关的是 RUSTSEC-2026-0349：未经认证的 ServerHello 可能让客户端之后的连接从混合后量子密钥交换退回到传统算法。PassManager 的 Agent 通道有内层的 ML-KEM-1024 + Classic McEliece 加密，内容一直是保密的；这次升级恢复了外层 TLS 的保证。
  - RUSTSEC-2026-0346 涉及客户端会话值的 `Debug` 输出，PassManager 从不打印这些值。
  - ECH（0347）与 Brotli 证书解压（0348）都没有用到。
- 其他依赖没有变化。

### 维护

- 每天定时检查 RustSec 安全公告（`.github/workflows/advisories.yml`），新公告会在下一次发布之前报告，而不是发布之后。发布改为先推到 `release/X.Y.Z` 分支，CI 全部通过后才推送标签。

## [0.3.9] - 2026-10-15

### 变更（对 Agent 不兼容）

- **按需查询：`lookup` 取代 `list`。** Agent 不再拿到全部条目的域名、备注、字段与用途。`lookup`（MCP 工具与 `passmanager lookup 目标 [--use http|ssh|scp|git]`）接收将要访问的 URL、`user@host` 或主机（基础地址本身是秘密时用 `{{名称}}`），只返回引用名、字段名与 `how`：一行照抄即可的 `http` / `ssh` / `scp` 调用。选择规则与真正执行请求时完全相同。备注永远不给 Agent。`list`（MCP 别名与 CLI）以及协议的 `List` 请求现在返回 `USE_LOOKUP`，不透露任何信息。
- **逐步披露、精简的使用说明**，照顾能力较弱的模型（参照 Anthropic 的工具编写指南与 MCP 规范）：`instructions` 最多 5 行（先 lookup、照抄 `how`、不泄露秘密、按 `Next:` 做）；4 个工具各 2~3 句、一个最小 JSON 示例，并带 `readOnlyHint` / `destructiveHint` / `openWorldHint` 标注；测试限制工具列表的大小。
- **每个错误最后都有 `Next:`**（CLI 是 `next` 字段），明确下一步：例如 `NO_CREDENTIAL` → 在服务器上导入，秘密不显示（`<输出秘密的命令> | ssh root@<服务器> passmanager import …`）；`DOMAIN_MISMATCH` → `passmanager update --name … --domain …`；`AMBIGUOUS` → 请用户指定用哪个引用名。文字集中在 `pm_proto::agent_text::next_step`。
- **使用规则 v4**（写入 Agent 的全局指令文件）：lookup 流程、git 与 ssh-agent、`Next:` 规则，以及拥有服务器 root SSH 的 Agent 如何新增或修改凭据。升级后运行 `passmanager show --rules --write` 原地更新，不需要重新注册。
- git-proxy 的主机发现改用只限令牌的 `git_hosts` 请求：只返回有 `git` 用途条目的域名。

### 新增

- `passmanager update --name 名称 [--domain 域名]… [--remove-domain 域名]… [--add-op 用途]… [--remove-op 用途]… [--note 文字]`（服务器上的 root）：只改绑定、用途与备注，不动密钥。对不限用途的条目，`--add-op` 不做任何改变，`--remove-op` 保留其余用途。
- `import` 与 `update` 在备注看起来含有路径、URL、账号或令牌时给出警告（备注只写一句用途）。

### 安全

- 错误信息不再列出条目绑定的域名（`DOMAIN_MISMATCH` 只说明该条目没有绑定所请求的主机）或允许的用途（`OP_NOT_ALLOWED`）；`AMBIGUOUS` 只列出并列的引用名。

### 升级

- 先升级服务器，再升级各客户端（在每台客户端上运行 `passmanager show --rules --write`）。
- 0.3.8 及更早的客户端的 `http`、`ssh`、`scp` 与 git 照常可用，但它们的 `list` 会返回 `USE_LOOKUP`；在升级客户端之前，`git-proxy --install` 无法发现主机。已有的 `insteadOf` 行不受影响。

## [0.3.8] - 2026-10-12

### 变更

- **唯一的接入命令：`passmanager show`。** `show --label 名称`（服务器上的 root）生成 10 分钟有效、只能使用一次的注册码，并打印给 AI Agent 的完整说明——一行命令 `sh -c "$(curl --proto '=https' --tlsv1.3 -fsSL https://<地址>/a/<注册码> || echo "exit $?")"`、curl 不支持后量子 TLS 时的备用方式（退出码 35：按固定的发布标签与提交从源码构建，再运行 `PassManager enroll '<pm-enroll://…>'`）以及使用规则。`show --label 名称 --url` 只打印 `pm-enroll://` 注册码，`show --rules` 只打印使用规则。不带参数的 `show`，或不是服务器上的 root 的任何用户，得到不含注册码的公开说明（已注册的机器上会写出连接的服务器）。默认中文，`--lang en` 为英文。文字仍然只有一个来源（`pm_proto::agent_text`）。
- **移除** `passmanager agent-setup`、`passmanager agent-instructions`、`passmanager token add` 与 `scripts/install-agent.sh`；改用 `show --label`、`show --rules`、`show --label --url` 与一行命令。`token list` / `token revoke`、`enroll`、`import` 不变。
- **使用规则 v3**：基于 HTTPS 的 git 直接使用 `https://` 地址，经常驻的 `git-proxy` 服务访问；`passmanager git-proxy --install` 刷新。

### 新增

- **注册后 git 直接可用**，适用于每个有 `git` 用途的条目（GitHub、自建的 git 服务器等一视同仁）：`enroll`——一行命令与源码构建的备用方式都用它——把 `git-proxy` 装成开机或登录时自动启动的用户服务（systemd 用户单元 `passmanager-git-proxy.service`，以不询问口令的方式尝试 `loginctl enable-linger`，没有权限时给出说明；macOS 上是 LaunchAgent `com.passmanager.git-proxy`；Windows 上打印 `schtasks` 步骤），并为每个 git 主机写入一行全局的 `url."http://127.0.0.1:7878/<路径令牌>/https/<主机>/".insteadOf "https://<主机>/"`。路径令牌持久保存（0600），重启后这些行仍然有效；重复运行只替换、不重复；只有服务已经运行时才写入这些行，没有用户服务管理器的机器上 git 保持可用。PAT 从不到达 Agent 机器。新选项：`enroll --no-git-proxy`、`enroll --git-proxy-listen 地址`、`git-proxy --install`、`git-proxy --uninstall`；`unenroll` 移除服务与这些行。
- `git-proxy` 不带 `--host` 时打印服务器上有 `git` 用途的所有条目的主机的配置（来自 `list` 调用）。配置错误（没有远程配置、`--listen` 不是回环地址）以 78 退出，服务管理器不再重启。

### 安全

- **注册码**：Agent 通道上的兑换失败现在按来源地址限速（10 分钟内失败 10 次 → 锁定 15 分钟；锁定期间有效的注册码也不受理、不被消耗）。审计日志记录每次兑换的标签、来源地址与结果（`enroll: ok …`、`enroll: rejected …`），从不记录注册码。确认不变：256 位随机注册码、只在内存里保存 SHA-256、10 分钟过期、只能使用一次（取出与作废是同一个原子操作）。

### 测试

- clap 解析 `show` 的每种形式与 `enroll` / `git-proxy` 的新选项，被移除的命令被拒绝；公开说明（不带 `--label`、不是 root）不含 `pm-enroll://` 注册码与 `/a/<注册码>`；注册码强度与只保存哈希、过期、重复使用、16 个线程并发兑换同一注册码（恰好一个成功）、按来源锁定；`agent_setup_e2e` 改用 `show`（包括经网络并发 `enroll` 同一注册码与锁定）；新的端到端测试运行 `show` → 在临时 HOME 里（替身 `systemctl` / `loginctl`）运行安装脚本 → 检查单元文件、调用与 `insteadOf` 行（`git-proxy --install` 可重复运行），按单元的 `ExecStart` 启动代理，对本地 git HTTP 服务器的 `git push` / `git ls-remote` 成功，临时 HOME 与输出里都没有 PAT，`token revoke` 之后 git 失败；systemd 单元 / LaunchAgent 的生成与安装步骤（替身服务管理器）、`systemd-analyze verify`；真实 git 下替换 `insteadOf` 并保留用户自己的配置；对生成的安装脚本运行 `shellcheck`；`install_scripts_test.sh` 用替身服务管理器覆盖 `git-proxy --install/--uninstall`。

## [0.3.7] - 2026-10-11

### 修复

- **升级后浏览器继续使用缓存里的旧样式表**：页面以固定地址 `/static/style.css`（以及 favicon）引用静态资源，缓存 `max-age=3600`，升级后浏览器会把新的 HTML 与缓存里的旧样式表拼在一起（图标巨大且没有样式、"跳到正文"链接可见），直到强制刷新。现在静态资源以 `/static/style.css?v=<哈希>` / `/static/icon.svg?v=<哈希>` 引用，哈希是编译进程序的文件内容 SHA-256 的前 10 个十六进制字符，内容一变地址就变。带当前哈希的请求返回 `max-age=31536000, immutable`；不带 `v` 或带旧的 / 未知的 `v` 仍然返回当前文件，缓存 `max-age=3600`（旧页面不会 404）。页面本身仍是 `no-store`，所以总是引用当前哈希。其他响应头（CSP、`nosniff`、CORP、Referrer-Policy）与 Host 校验不变。

### 测试

- 哈希函数（已知值；改一个字节地址就变）、`Cache-Control` 的选择、渲染出的页面包含每个资源当前的准确哈希、静态路由在带或不带（当前、旧的、格式错误的）`?v` 时都正常并保留所有安全头与 Host 校验。

## [0.3.6] - 2026-10-11

### 变更

- **网页管理界面重新设计**（仍是服务端渲染、没有 JavaScript、不加载外部资源）：统一的间距与字号层级；每页有带图标的标题、说明与主要操作；导航高亮当前页面（`aria-current`），窄屏时自动换行；状态磁贴与徽章显示密码库锁定状态、封存等级（L1/L2/L3）、证书到期（剩余天数；≤ 21 天为琥珀色，≤ 7 天或已过期为红色）、安全检查结果（未通过的项目直接列在状态页）、令牌状态（已使用 / 从未使用）与注册码倒计时；表单的标签与说明分开（`aria-describedby`），`:user-invalid` 错误样式，保存失败后明确提示"需要重新输入密钥"；条目表单用 CSS `:has()` 隐藏与所选类型无关的输入（不支持时全部显示，服务端仍会忽略它们）；删除与吊销通过 `<details>` 二次确认（无脚本）；条目、令牌、注册码、指纹与检查项都有空状态；窄于 720 px 时表格变为卡片式堆叠；跳到正文链接、`:focus-visible` 焦点框、支持 `prefers-reduced-motion` 与 `forced-colors`；浅色与深色两套配色按 WCAG AA 检查（所有文字 / 背景组合 ≥ 5.8:1）。
- **图标**：一套线性小图标（盾牌、钥匙、锁 / 解锁、服务器、令牌、链接、设置、警告、对勾、复制、删除等），以内联 SVG sprite 放在页面里；模板通过 `icon("名字")` 引用，只接受固定列表里的名字。新增同源 favicon `/static/icon.svg`。
- **CSP 收紧**：`img-src 'self' data:` → `img-src 'self'`（`data:` 从未使用；favicon 是同源的）。其他 CSP 指令不变。

### 修复

- **真实浏览器里网页表单全部被拒绝**（网页界面推出以来一直存在）：`Referrer-Policy: no-referrer` 让浏览器在表单 POST 中发送 `Origin: null`，入口检查（正确地）返回 403——登录确认、保存条目、锁定等全部失败。现在策略改为 `same-origin`（响应头与 `<meta>`）：同源请求带真实的 Origin / Referer，跨站请求仍然不带 Referer。入口检查不变，仍然拒绝 `Origin: null`、外站 Origin、错误的 Host 与跨站 Fetch Metadata。已在 Chrome 中端到端验证（一次性链接登录、条目新增 / 编辑 / 删除、令牌生成 / 吊销、锁定 / 解锁）；登录链接里的令牌只会发回同源，并在 POST 时被消耗。

### 测试

- 离线保证：模板、样式表与 favicon 不得引用外部地址（http/https、协议相对地址、`@import`、字体、`data:`），不得包含 `<script>`、事件处理属性、`javascript:` URL、可嵌入内容的元素或内联样式；链接、表单地址与资源只能是本站路径或页内片段。
- favicon / CSP 测试：CSP 字符串完全固定，favicon 的响应头（`image/svg+xml`、`nosniff`、CORP `same-origin`、CSP），静态文件同样经过 Host 校验，导航高亮。
- 图标测试（用到的名字都有定义，未知或注入的名字渲染为空）；XSS 注入测试覆盖新的模板变量（`nav`、`st.ready`、`st.issues`、`st.allow`）与新分支（空状态、证书到期、封存等级）。
- Referrer-Policy 测试：响应头与 `<meta>` 固定为 `same-origin`；入口检查仍然拒绝 `Origin: null` 与外站 Origin；浏览器式的同源 POST（`Origin: https://pm.test:8121`、`Sec-Fetch-Site: same-origin`、正确的 CSRF）在登录确认、保存条目、锁定上成功，同样的请求带 `Origin: null` 则被拒绝且不消耗登录链接。

## [0.3.5] - 2026-10-11

### 新增

- **单端口模式**：`install-server.sh --port N`（站点文件 `PORT`，`passmanager init --port N`）在一个 TLS 端口上同时提供网页与 Agent 通道，按协商出的 ALPN 分流——只有只请求 `pm-inner/1` 的客户端进入 Agent 通道（内层握手与 TLS exporter 绑定不变）；`h2`、`http/1.1`、没有 ALPN 以及浏览器式的组合都得到网页。所有生成的地址都带这个端口（网页 origin、登录链接、接入说明的一行命令、引导脚本的下载地址、`pm-enroll://` 注册码），网页的 Host / Origin 校验也要求它。网页端口与 Agent 端口相同即表示单端口模式。两端口模式（443/8443）不变，仍是默认。
- **IP 允许列表**：`--allow`（可重复，一个值可含多个以空格分隔的条目；站点文件 `ALLOW_IPS`）让 IPv4 / IPv6 地址或网段访问服务端口但不能访问 SSH；`--lan-cidr` 仍可访问 SSH 与服务。nftables 与服务自身的来源检查（网页与 Agent 通道）使用同一份列表；服务总是允许 `127.0.0.1` / `::1`。条目在安装脚本修改任何东西之前由服务的解析器校验（主机位必须为 0）；配置中的无效列表是配置错误（退出码 78）。IPv6 条目写在丢弃 IPv6 的规则之前，脚本会警告它们在 IPv6 关闭时不起作用。重新运行安装脚本会替换旧的规则与监听。
- **基础地址占位符**：http 的 URL 可以以 `{{条目}}` / `{{条目.字段}}` 开头（例如 `{{ai.base_url}}/models`）：保存的值原样作为基础地址（绝对 https、不带用户信息），其后的文本照原样追加，最终的主机必须属于该条目以及其他每个占位符的绑定。地址从不出现在消息、日志与响应中；URL 值还按路径单独脱敏。MCP 工具说明与使用规则（第 2 版）已说明。

### 修复

- `passmanager init` 重写 systemd 单元时只写 `tss` 组，会去掉安装脚本加入的 swtpm 套接字与目录的组；现在计算同样的组。

## [0.3.4] - 2026-10-11

### 修复

- **zsh 下的接入一行命令**：打印的命令用的是 `curl --proto =https …`；zsh（macOS 默认 shell）会把未加引号的 `=https` 当作命令路径展开（`zsh: https not found`），什么都没运行。现在各处（agent-setup 中英文说明、网页、README、部署说明）都改为 `sh -c "$(curl --proto '=https' --tlsv1.3 -fsSL https://<域名>/a/<注册码> || echo "exit $?")"`。
- **失败不再无声**：用 `curl … | sh` 时下载失败会让 `sh` 读到空输入并以 0 退出。新写法打印 curl 的错误并以 curl 的退出码退出；说明里告诉 AI：退出码 35（TLS 握手失败——客户端的 curl 不支持 X25519MLKEM768）表示"使用第 2 步（从固定的源码构建）"，其他错误（22 = 注册码过期或已用过，6/7 = 连不上服务器）要告诉用户。
- 测试把打印出来的命令原样经 `sh -c`、`bash -c`、`zsh -c` 对本地测试服务器运行，并检查失败时的退出码（已用过的注册码为 22，对纯后量子服务器的 TLS 握手为 35）；CI 安装 zsh。

## [0.3.3] - 2026-10-11

### 修复

- **没有附加组的 root 访问 swtpm 套接字**：`service-prepare`（systemd 以 `ExecStartPre=+…` 运行，即没有任何附加组的 root）看不到只能经组权限访问的 swtpm 套接字（例如非特权 LXC 里 `0750` 目录中的 `nobody:tss 0660` 套接字，未映射的属主让 root 没有 DAC 豁免），一直等待（"TPM 没有出现"）并无限重启。现在以 root 运行时，在任何 TPM 访问之前（service-prepare、reseal、init/status 的检测）先加入套接字所在目录与套接字的组（以及 tss），`systemd-creds` 子进程随之继承。从不修改文件权限。
- 等待时要求套接字能连接上，并报告实际的失败原因：不存在（ENOENT）、没有权限（EACCES——作为权限问题报告，而不是"TPM 没有出现"）或拒绝连接（swtpm 没有在监听）。
- `install-server.sh`：套接字及其目录只对某个组开放时，把这些组加入服务的 `SupplementaryGroups`（服务用套接字取 TPM 随机数）；`server-unit --tpm-group` 接受经过校验的空格分隔组名列表。

## [0.3.2] - 2026-10-11

### 修复

- `install-server.sh --agent-bundle`：服务器自身的程序总是作为它自己的目标提供（例如 arm64 服务器上的 `aarch64-unknown-linux-gnu`），发布包里同一目标的程序不再覆盖它，Agent 拿到的版本与服务器完全一致。与 `SHA256SUMS` 不一致的包仍然跳过并警告。此前本机目标的发布包会覆盖服务器自身的程序。
- 安装脚本测试假定主机是 x86_64（在 arm64 的 CI 运行器上失败）；现在在任何机器上都按每种模拟的 `uname -m`（`x86_64`、`amd64`、`aarch64`、`arm64` 与一种未知架构）运行发布包逻辑。

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

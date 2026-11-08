# PassManager 局域网在线版：部署指南

[English](DEPLOY-LAN.md) | 简体中文

本文中的域名、地址都是示例（`example.com` 与 RFC 5737 文档地址段），请换成你自己的值。设计与威胁模型见
[`DESIGN.zh-CN.md`](DESIGN.zh-CN.md) 第 10 节。

## 0. 前提

- 服务器：Linux + systemd ≥ 250（例如 Debian 13）；1 GiB 内存足够（无口令模式不运行 Argon2，服务常驻内存约 20 MB）。
- 一个域名，例如 `pm.example.com`，A 记录指向服务器的内网 IPv4 地址（例如 `198.51.100.10`）。Agent 通过这个域名连接。
- 证书：Let's Encrypt DNS-01，目前支持 Cloudflare。准备一个只有该区域 DNS 编辑权限（Zone → DNS → Edit）的 API token；
  安装时经**标准输入**交给程序（第一行），用设备密钥封存，不落盘明文。不用 ACME 时可以 `--skip-acme`，之后 `passmanager import-cert`。
- 允许访问的网段（必须指定，没有默认值），例如 `198.51.100.0/24`。
- 管理员凭据只有能以 root 登录服务器的 SSH 密钥：网页没有密码，靠 root 打印的一次性链接登录。

## 1. 服务器（root）

```sh
tar xzf PassManager-0.2.0-lan-x86_64-linux.tar.gz && cd PassManager-0.2.0-lan-x86_64-linux
./install-server.sh --domain pm.example.com --lan-cidr 198.51.100.0/24 < /root/cf-token
```

也可以把参数写进本地的站点配置文件（不要提交到任何仓库）：

```sh
cat > site.local.env <<'CONF'
DOMAIN=pm.example.com
LAN_CIDRS=198.51.100.0/24 203.0.113.0/24
# 可选：TPM_SOCKET=/run/swtpm/tpm.sock   WEB_PORT=443   AGENT_PORT=8443
CONF
./install-server.sh --site-file site.local.env < /root/cf-token
```

脚本可以重复执行，会：

1. 安装 `/usr/local/bin/PassManager` 与小写别名 `passmanager`；
2. 创建不可登录的系统账户 `passmanager`；root 加入 `tss` 组；发现 TPM 时补装 tss2 运行库；
3. 写 `/etc/sysctl.d/99-disable-ipv6.conf` 并应用（已关闭 IPv6 的现有文件保持不变；容器里无权限时给出警告）；
4. nftables：独立的 `table inet passmanager`（`/etc/nftables.d/passmanager.nft`，由 `/etc/nftables.conf` include），
   只放行给定网段访问 22 与网页 / Agent 端口，丢弃其余入站与全部 IPv6；
5. 写 systemd 单元与 tmpfiles；
6. `passmanager init`：设备密钥（有 TPM 用 L3，否则 L2）、内层通道密钥、无口令密码库、证书，启动服务。

### 检查

```sh
passmanager status          # 库已解锁、封存等级、证书到期时间、安全检查"全部通过"
ss -tlnp | grep -E ':(443|8443)\b'; ip -6 addr; nft list table inet passmanager
systemd-analyze security passmanager; journalctl -u passmanager -n 30 --no-pager
```

### 单端口模式与 IP 允许列表

只有一个端口能到达服务器时（例如只转发一个 TCP 端口的转发器），用单端口模式：一个 TLS 监听同时提供网页与 Agent 通道，
按 TLS 的 ALPN 区分（Agent 用 `pm-inner/1`；浏览器用 `h2`、`http/1.1` 或不带 ALPN）。所有生成的地址都带这个端口
（`https://pm.example.com:8121`、`pm-enroll://pm.example.com:8121/…`、`show --label` 接入说明的一行命令、登录链接）。

```sh
./install-server.sh --domain pm.example.com --port 8121 \
    --lan-cidr 198.51.100.0/24 \
    --allow "203.0.113.7 203.0.113.64/26" --allow 2001:db8::/32 --skip-acme
# 站点文件：PORT=8121   ALLOW_IPS="203.0.113.7 203.0.113.64/26"
```

- `--lan-cidr`（局域网）：可以访问 SSH（22）与服务端口。
- `--allow` / `ALLOW_IPS`：只能访问服务端口（不能访问 SSH）的 IPv4 / IPv6 地址或网段；一个值可以含多个以空格分隔的条目。
  防火墙与服务本身（网页与 Agent 通道）使用同一份列表；服务总是允许 `127.0.0.1` 与 `::1`。无效条目（例如主机位不为 0 的网段）
  会让安装脚本在修改任何东西之前退出；服务配置里的无效列表是配置错误（退出码 78）。
- IPv6 条目：安装脚本关闭了 IPv6 并丢弃全部 IPv6，所以在你自行启用 IPv6 之前它们不起作用（脚本会给出警告）。
- 重新运行安装脚本会整体替换 `inet passmanager` 表与服务配置：从 `--web-port/--agent-port` 换成 `--port`（或反过来）不会留下旧的规则或监听。
- 已注册的 Agent：端口变更后，把 `~/.config/passmanager/remote.toml` 里的 `port` 改成新端口（固定的服务端指纹不变），
  或者用新的 `passmanager show --label` 文字重新注册。

### 1.2 只允许部分地址打开网页管理

网页端口上还有 `/tang/` 和一次性 Agent 接入（`/a/`），防火墙规则分不开它们和管理页面。`--admin-allow` 只限制管理页面：

```sh
passmanager init --admin-allow "198.51.100.10 198.51.100.12"   # 会重启服务
passmanager init --admin-allow any                             # 取消限制
```

其他来源（包括服务器本机）只会得到 404：请从列表里的地址打开登录链接。Agent、`/tang/` 和 `/a/` 不受影响。重新运行安装脚本不会改变这项设置。
空列表是配置错误，绝不表示“所有人”。

## 2. 网页管理

在你自己已注册的电脑上，一条命令就能打开（没有密码，也不用复制链接）：

```sh
passmanager web --ssh root@192.0.2.5      # 第一次写服务器的 SSH 目标，之后记住
passmanager web --install                 # 启用登录页的一键登录按钮
```

`passmanager web` 经 PassManager 登录服务器，运行 `passmanager login --auto`，然后打开浏览器直接进入管理页面。链接不会出现在命令行或输出里，
只在一个私有文件里保留几秒。`--install` 注册 `passmanager-web://` 协议（Linux 桌面入口、macOS 的 `~/Applications` 应用、Windows 当前用户的注册表项）。
处理程序收不到链接里的任何内容，所以网页只能触发这一条固定的命令。`login --auto` 的链接打开即登录，不要发给别人。


```sh
ssh root@pm.example.com passmanager login     # 输出 https://pm.example.com/l/…（2 分钟内有效，只能用一次）
```

在浏览器打开链接 → 点"登录"。页面顶部显示本次连接的算法（`X25519MLKEM768 + TLS13_AES_256_GCM_SHA384`）。
条目的密钥只能写入，任何页面都不会显示。会话空闲 2 小时或登录满 12 小时失效。

## 3. Agent 机器

```sh
ssh root@pm.example.com passmanager show --label laptop            # 默认中文；--lang en 为英文
ssh root@pm.example.com passmanager show --label laptop --url      # 只打印 pm-enroll:// 注册码（给从源码构建的客户端）
passmanager show [--rules]                                         # 任何机器：不含注册码的公开说明 / 只打印使用规则
```

`show --label` 打印一段文字，把它交给 Agent 机器上的 AI Agent（网页"Agent 令牌"页也显示同样的文字）。不带 `--label`、
或不是服务器上的 root 运行时，`show` 只打印公开说明（没有注册码，也没有任何秘密）；在已注册的机器上还会写出连接的服务器。
这段文字里有一个一次性注册码（10 分钟、只能用一次），以及：

1. 命令 `sh -c "$(curl --proto '=https' --tlsv1.3 -fsSL https://pm.example.com/a/<注册码> || echo "exit $?")"`
   （`'=https'` 加引号，因为 zsh 会展开未加引号的 `=单词`；与 `curl … | sh` 不同，下载失败时以 curl 的退出码报错——35 表示 TLS
   握手失败，即客户端的 curl 不支持 X25519MLKEM768）。服务器返回为该注册码生成的 POSIX sh
   脚本：按本机的系统与 CPU 从服务器本身（`/a/<注册码>/bin/<目标>`）下载客户端、校验 SHA-256、装到 `~/.local/bin`（不需要 root），
   然后运行 `enroll`；
2. 在 TLS 握手失败（curl 不支持 ML-KEM，例如 macOS 或较旧的发行版）或在 Windows 上时：按文字中固定的发布标签与提交从源码构建客户端
   （`cargo build --release -p passmanager`；需要 Rust、cmake、C 编译器、libclang），再运行它的 `enroll`。服务器是开发构建时
   只给出说明，不给固定值；
3. 给 AI 的使用规则。

`enroll` 核对注册码里的服务端公钥指纹，令牌存到本人可读的配置目录（Linux `~/.config/passmanager`，0600），为检测到的 Agent 写入
MCP 配置（不含令牌），并把使用规则写入它们的全局指令文件中 `<!-- passmanager:begin -->` 与 `<!-- passmanager:end -->` 之间
（备份为 `*.passmanager.bak`；`--no-instructions` 跳过），然后配置基于 HTTPS 的 git（`--no-git-proxy` 跳过）：把
`passmanager git-proxy` 装成用户服务——Linux 上是 `~/.config/systemd/user/passmanager-git-proxy.service`（`systemctl --user enable`
并重启；以不询问口令的方式尝试 `loginctl enable-linger`，成功时开机即启动，否则登录后启动，输出会说明由管理员运行
`sudo loginctl enable-linger <用户>`），macOS 上是 LaunchAgent `~/Library/LaunchAgents/com.passmanager.git-proxy.plist`，Windows 上
打印 `schtasks` 的手动步骤——并为每个有 `git` 用途条目的主机（GitHub、自建的 git 服务器等，一视同仁）写入一行全局的
`url."http://127.0.0.1:7878/<路径令牌>/https/<主机>/".insteadOf "https://<主机>/"`。路径令牌持久保存在令牌旁边（0600），重启后这些行仍然有效。
只有服务已经运行时才写入这些行（没有 systemd 用户实例或在 Windows 上时，git 配置保持不变，直到代理运行后再运行 `--install`）。
新增 git 条目后重新运行 `passmanager git-proxy --install`（整体替换，不会重复）；`passmanager git-proxy --uninstall` 移除服务与这些行。
PAT 从不到达 Agent 机器。

注册码：256 位随机数，服务端只在内存里保存 SHA-256，10 分钟有效，只能用一次（取出与作废是同一个原子操作，并发兑换时恰好一个成功）。
注册失败按来源地址限速（10 分钟内失败 10 次 → 锁定 15 分钟，锁定期间有效的注册码也不受理、不被消耗）。审计日志只记录标签、来源地址与结果，
从不记录注册码。获取脚本不消耗注册码，`enroll` 才消耗。未知或过期的注册码返回 404；`/a/` 请求限速、记审计日志，并且和整个网页端口一样
只接受配置的网段。`passmanager unenroll` 从 Agent 机器上移除配置、MCP 项、使用规则与 git-proxy 服务；令牌请在网页"Agent 令牌"页或用
`passmanager token revoke <ID>` 吊销（未使用的注册码由 `token list` 列出，也用同样的方式作废）。

安装脚本把自身的程序复制到 `/var/lib/passmanager/agent-bin/`；其他平台用 `--agent-bundle <目录>` 提供发布包
（`PassManager-<版本>-<目标>.tar.gz` / `.zip`）和这个发布的 `SHA256SUMS`（必须有）；与服务器同一目标的发布包不会替换服务器自身的程序。
服务器在请求时从不联网下载。

agent-bin 目录里的 `SHA256SUMS` 同时打开接入说明的第 2 步：curl 不支持 X25519MLKEM768 的机器（macOS、Windows、较旧的 Linux）会得到现成的命令，
从固定到服务器标签的 GitHub 发布页下载本平台的发布包，并校验写在命令里的 SHA-256。要在运行中的服务器上添加或更新这些发布包而不重新运行安装脚本：
把服务器这个版本的发布资产和 `SHA256SUMS` 下载到同一个目录，以 root 运行 `agent-bundle.sh <目录>`（它在服务器包里，和 `install-server.sh` 放在一起）。
接入说明只列出与服务器同一版本的发布包。

### 3.1 导入密钥（服务器，root）

```sh
passmanager import --name github --ops http --domain api.github.com < token.txt                 # 单值（例如 PAT）
passmanager import --name mail --ops http --fields username,password --domain mail.example.com < creds.txt   # 每行一个字段值
passmanager import --name deploy-key --ops ssh --kind ssh-key --domain db1.example.com:22 \
    --host-key "$(ssh-keyscan -t ecdsa db1.example.com 2>/dev/null)" < id_ecdsa       # 未加密的私钥
passmanager import --name github --replace --domain api.github.com < new-token.txt    # 替换已有条目
passmanager import --name pin --ops http --interactive                                           # 在终端里不回显地输入
```

内容原样保存（只去掉末尾一个换行，上限 64 KiB），从不回显或写入日志，只打印 `已导入 <名称>（<n> 字节，<k> 个域名）`。
没有 `--domain` 的条目显示为"未绑定域名"，在网页里添加域名之前 Agent 无法使用。占位符：`{{secret}}`（单值条目）、
`{{名称.字段}}`、`{{字段}}`（只有一个条目匹配该主机时）；`sudo` 使用 `password` 字段。需要保密的基础地址（例如 AI 网关的地址）
放进 `base_url` 字段（`--fields base_url,api_key`）；Agent 用 `{{ai.base_url}}/models` 作为 URL，并带 `Authorization: Bearer {{ai.api_key}}`。

绑定可以是精确主机、`*.example.com`（只匹配子域名，不含顶点域名本身）、IP 或网段（如 `198.51.100.0/24`，只匹配直接用 IP 访问的目标），
都可以加 `:端口`；多个条目匹配时用最具体的。新机器的默认初始 SSH 口令（只用于 SSH，且只在已保存的私钥被拒后才使用）：

```sh
passmanager import --name init-pw --domain '*.example.com' --domain 198.51.100.0/24 --ops ssh < initial-password.txt
```

新条目必须写 `--ops`（`http`、`ssh`、`git`）：没有用途的条目什么都不能做，绝不表示“全部用途”。`--replace` 不写 `--ops` 时
保留原来的用途。旧版本保存的没有用途的条目，会在解锁时改写一次，明确列出全部用途（权限不变）；`passmanager status` 与安全页会
提示允许全部用途的通配符绑定和很宽的网段。

### 3.1.1 URL 别名

别名向 Agent 隐藏一个地址。在网页的条目表单里填写“别名”：条目要绑定一个具体主机并允许 `http`，清空即取消，删除条目时别名一起删除。
在服务器上以 root 运行时，别名还可以带基础路径：

```sh
passmanager alias add billing https://api.example.com:8443/v1 --note '账单接口'
passmanager alias list
passmanager alias remove billing
```

Agent 在 `http` 里写 `alias://billing/items?q=1`（`lookup alias://billing` 给出确切写法）。服务器代入真实地址和绑定到那台主机的凭据；
`{{secret}}` 照常使用，不带占位符的请求也可以。Agent 不能列出别名。

- **整台主机对 Agent 关闭**，所有端口、所有用途：`http`、`ssh`、`scp`、git、`lookup` 和 ssh-agent 桥都返回 `ALIAS_ONLY`，
  提到这台主机的 `ssh` 命令也会被拒绝。
- **真实地址从发给 Agent 的一切内容里去掉**：响应体、响应头、重定向与错误信息，包括明文、百分号、base64、hex 形式，不区分大小写，
  替换为 `alias://<名称>`。
- **路径不能离开别名**：`..`、`%2e`、`%2f`、`%5c` 都被拒绝，`Range` 请求也是。
- 别名是一个具体的 `https` URL：不能有通配符、占位符、用户信息、查询串或片段；每台主机一个别名。

限制，如实说明：检查针对名称，同一台服务器的其他主机名或 IP 是另一个目标，除非也给它设别名。Agent 如果在某台能访问这台服务器的主机上
有 shell，可以把地址一段段拼出来，文字过滤也看不穿 `rev` 这类有意的变换；必须隐藏的主机，不要给这类 Agent 留路径。
有别名的库用新格式保存，旧版本打不开，这是有意的：旧程序会忽略别名。回滚到没有别名功能的版本之前，先删除别名。

### 3.1.2 本机程序：`passmanager run --http`

Agent 机器上的程序（OpenAI 兼容的 SDK、CLI、curl）可以在一条命令的时间里调用需要凭据的 HTTPS API，而凭据从不到达那台机器。
服务器上的 root 先给凭据设中继策略；没有策略的凭据不能这样用：

```sh
passmanager relay set --name openrouter --allow 'POST /api/v1/chat/completions' --allow 'GET /api/v1/models' \
    --require 'json:model=@preset/gemma31b' --max-requests-day 2000
passmanager relay list
passmanager relay remove --name openrouter
```

在 Agent 机器上：

```sh
passmanager run --http https://openrouter.ai --env-url OPENAI_BASE_URL=/api/v1 --env-key OPENAI_API_KEY python3 app.py
```

程序拿到 `OPENAI_BASE_URL=http://127.0.0.1:<随机端口>/<一次性令牌>/api/v1`，以及一个离开这次运行就没有用的占位
`OPENAI_API_KEY`。有多个 `--http` 时写 `NAME=<origin>|<路径>`；`--max-requests`、`--max-bytes`、`--require` 只在这次运行里收窄策略。
对这个 API 的地址做 `lookup`，Agent 就能拿到准确的命令。

- **策略**（由 root 设置，客户端不能设）：允许的 `方法 路径`，要么是精确路径，要么是以 `/*` 结尾的前缀（没有其他通配写法）；
  凭据怎样发出（`--auth`，默认 `Authorization: Bearer {{secret}}`）；JSON 请求体规则（`json:键=值`，同一个键的多个值表示"之一"；
  有重复键的请求体一律拒绝；没有请求体的请求不检查）；每次运行与每 24 小时的上限；额外放行的响应头。任何一段是 `keys`、`auth`、
  `token`、`billing`、`account` 之类的路径永远不放行，策略怎么写都一样；路径先做百分号解码再比较，`..` 与编码的 `/` 一律拒绝。
- **每个请求**：令牌不对时，中继直接回 403，不联系服务器。服务器丢掉程序发来的任何凭据（`Authorization`、`x-api-key`、
  `x-goog-api-key`、`api-key`、`Cookie`、`key`/`api_key`/`access_token` 查询参数），加上真实凭据；主机、端口与 TLS 名称来自凭据的
  绑定。只跟随同源而且仍在策略之内的重定向。策略之外的请求回 403，超过上限回 429，上游都收不到。
- **每个回答**：服务器要求 `identity`，上游仍压缩时解开 gzip/deflate（其他编码拒绝）。库里的每个密钥（所有编码形式）与每个别名地址
  都在状态行、响应头与响应体里被替换（`[REDACTED:<名称>]` 或 `alias://<名称>`）。流式数据按滑动窗口处理，只扣住可能是匹配开头的
  几个字节，所以 SSE 事件立刻到达。响应头只放行一小份白名单。
- **日志**只记 origin、方法、路径的最后一段、状态、字节数、耗时与替换次数；不记请求头、请求体、令牌或凭据。单个请求最长 30 分钟；
  程序断开后，服务器在 10 秒内取消上游请求。

实际的边界：运行期间，同一个本机用户下、能读到这个程序环境变量的任何进程都可以在策略与上限之内使用这个中继，但仍然读不到凭据。
24 小时的计数在服务器内存里，重启后重新开始。有中继策略的库用新格式写入；回滚到旧版本之前先删除策略。

### 3.2 ssh-agent 桥（Agent 机器，Linux / macOS）

```sh
PassManager ssh-agent &                       # 打印 SSH_AUTH_SOCK=…（套接字 0600）
export SSH_AUTH_SOCK=…; ssh deploy@db1.example.com
```

私钥不离开服务器。服务器只为 publickey 认证请求签名，并要求 OpenSSH ≥ 8.9 的 `session-bind@openssh.com`
证明会话属于条目允许的主机密钥（`--host-key` / 网页绑定，或指纹库中与条目域名匹配的记录）；限速 30 次/分钟，每次签名记审计日志。

### 3.3 git 凭据代理（Agent 机器，各平台）

```sh
PassManager git-proxy --host github.com &     # 默认监听 127.0.0.1:7878，打印要执行的 git config 命令
git config --global url."http://127.0.0.1:7878/<路径令牌>/https/github.com/".insteadOf "https://github.com/"
git clone https://github.com/owner/repo.git
```

服务器上要有绑定该主机的条目：单值 PAT，或带 `username` 与 `token`/`password` 字段的多字段条目（用户名默认 `x-access-token`）。
只转发 smart-HTTP（`info/refs`、`git-upload-pack`、`git-receive-pack`），只允许 HTTPS 与条目的域名，不跟随重定向；
令牌只在服务器上注入，Agent 机器拿不到。路径令牌保存在配置目录（0600），防止本机其他程序借用代理。

## 4. TPM（L3）

TPM 自动检测 `/dev/tpmrm0`。如果宿主机以 swtpm Unix 套接字的形式给容器提供软件 TPM，用 `--tpm-socket <路径>` 配置
（例如 `/run/swtpm/tpm.sock`；需要 tss2 的 swtpm TCTI 运行库，脚本会安装）。套接字与所在目录只对某个组开放时
（例如 `0750` 目录里的 `nobody:tss 0660`），PassManager 以 root 运行时（包括没有附加组的 `ExecStartPre=+`）会加入这些组，
安装脚本也把它们加入服务的 `SupplementaryGroups`；从不修改权限。仍然无法访问时，`journalctl -u passmanager` 会区分
ENOENT、EACCES 与 ECONNREFUSED。之后：

```sh
./install-server.sh --site-file site.local.env --skip-acme   # 补装运行库、root 加入 tss（证书配置不变）
passmanager reseal                                           # L2 → L3（会重启服务）
```

效果与代价：磁盘镜像、快照、备份离开这份 TPM 状态就解不开；运行中的系统里的 root 仍然能解封；
不绑定 PCR；**TPM 状态丢失、被清除或迁移到别的主机后，密码库永久无法打开（没有恢复途径）。**

### 4.1 网络绑定加密（Clevis + Tang）

没有 TPM 的其他机器可以把密钥绑定到这台服务器：Debian 的 `tang`（服务器）与 `clevis`（客户端）完成密钥与交换，
PassManager 只在网页端口上提供 HTTPS 入口 `/tang/`（来源限制与网页相同，TLS 1.3 + 混合后量子组）。

```sh
# 服务器（root）。先写监听地址再装包：安装时 tangd.socket 会立即启动（否则先监听 80）。
mkdir -p /etc/systemd/system/tangd.socket.d
printf '[Socket]\nListenStream=\nListenStream=127.0.0.1:7500\n' > /etc/systemd/system/tangd.socket.d/loopback.conf
apt-get install tang
systemctl daemon-reload && systemctl restart tangd.socket
curl -sf -o /dev/null http://127.0.0.1:7500/adv     # 第一次请求时 tangd 生成签名与交换密钥
tang-show-keys 7500                                 # 签名密钥指纹（thp），给客户端用
passmanager init --tang 127.0.0.1:7500              # 网页端口提供 /tang/（会重启服务）

# 客户端（需要 OpenSSL 3.5，例如 Debian 13；源地址须在局域网网段或允许列表里）
echo test | clevis encrypt tang '{"url":"https://pm.example.com:8120/tang","thp":"<指纹>"}' | clevis decrypt
```

- 远程主机（Agent）：只能访问 PassManager 的 Agent 调用 `lookup tang`（MCP，或 `passmanager lookup tang`）。
  服务器当场从 tangd 读取当前签名密钥，返回 pin（地址与指纹，经已固定指纹的 Agent 通道送达）和远程主机上的步骤：
  安装与连通检查、加密并核对、开机解密到 `/run` 并等待本服务器的单元、把原路径换成指向该副本、撤销。
  没有配置 `--tang` 时返回 `NO_TANG`；tangd 无应答时返回 `UPSTREAM_ERROR`。
- 允许一台远程主机：把它的地址加入站点文件的 `ALLOW_IPS`，重新运行
  `./install-server.sh --site-file site.local.env --skip-acme`（防火墙与服务一起更新）。
  再移除后，那台主机不能再解密；已在它 `/run` 里的副本保留到它重启。
- Tang 的交换（P-521 上的 McCallum-Relyea）本身不是后量子的；后量子的是到服务器的传输。
- 服务器不可达时，绑定的密钥解不开：依赖它开机的机器会等待。`/var/lib/tang` 里的密钥丢失后，所有绑定都无法解开，
  请与 PassManager 的数据一起备份（快照）。

## 5. 故障与恢复

- 退出码：78 = 配置错误（不重启，查看 `journalctl -u passmanager`）；75 = 暂时性故障（TPM 还没出现、端口被占用），
  systemd 15 秒后重试，15 分钟内最多 10 次。
- 断电 / kill -9：所有文件原子写入；主库文件损坏时自动从 `vault.pmv.bak` 打开（`passmanager status` 会提示）。
- 证书续期失败不影响运行：旧证书在有效期内继续使用，失败后按 10 分钟到 6 小时退避重试。
- 卸载：`systemctl disable --now passmanager; rm -rf /var/lib/passmanager /etc/systemd/system/passmanager.service
  /etc/tmpfiles.d/passmanager.conf /etc/nftables.d/passmanager.nft`（删除即永久丢失全部凭据）。

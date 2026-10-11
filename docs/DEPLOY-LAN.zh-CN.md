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
（`https://pm.example.com:8121`、`pm-enroll://pm.example.com:8121/…`、接入说明的一行命令、登录链接）。

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
  或者用新的 `passmanager agent-setup` 文字重新注册。

## 2. 网页管理

```sh
ssh root@pm.example.com passmanager login     # 输出 https://pm.example.com/l/…（2 分钟内有效，只能用一次）
```

在浏览器打开链接 → 点"登录"。页面顶部显示本次连接的算法（`X25519MLKEM768 + TLS13_AES_256_GCM_SHA384`）。
条目的密钥只能写入，任何页面都不会显示。会话空闲 2 小时或登录满 12 小时失效。

## 3. Agent 机器

```sh
ssh root@pm.example.com passmanager agent-setup --label laptop --lang zh
```

它打印一段文字，把它交给 Agent 机器上的 AI Agent（网页"Agent 令牌"页也显示同样的文字）。其中有一个一次性注册码
（10 分钟、只能用一次），以及：

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
（备份为 `*.passmanager.bak`；`--no-instructions` 跳过）。获取脚本不消耗注册码，`enroll` 才消耗。未知或过期的注册码返回 404；
`/a/` 请求限速、记审计日志，并且和整个网页端口一样只接受配置的网段。`passmanager unenroll` 从 Agent 机器上移除配置、MCP 项与使用规则；
令牌请在网页"Agent 令牌"页或用 `passmanager token revoke <ID>` 吊销。

安装脚本把自身的程序复制到 `/var/lib/passmanager/agent-bin/`；其他平台用 `--agent-bundle <目录>` 提供发布包
（`PassManager-<版本>-<目标>.tar.gz`，可附 `SHA256SUMS`）；与服务器同一目标的发布包不会替换服务器自身的程序。服务器在请求时从不联网下载。

### 3.1 导入密钥（服务器，root）

```sh
passmanager import --name github --domain api.github.com < token.txt                 # 单值（例如 PAT）
passmanager import --name mail --fields username,password --domain mail.example.com < creds.txt   # 每行一个字段值
passmanager import --name deploy-key --kind ssh-key --domain db1.example.com:22 \
    --host-key "$(ssh-keyscan -t ecdsa db1.example.com 2>/dev/null)" < id_ecdsa       # 未加密的私钥
passmanager import --name github --replace --domain api.github.com < new-token.txt    # 替换已有条目
passmanager import --name pin --interactive                                           # 在终端里不回显地输入
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

## 5. 故障与恢复

- 退出码：78 = 配置错误（不重启，查看 `journalctl -u passmanager`）；75 = 暂时性故障（TPM 还没出现、端口被占用），
  systemd 15 秒后重试，15 分钟内最多 10 次。
- 断电 / kill -9：所有文件原子写入；主库文件损坏时自动从 `vault.pmv.bak` 打开（`passmanager status` 会提示）。
- 证书续期失败不影响运行：旧证书在有效期内继续使用，失败后按 10 分钟到 6 小时退避重试。
- 卸载：`systemctl disable --now passmanager; rm -rf /var/lib/passmanager /etc/systemd/system/passmanager.service
  /etc/tmpfiles.d/passmanager.conf /etc/nftables.d/passmanager.nft`（删除即永久丢失全部凭据）。

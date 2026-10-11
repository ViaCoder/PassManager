#!/usr/bin/env bash
# PassManager 局域网在线版：服务器一键安装（在服务器上以 root 运行，可重复执行）。
#
# 用法：
#   ./install-server.sh --domain pm.example.com --lan-cidr 198.51.100.0/24 < cf-token
#        Cloudflare API token 从标准输入读入（第一行，不回显、不落盘明文）
#   ./install-server.sh --domain pm.example.com --lan-cidr 198.51.100.0/24 --skip-acme
#        不申请证书（之后用 passmanager import-cert 导入）
#   ./install-server.sh --site-file site.local.env < cf-token
#        从本地站点配置文件读取参数（KEY=VALUE；只认下面列出的键，不会当作脚本执行）
#   ./install-server.sh --domain pm.example.com --port 8121 --lan-cidr 198.51.100.0/24 \
#        --allow "203.0.113.7 203.0.113.64/26" --skip-acme
#        单端口模式（只有一个端口可用时，例如经端口转发）；允许列表中的地址只能访问服务端口，不能访问 SSH
#
# 选项（域名与网段没有默认值，必须给出）：
#   --domain NAME        服务域名（证书与 Host 校验）                       站点文件键 DOMAIN
#   --lan-cidr CIDR      局域网 IPv4 网段，可重复；可访问 SSH（22）与服务端口  站点文件键 LAN_CIDRS（空格分隔）
#   --allow "列表"       额外允许访问服务端口（不含 SSH）的 IPv4 / IPv6 地址或网段，可重复，
#                        一个值可含多个以空格分隔的条目                    站点文件键 ALLOW_IPS（空格分隔）
#   --port N             单端口模式：网页与 Agent 通道共用这个端口（按 TLS ALPN 分流）  站点文件键 PORT
#   --web-port N         网页端口（默认 443；两端口模式）                  站点文件键 WEB_PORT
#   --agent-port N       Agent 端口（默认 8443；两端口模式）               站点文件键 AGENT_PORT
#   --tpm-socket PATH    可选：swtpm 的 Unix 数据套接字；不给时只自动检测 /dev/tpmrm0   站点文件键 TPM_SOCKET
#   --agent-bundle DIR   可选：放有发布包（PassManager-<版本>-<目标>.tar.gz，可附 SHA256SUMS）的目录，
#                        供一键接入（passmanager agent-setup）给其他平台的 Agent 机器下载；本机程序总会提供
#                                                                          站点文件键 AGENT_BUNDLE
#   --site-file FILE     读取站点配置文件（命令行参数优先）
#   --skip-acme          不申请 Let's Encrypt 证书
#   -h, --help           显示帮助
#
# 做的事情：
#   1. 安装 /usr/local/bin/PassManager（以及小写别名 passmanager）；
#   2. 专用系统账户 passmanager（不可登录）；root 加入 tss 组；发现 TPM 时安装 tss2 运行库；
#   3. /etc/sysctl.d/99-disable-ipv6.conf（all/default/lo 关闭 IPv6）并立即应用；
#   4. nftables：独立的 inet passmanager 表（每次整体替换）：局域网可访问 22 与服务端口，允许列表只能访问服务端口，
#      丢弃其余入站与全部 IPv6（允许列表里的 IPv6 条目在 IPv6 关闭时不起作用，会给出警告）；
#   5. systemd 单元（加固沙箱、network-online、有限次重试、78 不重启）；
#   6. passmanager init：设备密钥（有 TPM 用 L3，否则 L2）、内层通道密钥、无口令密码库、证书，启动服务。
#
# 测试：DRY_RUN=1 ROOT=<目录>：所有文件写到 $ROOT 下，系统命令（systemctl、nft、sysctl、useradd、usermod、
# apt-get、ldconfig）由 PATH 里的替身提供，passmanager init 以测试布局运行且不申请证书、不启动服务。
set -euo pipefail

DOMAIN=""
LANS=()
WEB_PORT=""
AGENT_PORT=""
PORT=""
ALLOWS=()
ALLOW_GIVEN=0
SKIP_ACME=0
TPM_SOCKET=""
SITE_FILE=""
AGENT_BUNDLE=""
DRY_RUN="${DRY_RUN:-0}"
ROOT="${ROOT:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?--domain 需要参数}"; shift 2 ;;
    --lan-cidr|--lan) LANS+=("${2:?--lan-cidr 需要参数}"); shift 2 ;;
    --web-port) WEB_PORT="${2:?--web-port 需要参数}"; shift 2 ;;
    --port) PORT="${2:?--port 需要参数}"; shift 2 ;;
    --allow) read -r -a _a <<< "${2?--allow 需要参数}"; ALLOWS+=("${_a[@]}"); ALLOW_GIVEN=1; shift 2 ;;
    --agent-port) AGENT_PORT="${2:?--agent-port 需要参数}"; shift 2 ;;
    --tpm-socket) TPM_SOCKET="${2:?--tpm-socket 需要参数}"; shift 2 ;;
    --site-file) SITE_FILE="${2:?--site-file 需要参数}"; shift 2 ;;
    --agent-bundle) AGENT_BUNDLE="${2:?--agent-bundle 需要参数}"; shift 2 ;;
    --skip-acme) SKIP_ACME=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：$1（--help 查看用法）" >&2; exit 2 ;;
  esac
done

# 站点配置文件：只解析已知的键（不 source，不执行任何内容）；命令行给出的值优先。
if [ -n "$SITE_FILE" ]; then
  [ -f "$SITE_FILE" ] || { echo "站点配置文件不存在：$SITE_FILE" >&2; exit 2; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    case "$line" in *=*) ;; *) continue ;; esac
    key="$(printf '%s' "${line%%=*}" | tr -d '[:space:]')"
    val="$(printf '%s' "${line#*=}" | sed -e 's/^[[:space:]"'"'"']*//' -e 's/[[:space:]"'"'"']*$//')"
    case "$key" in
      DOMAIN) [ -n "$DOMAIN" ] || DOMAIN="$val" ;;
      LAN_CIDRS) if [ ${#LANS[@]} -eq 0 ]; then read -r -a LANS <<< "$val"; fi ;;
      WEB_PORT) [ -n "$WEB_PORT" ] || WEB_PORT="$val" ;;
      PORT) [ -n "$PORT" ] || PORT="$val" ;;
      ALLOW_IPS) if [ "${ALLOW_GIVEN:-0}" != 1 ]; then read -r -a ALLOWS <<< "$val"; fi ;;
      AGENT_PORT) [ -n "$AGENT_PORT" ] || AGENT_PORT="$val" ;;
      TPM_SOCKET) [ -n "$TPM_SOCKET" ] || TPM_SOCKET="$val" ;;
      AGENT_BUNDLE) [ -n "$AGENT_BUNDLE" ] || AGENT_BUNDLE="$val" ;;
      "") ;;
      *) ;;  # 其他键（例如部署用的主机地址）与安装无关，忽略
    esac
  done < "$SITE_FILE"
fi

if [ -n "$PORT" ] && { [ -n "$WEB_PORT" ] || [ -n "$AGENT_PORT" ]; }; then
  echo "--port（单端口模式）不能与 --web-port / --agent-port 同时使用" >&2; exit 2
fi
WEB_PORT="${WEB_PORT:-443}"
AGENT_PORT="${AGENT_PORT:-8443}"
if [ -n "$PORT" ]; then
  WEB_PORT="$PORT"; AGENT_PORT="$PORT"
fi
[ -n "$DOMAIN" ] || { echo "必须指定 --domain（没有默认值）" >&2; exit 2; }
[ ${#LANS[@]} -gt 0 ] || { echo "必须至少指定一个 --lan-cidr（没有默认值；服务不会在没有网段限制时监听网络）" >&2; exit 2; }
for c in "${LANS[@]}"; do
  if ! printf '%s' "$c" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
    echo "网段格式无效：$c" >&2; exit 2
  fi
done
case "$DOMAIN" in
  *[!a-zA-Z0-9.-]*|"") echo "域名格式无效：$DOMAIN" >&2; exit 2 ;;
esac
for p in "$WEB_PORT" "$AGENT_PORT"; do
  case "$p" in ''|*[!0-9]*) echo "端口无效：$p" >&2; exit 2 ;; esac
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then echo "端口无效：$p" >&2; exit 2; fi
done
if [ "$WEB_PORT" = "$AGENT_PORT" ]; then
  PORTS="$WEB_PORT"
else
  PORTS="$WEB_PORT, $AGENT_PORT"
fi
case "$TPM_SOCKET" in
  ""|/*) ;;
  *) echo "--tpm-socket 必须是绝对路径" >&2; exit 2 ;;
esac
if [ -n "$AGENT_BUNDLE" ] && [ ! -d "$AGENT_BUNDLE" ]; then
  echo "--agent-bundle 不是目录：$AGENT_BUNDLE" >&2; exit 2
fi
LAN_SET="$(IFS=,; printf '%s' "${LANS[*]}" | sed 's/,/, /g')"

if [ "$DRY_RUN" = 1 ]; then
  [ -n "$ROOT" ] || { echo "DRY_RUN=1 需要 ROOT=<目录>" >&2; exit 2; }
  # 防止误用：DRY_RUN 下系统命令必须由 PATH 里的测试替身提供，不能是系统自带的命令。
  for c in systemctl useradd usermod apt-get sysctl nft ldconfig; do
    p="$(command -v "$c" 2>/dev/null || true)"
    case "$p" in
      "" | /usr/* | /bin/* | /sbin/* | /lib/* | /opt/*)
        echo "DRY_RUN=1：$c 必须由 PATH 里的测试替身提供（找到：${p:-无}），拒绝执行" >&2; exit 2 ;;
    esac
  done
  mkdir -p "$ROOT"
else
  ROOT=""
  [ "$(id -u)" -eq 0 ] || { echo "需要 root：sudo $0" >&2; exit 1; }
fi

say() { printf '== %s\n' "$*"; }
warn() { printf '\033[33m警告：%s\033[0m\n' "$*" >&2; }

BIN_SRC="$HERE/PassManager"
[ -x "$BIN_SRC" ] || BIN_SRC="$HERE/../PassManager"
[ -x "$BIN_SRC" ] || { echo "找不到 PassManager 可执行文件（应与本脚本放在同一目录）" >&2; exit 1; }

# 网段与允许列表用服务本身的解析器校验（防火墙与应用层使用同一份、同样解释的列表），在修改任何东西之前。
"$BIN_SRC" check-net --v4-only "${LANS[@]}" > /dev/null || { echo "局域网网段无效（见上）" >&2; exit 2; }
ALLOW4=()
ALLOW6=()
if [ ${#ALLOWS[@]} -gt 0 ]; then
  NETS="$("$BIN_SRC" check-net "${ALLOWS[@]}")" || { echo "--allow / ALLOW_IPS 中有无效条目（见上）" >&2; exit 2; }
  while read -r fam e; do
    [ -n "$e" ] || continue
    if [ "$fam" = 4 ]; then ALLOW4+=("$e"); else ALLOW6+=("$e"); fi
  done <<< "$NETS"
fi
SVC_V4_SET="$(IFS=,; printf '%s' "${LANS[*]}${ALLOW4[*]:+,${ALLOW4[*]}}" | sed 's/,/, /g')"
ALLOW6_SET="$(IFS=,; printf '%s' "${ALLOW6[*]}" | sed 's/,/, /g')"
ALLOW_ALL="${ALLOWS[*]}"

# ---- 1. 程序 ----
say "安装程序"
install -d -m 0755 "$ROOT/usr/local/bin"
install -m 0755 "$BIN_SRC" "$ROOT/usr/local/bin/PassManager.new"
mv -f "$ROOT/usr/local/bin/PassManager.new" "$ROOT/usr/local/bin/PassManager"
ln -sfn PassManager "$ROOT/usr/local/bin/passmanager"
PM="$ROOT/usr/local/bin/PassManager"

# ---- 2. 账户与 TPM 运行库 ----
say "服务账户与 TPM"
if ! getent passwd passmanager >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin passmanager
fi
TPM_GROUP=""
if getent group tss >/dev/null 2>&1; then
  TPM_GROUP="tss"
  # systemd-creds（root，在 ExecStartPre 里）访问 TPM（/dev/tpmrm0 或 swtpm 套接字，通常属于 tss 组）。
  usermod -aG tss root
fi
# swtpm 套接字及其所在目录只对某个组开放时（例如 nobody:tss 0660 / 0750），服务账户也需要那个组
# （服务进程用套接字取 TPM 随机数）。只加入组，从不修改宿主机提供的文件权限。
if [ -n "$TPM_SOCKET" ]; then
  for p in "$(dirname "$TPM_SOCKET")" "$TPM_SOCKET"; do
    st="$(stat -c '%a %G' "$p" 2>/dev/null || true)"
    [ -n "$st" ] || continue
    mode="${st%% *}"; grp="${st#* }"
    o=$(( 8#$mode % 8 )); g=$(( (8#$mode / 8) % 8 ))
    if [ -d "$p" ]; then need=$(( (o & 1) == 0 && (g & 1) == 1 )); else need=$(( (o & 6) != 6 && (g & 6) == 6 )); fi
    [ "$need" = 1 ] || continue
    case "$grp" in ""|root|nogroup|UNKNOWN) continue ;; esac
    case " $TPM_GROUP " in *" $grp "*) ;; *) TPM_GROUP="${TPM_GROUP:+$TPM_GROUP }$grp" ;; esac
  done
fi
if { [ -n "$TPM_SOCKET" ] && [ -S "$TPM_SOCKET" ]; } || [ -e /dev/tpmrm0 ]; then
  missing=""
  for pair in libtss2-esys.so.0:libtss2-esys-3.0.2-0t64 libtss2-rc.so.0:libtss2-rc0t64 libtss2-mu.so.0:libtss2-mu-4.0.1-0t64 \
              libtss2-tcti-swtpm.so.0:libtss2-tcti-swtpm0t64 libtss2-tcti-device.so.0:libtss2-tcti-device0t64; do
    lib="${pair%%:*}"; pkg="${pair#*:}"
    ldconfig -p | grep -q "$lib" || missing="$missing $pkg"
  done
  if [ -n "$missing" ]; then
    say "安装 TPM 运行库：$missing"
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $missing || warn "TPM 运行库安装失败，将使用 L2（主机密钥）封存"
  fi
else
  echo "   没有发现 TPM（/dev/tpmrm0${TPM_SOCKET:+ 或 $TPM_SOCKET}）：使用 L2（主机密钥）。有可用的 TPM 后运行 passmanager reseal。"
fi

# ---- 3. 关闭 IPv6 ----
say "关闭 IPv6"
SYSCTL_FILE="$ROOT/etc/sysctl.d/99-disable-ipv6.conf"
SYSCTL_WANT="# Managed by PassManager install-server.sh
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1"
install -d -m 0755 "$ROOT/etc/sysctl.d"
if [ ! -f "$SYSCTL_FILE" ] || ! diff -q <(printf '%s\n' "$SYSCTL_WANT") "$SYSCTL_FILE" >/dev/null 2>&1; then
  # 已有的配置（例如手工写的同名文件）只要已经关闭了 IPv6 就保留不动。
  if [ -f "$SYSCTL_FILE" ] && grep -Eq '^[[:space:]]*net\.ipv6\.conf\.all\.disable_ipv6[[:space:]]*=[[:space:]]*1' "$SYSCTL_FILE" \
     && grep -Eq '^[[:space:]]*net\.ipv6\.conf\.default\.disable_ipv6[[:space:]]*=[[:space:]]*1' "$SYSCTL_FILE"; then
    echo "   $SYSCTL_FILE 已关闭 IPv6，保持不变"
  else
    printf '%s\n' "$SYSCTL_WANT" > "$SYSCTL_FILE"
    chmod 0644 "$SYSCTL_FILE"
  fi
fi
if ! sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
  warn "无法应用 $SYSCTL_FILE（非特权 LXC 里可能没有权限）。请在宿主机上为容器关闭 IPv6，或确认已关闭：sysctl net.ipv6.conf.all.disable_ipv6"
fi

# ---- 4. nftables ----
say "防火墙（局域网 $LAN_SET → 22 与 $PORTS；${ALLOW4[*]:+允许列表 ${ALLOW4[*]} → $PORTS}）"
if [ ${#ALLOW6[@]} -gt 0 ]; then
  warn "允许列表中的 IPv6 条目（${ALLOW6[*]}）不起作用：本脚本关闭了 IPv6，防火墙也丢弃全部 IPv6。需要时请自行启用 IPv6。"
fi
IP6_RULE=""
if [ -n "$ALLOW6_SET" ]; then
  IP6_RULE="ip6 saddr { $ALLOW6_SET } tcp dport { $PORTS } ct state new accept"
fi
NFT_DIR="$ROOT/etc/nftables.d"
NFT_FILE="$NFT_DIR/passmanager.nft"
install -d -m 0755 "$NFT_DIR"
cat > "$NFT_FILE" <<EOF
# Managed by PassManager install-server.sh：只允许局域网访问 SSH、网页与 Agent 通道。
table inet passmanager
delete table inet passmanager
table inet passmanager {
	chain input {
		type filter hook input priority filter - 1; policy drop;
		iif "lo" accept
		${IP6_RULE:-# 没有 IPv6 允许条目}
		meta nfproto ipv6 drop
		ct state invalid drop
		ct state established,related accept
		ip protocol icmp accept
		ip saddr { $LAN_SET } tcp dport 22 ct state new accept
		ip saddr { $SVC_V4_SET } tcp dport { $PORTS } ct state new accept
	}
}
EOF
chmod 0644 "$NFT_FILE"
NFT_MAIN="$ROOT/etc/nftables.conf"
if [ ! -f "$NFT_MAIN" ]; then
  printf '#!/usr/sbin/nft -f\nflush ruleset\n' > "$NFT_MAIN"
fi
if ! grep -q '^include "/etc/nftables.d/\*.nft"' "$NFT_MAIN"; then
  printf '\ninclude "/etc/nftables.d/*.nft"\n' >> "$NFT_MAIN"
fi
if nft -c -f "$NFT_FILE" && nft -f "$NFT_FILE"; then
  systemctl enable nftables.service >/dev/null 2>&1 || warn "无法启用 nftables.service（重启后规则需要手动加载）"
else
  warn "nftables 规则加载失败（容器可能没有 CAP_NET_ADMIN）。应用内仍会拒绝局域网与允许列表以外的来源。"
fi

# ---- 5. systemd 单元 ----
say "systemd 单元"
install -d -m 0755 "$ROOT/etc/systemd/system" "$ROOT/etc/tmpfiles.d"
if [ -n "$TPM_GROUP" ]; then
  "$PM" server-unit --tpm-group "$TPM_GROUP" > "$ROOT/etc/systemd/system/passmanager.service"
else
  "$PM" server-unit > "$ROOT/etc/systemd/system/passmanager.service"
fi
"$PM" server-unit --tmpfiles > "$ROOT/etc/tmpfiles.d/passmanager.conf"
chmod 0644 "$ROOT/etc/systemd/system/passmanager.service" "$ROOT/etc/tmpfiles.d/passmanager.conf"
systemctl daemon-reload

# ---- 6. 初始化 ----
say "初始化（设备密钥、内层通道密钥、无口令密码库、证书）"
if [ -n "$PORT" ]; then
  INIT_ARGS=(init --domain "$DOMAIN" --port "$PORT")
else
  INIT_ARGS=(init --domain "$DOMAIN" --web-port "$WEB_PORT" --agent-port "$AGENT_PORT")
fi
# 允许列表总是整体传给 init（空字符串表示清空），重复运行时与本次参数一致。
INIT_ARGS+=(--allow "$ALLOW_ALL")
for c in "${LANS[@]}"; do INIT_ARGS+=(--lan-cidr "$c"); done
[ -n "$TPM_SOCKET" ] && INIT_ARGS+=(--tpm-socket "$TPM_SOCKET")
NO_CERT="$SKIP_ACME"
if [ "$DRY_RUN" = 1 ]; then
  export PASSMANAGER_HOME="$ROOT/var/lib/passmanager-dryrun"
  INIT_ARGS+=(--no-start)
  NO_CERT=1   # 测试不访问 Let's Encrypt（token 仍按正常流程封存）
fi
TOKEN=""
if [ "$SKIP_ACME" != 1 ]; then
  if [ -t 0 ]; then
    read -rsp "Cloudflare API token（Zone:DNS:Edit，输入不回显）：" TOKEN; echo
  else
    IFS= read -r TOKEN || true
  fi
  if [ -z "$TOKEN" ]; then
    warn "没有提供 Cloudflare token：跳过证书申请（之后可重新运行本脚本，或 passmanager import-cert）"
    NO_CERT=1
  fi
fi
[ "$NO_CERT" = 1 ] && INIT_ARGS+=(--skip-acme)
if [ -n "$TOKEN" ]; then
  INIT_ARGS+=(--cf-token-stdin)
  printf '%s\n' "$TOKEN" | "$PM" "${INIT_ARGS[@]}"
  TOKEN=""
else
  "$PM" "${INIT_ARGS[@]}" </dev/null
fi

# ---- 7. 一键接入用的 Agent 程序（只从本机与 --agent-bundle 复制，服务运行时从不联网下载） ----
say "一键接入用的 Agent 程序"
AGENT_BIN_DIR="$("$PM" agent-bin-dir)"
install -d -m 0755 "$AGENT_BIN_DIR"
# 本机程序与服务器版本完全一致，总是提供它；发布包里同一目标的程序不会覆盖它。
case "$(uname -m)" in
  x86_64|amd64) NATIVE_T="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) NATIVE_T="aarch64-unknown-linux-gnu" ;;
  *) NATIVE_T="" ;;
esac
[ -n "$NATIVE_T" ] && install -m 0644 "$BIN_SRC" "$AGENT_BIN_DIR/PassManager-$NATIVE_T"
if [ -n "$AGENT_BUNDLE" ]; then
  for f in "$AGENT_BUNDLE"/PassManager-*.tar.gz; do
    [ -e "$f" ] || continue
    name="$(basename "$f")"
    t=""
    for k in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu universal-apple-darwin aarch64-apple-darwin x86_64-apple-darwin; do
      case "$name" in *"-$k.tar.gz") t="$k" ;; esac
    done
    [ -n "$t" ] || continue
    if [ "$t" = "$NATIVE_T" ]; then
      echo "   $name：使用本机程序（与服务器版本一致），不用发布包里的"
      continue
    fi
    if [ -f "$AGENT_BUNDLE/SHA256SUMS" ]; then
      if ! (cd "$AGENT_BUNDLE" && grep -E "[[:space:]]\*?$name\$" SHA256SUMS | sha256sum -c --status - 2>/dev/null); then
        warn "跳过 $name：与 SHA256SUMS 不一致或没有记录"
        continue
      fi
    fi
    tmpd="$(mktemp -d)"
    if tar -xzf "$f" -C "$tmpd" 2>/dev/null; then
      b="$(find "$tmpd" -type f -name PassManager | head -n 1)"
      if [ -n "$b" ]; then
        install -m 0644 "$b" "$AGENT_BIN_DIR/PassManager-$t"
      else
        warn "跳过 $name：包里没有 PassManager"
      fi
    else
      warn "跳过 $name：无法解压"
    fi
    rm -rf "$tmpd"
  done
fi
for f in "$AGENT_BIN_DIR"/PassManager-*; do
  [ -e "$f" ] && echo "   $(basename "$f")"
done

say "完成"
echo "   状态：passmanager status"
echo "   网页：passmanager login（输出 2 分钟有效的一次性链接）"
echo "   Agent：passmanager agent-setup --label <名称>，把输出的整段文字交给那台机器上的 AI Agent"

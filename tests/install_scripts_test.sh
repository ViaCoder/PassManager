#!/usr/bin/env bash
# 检查项以单引号字符串交给 eval 延后求值（SC2016），其中用到的变量由 eval 读取（SC2034）。
# shellcheck disable=SC2016,SC2034
# 安装脚本测试（DRY_RUN：所有文件写到临时目录，系统命令由替身记录调用）。
# 用法：tests/install_scripts_test.sh <PassManager 可执行文件>
set -euo pipefail

BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d /tmp/pm-scripts.XXXXXX)"
trap 'rm -rf "$T"' EXIT
fails=0
ok() { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fails=$((fails + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# ---- 替身 ----
F="$T/fakes"; mkdir -p "$F"
LOG="$T/calls.log"
for c in systemctl useradd usermod apt-get; do
  printf '#!/bin/sh\necho "%s $*" >> "%s"\n' "$c" "$LOG" > "$F/$c"
done
cat > "$F/sysctl" <<EOF
#!/bin/sh
echo "sysctl \$*" >> "$LOG"
[ "\${FAKE_SYSCTL_FAIL:-0}" = 1 ] && { echo "sysctl: permission denied on key 'net.ipv6.conf.all.disable_ipv6'" >&2; exit 255; }
exit 0
EOF
cat > "$F/nft" <<EOF
#!/bin/sh
echo "nft \$*" >> "$LOG"
[ "\${FAKE_NFT_FAIL:-0}" = 1 ] && { echo "Operation not permitted" >&2; exit 1; }
exit 0
EOF
cat > "$F/ldconfig" <<EOF
#!/bin/sh
echo "ldconfig \$*" >> "$LOG"
[ "\${FAKE_LIBS:-0}" = 1 ] && printf '\tlibtss2-esys.so.0\n\tlibtss2-rc.so.0\n\tlibtss2-mu.so.0\n\tlibtss2-tcti-swtpm.so.0\n\tlibtss2-tcti-device.so.0\n'
exit 0
EOF
cat > "$F/getent" <<EOF
#!/bin/sh
case "\$1 \$2" in
  "group tss") echo "tss:x:996:"; exit 0 ;;
  "passwd passmanager") [ "\${FAKE_USER_EXISTS:-0}" = 1 ] && { echo "passmanager:x:998:998::/nonexistent:/usr/sbin/nologin"; exit 0; }; exit 2 ;;
esac
exit 2
EOF
chmod +x "$F"/*

PKG="$T/pkg"; mkdir -p "$PKG"
cp "$BIN" "$PKG/PassManager"
cp "$SRC/scripts/install-server.sh" "$PKG/"
SOCK="$T/swtpm/tpm.sock"
mkdir -p "$(dirname "$SOCK")"
python3 -I -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" "$SOCK"
chmod 0666 "$SOCK"   # 对所有人开放：服务账户不需要额外的组（组限制的情况见后面单独的检查）

export PASSMANAGER_TPM_SOCKET=/nonexistent/tpm.sock PASSMANAGER_TPM_DEVICE=/nonexistent/tpmrm0
TOKEN="cf-Secret-Token-Do-Not-Leak-123"

echo "== install-server.sh"
R="$T/root"
OUT="$T/out1.txt"
SITE_ARGS=(--domain pm.example.com --lan-cidr 198.51.100.0/24 --lan-cidr 203.0.113.0/24)
if printf '%s\n' "$TOKEN" | DRY_RUN=1 ROOT="$R" PATH="$F:$PATH" bash "$PKG/install-server.sh" "${SITE_ARGS[@]}" --tpm-socket "$SOCK" > "$OUT" 2>&1; then
  ok "首次安装成功"
else
  bad "首次安装失败"; cat "$OUT"
fi
check "程序已安装" '[ -x "$R/usr/local/bin/PassManager" ] && [ "$(readlink "$R/usr/local/bin/passmanager")" = PassManager ]'
check "创建服务账户" 'grep -q "^useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin passmanager$" "$LOG"'
check "root 加入 tss 组" 'grep -q "^usermod -aG tss root$" "$LOG"'
check "有 swtpm 套接字时安装 TPM 运行库" 'grep -q "^apt-get install -y --no-install-recommends.*libtss2-tcti-swtpm0t64" "$LOG"'
S="$R/etc/sysctl.d/99-disable-ipv6.conf"
check "sysctl 配置" 'grep -qx "net.ipv6.conf.all.disable_ipv6 = 1" "$S" && grep -qx "net.ipv6.conf.default.disable_ipv6 = 1" "$S" && grep -qx "net.ipv6.conf.lo.disable_ipv6 = 1" "$S"'
check "sysctl 已应用" 'grep -q "^sysctl -p $S$" "$LOG"'
N="$R/etc/nftables.d/passmanager.nft"
check "nft：局域网可访问 22 与 443/8443" 'grep -qx "		ip saddr { 198.51.100.0/24, 203.0.113.0/24 } tcp dport 22 ct state new accept" "$N" && grep -qx "		ip saddr { 198.51.100.0/24, 203.0.113.0/24 } tcp dport { 443, 8443 } ct state new accept" "$N"'
check "nft：默认丢弃、丢弃 IPv6" 'grep -q "policy drop;" "$N" && grep -q "meta nfproto ipv6 drop" "$N"'
check "nft：没有其他放行端口" '[ "$(grep -c "dport" "$N")" = 2 ]'
check "nft：先检查再加载、持久化" 'grep -q "^nft -c -f $N$" "$LOG" && grep -q "^nft -f $N$" "$LOG" && grep -q "^systemctl enable nftables.service$" "$LOG"'
check "nftables.conf 包含 include" '[ "$(grep -c "^include \"/etc/nftables.d/\*.nft\"" "$R/etc/nftables.conf")" = 1 ]'
U="$R/etc/systemd/system/passmanager.service"
check "单元：加固、重试、78 不重启、tss 组" 'grep -qx "RestartPreventExitStatus=78" "$U" && grep -qx "Restart=on-failure" "$U" && grep -qx "StartLimitBurst=10" "$U" && grep -qx "SupplementaryGroups=tss" "$U" && grep -qx "Wants=network-online.target" "$U" && grep -qx "ProtectSystem=strict" "$U" && grep -qx "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" "$U"'
if command -v systemd-analyze >/dev/null; then
  sed 's#/usr/local/bin/PassManager#/bin/true#' "$U" > "$T/passmanager.service"
  check "单元通过 systemd-analyze verify" '! systemd-analyze verify --man=no "$T/passmanager.service" 2>&1 | grep -Eq "Unknown key|Failed to parse|Invalid|unknown"'
fi
check "tmpfiles" 'grep -q "^d /run/passmanager-key 0700 passmanager passmanager -$" "$R/etc/tmpfiles.d/passmanager.conf"'
check "daemon-reload" 'grep -q "^systemctl daemon-reload$" "$LOG"'
D="$R/var/lib/passmanager-dryrun/data"
check "init：无口令库、内层密钥、封存的 Cloudflare token" '[ -f "$D/vault.pmv" ] && [ -f "$D/server-keys.pub" ] && [ -f "$D/cf-token.sealed" ]'
check "init：配置来自参数（域名、两个网段、套接字）" 'grep -q "\"pm.example.com\"" "$D/install.json" && grep -q "203.0.113.0/24" "$D/install.json" && grep -qF "$SOCK" "$D/install.json"'
ARCH_T="$(uname -m | sed 's/amd64/x86_64/; s/arm64/aarch64/')-unknown-linux-gnu"
check "一键接入：本机程序复制到 Agent 程序目录" 'cmp -s "$D/agent-bin/PassManager-$ARCH_T" "$BIN"'
check "完成提示 show --label" 'grep -q "passmanager show --label" "$OUT" && ! grep -q "agent-setup" "$OUT"'
check "Cloudflare token 没有出现在任何文件或输出里" '! grep -rqF "$TOKEN" "$R" && ! grep -qF "$TOKEN" "$OUT"'

echo "== 重复运行（幂等）、已有的 sysctl 文件、权限受限的容器"
: > "$LOG"
printf '# 手工配置\nnet.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n' > "$S"
before_keys="$(sha256sum "$D/server-keys.pub")"
if printf '%s\n' "$TOKEN" | FAKE_SYSCTL_FAIL=1 FAKE_NFT_FAIL=1 FAKE_USER_EXISTS=1 FAKE_LIBS=1 DRY_RUN=1 ROOT="$R" PATH="$F:$PATH" bash "$PKG/install-server.sh" "${SITE_ARGS[@]}" --tpm-socket "$SOCK" > "$T/out2.txt" 2>&1; then
  ok "sysctl / nft 被拒绝时继续并给出警告"
else
  bad "第二次运行失败"; cat "$T/out2.txt"
fi
check "已关闭 IPv6 的手工文件保持不变" 'grep -q "^# 手工配置" "$S"'
check "提示非特权 LXC" 'grep -q "非特权 LXC" "$T/out2.txt" && grep -q "nftables 规则加载失败" "$T/out2.txt"'
check "账户已存在时不再创建" '! grep -q "^useradd" "$LOG"'
check "运行库齐全时不调用 apt-get" '! grep -q "^apt-get" "$LOG"'
check "include 不重复" '[ "$(grep -c "^include" "$R/etc/nftables.conf")" = 1 ]'
check "内层密钥保持不变（Agent 的指纹继续有效）" '[ "$(sha256sum "$D/server-keys.pub")" = "$before_keys" ]'

echo "== 站点配置文件、没有 TPM、没有 token：L2 + 跳过证书"
R2="$T/root2"
: > "$LOG"
SITE="$T/site.local.env"
printf '# 本地站点配置\nDOMAIN=pm2.example.com\nLAN_CIDRS="192.0.2.0/24 198.51.100.0/25"\nWEB_PORT=8444\nSERVER_HOST=203.0.113.9   # 与安装无关的键被忽略\n$(touch %s/pwned)\n' "$T" > "$SITE"
# 发布包目录：x86_64 Linux 与 macOS 包校验通过；aarch64 Linux 包与 SHA256SUMS 不一致；Windows 包与未知文件忽略。
B="$T/bundle"
mkpkg() { # 目标 内容
  mkdir -p "$B/s/PassManager-0.3.0-$1"
  printf '%s' "$2" > "$B/s/PassManager-0.3.0-$1/PassManager"
  tar -C "$B/s" -czf "$B/PassManager-0.3.0-$1.tar.gz" "PassManager-0.3.0-$1"
}
mkpkg universal-apple-darwin mac-client
mkpkg x86_64-unknown-linux-gnu x86-client
mkpkg aarch64-unknown-linux-gnu arm-client
printf 'zip' > "$B/PassManager-0.3.0-x86_64-pc-windows-msvc.zip"
(cd "$B" && sha256sum PassManager-0.3.0-universal-apple-darwin.tar.gz PassManager-0.3.0-x86_64-unknown-linux-gnu.tar.gz > SHA256SUMS \
  && printf '%064d  PassManager-0.3.0-aarch64-unknown-linux-gnu.tar.gz\n' 0 >> SHA256SUMS)
printf 'AGENT_BUNDLE=%s\n' "$B" >> "$SITE"
if DRY_RUN=1 ROOT="$R2" PATH="$F:$PATH" bash "$PKG/install-server.sh" --site-file "$SITE" < /dev/null > "$T/out3.txt" 2>&1; then
  ok "无 token 时跳过证书申请"
else
  bad "无 token 运行失败"; cat "$T/out3.txt"
fi
check "提示 reseal" 'grep -q "passmanager reseal" "$T/out3.txt"'
check "没有 TPM 时不安装运行库" '! grep -q "^apt-get" "$LOG"'
check "没有 token 文件" '[ ! -f "$R2/var/lib/passmanager-dryrun/data/cf-token.sealed" ]'
check "站点文件：域名、网段、端口生效" 'grep -q "ip saddr { 192.0.2.0/24, 198.51.100.0/25 } tcp dport 22 ct state new accept" "$R2/etc/nftables.d/passmanager.nft" && grep -q "ip saddr { 192.0.2.0/24, 198.51.100.0/25 } tcp dport { 8444, 8443 } ct state new accept" "$R2/etc/nftables.d/passmanager.nft" && grep -q "\"pm2.example.com\"" "$R2/var/lib/passmanager-dryrun/data/install.json"'
check "站点文件不会被当作脚本执行" '[ ! -e "$T/pwned" ]'
check "没有配置 TPM 套接字" '! grep -q "tpm_socket" "$R2/var/lib/passmanager-dryrun/data/install.json"'
AB="$R2/var/lib/passmanager-dryrun/data/agent-bin"
check "发布包：校验通过的 macOS 程序已解出" '[ "$(cat "$AB/PassManager-universal-apple-darwin")" = mac-client ]'
# 与服务器架构无关：aarch64 包要么因校验不一致被跳过，要么（aarch64 服务器上）让位给本机程序；内容都不会被安装。
check "发布包：校验不一致的跳过并警告" '! grep -q arm-client "$AB"/* && grep -Eq "跳过 PassManager-0.3.0-aarch64-unknown-linux-gnu.tar.gz|PassManager-0.3.0-aarch64-unknown-linux-gnu.tar.gz：使用本机程序" "$T/out3.txt"'
check "发布包：Windows 包与未知文件忽略" '[ ! -e "$AB/PassManager-x86_64-pc-windows-msvc" ] && [ -z "$(find "$AB" -type f ! -name PassManager-x86_64-unknown-linux-gnu ! -name PassManager-aarch64-unknown-linux-gnu ! -name PassManager-universal-apple-darwin)" ]'

echo "== 单端口模式与允许列表"
RP="$T/root-port"
# 先以两端口模式安装，再以单端口 + 允许列表重新运行：旧规则被整体替换，不留下 443/8443。
DRY_RUN=1 ROOT="$RP" PATH="$F:$PATH" bash "$PKG/install-server.sh" --domain pm.example.com --lan-cidr 198.51.100.0/24 --skip-acme < /dev/null > /dev/null 2>&1
check "两端口：443 与 8443" 'grep -q "tcp dport { 443, 8443 }" "$RP/etc/nftables.d/passmanager.nft"'
if DRY_RUN=1 ROOT="$RP" PATH="$F:$PATH" bash "$PKG/install-server.sh" --domain pm.example.com --port 8121 --lan-cidr 198.51.100.0/24 --lan-cidr 192.0.2.0/24 \
     --allow "203.0.113.7 203.0.113.64/26" --allow 2001:db8::/32 --skip-acme < /dev/null > "$T/out-port.txt" 2>&1; then
  NP="$RP/etc/nftables.d/passmanager.nft"
  JP="$RP/var/lib/passmanager-dryrun/data/install.json"
  check "单端口：22 只对局域网开放" 'grep -qx "		ip saddr { 198.51.100.0/24, 192.0.2.0/24 } tcp dport 22 ct state new accept" "$NP"'
  check "单端口：8121 对局域网与允许列表开放" 'grep -qx "		ip saddr { 198.51.100.0/24, 192.0.2.0/24, 203.0.113.7, 203.0.113.64/26 } tcp dport { 8121 } ct state new accept" "$NP"'
  check "单端口：没有 443 / 8443，只有两条 IPv4 放行规则" '! grep -Eq "443|8443" "$NP" && [ "$(grep -c "ip saddr" "$NP")" = 2 ]'
  check "IPv6 条目：规则在丢弃 IPv6 之前，并给出不起作用的警告" 'grep -n "ip6 saddr { 2001:db8::/32 } tcp dport { 8121 } ct state new accept" "$NP" | cut -d: -f1 | { read -r a; b=$(grep -n "meta nfproto ipv6 drop" "$NP" | cut -d: -f1); [ "$a" -lt "$b" ]; } && grep -q "IPv6 条目" "$T/out-port.txt"'
  check "配置：单端口与允许列表写入 install.json" 'grep -q "\"web_port\": 8121" "$JP" && grep -q "\"agent_port\": 8121" "$JP" && grep -q "203.0.113.64/26" "$JP" && grep -q "2001:db8::/32" "$JP"'
  check "单元文件照常生成" '[ -s "$RP/etc/systemd/system/passmanager.service" ]'
else
  bad "单端口安装失败"; cat "$T/out-port.txt"
fi
# 去掉允许列表与单端口：重新运行后规则与配置都回到只有局域网。
DRY_RUN=1 ROOT="$RP" PATH="$F:$PATH" bash "$PKG/install-server.sh" --domain pm.example.com --lan-cidr 198.51.100.0/24 --skip-acme < /dev/null > /dev/null 2>&1
check "重新运行：允许列表被清空、恢复两端口" '! grep -q "203.0.113" "$RP/etc/nftables.d/passmanager.nft" && ! grep -q "ip6 saddr" "$RP/etc/nftables.d/passmanager.nft" && ! grep -q "203.0.113" "$RP/var/lib/passmanager-dryrun/data/install.json" && grep -q "\"agent_port\": 8443" "$RP/var/lib/passmanager-dryrun/data/install.json"'
# 站点文件：PORT 与 ALLOW_IPS（一行、空格分隔）。
SP="$T/site-port.env"
printf 'DOMAIN=pm.example.com\nLAN_CIDRS=198.51.100.0/24\nPORT=8121\nALLOW_IPS="203.0.113.7 203.0.113.9"\n' > "$SP"
if DRY_RUN=1 ROOT="$T/root-sp" PATH="$F:$PATH" bash "$PKG/install-server.sh" --site-file "$SP" --skip-acme < /dev/null > "$T/out-sp.txt" 2>&1; then
  check "站点文件：PORT 与 ALLOW_IPS" 'grep -q "ip saddr { 198.51.100.0/24, 203.0.113.7, 203.0.113.9 } tcp dport { 8121 }" "$T/root-sp/etc/nftables.d/passmanager.nft"'
else
  bad "站点文件（单端口）安装失败"; cat "$T/out-sp.txt"
fi
# 无效条目与冲突的参数：在修改任何东西之前以非 0 退出，并说明原因。
for a in "--allow 203.0.113.1/24" "--allow not-an-ip" "--allow 203.0.113.300" "--lan-cidr 2001:db8::/32" "--port 8121 --web-port 443" "--port 0" "--port 70000"; do
  RX="$T/root-x"; rm -rf "$RX"
  # shellcheck disable=SC2086
  if DRY_RUN=1 ROOT="$RX" PATH="$F:$PATH" bash "$PKG/install-server.sh" --domain pm.example.com --lan-cidr 198.51.100.0/24 $a --skip-acme < /dev/null > "$T/out-x.txt" 2>&1; then
    bad "拒绝 $a"
  else
    check "拒绝 $a（有说明、没有写入任何文件）" '[ -s "$T/out-x.txt" ] && [ ! -e "$RX/etc" ]'
  fi
done

echo "== swtpm 套接字只对某个组开放：服务账户加入该组（不修改套接字权限）"
GS="$T/gsock/tpm.sock"
mkdir -p "$(dirname "$GS")"
python3 -I -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" "$GS"
chmod 0750 "$(dirname "$GS")"; chmod 0660 "$GS"
GRP="$(stat -c %G "$GS")"
if DRY_RUN=1 ROOT="$T/root-g" PATH="$F:$PATH" bash "$PKG/install-server.sh" --domain pm.example.com --lan-cidr 198.51.100.0/24 --skip-acme --tpm-socket "$GS" < /dev/null > "$T/out-g.txt" 2>&1; then
  check "单元：SupplementaryGroups 包含 tss 与套接字的组" 'grep -qx "SupplementaryGroups=tss $GRP" "$T/root-g/etc/systemd/system/passmanager.service"'
  check "套接字与目录的权限没有被修改" '[ "$(stat -c %a "$GS")" = 660 ] && [ "$(stat -c %a "$(dirname "$GS")")" = 750 ]'
else
  bad "组限制的套接字：安装失败"; cat "$T/out-g.txt"
fi
check "server-unit 拒绝无效的组名" '! "$PKG/PassManager" server-unit --tpm-group "tss
ExecStart=/bin/sh" > /dev/null 2>&1'

echo "== 一键接入的程序目录：按服务器架构（模拟 uname -m）"
# 本机程序总是提供且不被发布包覆盖；其他目标来自校验通过的发布包；校验不一致的从不安装。
REAL_UNAME="$(command -v uname)"
for arch in x86_64 amd64 aarch64 arm64 riscv64; do
  case "$arch" in
    x86_64|amd64) native=x86_64-unknown-linux-gnu ;;
    aarch64|arm64) native=aarch64-unknown-linux-gnu ;;
    *) native="" ;;
  esac
  RA="$T/root-arch-$arch"
  printf '#!/bin/sh\n[ "$1" = -m ] && { echo %s; exit 0; }\nexec %s "$@"\n' "$arch" "$REAL_UNAME" > "$F/uname"
  chmod +x "$F/uname"
  if DRY_RUN=1 ROOT="$RA" PATH="$F:$PATH" bash "$PKG/install-server.sh" --domain pm.example.com --lan-cidr 198.51.100.0/24 --skip-acme --agent-bundle "$B" < /dev/null > "$T/out-$arch.txt" 2>&1; then
    A="$RA/var/lib/passmanager-dryrun/data/agent-bin"
    if [ -n "$native" ]; then
      check "$arch：本机程序 = 正在安装的程序（发布包不覆盖）" 'cmp -s "$A/PassManager-$native" "$BIN"'
    else
      check "$arch：不认识的架构不提供本机程序" '! cmp -s "$A/PassManager-x86_64-unknown-linux-gnu" "$BIN" && ! cmp -s "$A/PassManager-aarch64-unknown-linux-gnu" "$BIN"'
    fi
    check "$arch：校验不一致的 aarch64 包从不安装" '! grep -q arm-client "$A"/* && { grep -q "跳过 PassManager-0.3.0-aarch64-unknown-linux-gnu.tar.gz" "$T/out-$arch.txt" || [ "$native" = aarch64-unknown-linux-gnu ]; }'
    check "$arch：x86_64 包只在不是本机目标时安装" 'if [ "$native" = x86_64-unknown-linux-gnu ]; then cmp -s "$A/PassManager-x86_64-unknown-linux-gnu" "$BIN"; else [ "$(cat "$A/PassManager-x86_64-unknown-linux-gnu")" = x86-client ]; fi'
    check "$arch：macOS 包已解出" '[ "$(cat "$A/PassManager-universal-apple-darwin")" = mac-client ]'
  else
    bad "$arch：安装失败"; cat "$T/out-$arch.txt"
  fi
done
rm -f "$F/uname"
check "--agent-bundle 不是目录时拒绝" '! DRY_RUN=1 ROOT="$T/r5" PATH="$F:$PATH" bash "$PKG/install-server.sh" --domain pm.example.com --lan-cidr 198.51.100.0/24 --agent-bundle "$T/nope" < /dev/null > /dev/null 2>&1'

echo "== 参数校验"
for a in "--domain pm.example.com" "--lan-cidr 198.51.100.0/24" "--domain pm.example.com --lan-cidr 198.51.100.0/24;rm" "--domain a/b --lan-cidr 198.51.100.0/24" "--domain pm.example.com --lan-cidr 198.51.100.0/24 --web-port x" "--domain pm.example.com --lan-cidr 198.51.100.0/24 --tpm-socket rel.sock" "--site-file /nonexistent" "--bogus"; do
  # shellcheck disable=SC2086
  if DRY_RUN=1 ROOT="$T/r3" PATH="$F:$PATH" bash "$PKG/install-server.sh" $a < /dev/null > /dev/null 2>&1; then bad "拒绝 $a"; else ok "拒绝 $a"; fi
done
check "DRY_RUN 没有测试替身时拒绝（不执行任何系统命令、不写文件）" '! DRY_RUN=1 ROOT="$T/r4" bash "$PKG/install-server.sh" --domain pm.example.com --lan-cidr 198.51.100.0/24 --skip-acme < /dev/null > "$T/out4.txt" 2>&1 && grep -q "测试替身" "$T/out4.txt" && [ ! -e "$T/r4/usr" ]'
check "--help" 'bash "$PKG/install-server.sh" --help | grep -q "DRY_RUN"'
check "非 DRY_RUN 且不是 root 时拒绝" '[ "$(id -u)" = 0 ] || ! bash "$PKG/install-server.sh" --skip-acme < /dev/null > /dev/null 2>&1'

echo "== git-proxy 服务（替身 systemctl / loginctl / launchctl，未注册时拒绝）"
GH="$T/gp-home"; mkdir -p "$GH"
for c in loginctl launchctl; do
  printf '#!/bin/sh\necho "%s $*" >> "%s"\n' "$c" "$LOG" > "$F/$c"; chmod +x "$F/$c"
done
: > "$LOG"
check "git-proxy --install：没有远程配置时拒绝，不写服务文件、不调用服务管理器" '! HOME="$GH" PATH="$F:$PATH" env -u PASSMANAGER_HOME -u PASSMANAGER_CONFIG_DIR -u XDG_CONFIG_HOME "$BIN" git-proxy --install > "$T/out-gp.txt" 2>&1 && grep -q "passmanager enroll" "$T/out-gp.txt" && [ ! -e "$GH/.config/systemd" ] && [ ! -s "$LOG" ]'
check "git-proxy：没有远程配置时以 78 退出（服务管理器不重启）" 'HOME="$GH" env -u PASSMANAGER_HOME -u PASSMANAGER_CONFIG_DIR -u XDG_CONFIG_HOME "$BIN" git-proxy --listen 127.0.0.1:1 > /dev/null 2>&1; [ $? = 78 ]'
check "git-proxy：只监听回环地址" 'HOME="$GH" env -u PASSMANAGER_HOME -u PASSMANAGER_CONFIG_DIR "$BIN" git-proxy --listen 0.0.0.0:7878 > /dev/null 2>&1; [ $? = 78 ]'
mkdir -p "$GH/.config/systemd/user"
printf '[Service]\nExecStart=/bin/true\n' > "$GH/.config/systemd/user/passmanager-git-proxy.service"
check "git-proxy --uninstall：停止并移除用户服务" 'HOME="$GH" PATH="$F:$PATH" env -u PASSMANAGER_HOME -u PASSMANAGER_CONFIG_DIR GIT_CONFIG_GLOBAL="$T/gp-gitconfig" "$BIN" git-proxy --uninstall > /dev/null 2>&1 && grep -qx "systemctl --user disable --now passmanager-git-proxy.service" "$LOG" && [ ! -e "$GH/.config/systemd/user/passmanager-git-proxy.service" ]'

if command -v shellcheck >/dev/null; then
  echo "== shellcheck"
  check "shellcheck 通过" 'shellcheck "$SRC/scripts/install-server.sh" "$SRC/scripts/package-lan.sh" "$0"'
fi

echo
if [ "$fails" -eq 0 ]; then echo "全部通过"; else echo "$fails 项失败"; exit 1; fi

#!/usr/bin/env bash
# PassManager 局域网在线版：Agent 机器一键安装。
#
# 用法：
#   sudo ./install-agent.sh 'pm-enroll://pm.example.com:8443/<注册码>#<指纹>'
#        安装到 /usr/local/bin，然后以调用 sudo 的用户身份注册（配置写在该用户的 ~/.config/passmanager）
#   ./install-agent.sh 'pm-enroll://…'
#        没有 root：安装到 ~/.local/bin 并注册
#   ./install-agent.sh --no-mcp 'pm-enroll://…'
#        只保存令牌，不写 Claude Code / Codex 等的 MCP 配置
#   -h, --help  显示帮助
#
# 注册码由服务器上的 root 生成：passmanager token add <标签>（10 分钟有效，只能使用一次）。
# 注册时核对注册码里的服务端公钥指纹（SHA-384），令牌保存在 0600 文件里，不写进任何 Agent 配置。
#
# 测试：DRY_RUN=1 ROOT=<目录>：程序装到 $ROOT 下，sudo / id 等由 PATH 里的替身提供。
set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"
ROOT="${ROOT:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NO_MCP=()
CODE=""

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --no-mcp) NO_MCP=(--no-mcp); shift ;;
    -h|--help) usage; exit 0 ;;
    pm-enroll://*) CODE="$1"; shift ;;
    *) echo "未知参数：$1（--help 查看用法）" >&2; exit 2 ;;
  esac
done
[ -n "$CODE" ] || { usage >&2; exit 2; }
if [ "$DRY_RUN" = 1 ]; then
  [ -n "$ROOT" ] || { echo "DRY_RUN=1 需要 ROOT=<目录>" >&2; exit 2; }
  # 防止误用：DRY_RUN 下系统命令必须由 PATH 里的测试替身提供，不能是系统自带的命令。
  for c in id sudo; do
    p="$(command -v "$c" 2>/dev/null || true)"
    case "$p" in
      "" | /usr/* | /bin/* | /sbin/* | /lib/* | /opt/*)
        echo "DRY_RUN=1：$c 必须由 PATH 里的测试替身提供（找到：${p:-无}），拒绝执行" >&2; exit 2 ;;
    esac
  done
else
  ROOT=""
fi

BIN_SRC="$HERE/PassManager"
[ -x "$BIN_SRC" ] || BIN_SRC="$HERE/../PassManager"
[ -x "$BIN_SRC" ] || { echo "找不到 PassManager 可执行文件（应与本脚本放在同一目录）" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
  TARGET_USER="${SUDO_USER:-}"
  if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = root ]; then
    echo "请用 sudo 从 Agent 所在的普通账户运行（Agent 不应以 root 运行；服务端也会拒绝 root 的令牌连接）。" >&2
    exit 1
  fi
  DEST="$ROOT/usr/local/bin"
  install -d -m 0755 "$DEST"
  install -m 0755 "$BIN_SRC" "$DEST/PassManager.new"
  mv -f "$DEST/PassManager.new" "$DEST/PassManager"
  ln -sfn PassManager "$DEST/passmanager"
  echo "== 已安装 $DEST/PassManager"
  echo "== 以 $TARGET_USER 的身份注册"
  exec sudo -u "$TARGET_USER" -H "$DEST/PassManager" enroll "${NO_MCP[@]}" "$CODE"
else
  DEST="$ROOT${HOME:?}/.local/bin"
  install -d -m 0755 "$DEST"
  install -m 0755 "$BIN_SRC" "$DEST/PassManager.new"
  mv -f "$DEST/PassManager.new" "$DEST/PassManager"
  ln -sfn PassManager "$DEST/passmanager"
  echo "== 已安装 $DEST/PassManager（确认它在 PATH 中）"
  exec "$DEST/PassManager" enroll "${NO_MCP[@]}" "$CODE"
fi

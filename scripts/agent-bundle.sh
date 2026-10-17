#!/usr/bin/env bash
# 把 GitHub 发布包放进一键接入用的 Agent 程序目录（服务器上的 root 运行；install-server.sh 的 --agent-bundle 也调用它）。
#
# 用法：scripts/agent-bundle.sh [--agent-bin 目录] [--native 目标] <发布包目录>
#   发布包目录：GitHub 发布页下载的 PassManager-<版本>-<目标>.tar.gz / .zip 与 SHA256SUMS（必须有）。
#   --agent-bin：默认 `passmanager agent-bin-dir`（/var/lib/passmanager/agent-bin）。
#   --native：服务器自身的目标（默认按 uname -m）；这个目标的程序由服务器自己提供，发布包里的不替换它。
#
# 做的事：
#   1. 每个 Linux / macOS 发布包都先按 SHA256SUMS 校验；不一致或没有记录的跳过并警告（不安装）；
#   2. 校验通过的解出其中的 PassManager，原子地放到 <目录>/PassManager-<目标>（Windows 包不解出：一行接入只用于 sh）；
#   3. 把 SHA256SUMS 原子地复制到 <目录>/SHA256SUMS：`passmanager show --label` 的说明据此给出各平台（含 Windows）
#      从 GitHub 发布页下载的命令和 SHA-256（只用与服务器同一版本的包）。
# 服务器在请求时从不联网下载；这个脚本也不联网，只读给定的目录。
set -euo pipefail

die() { echo "agent-bundle.sh：$*" >&2; exit 2; }
warn() { echo "   警告：$*" >&2; }

AGENT_BIN_DIR=""
NATIVE_T="-"
BUNDLE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --agent-bin) AGENT_BIN_DIR="${2:?--agent-bin 需要参数}"; shift 2 ;;
    --native) NATIVE_T="${2?--native 需要参数}"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    -*) die "不认识的选项 $1" ;;
    *) [ -z "$BUNDLE" ] || die "只能给一个发布包目录"; BUNDLE="$1"; shift ;;
  esac
done
[ -n "$BUNDLE" ] || die "缺少发布包目录（--help 看用法）"
[ -d "$BUNDLE" ] || die "--agent-bundle 不是目录：$BUNDLE"
SUMS="$BUNDLE/SHA256SUMS"
if [ ! -f "$SUMS" ] || [ -L "$SUMS" ]; then
  die "$BUNDLE 里没有 SHA256SUMS（从同一个 GitHub 发布页下载）"
fi
[ "$(wc -c < "$SUMS")" -le 65536 ] || die "SHA256SUMS 太大"
if [ -z "$AGENT_BIN_DIR" ]; then
  AGENT_BIN_DIR="$(passmanager agent-bin-dir)" || die "无法确定 Agent 程序目录（用 --agent-bin 指定）"
fi
if [ "$NATIVE_T" = "-" ]; then
  case "$(uname -m)" in
    x86_64|amd64) NATIVE_T="x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) NATIVE_T="aarch64-unknown-linux-gnu" ;;
    *) NATIVE_T="" ;;
  esac
fi
install -d -m 0755 "$AGENT_BIN_DIR"

for f in "$BUNDLE"/PassManager-*.tar.gz; do
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
  if ! (cd "$BUNDLE" && grep -E "[[:space:]]\*?$name\$" SHA256SUMS | sha256sum -c --status - 2>/dev/null); then
    warn "跳过 $name：与 SHA256SUMS 不一致或没有记录"
    continue
  fi
  tmpd="$(mktemp -d)"
  if tar -xzf "$f" -C "$tmpd" 2>/dev/null; then
    b="$(find "$tmpd" -type f -name PassManager | head -n 1)"
    if [ -n "$b" ]; then
      install -m 0644 "$b" "$AGENT_BIN_DIR/.PassManager-$t.new"
      mv -f "$AGENT_BIN_DIR/.PassManager-$t.new" "$AGENT_BIN_DIR/PassManager-$t"
    else
      warn "跳过 $name：包里没有 PassManager"
    fi
  else
    warn "跳过 $name：无法解压"
  fi
  rm -rf "$tmpd"
done

install -m 0644 "$SUMS" "$AGENT_BIN_DIR/.SHA256SUMS.new"
mv -f "$AGENT_BIN_DIR/.SHA256SUMS.new" "$AGENT_BIN_DIR/SHA256SUMS"
echo "   SHA256SUMS：已复制（接入说明据此给出各平台发布包的下载命令）"

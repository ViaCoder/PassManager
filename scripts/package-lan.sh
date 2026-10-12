#!/usr/bin/env bash
# 打包局域网服务器发布包：<输出目录>/PassManager-<版本>-lan-<架构>-linux.tar.gz 与 SHA256SUMS.<版本>。
#
# 用法：scripts/package-lan.sh [输出目录]          （默认 dist）
#
# 发布版必须固定到公开的源码（passmanager show --label 的源码构建回退会打印它）：在标签 v<版本> 的干净检出上运行，
# 或设置 PASSMANAGER_RELEASE_TAG=v<版本> 与 PASSMANAGER_RELEASE_COMMIT=<40 位提交>。否则得到开发构建
# （show --label 会说明没有固定的源码）。离线构建可设置 CARGO_NET_OFFLINE=true。
# 构建路径经 --remap-path-prefix / -ffile-prefix-map 改写，程序里不含本机目录。
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-dist}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
arch="$(uname -m)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/lan}"
export RUSTFLAGS="--remap-path-prefix=$PWD=/build/PassManager --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME=/home/build"
export CFLAGS="-ffile-prefix-map=$PWD=/build/PassManager -ffile-prefix-map=$HOME=/home/build"
export CXXFLAGS="$CFLAGS"
cargo build --release --locked -p passmanager
bin="$CARGO_TARGET_DIR/release/PassManager"
"$bin" build-info

name="PassManager-$version-lan-$arch-linux"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name"
install -m 0755 "$bin" scripts/install-server.sh "$stage/$name/"
install -m 0644 README.md README.zh-CN.md CHANGELOG.md CHANGELOG.zh-CN.md LICENSE LICENSE-CONTRIBUTING.md \
  docs/DESIGN.md docs/DESIGN.zh-CN.md "$stage/$name/"
sed 's|](DEPLOY-LAN.zh-CN.md)|](README-DEPLOY.zh-CN.md)|' docs/DEPLOY-LAN.md > "$stage/$name/README-DEPLOY.md"
sed 's|](DEPLOY-LAN.md)|](README-DEPLOY.md)|' docs/DEPLOY-LAN.zh-CN.md > "$stage/$name/README-DEPLOY.zh-CN.md"
chmod 0644 "$stage/$name/README-DEPLOY.md" "$stage/$name/README-DEPLOY.zh-CN.md"
tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime="${SOURCE_DATE:-2026-01-01 00:00:00}" \
  -czf "$OUT/$name.tar.gz" "$name"
(
  cd "$OUT"
  sha256sum "$name.tar.gz"
  cd "$stage/$name" && sha256sum PassManager
) > "$OUT/SHA256SUMS.$version"
cat "$OUT/SHA256SUMS.$version"

#!/usr/bin/env bash
# 在 Linux 上用 Zig 交叉构建发布包：Linux x86_64 / arm64（glibc ≥ 2.28）与 Windows x86_64。
# macOS 版本需要 Apple 的 macOS SDK，只能在 Mac 上或 GitHub Actions 的 macOS 运行器上构建。
#
# 依赖：Rust（rustup）、cmake、zig（0.14 及以上）、cargo-zigbuild（cargo install cargo-zigbuild --locked）。
# 用法：scripts/cross-build.sh [目标 ...]
#   默认目标：x86_64-unknown-linux-gnu.2.28 aarch64-unknown-linux-gnu.2.28 x86_64-pc-windows-gnu
# 输出：dist/PassManager-<版本>-<目标>.tar.gz / .zip 与 dist/SHA256SUMS
set -euo pipefail

cd "$(dirname "$0")/.."
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(x86_64-unknown-linux-gnu.2.28 aarch64-unknown-linux-gnu.2.28 x86_64-pc-windows-gnu)
fi

for tool in cargo rustup cmake zig cargo-zigbuild; do
  command -v "$tool" >/dev/null || { echo "缺少 $tool" >&2; exit 1; }
done

zig_lib=$(zig env | sed -n 's/.*"lib_dir": *"\([^"]*\)".*/\1/p')
[ -d "$zig_lib/libc/include" ] || { echo "无法定位 zig 的 lib 目录" >&2; exit 1; }
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/cross}"
mkdir -p dist

for t in "${targets[@]}"; do
  triple="${t%%.2.*}"            # 去掉 glibc 版本后缀
  rustup target add "$triple" >/dev/null
  var="BINDGEN_EXTRA_CLANG_ARGS_${triple//-/_}"
  case "$triple" in
    x86_64-pc-windows-gnu)
      export "$var=--target=$triple -I$zig_lib/libc/include/any-windows-any -I$zig_lib/libc/include/generic-mingw -I$zig_lib/include" ;;
    *-linux-gnu)
      arch="${triple%%-*}"
      export "$var=--target=$triple -I$zig_lib/libc/include/$arch-linux-gnu -I$zig_lib/libc/include/generic-glibc -I$zig_lib/libc/include/any-linux-any -I$zig_lib/include" ;;
    *apple-darwin)
      echo "跳过 $t：macOS 需要在 Mac 上构建（见 .github/workflows/release.yml）" >&2; continue ;;
  esac
  echo "== 构建 $t =="
  cargo zigbuild --release --locked -p passmanager --target "$t"

  name="PassManager-$version-$triple"
  stage=$(mktemp -d)
  mkdir -p "$stage/$name/docs"
  cp README.md README.zh-CN.md CHANGELOG.md CHANGELOG.zh-CN.md LICENSE LICENSE-CONTRIBUTING.md "$stage/$name/"
  cp docs/DESIGN.md docs/DESIGN.zh-CN.md "$stage/$name/docs/"
  if [[ "$triple" == *windows* ]]; then
    cp "$CARGO_TARGET_DIR/$triple/release/PassManager.exe" "$stage/$name/"
    (cd "$stage" && zip -qr "$OLDPWD/dist/$name.zip" "$name")
  else
    cp "$CARGO_TARGET_DIR/$triple/release/PassManager" "$stage/$name/"
    tar -C "$stage" -czf "dist/$name.tar.gz" "$name"
  fi
  rm -r "$stage"
done

(cd dist && sha256sum PassManager-* > SHA256SUMS && cat SHA256SUMS)

#!/bin/bash
set -e

cd "$(dirname "$0")"

source scripts/sing-box.env
case "$(uname -m)" in
  x86_64) SING_BOX_ARCH=amd64 ;;
  aarch64) SING_BOX_ARCH=arm64 ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac
SING_BOX_BIN="embedded/sing-box-$SING_BOX_ARCH"
# Always rebuild from the pinned source: an existing binary may belong to an older release.
SING_BOX_BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$SING_BOX_BUILD_DIR"' EXIT
git clone --depth=1 --branch "v$SING_BOX_VERSION" https://github.com/SagerNet/sing-box.git "$SING_BOX_BUILD_DIR/source"
test "$(git -C "$SING_BOX_BUILD_DIR/source" rev-parse HEAD)" = "$SING_BOX_REVISION"
mkdir -p embedded
SING_BOX_OUTPUT="$PWD/$SING_BOX_BIN"
(
  cd "$SING_BOX_BUILD_DIR/source"
  CGO_ENABLED=0 GOOS=linux GOARCH="$SING_BOX_ARCH" go build -trimpath \
    -ldflags "-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=$SING_BOX_VERSION" \
    -tags "$SING_BOX_TAGS" -o "$SING_BOX_OUTPUT" ./cmd/sing-box
)
"$SING_BOX_BIN" version

echo "==> 构建 Vite + React 前端..."
npm --prefix frontend ci
npm --prefix frontend run build

echo "==> 编译 miao-rust (release)..."
cargo build --release

echo "==> 完成: target/release/miao-rust"

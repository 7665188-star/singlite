#!/usr/bin/env bash
# Build the pinned upstream core with its optional per-user statistics service.
set -Eeuo pipefail
umask 077
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUTPUT_DIR="${1:?需要输出目录}"
install -d -m 0700 "$OUTPUT_DIR"
case "$(uname -m)" in
 x86_64) GO_ARCH=amd64;GO_SHA=ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5;;
 aarch64|arm64) GO_ARCH=arm64;GO_SHA=94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8;;
 *) printf '仅支持 amd64 / arm64。\n' >&2;exit 1;;
esac
# Reuse the same verified build on subsequent single-panel upgrades.
STATS_SHA="$(sha256sum "$SOURCE_DIR/scripts/singbox-stats.go" | cut -d ' ' -f 1)"
if [[ -x /opt/singlite/bin/sing-box && -x /opt/singlite/bin/singbox-stats && -f /opt/singlite/core-build ]]; then
 if [[ "$(cat /opt/singlite/core-build)" == "sing-box-1.14.3:$STATS_SHA" ]] && /opt/singlite/bin/sing-box version | python3 -c 'import sys;v=sys.stdin.read();sys.exit(0 if "version 1.14.3-singlite" in v and "with_v2ray_api" in v else 1)'; then
  cp /opt/singlite/bin/sing-box /opt/singlite/bin/singbox-stats "$OUTPUT_DIR/"
  cp /opt/singlite/core-build "$OUTPUT_DIR/core-build"
  [[ ! -f /opt/singlite/CORE-LICENSE.txt ]] || cp /opt/singlite/CORE-LICENSE.txt "$OUTPUT_DIR/LICENSE"
  printf '复用已安装的 sing-box 1.14.3 统计版。\n'
  exit 0
 fi
fi
WORK_DIR="$(mktemp -d /tmp/singlite-core-build.XXXXXXXX)"
cleanup(){
 rc=$?
 trap - EXIT
 # Go module cache directories are read-only, including for the owning user.
 chmod -R u+rwX -- "$WORK_DIR" 2>/dev/null || true
 rm -rf -- "$WORK_DIR"
 exit "$rc"
}
trap cleanup EXIT
fetch(){ curl --fail --silent --show-error --location --retry 3 --proto '=https' --proto-redir '=https' "$1" --output "$2"; }
printf '正在构建 sing-box 1.14.3 统计版，首次需要数分钟及约 2 GB 临时磁盘空间。构建完成前现有节点继续运行。\n'
fetch "https://go.dev/dl/go1.27.2.linux-$GO_ARCH.tar.gz" "$WORK_DIR/go.tar.gz"
printf '%s  %s\n' "$GO_SHA" "$WORK_DIR/go.tar.gz" | sha256sum --check --strict -
fetch https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v1.14.3 "$WORK_DIR/source.tar.gz"
printf '%s  %s\n' 9a8e3712a5f611ad95f1d16874bbdcdffbd3b8eed16dae2d71ce7042a33c3386 "$WORK_DIR/source.tar.gz" | sha256sum --check --strict -
mkdir "$WORK_DIR/source"
tar -xzf "$WORK_DIR/go.tar.gz" -C "$WORK_DIR"
tar -xzf "$WORK_DIR/source.tar.gz" -C "$WORK_DIR/source" --strip-components=1
export GOTOOLCHAIN=local GOCACHE="$WORK_DIR/cache" GOPATH="$WORK_DIR/modules" GOMAXPROCS=2 GOMEMLIMIT=384MiB CGO_ENABLED=0
(
 cd "$WORK_DIR/source"
 "$WORK_DIR/go/bin/go" build -p 1 -buildvcs=false -trimpath -tags with_v2ray_api,with_utls -ldflags '-X github.com/sagernet/sing-box/constant.Version=1.14.3-singlite -s -w -buildid=' -o "$OUTPUT_DIR/sing-box" ./cmd/sing-box
 "$WORK_DIR/go/bin/go" build -p 1 -buildvcs=false -trimpath -tags with_v2ray_api -ldflags '-s -w -buildid=' -o "$OUTPUT_DIR/singbox-stats" "$SOURCE_DIR/scripts/singbox-stats.go"
)
"$OUTPUT_DIR/sing-box" version | python3 -c 'import sys;v=sys.stdin.read();assert "with_v2ray_api" in v;print(v)'
cp "$WORK_DIR/source/LICENSE" "$OUTPUT_DIR/LICENSE"
printf 'sing-box-1.14.3:%s\n' "$STATS_SHA" > "$OUTPUT_DIR/core-build"

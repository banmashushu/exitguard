#!/bin/sh
# Explicit allowlist only. Does not launch a proxy, install or change networking.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
platform=${1:?Usage: stage-managed-core.sh GOOS/GOARCH EXECUTABLE_DIR NOTICE_DIR}
executable_dir=${2:?Missing executable directory}
notice_dir=${3:?Missing notice directory}
case "$platform" in
  darwin/arm64) helper=exitguard-proxy-supervisor; core=mihomo; ldflags='-s -w' ;;
  windows/amd64) helper=ExitGuardProxySupervisor.exe; core=mihomo.exe; ldflags='-s -w -H=windowsgui' ;;
  *) printf '%s\n' 'Unsupported managed proxy platform.' >&2; exit 1 ;;
esac
python3 scripts/fetch-managed-core.py "$platform"
go_bin=${EXITGUARD_GO:-"$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.darwin-arm64/bin/go"}
case "$(GOTOOLCHAIN=local "$go_bin" version)" in 'go version go1.27.3 '*) ;; *) exit 1 ;; esac
python3 scripts/build-native-importer.py "$platform" "$repo_dir/.work/native-importer"
mkdir -p "$executable_dir" "$notice_dir"
case "$platform" in
  darwin/arm64) importer=mihomo-importer ;;
  windows/amd64) importer=MihomoImporter.exe ;;
esac
cp ".work/native-importer/$(printf '%s' "$platform" | tr / -)/$importer" "$executable_dir/$importer"
cp internal/managedproxy/importer_manifest.json "$notice_dir/importer-manifest.json"
cp .work/native-importer/mihomo-importer-source.tar.gz "$notice_dir/mihomo-importer-source.tar.gz"
CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS='' GOOS=${platform%/*} GOARCH=${platform#*/} \
  "$go_bin" build -trimpath -ldflags "$ldflags" -o "$executable_dir/$helper" ./cmd/exitguard-proxy-supervisor
cp ".work/managed-core/$(printf '%s' "$platform" | tr / -)/$core" "$executable_dir/$core"
cp internal/managedproxy/manifest.json "$notice_dir/manifest.json"
cp third_party/mihomo/LICENSE "$notice_dir/LICENSE"
cp third_party/mihomo/SOURCE.txt "$notice_dir/SOURCE.txt"
cp .work/managed-core/mihomo-source.tar.gz "$notice_dir/mihomo-source.tar.gz"
cp .work/managed-core/mihomo-vendor.tar.gz "$notice_dir/mihomo-vendor.tar.gz"
if [ "$platform" = darwin/arm64 ]; then
  # Preserve the exact official core bytes and its upstream linker signature.
  codesign --verify --strict "$executable_dir/$core"
  codesign --verify --strict "$executable_dir/$importer"
  codesign --force --sign - "$executable_dir/$helper"
fi

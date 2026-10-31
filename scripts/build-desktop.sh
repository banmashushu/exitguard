#!/bin/sh
# Build the native MyGo desktop entry, without starting or installing it.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
platform=${1:?Usage: build-desktop.sh GOOS/GOARCH [OUTPUT_DIR]}
output_dir=${2:-"${EXITGUARD_OUTPUT_DIR:-"$repo_dir/dist/mygo"}"}

# Keep all tool selection local to this invocation. Never run go env -w.
go_bin=${EXITGUARD_GO:-"$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.darwin-arm64/bin/go"}
mygo_bin=${EXITGUARD_MYGO:-"$repo_dir/.work/mygo-preflight/bin/mygo"}
if [ ! -x "$go_bin" ]; then
  printf '%s\n' 'Go 1.27.3 is required. Set EXITGUARD_GO to its go executable.' >&2
  exit 1
fi
if [ ! -x "$mygo_bin" ]; then
  printf '%s\n' 'MyGo v0.7.3 is required. Set EXITGUARD_MYGO to its executable.' >&2
  exit 1
fi
go_version=$(GOTOOLCHAIN=local "$go_bin" version)
case "$go_version" in
  'go version go1.27.3 '*) ;;
  *) printf '%s\n' 'Refusing to build without the pinned Go 1.27.3 toolchain.' >&2; exit 1 ;;
esac
mygo_version=$("$mygo_bin" version)
case "$mygo_version" in
  v0.7.3|0.7.3|'mygo 0.7.3'|'mygo v0.7.3'|'MyGo v0.7.3') ;;
  *) printf '%s\n' "Expected MyGo v0.7.3; found: $mygo_version" >&2; exit 1 ;;
esac
go_dir=$(CDPATH= cd -- "$(dirname -- "$go_bin")" && pwd)
case "$platform" in
  darwin/*) set -- -skip-dmg -skip-notarize -sign - ;;
  *) set -- ;;
esac
PATH="$go_dir:$PATH" GOTOOLCHAIN=local CGO_ENABLED=0 \
  "$mygo_bin" build -platform "$platform" -o "$output_dir" "$@" .

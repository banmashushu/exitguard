#!/bin/sh
# Build a diagnostic starter; cross-compilation is not Windows runtime validation.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
output_dir=${EXITGUARD_OUTPUT_DIR:-"$repo_dir/dist"}
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
staging_dir=$(mktemp -d "${TMPDIR:-/tmp}/exitguard-windows-starter.XXXXXX")
trap 'rm -rf "$staging_dir"' EXIT HUP INT TERM
mkdir "$staging_dir/package"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o "$staging_dir/package/ExitGuard.exe" ./cmd/exitguard
cp platform/windows/starter/1-check-environment.cmd platform/windows/starter/2-open-panel.cmd platform/windows/starter/START-HERE-zh-CN.txt examples/mihomo-party-exitguard.js "$staging_dir/package/"
(
 cd "$staging_dir/package"
 zip -q "$staging_dir/ExitGuard-Windows-MihomoParty-starter.zip" ./*
)
mv "$staging_dir/ExitGuard-Windows-MihomoParty-starter.zip" "$output_dir/ExitGuard-Windows-MihomoParty-starter.zip"
printf '%s\n' "Built: $output_dir/ExitGuard-Windows-MihomoParty-starter.zip" 'Cross-compiled only; Windows runtime and enforcement are not verified.'

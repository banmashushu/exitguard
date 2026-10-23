#!/bin/sh
# This is a cross-build artifact; real Windows enforcement still needs testing.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
output_dir=${EXITGUARD_OUTPUT_DIR:-"$repo_dir/dist"}
mkdir -p "$output_dir"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o "$output_dir/ExitGuard-windows-amd64.exe" ./cmd/exitguard
printf '%s\n' "Built: $output_dir/ExitGuard-windows-amd64.exe" 'Cross-compiled only. Windows WFP and actual browser/client traffic are not runtime-verified.'

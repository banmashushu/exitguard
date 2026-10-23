#!/bin/sh
# Build an ordinary local app. This does not install or enable OS filtering.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
output_dir=${EXITGUARD_OUTPUT_DIR:-"$repo_dir/dist"}
mkdir -p "$output_dir/ExitGuard.app/Contents/MacOS" "$output_dir/ExitGuard.app/Contents/Resources"
app_dir="$output_dir/ExitGuard.app"
CGO_ENABLED=0 go build -trimpath -o "$app_dir/Contents/MacOS/exitguard-core" ./cmd/exitguard
swiftc -parse-as-library -O -target "$(uname -m)-apple-macosx13.0" -framework AppKit -framework WebKit platform/macos/App.swift -o "$app_dir/Contents/MacOS/ExitGuard"
cp platform/macos/Info.plist "$app_dir/Contents/Info.plist"
codesign --force --sign - "$app_dir/Contents/MacOS/exitguard-core"
codesign --force --sign - "$app_dir"
printf '%s\n' "Built: $app_dir" 'Local ad-hoc app only. Network Extension protection remains unavailable; no filters were installed.'

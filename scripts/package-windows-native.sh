#!/bin/sh
# Build native preview only. A cross-build is not Windows enforcement evidence.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
output_dir=${EXITGUARD_OUTPUT_DIR:-"$repo_dir/dist"}
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
staging_dir=$(mktemp -d "${TMPDIR:-/tmp}/exitguard-windows-native.XXXXXX")
trap 'rm -rf "$staging_dir"' EXIT HUP INT TERM
mkdir "$staging_dir/package"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o "$staging_dir/package/ExitGuard.exe" ./cmd/exitguard
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o "$staging_dir/package/ExitGuardNativeProbe.exe" ./cmd/exitguard-native-probe
cp platform/windows/native/* "$staging_dir/package/"
cp docs/windows-native-preview.md "$staging_dir/package/TECHNICAL-LIMITS.md"
cp third_party/sandboxie/NOTICE.txt "$staging_dir/package/THIRD-PARTY-NOTICES.txt"
cp third_party/sandboxie/GPL-3.0.txt "$staging_dir/package/Sandboxie-GPL-3.0.txt"
cp internal/nativeapp/data/sandboxie-defaults-5.73.8.json "$staging_dir/package/sandboxie-defaults-5.73.8.json"
(
 cd "$staging_dir/package"
 shasum -a 256 ./*.exe ./*.cmd ./*.txt ./*.md ./*.json > SHA256SUMS.txt
 python3 - "$staging_dir/ExitGuard-Windows-Native-Preview.zip" <<'PYZIP'
import pathlib
import sys
import zipfile
with zipfile.ZipFile(sys.argv[1], "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(pathlib.Path(".").iterdir()):
        if path.is_file():
            archive.write(path, arcname=path.name)
PYZIP
)
mv "$staging_dir/ExitGuard-Windows-Native-Preview.zip" "$output_dir/ExitGuard-Windows-Native-Preview.zip"
printf '%s\n' "Built: $output_dir/ExitGuard-Windows-Native-Preview.zip" 'Cross-compiled native preview. Windows behavior and DNS broker containment remain incomplete.'

#!/bin/sh
# Native GUI-only release: build in staging, verify, then publish named outputs.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
output_dir=${EXITGUARD_OUTPUT_DIR:-"$repo_dir/dist"}
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
nsis_prefix="$repo_dir/.work/mygo-preflight/makensis/3.13"
makensis_bin=${EXITGUARD_MAKENSIS:-"$nsis_prefix/bin/makensis"}
nsis_dir=${NSISDIR:-"$nsis_prefix/share/nsis"}
if [ ! -x "$makensis_bin" ] || [ ! -d "$nsis_dir" ]; then
  printf '%s\n' 'NSIS 3.13 is required. Set EXITGUARD_MAKENSIS and NSISDIR.' >&2
  exit 1
fi
nsis_version=$(NSISDIR="$nsis_dir" "$makensis_bin" -VERSION)
if [ "$nsis_version" != 'v3.13' ]; then
  printf '%s\n' "Expected NSIS v3.13; found: $nsis_version" >&2
  exit 1
fi
staging_dir=$(mktemp -d "$output_dir/.windows-desktop.XXXXXX")
trap 'rm -rf "$staging_dir"' EXIT HUP INT TERM
nsis_bin_dir=$(CDPATH= cd -- "$(dirname -- "$makensis_bin")" && pwd)
# MyGo also emits its standard NSIS installer when makensis is available.
# Keep that build output here; only our project installer is published.
PATH="$nsis_bin_dir:$PATH" NSISDIR="$nsis_dir" \
  sh scripts/build-desktop.sh windows/amd64 "$staging_dir/mygo"
package_dir="$staging_dir/package"
mkdir "$package_dir"
# Never copy dist, a user directory, resources/* or arbitrary build outputs.
cp "$staging_dir/mygo/windows-amd64/ExitGuard.exe" "$package_dir/ExitGuard.exe"
python3 scripts/extract-windows-icon.py "$package_dir/ExitGuard.exe" "$package_dir/ExitGuard.ico"
cp platform/windows/desktop/README-zh-CN.txt "$package_dir/README-zh-CN.txt"
cp platform/windows/desktop/THIRD-PARTY-NOTICES.txt "$package_dir/THIRD-PARTY-NOTICES.txt"
python3 - "$package_dir" "$staging_dir/ExitGuard-Windows-x64.zip" <<'PYZIP'
import hashlib
import pathlib
import sys
import zipfile

package, output = map(pathlib.Path, sys.argv[1:])
names = ("ExitGuard.exe", "ExitGuard.ico", "README-zh-CN.txt", "THIRD-PARTY-NOTICES.txt")
checksums = "".join(f"{hashlib.sha256((package / name).read_bytes()).hexdigest()}  {name}\n" for name in names)
(package / "SHA256SUMS.txt").write_bytes(checksums.encode("utf-8"))
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name in (*names, "SHA256SUMS.txt"):
        info = zipfile.ZipInfo(name, date_time=(2026, 10, 30, 0, 0, 0))
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        archive.writestr(info, (package / name).read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
PYZIP
NSISDIR="$nsis_dir" "$makensis_bin" -V2 \
  "-DPACKAGE_DIR=$package_dir" \
  "-DOUTPUT_FILE=$staging_dir/ExitGuard-Windows-x64-Setup.exe" \
  "-DPYTHON_EXE=$(command -v python3)" \
  "-DCAPTURE_SCRIPT=$repo_dir/scripts/capture-nsis-uninstaller.py" \
  "-DUNINSTALLER_EXPORT=$staging_dir/ExitGuard-Uninstall.exe" \
  platform/windows/desktop/installer.nsi
python3 scripts/verify-windows-desktop.py \
  "$staging_dir/ExitGuard-Windows-x64.zip" \
  "$staging_dir/ExitGuard-Windows-x64-Setup.exe" \
  "$staging_dir/ExitGuard-Uninstall.exe"
if [ -n "${EXITGUARD_WINDOWS_VALIDATION_DIR:-}" ]; then
  mkdir -p "$EXITGUARD_WINDOWS_VALIDATION_DIR"
  cp "$staging_dir/ExitGuard-Uninstall.exe" "$EXITGUARD_WINDOWS_VALIDATION_DIR/ExitGuard-Uninstall.exe"
fi
python3 - "$staging_dir" <<'PYHASH'
import hashlib
import pathlib
import sys

stage = pathlib.Path(sys.argv[1])
names = ("ExitGuard-Windows-x64.zip", "ExitGuard-Windows-x64-Setup.exe")
checksums = "".join(f"{hashlib.sha256((stage / name).read_bytes()).hexdigest()}  {name}\n" for name in names)
(stage / "ExitGuard-Windows-x64-SHA256SUMS.txt").write_bytes(checksums.encode("utf-8"))
PYHASH
for name in ExitGuard-Windows-x64.zip ExitGuard-Windows-x64-Setup.exe ExitGuard-Windows-x64-SHA256SUMS.txt; do
  mv "$staging_dir/$name" "$output_dir/$name"
done
printf '%s\n' "Built: $output_dir/ExitGuard-Windows-x64.zip" \
  "Built: $output_dir/ExitGuard-Windows-x64-Setup.exe" \
  'Unsigned cross-build only; Windows GUI, ACLs, discovery and traffic need real-device validation.'

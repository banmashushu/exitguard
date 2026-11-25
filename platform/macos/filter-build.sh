#!/bin/sh
# Compile only. This never signs, installs, activates or changes networking.
set -eu
EXITGUARD_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
EXITGUARD_FILTER_OUT=${1:-"$EXITGUARD_REPO/dist/native-macos"}
EXITGUARD_FILTER_ARCH=${EXITGUARD_FILTER_ARCH:-$(uname -m)}
case "$EXITGUARD_FILTER_ARCH" in arm64|x86_64) ;; *) echo "Unsupported Mac architecture" >&2; exit 1;; esac
mkdir -p "$EXITGUARD_FILTER_OUT"
EXITGUARD_FILTER_OUT=$(CDPATH= cd -- "$EXITGUARD_FILTER_OUT" && pwd)
EXITGUARD_FILTER_SOURCE="$EXITGUARD_REPO/platform/macos"
EXITGUARD_FILTER_BUNDLE="$EXITGUARD_FILTER_OUT/com.exitguard.Filter.systemextension"
mkdir -p "$EXITGUARD_FILTER_BUNDLE/Contents/MacOS"
EXITGUARD_FILTER_SDK=$(xcrun --show-sdk-path)
swiftc -parse-as-library -sdk "$EXITGUARD_FILTER_SDK" -target "$EXITGUARD_FILTER_ARCH-apple-macosx13.0" -module-name ExitGuardFilter \
  -framework NetworkExtension -framework Network -framework Security \
  "$EXITGUARD_FILTER_SOURCE/FilterPolicy.swift" "$EXITGUARD_FILTER_SOURCE/FilterIdentity.swift" "$EXITGUARD_FILTER_SOURCE/FilterDataProvider.swift" \
  -o "$EXITGUARD_FILTER_BUNDLE/Contents/MacOS/ExitGuardFilter"
cp "$EXITGUARD_FILTER_SOURCE/Filter-Info.plist" "$EXITGUARD_FILTER_BUNDLE/Contents/Info.plist"
swiftc -parse-as-library -sdk "$EXITGUARD_FILTER_SDK" -target "$EXITGUARD_FILTER_ARCH-apple-macosx13.0" -module-name ExitGuardFilterManager \
  -framework NetworkExtension -framework SystemExtensions -framework Security \
  "$EXITGUARD_FILTER_SOURCE/FilterPolicy.swift" "$EXITGUARD_FILTER_SOURCE/FilterIdentity.swift" "$EXITGUARD_FILTER_SOURCE/FilterProcesses.swift" "$EXITGUARD_FILTER_SOURCE/FilterManager.swift" \
  -o "$EXITGUARD_FILTER_OUT/ExitGuardFilterManager"
swiftc -parse-as-library -sdk "$EXITGUARD_FILTER_SDK" -target "$EXITGUARD_FILTER_ARCH-apple-macosx13.0" \
  "$EXITGUARD_FILTER_SOURCE/FilterPolicy.swift" "$EXITGUARD_FILTER_SOURCE/FilterPolicyTests.swift" -o "$EXITGUARD_FILTER_OUT/filter-policy-tests"
swiftc -parse-as-library -sdk "$EXITGUARD_FILTER_SDK" -target "$EXITGUARD_FILTER_ARCH-apple-macosx13.0" -framework Security \
  "$EXITGUARD_FILTER_SOURCE/FilterPolicy.swift" "$EXITGUARD_FILTER_SOURCE/FilterIdentity.swift" "$EXITGUARD_FILTER_SOURCE/FilterProcesses.swift" "$EXITGUARD_FILTER_SOURCE/FilterProcessTests.swift" -o "$EXITGUARD_FILTER_OUT/filter-process-tests"
if [ "$EXITGUARD_FILTER_ARCH" = "$(uname -m)" ]; then
"$EXITGUARD_FILTER_OUT/filter-policy-tests"
# The process snapshot scans every live process on this machine and correctly
# fails closed on any whose executable was deleted. Hosted CI runners can have
# such a system daemon, so CI compiles this check but leaves running it to
# development machines.
if [ "${EXITGUARD_FILTER_SKIP_LIVE_SCAN:-}" = 1 ]; then
echo "Live process snapshot test compiled but not run (EXITGUARD_FILTER_SKIP_LIVE_SCAN=1)."
else
"$EXITGUARD_FILTER_OUT/filter-process-tests"
fi
else
  echo "Cross-compiled tests were not executed on this CPU architecture."
fi
plutil -lint "$EXITGUARD_FILTER_BUNDLE/Contents/Info.plist"
echo "Native components compiled at $EXITGUARD_FILTER_OUT; unsigned and inactive."

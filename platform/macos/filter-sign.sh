#!/bin/sh
# Prepare a signed artifact only. Never copies to /Applications or activates NE.
set -eu
: "${EXITGUARD_SIGN_IDENTITY:?Set the exact Developer ID Application identity}"
: "${EXITGUARD_SIGN_TEAM:?Set its 10-character Apple Team ID}"
: "${EXITGUARD_APP_PROFILE:?Set the app's Network Extension provisioning profile path}"
: "${EXITGUARD_FILTER_PROFILE:?Set the filter's provisioning profile path}"
case "$EXITGUARD_SIGN_TEAM" in *[!A-Z0-9]*|'') echo "Invalid Apple Team ID" >&2; exit 1;; esac
[ "${#EXITGUARD_SIGN_TEAM}" -eq 10 ] || { echo "Apple Team ID must have 10 characters" >&2; exit 1; }
EXITGUARD_REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
EXITGUARD_SIGN_APP=${1:-"$EXITGUARD_REPO/dist/ExitGuard.app"}
[ -f "$EXITGUARD_SIGN_APP/Contents/Info.plist" ] || { echo "Build the app bundle first" >&2; exit 1; }
EXITGUARD_SIGN_APP=$(CDPATH= cd -- "$EXITGUARD_SIGN_APP" && pwd)
[ -f "$EXITGUARD_APP_PROFILE" ] && [ -f "$EXITGUARD_FILTER_PROFILE" ] || { echo "Both provisioning profiles must exist" >&2; exit 1; }
EXITGUARD_SIGN_WORK=$(mktemp -d "${TMPDIR:-/tmp}/exitguard-sign.XXXXXX")
trap 'rm -rf "$EXITGUARD_SIGN_WORK"' EXIT HUP INT TERM
"$EXITGUARD_REPO/platform/macos/filter-build.sh" "$EXITGUARD_SIGN_WORK/native"
mkdir -p "$EXITGUARD_SIGN_APP/Contents/Library/SystemExtensions"
cp -R "$EXITGUARD_SIGN_WORK/native/com.exitguard.Filter.systemextension" "$EXITGUARD_SIGN_APP/Contents/Library/SystemExtensions/"
cp "$EXITGUARD_SIGN_WORK/native/ExitGuardFilterManager" "$EXITGUARD_SIGN_APP/Contents/MacOS/ExitGuardFilterManager"
EXITGUARD_SIGN_EXTENSION="$EXITGUARD_SIGN_APP/Contents/Library/SystemExtensions/com.exitguard.Filter.systemextension"
sed "s/__TEAM_ID__/$EXITGUARD_SIGN_TEAM/g" "$EXITGUARD_REPO/platform/macos/Filter-Info.plist" > "$EXITGUARD_SIGN_EXTENSION/Contents/Info.plist"
sed "s/__TEAM_ID__/$EXITGUARD_SIGN_TEAM/g" "$EXITGUARD_REPO/platform/macos/Filter.entitlements.plist" > "$EXITGUARD_SIGN_WORK/filter-entitlements.plist"
sed "s/__TEAM_ID__/$EXITGUARD_SIGN_TEAM/g" "$EXITGUARD_REPO/platform/macos/FilterManager.entitlements.plist" > "$EXITGUARD_SIGN_WORK/app-entitlements.plist"
cp "$EXITGUARD_APP_PROFILE" "$EXITGUARD_SIGN_APP/Contents/embedded.provisionprofile"
cp "$EXITGUARD_FILTER_PROFILE" "$EXITGUARD_SIGN_EXTENSION/Contents/embedded.provisionprofile"
(cd "$EXITGUARD_REPO" && go build -trimpath -ldflags "-X exitguard/internal/enforce.signingTeamID=$EXITGUARD_SIGN_TEAM" -o "$EXITGUARD_SIGN_APP/Contents/MacOS/exitguard-core" ./cmd/exitguard)
codesign --force --timestamp --options runtime --sign "$EXITGUARD_SIGN_IDENTITY" --identifier com.exitguard.Filter --entitlements "$EXITGUARD_SIGN_WORK/filter-entitlements.plist" "$EXITGUARD_SIGN_EXTENSION"
codesign --force --timestamp --options runtime --sign "$EXITGUARD_SIGN_IDENTITY" --identifier com.exitguard.app --entitlements "$EXITGUARD_SIGN_WORK/app-entitlements.plist" "$EXITGUARD_SIGN_APP/Contents/MacOS/ExitGuardFilterManager"
codesign --force --timestamp --options runtime --sign "$EXITGUARD_SIGN_IDENTITY" "$EXITGUARD_SIGN_APP/Contents/MacOS/exitguard-core"
codesign --force --timestamp --options runtime --sign "$EXITGUARD_SIGN_IDENTITY" --entitlements "$EXITGUARD_SIGN_WORK/app-entitlements.plist" "$EXITGUARD_SIGN_APP"
codesign --verify --strict --deep "$EXITGUARD_SIGN_APP"
echo "Signed artifact prepared at $EXITGUARD_SIGN_APP. Not installed or activated; notarization and real-device validation remain required."

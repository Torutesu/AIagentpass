#!/bin/bash
set -euo pipefail

[[ $# -eq 5 ]] || { echo "Usage: verify-macos-release.sh RELEASE-MANIFEST.json SIGNATURE RELEASE-PUBLIC-KEY EXPECTED-KEY-FINGERPRINT EXPECTED-TEAM-ID" >&2; exit 2; }
SOURCE_MANIFEST="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
SOURCE_SIGNATURE="$(cd "$(dirname "$2")" && pwd -P)/$(basename "$2")"
SOURCE_PUBLIC_KEY="$(cd "$(dirname "$3")" && pwd -P)/$(basename "$3")"
EXPECTED_FINGERPRINT="$4"
EXPECTED_TEAM_ID="$5"
[[ "$EXPECTED_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "Expected TeamIdentifier is invalid" >&2; exit 2; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-release-verify.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
STAGED_DIR="$TEMP_DIR/staged"
/bin/mkdir -m 0700 "$STAGED_DIR"
node "$SCRIPT_DIR/stage-release.mjs" "$STAGED_DIR" "$SOURCE_MANIFEST" "$SOURCE_SIGNATURE" "$SOURCE_PUBLIC_KEY" >/dev/null
MANIFEST="$STAGED_DIR/release-manifest.json"
SIGNATURE="$STAGED_DIR/release-manifest.sig"
PUBLIC_KEY="$STAGED_DIR/release-public.pem"
node "$SCRIPT_DIR/verify-release.mjs" "$MANIFEST" "$SIGNATURE" "$PUBLIC_KEY" "$EXPECTED_FINGERPRINT" >/dev/null
[[ "$(node -e 'process.stdout.write(require(process.argv[1]).evidence?.notarization?.status || "")' "$MANIFEST")" == "accepted_stapled" ]] || { echo "Manifest does not claim an explicitly accepted and stapled release" >&2; exit 1; }
ARTIFACT_DIR="$(dirname "$MANIFEST")"
PKG_NAME="$(node -e 'const m=require(process.argv[1]); const a=m.artifacts.filter(x=>x.role==="product" && x.name.endsWith("-macos-universal.pkg") && x.media_type==="application/vnd.apple.installer+xml"); if(a.length!==1) process.exit(1); process.stdout.write(a[0].name)' "$MANIFEST")" || { echo "Manifest must contain exactly one macOS universal installer package" >&2; exit 1; }
PACKAGE="$ARTIFACT_DIR/$PKG_NAME"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
"$ROOT_DIR/native/macos/scripts/verify-installer-package.sh" "$PACKAGE" "$EXPECTED_TEAM_ID"
/usr/bin/xcrun stapler validate "$PACKAGE"
/usr/sbin/spctl --assess --type install --verbose=4 "$PACKAGE"
/usr/sbin/pkgutil --expand-full "$PACKAGE" "$TEMP_DIR/extracted"
APP="$(/usr/bin/find -P "$TEMP_DIR/extracted" -type d -name AgentPass.app -print -quit)"
SERVICE="$APP/Contents/Library/HelperTools/AgentPassNativeService.app"
CLIENT="$APP/Contents/Library/HelperTools/AgentPassNativeClient.app"
[[ -d "$APP" && -d "$SERVICE" && -d "$CLIENT" ]] || { echo "Expected nested AgentPass app layout is missing" >&2; exit 1; }
if find "$APP" -type l -print -quit | grep -q .; then echo "Release app contains a symlink" >&2; exit 1; fi
if find "$APP" -type f \( -perm -002 -o -perm -020 \) -print -quit | grep -q .; then echo "Release app contains group/world-writable files" >&2; exit 1; fi
for item in "$SERVICE" "$CLIENT" "$APP"; do /usr/bin/codesign --verify --strict --verbose=4 "$item"; done
identifier() { /usr/bin/codesign -dv --verbose=4 "$1" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}'; }
SERVICE_BINARY="$SERVICE/Contents/MacOS/agentpass-native-service"
CLIENT_BINARY="$CLIENT/Contents/MacOS/agentpass-native-client"
MANAGER_BINARY="$APP/Contents/MacOS/agentpass-native-manager"
ONBOARDING_BINARY="$APP/Contents/MacOS/agentpass-onboarding"
ATOMIC_RENAME_BINARY="$APP/Contents/Library/HelperTools/agentpass-atomic-rename"
[[ "$(identifier "$SERVICE")" == "dev.agentpass.native-service" && "$(identifier "$CLIENT")" == "dev.agentpass.native-client" && "$(identifier "$ATOMIC_RENAME_BINARY")" == "dev.agentpass.atomic-rename" && "$(identifier "$MANAGER_BINARY")" == "dev.agentpass.native-manager" && "$(identifier "$ONBOARDING_BINARY")" == "dev.agentpass" && "$(identifier "$APP")" == "dev.agentpass" ]] || { echo "Release signing identifier mismatch" >&2; exit 1; }
for binary in "$SERVICE_BINARY" "$CLIENT_BINARY" "$ATOMIC_RENAME_BINARY" "$MANAGER_BINARY" "$ONBOARDING_BINARY"; do
  [[ "$(/usr/bin/lipo -archs "$binary")" == *arm64* && "$(/usr/bin/lipo -archs "$binary")" == *x86_64* ]] || { echo "Universal slices missing from $binary" >&2; exit 1; }
done
team_identifier() { /usr/bin/codesign -dv --verbose=4 "$1" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}'; }
for item in "$SERVICE" "$CLIENT" "$ATOMIC_RENAME_BINARY" "$MANAGER_BINARY" "$ONBOARDING_BINARY" "$APP"; do
  [[ "$(team_identifier "$item")" == "$EXPECTED_TEAM_ID" ]] || { echo "TeamIdentifier mismatch on $item" >&2; exit 1; }
done
TEAM_ID="$EXPECTED_TEAM_ID"
verify_requirement() {
  local item="$1" expected_identifier="$2"
  /usr/bin/codesign --verify --strict --test-requirement "=identifier \"${expected_identifier}\" and anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${TEAM_ID}\"" "$item"
}
verify_requirement "$SERVICE" dev.agentpass.native-service
verify_requirement "$CLIENT" dev.agentpass.native-client
verify_requirement "$ATOMIC_RENAME_BINARY" dev.agentpass.atomic-rename
verify_requirement "$MANAGER_BINARY" dev.agentpass.native-manager
verify_requirement "$ONBOARDING_BINARY" dev.agentpass
verify_requirement "$APP" dev.agentpass
for helper in "$SERVICE" "$CLIENT"; do [[ -f "$helper/Contents/embedded.provisionprofile" && ! -L "$helper/Contents/embedded.provisionprofile" ]] || { echo "Helper provisioning profile missing" >&2; exit 1; }; done
/usr/bin/security cms -D -i "$SERVICE/Contents/embedded.provisionprofile" >"$TEMP_DIR/service-profile.plist"
PREFIX="$(/usr/libexec/PlistBuddy -c 'Print :ApplicationIdentifierPrefix:0' "$TEMP_DIR/service-profile.plist")"
"$ROOT_DIR/native/macos/scripts/verify-profile.sh" "$SERVICE/Contents/embedded.provisionprofile" "$TEAM_ID" "$PREFIX" dev.agentpass.native-service "${PREFIX}.dev.agentpass.service-keys" service
"$ROOT_DIR/native/macos/scripts/verify-profile.sh" "$CLIENT/Contents/embedded.provisionprofile" "$TEAM_ID" "$PREFIX" dev.agentpass.native-client "${PREFIX}.dev.agentpass.approval-keys" client
extract_entitlements() {
  local item="$1" output="$2"
  /usr/bin/codesign -d --entitlements :- "$item" >"$output" 2>/dev/null
  /usr/bin/plutil -lint "$output" >/dev/null
}
verify_helper_entitlements() {
  local item="$1" expected_group="$2" label="$3" plist="$TEMP_DIR/${label}-entitlements.plist"
  extract_entitlements "$item" "$plist"
  /usr/bin/plutil -convert json -o - "$plist" | node "$SCRIPT_DIR/verify-macos-entitlements.mjs" "$label" "$expected_group" >/dev/null
}
verify_no_dangerous_entitlements() {
  local item="$1" label="$2" plist="$TEMP_DIR/${label}-entitlements.plist"
  extract_entitlements "$item" "$plist"
  /usr/bin/plutil -convert json -o - "$plist" | node "$SCRIPT_DIR/verify-macos-entitlements.mjs" "$label" >/dev/null
}
verify_helper_entitlements "$SERVICE" "${PREFIX}.dev.agentpass.service-keys" service
verify_helper_entitlements "$CLIENT" "${PREFIX}.dev.agentpass.approval-keys" client
verify_no_dangerous_entitlements "$MANAGER_BINARY" manager
verify_no_dangerous_entitlements "$ONBOARDING_BINARY" onboarding
verify_no_dangerous_entitlements "$APP" outer
for item in "$SERVICE" "$CLIENT" "$MANAGER_BINARY" "$ONBOARDING_BINARY" "$APP"; do
  details="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1)"
  grep -q '^Runtime Version=' <<<"$details" || { echo "Hardened Runtime missing on $item" >&2; exit 1; }
  grep -q '^Timestamp=' <<<"$details" || { echo "Secure timestamp missing on $item" >&2; exit 1; }
done
# The accepted ticket and Gatekeeper assessment above were performed on the
# staged, manifest-bound installer package. The nested app is independently
# checked for its Developer ID requirements and hardened runtime here.
echo "Offline macOS release verification passed"

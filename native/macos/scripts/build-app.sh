#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESOURCE_DIR="$PACKAGE_DIR/Resources"
OUTPUT_DIR="$PACKAGE_DIR/dist"
SIGNING_IDENTITY="${AGENTPASS_SIGNING_IDENTITY:-}"
TEAM_ID="${AGENTPASS_TEAM_ID:-}"
APP_IDENTIFIER_PREFIX="${AGENTPASS_APP_IDENTIFIER_PREFIX:-}"
PROVISIONING_PROFILE="${AGENTPASS_PROVISIONING_PROFILE:-}"
NOTARY_PROFILE=""
ADHOC=0
FORCE=0
ARCHITECTURES=("$(uname -m)")

usage() {
  echo "Usage: build-app.sh [--output-dir DIR] [--identity IDENTITY --team-id TEAMID --profile FILE] [--app-identifier-prefix PREFIX] [--notary-profile PROFILE] [--universal] [--adhoc] [--force]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) [[ $# -ge 2 ]] || usage; OUTPUT_DIR="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; SIGNING_IDENTITY="$2"; shift 2 ;;
    --team-id) [[ $# -ge 2 ]] || usage; TEAM_ID="$2"; shift 2 ;;
    --app-identifier-prefix) [[ $# -ge 2 ]] || usage; APP_IDENTIFIER_PREFIX="$2"; shift 2 ;;
    --profile) [[ $# -ge 2 ]] || usage; PROVISIONING_PROFILE="$2"; shift 2 ;;
    --notary-profile) [[ $# -ge 2 ]] || usage; NOTARY_PROFILE="$2"; shift 2 ;;
    --universal) ARCHITECTURES=(arm64 x86_64); shift ;;
    --adhoc) ADHOC=1; shift ;;
    --force) FORCE=1; shift ;;
    *) usage ;;
  esac
done

if [[ "$ADHOC" -eq 0 ]]; then
  [[ -n "$SIGNING_IDENTITY" ]] || { echo "A signing identity is required; use --adhoc only for local testing" >&2; exit 1; }
  [[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "A 10-character Apple Team ID is required" >&2; exit 1; }
  [[ -n "$PROVISIONING_PROFILE" ]] || { echo "A provisioning profile is required for a production build" >&2; exit 1; }
else
  [[ -z "$NOTARY_PROFILE" ]] || { echo "Ad-hoc bundles cannot be notarized" >&2; exit 1; }
  TEAM_ID="ADHOC00000"
  APP_IDENTIFIER_PREFIX="ADHOC00000"
  SIGNING_IDENTITY="-"
fi

if [[ -n "$PROVISIONING_PROFILE" ]]; then
  [[ -f "$PROVISIONING_PROFILE" && ! -L "$PROVISIONING_PROFILE" ]] || { echo "Provisioning profile must be a regular non-symlink file" >&2; exit 1; }
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
[[ "$OUTPUT_DIR" != "/" ]] || { echo "Refusing to use the filesystem root as output" >&2; exit 1; }
TARGET_APP="$OUTPUT_DIR/AgentPass.app"
if [[ -e "$TARGET_APP" || -L "$TARGET_APP" ]]; then
  [[ "$FORCE" -eq 1 ]] || { echo "$TARGET_APP already exists; pass --force to replace it" >&2; exit 1; }
  rm -rf -- "$TARGET_APP"
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-build.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT

if [[ "$ADHOC" -eq 0 ]]; then
  DECODED_PROFILE="$TEMP_DIR/provisioning-profile.plist"
  /usr/bin/security cms -D -i "$PROVISIONING_PROFILE" >"$DECODED_PROFILE"
  PROFILE_TEAM_ID="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$DECODED_PROFILE")"
  PROFILE_PREFIX="$(/usr/libexec/PlistBuddy -c 'Print :ApplicationIdentifierPrefix:0' "$DECODED_PROFILE")"
  PROFILE_KEYCHAIN_GROUP="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:keychain-access-groups:0' "$DECODED_PROFILE")"
  [[ "$PROFILE_TEAM_ID" == "$TEAM_ID" ]] || { echo "Provisioning profile Team ID does not match --team-id" >&2; exit 1; }
  if [[ -n "$APP_IDENTIFIER_PREFIX" && "$APP_IDENTIFIER_PREFIX" != "$PROFILE_PREFIX" ]]; then
    echo "Provisioning profile App Identifier Prefix does not match --app-identifier-prefix" >&2
    exit 1
  fi
  APP_IDENTIFIER_PREFIX="$PROFILE_PREFIX"
  [[ "$APP_IDENTIFIER_PREFIX" =~ ^[A-Z0-9]{10}$ ]] || { echo "Provisioning profile has an invalid App Identifier Prefix" >&2; exit 1; }
  [[ "$PROFILE_KEYCHAIN_GROUP" == "${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys" ]] || { echo "Provisioning profile does not authorize the AgentPass keychain access group" >&2; exit 1; }
fi

APP="$TEMP_DIR/AgentPass.app"
MACOS_DIR="$APP/Contents/MacOS"
DAEMON_DIR="$APP/Contents/Library/LaunchDaemons"
ENTITLEMENT_DIR="$TEMP_DIR/entitlements"
mkdir -p "$MACOS_DIR" "$DAEMON_DIR" "$ENTITLEMENT_DIR"

PRODUCTS=(agentpass-native-manager agentpass-native-client agentpass-native-service)
for architecture in "${ARCHITECTURES[@]}"; do
  MACOSX_DEPLOYMENT_TARGET=14.0 swift build -c release --package-path "$PACKAGE_DIR" --arch "$architecture" >&2
done

for product in "${PRODUCTS[@]}"; do
  slices=()
  for architecture in "${ARCHITECTURES[@]}"; do
    bin_dir="$(swift build -c release --package-path "$PACKAGE_DIR" --arch "$architecture" --show-bin-path)"
    slices+=("$bin_dir/$product")
  done
  if [[ "${#slices[@]}" -eq 1 ]]; then
    install -m 0755 "${slices[0]}" "$MACOS_DIR/$product"
  else
    xcrun lipo -create "${slices[@]}" -output "$MACOS_DIR/$product"
    chmod 0755 "$MACOS_DIR/$product"
  fi
done

install -m 0644 "$RESOURCE_DIR/AgentPass-Info.plist" "$APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/dev.agentpass.native-service.plist" "$DAEMON_DIR/dev.agentpass.native-service.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeManager.entitlements" "$ENTITLEMENT_DIR/manager.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeClient.entitlements" "$ENTITLEMENT_DIR/client.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeService.entitlements" "$ENTITLEMENT_DIR/service.plist"
for entitlement in "$ENTITLEMENT_DIR/client.plist" "$ENTITLEMENT_DIR/service.plist"; do
  /usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys" "$entitlement"
done
if [[ -n "$PROVISIONING_PROFILE" ]]; then
  install -m 0644 "$PROVISIONING_PROFILE" "$APP/Contents/embedded.provisionprofile"
fi

/usr/bin/plutil -lint "$APP/Contents/Info.plist" "$DAEMON_DIR/dev.agentpass.native-service.plist" "$ENTITLEMENT_DIR/manager.plist" "$ENTITLEMENT_DIR/client.plist" "$ENTITLEMENT_DIR/service.plist" >/dev/null

sign_item() {
  local item="$1" identifier="$2" entitlements="$3"
  if [[ "$ADHOC" -eq 1 ]]; then
    /usr/bin/codesign --force --sign - --identifier "$identifier" --entitlements "$entitlements" "$item"
  else
    /usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --identifier "$identifier" --entitlements "$entitlements" --options runtime --timestamp "$item"
  fi
}

sign_item "$MACOS_DIR/agentpass-native-service" "dev.agentpass.native-service" "$ENTITLEMENT_DIR/service.plist"
sign_item "$MACOS_DIR/agentpass-native-client" "dev.agentpass.native-client" "$ENTITLEMENT_DIR/client.plist"
sign_item "$MACOS_DIR/agentpass-native-manager" "dev.agentpass" "$ENTITLEMENT_DIR/manager.plist"
sign_item "$APP" "dev.agentpass" "$ENTITLEMENT_DIR/manager.plist"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"

verify_identifier() {
  local item="$1" expected="$2" actual
  actual="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')"
  [[ "$actual" == "$expected" ]] || { echo "Unexpected signing identifier on $item: $actual" >&2; exit 1; }
}

verify_keychain_group() {
  local item="$1" expected="$2" extracted actual
  extracted="$TEMP_DIR/$(basename "$item").signed-entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$item" >"$extracted" 2>/dev/null
  actual="$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$extracted")"
  [[ "$actual" == "$expected" ]] || { echo "Unexpected keychain access group on $item: $actual" >&2; exit 1; }
}

verify_identifier "$MACOS_DIR/agentpass-native-service" "dev.agentpass.native-service"
verify_identifier "$MACOS_DIR/agentpass-native-client" "dev.agentpass.native-client"
verify_identifier "$MACOS_DIR/agentpass-native-manager" "dev.agentpass"
verify_identifier "$APP" "dev.agentpass"
verify_keychain_group "$MACOS_DIR/agentpass-native-service" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys"
verify_keychain_group "$MACOS_DIR/agentpass-native-client" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist")" == "agentpass-native-manager" ]] || { echo "Unexpected app executable" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :Label' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "dev.agentpass.native-service" ]] || { echo "Unexpected daemon label" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :BundleProgram' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "Contents/MacOS/agentpass-native-service" ]] || { echo "Unexpected daemon bundle program" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :MachServices:dev.agentpass.native-service' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "true" ]] || { echo "Missing daemon Mach service" >&2; exit 1; }

if [[ "$ADHOC" -eq 0 ]]; then
  for item in "$MACOS_DIR/agentpass-native-service" "$MACOS_DIR/agentpass-native-client" "$MACOS_DIR/agentpass-native-manager" "$APP"; do
    actual_team="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
    [[ "$actual_team" == "$TEAM_ID" ]] || { echo "Unexpected TeamIdentifier on $item" >&2; exit 1; }
  done
fi

/usr/bin/ditto "$APP" "$TARGET_APP"
if [[ -n "$NOTARY_PROFILE" ]]; then
  ARCHIVE="$TEMP_DIR/AgentPass.zip"
  /usr/bin/ditto -c -k --keepParent "$TARGET_APP" "$ARCHIVE"
  xcrun notarytool submit "$ARCHIVE" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$TARGET_APP"
  xcrun stapler validate "$TARGET_APP"
fi

/usr/bin/codesign --verify --deep --strict --verbose=2 "$TARGET_APP"
echo "$TARGET_APP"

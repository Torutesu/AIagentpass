#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESOURCE_DIR="$PACKAGE_DIR/Resources"
OUTPUT_DIR="$PACKAGE_DIR/dist"
SIGNING_IDENTITY="${AGENTPASS_SIGNING_IDENTITY:-}"
TEAM_ID="${AGENTPASS_TEAM_ID:-}"
APP_IDENTIFIER_PREFIX="${AGENTPASS_APP_IDENTIFIER_PREFIX:-}"
SERVICE_PROFILE="${AGENTPASS_SERVICE_PROVISIONING_PROFILE:-}"
CLIENT_PROFILE="${AGENTPASS_CLIENT_PROVISIONING_PROFILE:-}"
ADHOC=0
FORCE=0
ARCHITECTURES=("$(uname -m)")

usage() {
  echo "Usage: build-app.sh [--output-dir DIR] [--identity IDENTITY --team-id TEAMID --app-identifier-prefix PREFIX --service-profile FILE --client-profile FILE] [--universal] [--adhoc] [--force]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) [[ $# -ge 2 ]] || usage; OUTPUT_DIR="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; SIGNING_IDENTITY="$2"; shift 2 ;;
    --team-id) [[ $# -ge 2 ]] || usage; TEAM_ID="$2"; shift 2 ;;
    --app-identifier-prefix) [[ $# -ge 2 ]] || usage; APP_IDENTIFIER_PREFIX="$2"; shift 2 ;;
    --service-profile) [[ $# -ge 2 ]] || usage; SERVICE_PROFILE="$2"; shift 2 ;;
    --client-profile) [[ $# -ge 2 ]] || usage; CLIENT_PROFILE="$2"; shift 2 ;;
    --profile|--notary-profile) echo "$1 is not supported: use separate helper profiles and notarize after assembly" >&2; exit 2 ;;
    --universal) ARCHITECTURES=(arm64 x86_64); shift ;;
    --adhoc) ADHOC=1; shift ;;
    --force) FORCE=1; shift ;;
    *) usage ;;
  esac
done

if [[ "$ADHOC" -eq 1 ]]; then
  [[ -z "$SERVICE_PROFILE" && -z "$CLIENT_PROFILE" ]] || { echo "Ad-hoc builds must not embed provisioning profiles" >&2; exit 1; }
  TEAM_ID="ADHOC00000"
  APP_IDENTIFIER_PREFIX="ADHOC00000"
  SIGNING_IDENTITY="-"
else
  [[ -n "$SIGNING_IDENTITY" ]] || { echo "Production build requires --identity" >&2; exit 1; }
  [[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "Production build requires a 10-character --team-id" >&2; exit 1; }
  [[ "$APP_IDENTIFIER_PREFIX" =~ ^[A-Z0-9]{10}$ ]] || { echo "Production build requires a 10-character --app-identifier-prefix" >&2; exit 1; }
  [[ -n "$SERVICE_PROFILE" && -n "$CLIENT_PROFILE" ]] || { echo "Production build requires separate --service-profile and --client-profile files" >&2; exit 1; }
  [[ -f "$SERVICE_PROFILE" && ! -L "$SERVICE_PROFILE" && -f "$CLIENT_PROFILE" && ! -L "$CLIENT_PROFILE" ]] || { echo "Helper profiles must be regular non-symlink files" >&2; exit 1; }
  [[ ! "$SERVICE_PROFILE" -ef "$CLIENT_PROFILE" ]] || { echo "Service and client provisioning profiles must be separate files" >&2; exit 1; }
  "$SCRIPT_DIR/verify-profile.sh" "$SERVICE_PROFILE" "$TEAM_ID" "$APP_IDENTIFIER_PREFIX" \
    "dev.agentpass.native-service" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" "service"
  "$SCRIPT_DIR/verify-profile.sh" "$CLIENT_PROFILE" "$TEAM_ID" "$APP_IDENTIFIER_PREFIX" \
    "dev.agentpass.native-client" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys" "client"
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
APP="$TEMP_DIR/AgentPass.app"
MACOS_DIR="$APP/Contents/MacOS"
DAEMON_DIR="$APP/Contents/Library/LaunchDaemons"
HELPER_DIR="$APP/Contents/Library/HelperTools"
SERVICE_APP="$HELPER_DIR/AgentPassNativeService.app"
CLIENT_APP="$HELPER_DIR/AgentPassNativeClient.app"
ENTITLEMENT_DIR="$TEMP_DIR/entitlements"
mkdir -p "$MACOS_DIR" "$DAEMON_DIR" "$SERVICE_APP/Contents/MacOS" "$CLIENT_APP/Contents/MacOS" "$ENTITLEMENT_DIR"

for architecture in "${ARCHITECTURES[@]}"; do
  MACOSX_DEPLOYMENT_TARGET=14.0 swift build -c release --package-path "$PACKAGE_DIR" --arch "$architecture" >&2
done

install_product() {
  local product="$1" destination="$2" slices=() architecture bin_dir
  for architecture in "${ARCHITECTURES[@]}"; do
    bin_dir="$(swift build -c release --package-path "$PACKAGE_DIR" --arch "$architecture" --show-bin-path)"
    slices+=("$bin_dir/$product")
  done
  if [[ "${#slices[@]}" -eq 1 ]]; then
    install -m 0755 "${slices[0]}" "$destination"
  else
    xcrun lipo -create "${slices[@]}" -output "$destination"
    chmod 0755 "$destination"
  fi
}

install_product agentpass-native-manager "$MACOS_DIR/agentpass-native-manager"
install_product agentpass-native-service "$SERVICE_APP/Contents/MacOS/agentpass-native-service"
install_product agentpass-native-client "$CLIENT_APP/Contents/MacOS/agentpass-native-client"
install_product agentpass-atomic-rename "$HELPER_DIR/agentpass-atomic-rename"
install -m 0644 "$RESOURCE_DIR/AgentPass-Info.plist" "$APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeService-Info.plist" "$SERVICE_APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeClient-Info.plist" "$CLIENT_APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/dev.agentpass.native-service.plist" "$DAEMON_DIR/dev.agentpass.native-service.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeManager.entitlements" "$ENTITLEMENT_DIR/manager.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeClient.entitlements" "$ENTITLEMENT_DIR/client.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeService.entitlements" "$ENTITLEMENT_DIR/service.plist"
/usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys" "$ENTITLEMENT_DIR/client.plist"
/usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" "$ENTITLEMENT_DIR/service.plist"
if [[ "$ADHOC" -eq 0 ]]; then
  install -m 0644 "$SERVICE_PROFILE" "$SERVICE_APP/Contents/embedded.provisionprofile"
  install -m 0644 "$CLIENT_PROFILE" "$CLIENT_APP/Contents/embedded.provisionprofile"
fi

/usr/bin/plutil -lint "$APP/Contents/Info.plist" "$SERVICE_APP/Contents/Info.plist" "$CLIENT_APP/Contents/Info.plist" \
  "$DAEMON_DIR/dev.agentpass.native-service.plist" "$ENTITLEMENT_DIR/manager.plist" "$ENTITLEMENT_DIR/client.plist" "$ENTITLEMENT_DIR/service.plist" >/dev/null

sign_item() {
  local item="$1" identifier="$2" entitlements="$3"
  if [[ "$ADHOC" -eq 1 ]]; then
    /usr/bin/codesign --force --sign - --identifier "$identifier" --entitlements "$entitlements" "$item"
  else
    /usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --identifier "$identifier" --entitlements "$entitlements" --options runtime --timestamp "$item"
  fi
}

# Sign app-like helpers before their containing application. Never use --deep for signing.
sign_item "$SERVICE_APP" "dev.agentpass.native-service" "$ENTITLEMENT_DIR/service.plist"
sign_item "$CLIENT_APP" "dev.agentpass.native-client" "$ENTITLEMENT_DIR/client.plist"
if [[ "$ADHOC" -eq 1 ]]; then
  /usr/bin/codesign --force --sign - --identifier "dev.agentpass.atomic-rename" "$HELPER_DIR/agentpass-atomic-rename"
else
  /usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --identifier "dev.agentpass.atomic-rename" --options runtime --timestamp "$HELPER_DIR/agentpass-atomic-rename"
fi
sign_item "$MACOS_DIR/agentpass-native-manager" "dev.agentpass" "$ENTITLEMENT_DIR/manager.plist"
sign_item "$APP" "dev.agentpass" "$ENTITLEMENT_DIR/manager.plist"

verify_identifier() {
  local item="$1" expected="$2" actual
  actual="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')"
  [[ "$actual" == "$expected" ]] || { echo "Unexpected signing identifier on $item: $actual" >&2; exit 1; }
}
verify_group() {
  local item="$1" expected="$2" extracted actual
  extracted="$TEMP_DIR/$(basename "$item").entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$item" >"$extracted" 2>/dev/null
  actual="$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$extracted")"
  [[ "$actual" == "$expected" ]] || { echo "Unexpected keychain group on $item: $actual" >&2; exit 1; }
  if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:1' "$extracted" >/dev/null 2>&1; then
    echo "Unexpected additional keychain group on $item" >&2
    exit 1
  fi
}

/usr/bin/codesign --verify --strict --verbose=2 "$SERVICE_APP"
/usr/bin/codesign --verify --strict --verbose=2 "$CLIENT_APP"
/usr/bin/codesign --verify --strict --verbose=2 "$HELPER_DIR/agentpass-atomic-rename"
/usr/bin/codesign --verify --strict --verbose=2 "$APP"
verify_identifier "$SERVICE_APP" "dev.agentpass.native-service"
verify_identifier "$CLIENT_APP" "dev.agentpass.native-client"
verify_identifier "$HELPER_DIR/agentpass-atomic-rename" "dev.agentpass.atomic-rename"
verify_identifier "$MACOS_DIR/agentpass-native-manager" "dev.agentpass"
verify_identifier "$APP" "dev.agentpass"
verify_group "$SERVICE_APP" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys"
verify_group "$CLIENT_APP" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist")" == "agentpass-native-manager" ]] || { echo "Unexpected outer app executable" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :Label' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "dev.agentpass.native-service" ]] || { echo "Unexpected daemon label" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :BundleProgram' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service" ]] || { echo "Unexpected daemon BundleProgram" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :MachServices:dev.agentpass.native-service' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "true" ]] || { echo "Missing daemon Mach service" >&2; exit 1; }

if [[ "$ADHOC" -eq 0 ]]; then
  for item in "$SERVICE_APP" "$CLIENT_APP" "$HELPER_DIR/agentpass-atomic-rename" "$MACOS_DIR/agentpass-native-manager" "$APP"; do
    actual_team="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
    [[ "$actual_team" == "$TEAM_ID" ]] || { echo "Unexpected TeamIdentifier on $item" >&2; exit 1; }
  done
fi

/usr/bin/ditto "$APP" "$TARGET_APP"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$TARGET_APP"
echo "$TARGET_APP"

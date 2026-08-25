#!/bin/bash
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: verify-installed-qualification-client.sh SOURCE_LAUNCHER EXPECTED_TEAM_ID APP_IDENTIFIER_PREFIX" >&2; exit 2; }
SOURCE_LAUNCHER="$1"
EXPECTED_TEAM_ID="$2"
APP_IDENTIFIER_PREFIX="$3"
FIXED_LAUNCHER=/opt/agentpass/p0c/qualification-client/agentpass-qualification-grant-client
SOURCE_APP="${SOURCE_LAUNCHER}.app"
FIXED_APP="${FIXED_LAUNCHER}.app"
SOURCE_BINARY="$SOURCE_APP/Contents/MacOS/agentpass-qualification-grant-client"
FIXED_BINARY="$FIXED_APP/Contents/MacOS/agentpass-qualification-grant-client"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
EXPECTED_IDENTIFIER=dev.agentpass.qualification-grant-client
EXPECTED_KEYCHAIN_GROUP="$APP_IDENTIFIER_PREFIX.dev.agentpass.service-keys"

test -f "$SOURCE_LAUNCHER" -a ! -L "$SOURCE_LAUNCHER"
[[ "$(stat -f '%u:%g:%Lp:%l' "$SOURCE_LAUNCHER")" == '0:0:755:1' ]]
test -f "$SOURCE_APP/Contents/embedded.provisionprofile" -a -x "$SOURCE_BINARY"

ENTITLEMENTS_DIR="${TMPDIR:-/tmp}/agentpass-qualification-client-entitlements.$$"
mkdir -m 700 "$ENTITLEMENTS_DIR"
trap 'rm -rf -- "$ENTITLEMENTS_DIR"' EXIT

AS_ROOT=0
run_macos() {
  if [[ "$AS_ROOT" -eq 1 ]]; then
    sudo -n "$@"
  else
    "$@"
  fi
}

verify_signed_item() {
  local item="$1" label="$2" details identifier team entitlements safe_label
  run_macos /usr/bin/codesign --verify --strict --verbose=2 "$item"
  details="$(run_macos /usr/bin/codesign -dv --verbose=4 "$item" 2>&1)"
  identifier="$(awk -F= '/^Identifier=/{print $2; exit}' <<<"$details")"
  team="$(awk -F= '/^TeamIdentifier=/{print $2; exit}' <<<"$details")"
  [[ "$identifier" == "$EXPECTED_IDENTIFIER" ]] || { echo "$label identifier mismatch" >&2; exit 1; }
  [[ "$team" == "$EXPECTED_TEAM_ID" ]] || { echo "$label Team ID mismatch" >&2; exit 1; }
  grep -q '^Authority=Developer ID Application:' <<<"$details" || { echo "$label is not Developer ID signed" >&2; exit 1; }
  safe_label="${label//[^A-Za-z0-9_-]/_}"
  entitlements="$ENTITLEMENTS_DIR/$safe_label.plist"
  run_macos /usr/bin/codesign -d --entitlements :- "$item" >"$entitlements" 2>/dev/null
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :application-identifier' "$entitlements")" == "$APP_IDENTIFIER_PREFIX.$EXPECTED_IDENTIFIER" ]] || { echo "$label application-identifier entitlement mismatch" >&2; exit 1; }
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$entitlements")" == "$EXPECTED_TEAM_ID" ]] || { echo "$label Team ID entitlement mismatch" >&2; exit 1; }
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$entitlements")" == "$EXPECTED_KEYCHAIN_GROUP" ]] || { echo "$label keychain access group mismatch" >&2; exit 1; }
  if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:1' "$entitlements" >/dev/null 2>&1; then
    echo "$label has an unexpected additional keychain group" >&2
    exit 1
  fi
  for forbidden in get-task-allow com.apple.security.get-task-allow com.apple.security.cs.disable-library-validation com.apple.security.cs.allow-dyld-environment-variables; do
    if /usr/libexec/PlistBuddy -c "Print :$forbidden" "$entitlements" >/dev/null 2>&1; then
      echo "$label has forbidden entitlement: $forbidden" >&2
      exit 1
    fi
  done
  printf '%s\t%s\n' "$identifier" "$team"
}

verify_profile() {
  local app="$1" label="$2"
  if [[ "$AS_ROOT" -eq 1 ]]; then
    sudo -n /bin/bash "$SCRIPT_DIR/verify-profile.sh" "$app/Contents/embedded.provisionprofile" "$EXPECTED_TEAM_ID" "$APP_IDENTIFIER_PREFIX" \
      "$EXPECTED_IDENTIFIER" "$EXPECTED_KEYCHAIN_GROUP" "$label"
  else
    "$SCRIPT_DIR/verify-profile.sh" "$app/Contents/embedded.provisionprofile" "$EXPECTED_TEAM_ID" "$APP_IDENTIFIER_PREFIX" \
      "$EXPECTED_IDENTIFIER" "$EXPECTED_KEYCHAIN_GROUP" "$label"
  fi
}

source_app_identity="$(verify_signed_item "$SOURCE_APP" source-app)"
source_binary_identity="$(verify_signed_item "$SOURCE_BINARY" source-binary)"
[[ "$source_app_identity" == "$source_binary_identity" ]] || { echo "source helper app and executable signing identity differ" >&2; exit 1; }
/usr/bin/lipo -info "$SOURCE_BINARY" | grep -Eq 'arm64.*x86_64|x86_64.*arm64'
verify_profile "$SOURCE_APP" source-profile

AS_ROOT=1
sudo -n /usr/bin/test -d /opt/agentpass/p0c/qualification-client
[[ "$(sudo -n /usr/bin/stat -f '%u:%g:%Lp' /opt/agentpass/p0c/qualification-client)" == '0:0:700' ]]
[[ "$(sudo -n /usr/bin/stat -f '%u:%g:%Lp:%l' "$FIXED_LAUNCHER")" == '0:0:755:1' ]]
fixed_digest="$(sudo -n /usr/bin/shasum -a 256 "$FIXED_LAUNCHER" | awk '{print $1}')"
source_digest="$(/usr/bin/shasum -a 256 "$SOURCE_LAUNCHER" | awk '{print $1}')"
[[ "$fixed_digest" == "$source_digest" ]] || { echo "fixed launcher is not copied from the trusted installed app" >&2; exit 1; }
sudo -n /usr/bin/test -f "$FIXED_APP/Contents/embedded.provisionprofile" -a -x "$FIXED_BINARY"
fixed_app_identity="$(verify_signed_item "$FIXED_APP" installed-app)"
fixed_binary_identity="$(verify_signed_item "$FIXED_BINARY" installed-binary)"
[[ "$fixed_app_identity" == "$fixed_binary_identity" ]] || { echo "installed helper app and executable signing identity differ" >&2; exit 1; }
sudo -n /usr/bin/lipo -info "$FIXED_BINARY" | grep -Eq 'arm64.*x86_64|x86_64.*arm64'
[[ "$(sudo -n /usr/bin/shasum -a 256 "$FIXED_BINARY" | awk '{print $1}')" == "$(/usr/bin/shasum -a 256 "$SOURCE_BINARY" | awk '{print $1}')" ]] || { echo "installed helper executable is not copied from the trusted app" >&2; exit 1; }
[[ "$(sudo -n /usr/bin/shasum -a 256 "$FIXED_APP/Contents/embedded.provisionprofile" | awk '{print $1}')" == "$(/usr/bin/shasum -a 256 "$SOURCE_APP/Contents/embedded.provisionprofile" | awk '{print $1}')" ]] || { echo "installed provisioning profile differs from the trusted app" >&2; exit 1; }
verify_profile "$FIXED_APP" installed-profile

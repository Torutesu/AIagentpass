#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-app-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

APP_PATH="$($SCRIPT_DIR/build-app.sh --adhoc --output-dir "$TEST_DIR/output")"
/usr/bin/codesign --verify --deep --strict "$APP_PATH"
SERVICE_APP="$APP_PATH/Contents/Library/HelperTools/AgentPassNativeService.app"
CLIENT_APP="$APP_PATH/Contents/Library/HelperTools/AgentPassNativeClient.app"
ATOMIC_RENAME="$APP_PATH/Contents/Library/HelperTools/agentpass-atomic-rename"
ONBOARDING="$APP_PATH/Contents/MacOS/agentpass-onboarding"
[[ -d "$SERVICE_APP" && -d "$CLIENT_APP" ]] || { echo "Nested helper app layout is missing" >&2; exit 1; }
[[ ! -e "$APP_PATH/Contents/MacOS/agentpass-native-service" && ! -e "$APP_PATH/Contents/MacOS/agentpass-native-client" ]] || { echo "Helpers were duplicated outside their bundles" >&2; exit 1; }
[[ -x "$ATOMIC_RENAME" && ! -L "$ATOMIC_RENAME" ]] || { echo "Atomic rename helper is missing or unsafe" >&2; exit 1; }
[[ -x "$ONBOARDING" && ! -L "$ONBOARDING" ]] || { echo "Onboarding UI executable is missing or unsafe" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP_PATH/Contents/Info.plist")" == "agentpass-onboarding" ]] || { echo "Unexpected outer app executable" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :LSUIElement' "$APP_PATH/Contents/Info.plist")" == "false" ]] || { echo "Onboarding app is unexpectedly hidden" >&2; exit 1; }
AGENTPASS_ATOMIC_RENAME_HELPER="$ATOMIC_RENAME" "$SCRIPT_DIR/test-atomic-rename.sh"
[[ ! -e "$SERVICE_APP/Contents/embedded.provisionprofile" && ! -e "$CLIENT_APP/Contents/embedded.provisionprofile" ]] || { echo "Ad-hoc helpers unexpectedly embed profiles" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$SERVICE_APP/Contents/Info.plist")" == "dev.agentpass.native-service" ]] || exit 1
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$CLIENT_APP/Contents/Info.plist")" == "dev.agentpass.native-client" ]] || exit 1
[[ "$(/usr/libexec/PlistBuddy -c 'Print :BundleProgram' "$APP_PATH/Contents/Library/LaunchDaemons/dev.agentpass.native-service.plist")" == "Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service" ]] || exit 1

extract_group() {
  local item="$1" output
  output="$TEST_DIR/$(basename "$item").entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$item" >"$output" 2>/dev/null
  /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$output"
}
[[ "$(extract_group "$SERVICE_APP")" == "ADHOC00000.dev.agentpass.service-keys" ]] || exit 1
[[ "$(extract_group "$CLIENT_APP")" == "ADHOC00000.dev.agentpass.approval-keys" ]] || exit 1

STATUS_JSON="$($APP_PATH/Contents/MacOS/agentpass-native-manager status)"
node -e '
  const fs = require("node:fs");
  const value = JSON.parse(process.argv[1]);
  if (!value.ok || !value.plist_present || fs.realpathSync(value.bundle_path) !== fs.realpathSync(process.argv[2])) process.exit(1);
  if (!["not_found", "not_registered", "enabled", "requires_approval"].includes(value.status)) process.exit(1);
' "$STATUS_JSON" "$APP_PATH"

install -m 0755 "$APP_PATH/Contents/MacOS/agentpass-native-manager" "$TEST_DIR/unbundled-manager"
if "$TEST_DIR/unbundled-manager" status >/dev/null 2>&1; then
  echo "Unbundled manager unexpectedly accepted a status request" >&2
  exit 1
fi

if "$SCRIPT_DIR/build-app.sh" --output-dir "$TEST_DIR/unsigned" >/dev/null 2>&1; then
  echo "Unsigned production build unexpectedly succeeded" >&2
  exit 1
fi
if "$SCRIPT_DIR/build-app.sh" --adhoc --service-profile invalid --output-dir "$TEST_DIR/profile" >/dev/null 2>&1; then
  echo "Ad-hoc build unexpectedly accepted a profile" >&2
  exit 1
fi
if "$SCRIPT_DIR/build-app.sh" --identity invalid --team-id ABCDE12345 --app-identifier-prefix ABCDE12345 --output-dir "$TEST_DIR/missing-profiles" >/dev/null 2>&1; then
  echo "Production build unexpectedly accepted missing helper profiles" >&2
  exit 1
fi
touch "$TEST_DIR/fake.provisionprofile"
ln -s "$TEST_DIR/fake.provisionprofile" "$TEST_DIR/profile-link"
if "$SCRIPT_DIR/verify-profile.sh" "$TEST_DIR/profile-link" ABCDE12345 ABCDE12345 dev.agentpass.native-service ABCDE12345.dev.agentpass.service-keys service >/dev/null 2>&1; then
  echo "Profile verifier unexpectedly accepted a symlink" >&2
  exit 1
fi
if "$SCRIPT_DIR/build-app.sh" --adhoc --output-dir "$TEST_DIR/output" >/dev/null 2>&1; then
  echo "Existing output was unexpectedly overwritten without --force" >&2
  exit 1
fi

echo "AgentPass app bundle verification passed"

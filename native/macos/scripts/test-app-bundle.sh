#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-app-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

APP_PATH="$($SCRIPT_DIR/build-app.sh --adhoc --output-dir "$TEST_DIR/output")"
/usr/bin/codesign --verify --deep --strict "$APP_PATH"
SERVICE_APP="$APP_PATH/Contents/Library/HelperTools/AgentPassNativeService.app"
CLIENT_APP="$APP_PATH/Contents/Library/HelperTools/AgentPassNativeClient.app"
AGENT_HOST_APP="$APP_PATH/Contents/Library/HelperTools/AgentPassNativeAgentHost.app"
QUALIFICATION_CLIENT="$APP_PATH/Contents/Library/HelperTools/agentpass-qualification-grant-client"
QUALIFICATION_CLIENT_APP="$APP_PATH/Contents/Library/HelperTools/agentpass-qualification-grant-client.app"
QUALIFICATION_CLIENT_BINARY="$QUALIFICATION_CLIENT_APP/Contents/MacOS/agentpass-qualification-grant-client"
ATOMIC_RENAME="$APP_PATH/Contents/Library/HelperTools/agentpass-atomic-rename"
GIT_SIGNING_HELPER="$APP_PATH/Contents/Resources/bin/agentpass-git-sign"
ONBOARDING="$APP_PATH/Contents/MacOS/agentpass-onboarding"
[[ -d "$SERVICE_APP" && -d "$CLIENT_APP" && -d "$AGENT_HOST_APP" ]] || { echo "Nested helper app layout is missing" >&2; exit 1; }
[[ ! -e "$APP_PATH/Contents/MacOS/agentpass-native-service" && ! -e "$APP_PATH/Contents/MacOS/agentpass-native-client" ]] || { echo "Helpers were duplicated outside their bundles" >&2; exit 1; }
[[ -x "$ATOMIC_RENAME" && ! -L "$ATOMIC_RENAME" ]] || { echo "Atomic rename helper is missing or unsafe" >&2; exit 1; }
[[ -x "$GIT_SIGNING_HELPER" && ! -L "$GIT_SIGNING_HELPER" ]] || { echo "Git signing helper is missing or unsafe" >&2; exit 1; }
[[ "$(/usr/bin/find "$APP_PATH" -name agentpass-git-sign -print | /usr/bin/wc -l | /usr/bin/tr -d '[:space:]')" == "1" ]] || { echo "Git signing helper must appear exactly once in the app bundle" >&2; exit 1; }
[[ ! -e "$APP_PATH/Contents/MacOS/agentpass-git-sign" && ! -e "$APP_PATH/Contents/Library/HelperTools/agentpass-git-sign" ]] || { echo "Git signing helper was duplicated outside the frozen resource path" >&2; exit 1; }
[[ -x "$QUALIFICATION_CLIENT" && ! -L "$QUALIFICATION_CLIENT" ]] || { echo "Qualification grant client is missing or unsafe" >&2; exit 1; }
[[ -d "$QUALIFICATION_CLIENT_APP" && -x "$QUALIFICATION_CLIENT_BINARY" && ! -L "$QUALIFICATION_CLIENT_APP" && ! -L "$QUALIFICATION_CLIENT_BINARY" ]] || { echo "Qualification grant client helper bundle is missing or unsafe" >&2; exit 1; }
grep -q '/opt/agentpass/p0c/qualification-client/agentpass-qualification-grant-client.app/Contents/MacOS/agentpass-qualification-grant-client' "$QUALIFICATION_CLIENT" || { echo "Qualification grant client launcher does not resolve to its signed helper app" >&2; exit 1; }
[[ -x "$ONBOARDING" && ! -L "$ONBOARDING" ]] || { echo "Onboarding UI executable is missing or unsafe" >&2; exit 1; }
/usr/bin/codesign --verify --deep --strict "$QUALIFICATION_CLIENT_APP"
/usr/bin/codesign --verify --strict "$GIT_SIGNING_HELPER"
[[ "$(/usr/bin/codesign -dv --verbose=4 "$GIT_SIGNING_HELPER" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')" == "dev.agentpass.git-sign" ]] || { echo "Git signing helper identifier mismatch" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP_PATH/Contents/Info.plist")" == "agentpass-onboarding" ]] || { echo "Unexpected outer app executable" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :LSUIElement' "$APP_PATH/Contents/Info.plist")" == "false" ]] || { echo "Onboarding app is unexpectedly hidden" >&2; exit 1; }
AGENTPASS_ATOMIC_RENAME_HELPER="$ATOMIC_RENAME" "$SCRIPT_DIR/test-atomic-rename.sh"
[[ ! -e "$SERVICE_APP/Contents/embedded.provisionprofile" && ! -e "$CLIENT_APP/Contents/embedded.provisionprofile" && ! -e "$AGENT_HOST_APP/Contents/embedded.provisionprofile" ]] || { echo "Ad-hoc helpers unexpectedly embed profiles" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$SERVICE_APP/Contents/Info.plist")" == "dev.agentpass.native-service" ]] || exit 1
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$CLIENT_APP/Contents/Info.plist")" == "dev.agentpass.native-client" ]] || exit 1
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$AGENT_HOST_APP/Contents/Info.plist")" == "dev.agentpass.agent-host" ]] || exit 1
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$AGENT_HOST_APP/Contents/Info.plist")" == "agentpass-native-agent-host" ]] || exit 1
[[ "$(/usr/libexec/PlistBuddy -c 'Print :BundleProgram' "$APP_PATH/Contents/Library/LaunchDaemons/dev.agentpass.native-service.plist")" == "Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service" ]] || exit 1
[[ "$(/usr/libexec/PlistBuddy -c 'Print :MachServices:dev.agentpass.native-service' "$APP_PATH/Contents/Library/LaunchDaemons/dev.agentpass.native-service.plist")" == "true" ]] || { echo "Management Mach service is missing" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :MachServices:dev.agentpass.agent-session' "$APP_PATH/Contents/Library/LaunchDaemons/dev.agentpass.native-service.plist")" == "true" ]] || { echo "Agent session Mach service is missing" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :MachServices:dev.agentpass.n3e-qualification' "$APP_PATH/Contents/Library/LaunchDaemons/dev.agentpass.native-service.plist")" == "true" ]] || { echo "Reserved qualification Mach service is missing" >&2; exit 1; }
[[ ! -e "$APP_PATH/Contents/Library/HelperTools/AgentPassQualificationController.app" && ! -e "$APP_PATH/Contents/MacOS/agentpass-qualification-controller" ]] || { echo "Qualification controller must not be bundled" >&2; exit 1; }

node - "$SCRIPT_DIR/../Resources/native-service.example.json" <<'NODE'
const fs = require("node:fs");

const [configPath] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const expectedManagementRequirement = 'anchor apple generic and identifier "dev.agentpass.native-client" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "TEAMID" and entitlement["keychain-access-groups"] = "TEAMID.dev.agentpass.approval-keys"';
const expectedAgentRequirement = 'anchor apple generic and identifier "dev.agentpass.agent-host" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "TEAMID" and entitlement["dev.agentpass.agent-session-client"] = true';
if (config.mach_service_name !== "dev.agentpass.native-service") throw new Error("Management Mach service example changed");
if (config.agent_mach_service_name !== "dev.agentpass.agent-session") throw new Error("Agent Mach service example is missing or invalid");
if (config.client_code_signing_requirement !== expectedManagementRequirement) throw new Error("Management code-signing requirement example changed");
if (config.agent_client_code_signing_requirement !== expectedAgentRequirement) throw new Error("Agent code-signing requirement example is missing or invalid");
NODE

extract_group() {
  local item="$1" output
  output="$TEST_DIR/$(basename "$item").entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$item" >"$output" 2>/dev/null
  /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$output"
}
extract_agent_entitlement() {
  local item="$1" output
  output="$TEST_DIR/$(basename "$item").agent-entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$item" >"$output" 2>/dev/null
  /usr/libexec/PlistBuddy -c 'Print :dev.agentpass.agent-session-client' "$output"
}
extract_qualification_entitlements() {
  local output="$TEST_DIR/qualification-client.entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$QUALIFICATION_CLIENT_APP" >"$output" 2>/dev/null
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :application-identifier' "$output")" == "ADHOC00000.dev.agentpass.qualification-grant-client" ]] || exit 1
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$output")" == "ADHOC00000" ]] || exit 1
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$output")" == "ADHOC00000.dev.agentpass.service-keys" ]] || exit 1
  if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:1' "$output" >/dev/null 2>&1; then exit 1; fi
  for forbidden in get-task-allow com.apple.security.get-task-allow com.apple.security.cs.disable-library-validation com.apple.security.cs.allow-dyld-environment-variables; do
    if /usr/libexec/PlistBuddy -c "Print :$forbidden" "$output" >/dev/null 2>&1; then exit 1; fi
  done
}
[[ "$(extract_group "$SERVICE_APP")" == "ADHOC00000.dev.agentpass.service-keys" ]] || exit 1
[[ "$(extract_group "$CLIENT_APP")" == "ADHOC00000.dev.agentpass.approval-keys" ]] || exit 1
[[ "$(extract_agent_entitlement "$AGENT_HOST_APP")" == "true" ]] || exit 1
extract_qualification_entitlements
[[ ! -e "$QUALIFICATION_CLIENT_APP/Contents/embedded.provisionprofile" ]] || { echo "Ad-hoc qualification helper unexpectedly embeds a profile" >&2; exit 1; }
if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$TEST_DIR/$(basename "$AGENT_HOST_APP").agent-entitlements.plist" >/dev/null 2>&1; then
  echo "Ad-hoc Agent Host unexpectedly has a keychain access group" >&2
  exit 1
fi

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
if "$SCRIPT_DIR/build-app.sh" --identity invalid --team-id ABCDE12345 --app-identifier-prefix ABCDE12345 --service-profile "$TEST_DIR/fake.provisionprofile" --client-profile "$TEST_DIR/fake.provisionprofile" --output-dir "$TEST_DIR/missing-agent-profile" >/dev/null 2>&1; then
  echo "Production build unexpectedly accepted a missing Agent profile" >&2
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

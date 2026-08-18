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
AGENT_PROFILE="${AGENTPASS_AGENT_PROVISIONING_PROFILE:-}"
QUALIFICATION_CLIENT_PROFILE="${AGENTPASS_QUALIFICATION_CLIENT_PROVISIONING_PROFILE:-}"
ADHOC=0
FORCE=0
ARCHITECTURES=("$(uname -m)")
SWIFT_BUILD_OPTIONS=()
if [[ "${AGENTPASS_DISABLE_SWIFTPM_SANDBOX:-0}" == "1" ]]; then
  SWIFT_BUILD_OPTIONS+=(--disable-sandbox)
fi

swift_build() {
  if [[ "${#SWIFT_BUILD_OPTIONS[@]}" -gt 0 ]]; then
    swift build "${SWIFT_BUILD_OPTIONS[@]}" "$@"
  else
    swift build "$@"
  fi
}

usage() {
  echo "Usage: build-app.sh [--output-dir DIR] [--identity IDENTITY --team-id TEAMID --app-identifier-prefix PREFIX --service-profile FILE --client-profile FILE --agent-profile FILE --qualification-client-profile FILE] [--universal] [--adhoc] [--force]" >&2
  exit 2
}

verify_agent_profile() {
  local profile="$1" team_id="$2" identifier_prefix="$3" profile_dir profile_plist
  profile_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-agent-profile.XXXXXX")"
  profile_plist="$profile_dir/profile.plist"
  if ! /usr/bin/security cms -D -i "$profile" >"$profile_plist"; then
    rm -rf -- "$profile_dir"
    echo "Agent profile CMS signature is invalid" >&2
    exit 1
  fi
  /usr/bin/plutil -lint "$profile_plist" >/dev/null
  read_agent_profile() { /usr/libexec/PlistBuddy -c "Print $1" "$profile_plist" 2>/dev/null; }
  [[ "$(read_agent_profile :TeamIdentifier:0)" == "$team_id" ]] || { rm -rf -- "$profile_dir"; echo "Agent profile TeamIdentifier mismatch" >&2; exit 1; }
  [[ "$(read_agent_profile :ApplicationIdentifierPrefix:0)" == "$identifier_prefix" ]] || { rm -rf -- "$profile_dir"; echo "Agent profile ApplicationIdentifierPrefix mismatch" >&2; exit 1; }
  [[ "$(read_agent_profile :Entitlements:application-identifier)" == "${identifier_prefix}.dev.agentpass.agent-host" ]] || { rm -rf -- "$profile_dir"; echo "Agent profile application-identifier mismatch" >&2; exit 1; }
  [[ "$(read_agent_profile :Entitlements:com.apple.developer.team-identifier)" == "$team_id" ]] || { rm -rf -- "$profile_dir"; echo "Agent profile entitlement Team ID mismatch" >&2; exit 1; }
  [[ "$(read_agent_profile :Entitlements:dev.agentpass.agent-session-client)" == "true" ]] || { rm -rf -- "$profile_dir"; echo "Agent profile is missing the exact Agent session entitlement" >&2; exit 1; }
  if read_agent_profile :Entitlements:keychain-access-groups:0 >/dev/null; then
    rm -rf -- "$profile_dir"
    echo "Agent profile must not authorize keychain access groups" >&2
    exit 1
  fi
  [[ "$(read_agent_profile :Entitlements:get-task-allow || true)" != "true" ]] || { rm -rf -- "$profile_dir"; echo "Agent profile enables get-task-allow" >&2; exit 1; }
  [[ "$(read_agent_profile :ProvisionsAllDevices)" == "true" ]] || { rm -rf -- "$profile_dir"; echo "Agent profile is not a Developer ID distribution profile" >&2; exit 1; }
  /usr/bin/ruby -rtime -e 'abort "expired" unless Time.parse(ARGV[0]) > Time.now' "$(read_agent_profile :ExpirationDate)" || { rm -rf -- "$profile_dir"; echo "Agent profile is expired" >&2; exit 1; }
  [[ -n "$(read_agent_profile :UUID)" ]] || { rm -rf -- "$profile_dir"; echo "Agent profile has no UUID" >&2; exit 1; }
  rm -rf -- "$profile_dir"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) [[ $# -ge 2 ]] || usage; OUTPUT_DIR="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; SIGNING_IDENTITY="$2"; shift 2 ;;
    --team-id) [[ $# -ge 2 ]] || usage; TEAM_ID="$2"; shift 2 ;;
    --app-identifier-prefix) [[ $# -ge 2 ]] || usage; APP_IDENTIFIER_PREFIX="$2"; shift 2 ;;
    --service-profile) [[ $# -ge 2 ]] || usage; SERVICE_PROFILE="$2"; shift 2 ;;
    --client-profile) [[ $# -ge 2 ]] || usage; CLIENT_PROFILE="$2"; shift 2 ;;
    --agent-profile) [[ $# -ge 2 ]] || usage; AGENT_PROFILE="$2"; shift 2 ;;
    --qualification-client-profile) [[ $# -ge 2 ]] || usage; QUALIFICATION_CLIENT_PROFILE="$2"; shift 2 ;;
    --profile|--notary-profile) echo "$1 is not supported: use separate helper profiles and notarize after assembly" >&2; exit 2 ;;
    --universal) ARCHITECTURES=(arm64 x86_64); shift ;;
    --adhoc) ADHOC=1; shift ;;
    --force) FORCE=1; shift ;;
    *) usage ;;
  esac
done

if [[ "$ADHOC" -eq 1 ]]; then
  [[ -z "$SERVICE_PROFILE" && -z "$CLIENT_PROFILE" && -z "$AGENT_PROFILE" && -z "$QUALIFICATION_CLIENT_PROFILE" ]] || { echo "Ad-hoc builds must not embed provisioning profiles" >&2; exit 1; }
  TEAM_ID="ADHOC00000"
  APP_IDENTIFIER_PREFIX="ADHOC00000"
  SIGNING_IDENTITY="-"
else
  [[ -n "$SIGNING_IDENTITY" ]] || { echo "Production build requires --identity" >&2; exit 1; }
  [[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "Production build requires a 10-character --team-id" >&2; exit 1; }
  [[ "$APP_IDENTIFIER_PREFIX" =~ ^[A-Z0-9]{10}$ ]] || { echo "Production build requires a 10-character --app-identifier-prefix" >&2; exit 1; }
  [[ -n "$SERVICE_PROFILE" && -n "$CLIENT_PROFILE" && -n "$AGENT_PROFILE" && -n "$QUALIFICATION_CLIENT_PROFILE" ]] || { echo "Production build requires separate helper profiles including the qualification client profile" >&2; exit 1; }
  [[ -f "$SERVICE_PROFILE" && ! -L "$SERVICE_PROFILE" && -f "$CLIENT_PROFILE" && ! -L "$CLIENT_PROFILE" && -f "$AGENT_PROFILE" && ! -L "$AGENT_PROFILE" && -f "$QUALIFICATION_CLIENT_PROFILE" && ! -L "$QUALIFICATION_CLIENT_PROFILE" ]] || { echo "Helper profiles must be regular non-symlink files" >&2; exit 1; }
  [[ ! "$SERVICE_PROFILE" -ef "$CLIENT_PROFILE" && ! "$SERVICE_PROFILE" -ef "$AGENT_PROFILE" && ! "$SERVICE_PROFILE" -ef "$QUALIFICATION_CLIENT_PROFILE" && ! "$CLIENT_PROFILE" -ef "$AGENT_PROFILE" && ! "$CLIENT_PROFILE" -ef "$QUALIFICATION_CLIENT_PROFILE" && ! "$AGENT_PROFILE" -ef "$QUALIFICATION_CLIENT_PROFILE" ]] || { echo "Helper provisioning profiles must be separate files" >&2; exit 1; }
  "$SCRIPT_DIR/verify-profile.sh" "$SERVICE_PROFILE" "$TEAM_ID" "$APP_IDENTIFIER_PREFIX" \
    "dev.agentpass.native-service" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" "service"
  "$SCRIPT_DIR/verify-profile.sh" "$CLIENT_PROFILE" "$TEAM_ID" "$APP_IDENTIFIER_PREFIX" \
    "dev.agentpass.native-client" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys" "client"
  verify_agent_profile "$AGENT_PROFILE" "$TEAM_ID" "$APP_IDENTIFIER_PREFIX"
  "$SCRIPT_DIR/verify-profile.sh" "$QUALIFICATION_CLIENT_PROFILE" "$TEAM_ID" "$APP_IDENTIFIER_PREFIX" \
    "dev.agentpass.qualification-grant-client" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" "qualification-client"
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
RESOURCE_BIN_DIR="$APP/Contents/Resources/bin"
DAEMON_DIR="$APP/Contents/Library/LaunchDaemons"
HELPER_DIR="$APP/Contents/Library/HelperTools"
SERVICE_APP="$HELPER_DIR/AgentPassNativeService.app"
CLIENT_APP="$HELPER_DIR/AgentPassNativeClient.app"
AGENT_HOST_APP="$HELPER_DIR/AgentPassNativeAgentHost.app"
QUALIFICATION_CLIENT="$HELPER_DIR/agentpass-qualification-grant-client"
QUALIFICATION_CLIENT_APP="$HELPER_DIR/agentpass-qualification-grant-client.app"
QUALIFICATION_CLIENT_BINARY="$QUALIFICATION_CLIENT_APP/Contents/MacOS/agentpass-qualification-grant-client"
GIT_SIGNING_HELPER="$RESOURCE_BIN_DIR/agentpass-git-sign"
ENTITLEMENT_DIR="$TEMP_DIR/entitlements"
mkdir -p "$MACOS_DIR" "$RESOURCE_BIN_DIR" "$DAEMON_DIR" "$SERVICE_APP/Contents/MacOS" "$CLIENT_APP/Contents/MacOS" "$AGENT_HOST_APP/Contents/MacOS" "$QUALIFICATION_CLIENT_APP/Contents/MacOS" "$ENTITLEMENT_DIR"

for architecture in "${ARCHITECTURES[@]}"; do
  MACOSX_DEPLOYMENT_TARGET=14.0 swift_build -c release --package-path "$PACKAGE_DIR" --arch "$architecture" >&2
done

install_product() {
  local product="$1" destination="$2" slices=() architecture bin_dir
  for architecture in "${ARCHITECTURES[@]}"; do
    bin_dir="$(swift_build -c release --package-path "$PACKAGE_DIR" --arch "$architecture" --show-bin-path)"
    slices+=("$bin_dir/$product")
  done
  if [[ "${#slices[@]}" -eq 1 ]]; then
    install -m 0755 "${slices[0]}" "$destination"
  else
    xcrun lipo -create "${slices[@]}" -output "$destination"
    chmod 0755 "$destination"
  fi
}

install_product agentpass-onboarding "$MACOS_DIR/agentpass-onboarding"
install_product agentpass-native-manager "$MACOS_DIR/agentpass-native-manager"
install_product agentpass-native-service "$SERVICE_APP/Contents/MacOS/agentpass-native-service"
install_product agentpass-native-client "$CLIENT_APP/Contents/MacOS/agentpass-native-client"
install_product agentpass-native-agent-host "$AGENT_HOST_APP/Contents/MacOS/agentpass-native-agent-host"
install_product agentpass-git-sign "$GIT_SIGNING_HELPER"
install_product agentpass-atomic-rename "$HELPER_DIR/agentpass-atomic-rename"
install_product agentpass-qualification-grant-client "$QUALIFICATION_CLIENT_BINARY"
install -m 0755 "$SCRIPT_DIR/qualification-grant-client-launcher.sh" "$QUALIFICATION_CLIENT"
install -m 0644 "$RESOURCE_DIR/AgentPass-Info.plist" "$APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeService-Info.plist" "$SERVICE_APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeClient-Info.plist" "$CLIENT_APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeAgentHost-Info.plist" "$AGENT_HOST_APP/Contents/Info.plist"
install -m 0644 "$SCRIPT_DIR/AgentPassQualificationGrantClient-Info.plist" "$QUALIFICATION_CLIENT_APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/dev.agentpass.native-service.plist" "$DAEMON_DIR/dev.agentpass.native-service.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeManager.entitlements" "$ENTITLEMENT_DIR/manager.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeClient.entitlements" "$ENTITLEMENT_DIR/client.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeService.entitlements" "$ENTITLEMENT_DIR/service.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassNativeAgentHost.entitlements" "$ENTITLEMENT_DIR/agent-host.plist"
install -m 0644 "$SCRIPT_DIR/qualification-grant-client.entitlements" "$ENTITLEMENT_DIR/qualification-client.plist"
/usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys" "$ENTITLEMENT_DIR/client.plist"
/usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" "$ENTITLEMENT_DIR/service.plist"
/usr/libexec/PlistBuddy -c "Set :application-identifier ${APP_IDENTIFIER_PREFIX}.dev.agentpass.qualification-grant-client" "$ENTITLEMENT_DIR/qualification-client.plist"
/usr/libexec/PlistBuddy -c "Set :com.apple.developer.team-identifier ${TEAM_ID}" "$ENTITLEMENT_DIR/qualification-client.plist"
/usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" "$ENTITLEMENT_DIR/qualification-client.plist"
if [[ "$ADHOC" -eq 0 ]]; then
  install -m 0644 "$SERVICE_PROFILE" "$SERVICE_APP/Contents/embedded.provisionprofile"
  install -m 0644 "$CLIENT_PROFILE" "$CLIENT_APP/Contents/embedded.provisionprofile"
  install -m 0644 "$AGENT_PROFILE" "$AGENT_HOST_APP/Contents/embedded.provisionprofile"
  install -m 0644 "$QUALIFICATION_CLIENT_PROFILE" "$QUALIFICATION_CLIENT_APP/Contents/embedded.provisionprofile"
fi

/usr/bin/plutil -lint "$APP/Contents/Info.plist" "$SERVICE_APP/Contents/Info.plist" "$CLIENT_APP/Contents/Info.plist" \
  "$AGENT_HOST_APP/Contents/Info.plist" "$QUALIFICATION_CLIENT_APP/Contents/Info.plist" "$DAEMON_DIR/dev.agentpass.native-service.plist" "$ENTITLEMENT_DIR/manager.plist" "$ENTITLEMENT_DIR/client.plist" "$ENTITLEMENT_DIR/service.plist" "$ENTITLEMENT_DIR/agent-host.plist" "$ENTITLEMENT_DIR/qualification-client.plist" >/dev/null

node - "$RESOURCE_DIR/native-service.example.json" <<'NODE'
const fs = require("node:fs");

const [configPath] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const managementMachService = "dev.agentpass.native-service";
const agentMachService = "dev.agentpass.agent-session";
const expectedManagementRequirement = 'anchor apple generic and identifier "dev.agentpass.native-client" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "TEAMID" and entitlement["keychain-access-groups"] = "TEAMID.dev.agentpass.approval-keys"';
const expectedAgentRequirement = 'anchor apple generic and identifier "dev.agentpass.agent-host" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "TEAMID" and entitlement["dev.agentpass.agent-session-client"] = true';
const managementRequirement = config.client_code_signing_requirement;
const agentRequirement = config.agent_client_code_signing_requirement;

if (config.mach_service_name !== managementMachService) throw new Error("Management Mach service example changed");
if (config.agent_mach_service_name !== agentMachService) throw new Error("Agent Mach service example is missing or invalid");
if (managementRequirement !== expectedManagementRequirement) throw new Error("Management code-signing requirement example changed");
if (agentRequirement !== expectedAgentRequirement) throw new Error("Agent code-signing requirement example is missing or invalid");
NODE

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
sign_item "$AGENT_HOST_APP" "dev.agentpass.agent-host" "$ENTITLEMENT_DIR/agent-host.plist"
sign_item "$QUALIFICATION_CLIENT_BINARY" "dev.agentpass.qualification-grant-client" "$ENTITLEMENT_DIR/qualification-client.plist"
sign_item "$QUALIFICATION_CLIENT_APP" "dev.agentpass.qualification-grant-client" "$ENTITLEMENT_DIR/qualification-client.plist"
if [[ "$ADHOC" -eq 1 ]]; then
  /usr/bin/codesign --force --sign - --identifier "dev.agentpass.atomic-rename" "$HELPER_DIR/agentpass-atomic-rename"
  /usr/bin/codesign --force --sign - --identifier "dev.agentpass.git-sign" "$GIT_SIGNING_HELPER"
else
  /usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --identifier "dev.agentpass.atomic-rename" --options runtime --timestamp "$HELPER_DIR/agentpass-atomic-rename"
  /usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --identifier "dev.agentpass.git-sign" --options runtime --timestamp "$GIT_SIGNING_HELPER"
fi
sign_item "$MACOS_DIR/agentpass-native-manager" "dev.agentpass.native-manager" "$ENTITLEMENT_DIR/manager.plist"
sign_item "$MACOS_DIR/agentpass-onboarding" "dev.agentpass" "$ENTITLEMENT_DIR/manager.plist"
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
verify_agent_entitlement() {
  local item="$1" extracted actual
  extracted="$TEMP_DIR/$(basename "$item").agent-entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$item" >"$extracted" 2>/dev/null
  actual="$(/usr/libexec/PlistBuddy -c 'Print :dev.agentpass.agent-session-client' "$extracted")"
  [[ "$actual" == "true" ]] || { echo "Agent Host is missing its exact session-client entitlement" >&2; exit 1; }
  if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$extracted" >/dev/null 2>&1; then
    echo "Agent Host unexpectedly has a keychain access group" >&2
    exit 1
  fi
}

/usr/bin/codesign --verify --strict --verbose=2 "$SERVICE_APP"
/usr/bin/codesign --verify --strict --verbose=2 "$CLIENT_APP"
/usr/bin/codesign --verify --strict --verbose=2 "$AGENT_HOST_APP"
/usr/bin/codesign --verify --strict --verbose=2 "$QUALIFICATION_CLIENT_APP"
/usr/bin/codesign --verify --strict --verbose=2 "$HELPER_DIR/agentpass-atomic-rename"
/usr/bin/codesign --verify --strict --verbose=2 "$GIT_SIGNING_HELPER"
/usr/bin/codesign --verify --strict --verbose=2 "$APP"
verify_identifier "$SERVICE_APP" "dev.agentpass.native-service"
verify_identifier "$CLIENT_APP" "dev.agentpass.native-client"
verify_identifier "$AGENT_HOST_APP" "dev.agentpass.agent-host"
verify_identifier "$HELPER_DIR/agentpass-atomic-rename" "dev.agentpass.atomic-rename"
verify_identifier "$GIT_SIGNING_HELPER" "dev.agentpass.git-sign"
verify_identifier "$MACOS_DIR/agentpass-native-manager" "dev.agentpass.native-manager"
verify_identifier "$MACOS_DIR/agentpass-onboarding" "dev.agentpass"
verify_identifier "$APP" "dev.agentpass"
verify_group "$SERVICE_APP" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys"
verify_group "$CLIENT_APP" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys"
verify_agent_entitlement "$AGENT_HOST_APP"
verify_qualification_client_entitlements() {
  local item="$1" extracted
  extracted="$TEMP_DIR/qualification-client-signed-entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$item" >"$extracted" 2>/dev/null
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :application-identifier' "$extracted")" == "${APP_IDENTIFIER_PREFIX}.dev.agentpass.qualification-grant-client" ]] || { echo "Qualification client application identifier mismatch" >&2; exit 1; }
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$extracted")" == "$TEAM_ID" ]] || { echo "Qualification client Team ID entitlement mismatch" >&2; exit 1; }
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$extracted")" == "${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" ]] || { echo "Qualification client keychain group mismatch" >&2; exit 1; }
  if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:1' "$extracted" >/dev/null 2>&1; then
    echo "Qualification client has an unexpected additional keychain group" >&2
    exit 1
  fi
  for forbidden in get-task-allow com.apple.security.get-task-allow com.apple.security.cs.disable-library-validation com.apple.security.cs.allow-dyld-environment-variables; do
    if /usr/libexec/PlistBuddy -c "Print :$forbidden" "$extracted" >/dev/null 2>&1; then
      echo "Qualification client has forbidden entitlement: $forbidden" >&2
      exit 1
    fi
  done
}
verify_qualification_client_entitlements "$QUALIFICATION_CLIENT_APP"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist")" == "agentpass-onboarding" ]] || { echo "Unexpected outer app executable" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :LSUIElement' "$APP/Contents/Info.plist")" == "false" ]] || { echo "Outer app must be visible to users" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :Label' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "dev.agentpass.native-service" ]] || { echo "Unexpected daemon label" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :BundleProgram' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service" ]] || { echo "Unexpected daemon BundleProgram" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :MachServices:dev.agentpass.native-service' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "true" ]] || { echo "Missing daemon Mach service" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :MachServices:dev.agentpass.agent-session' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "true" ]] || { echo "Missing Agent session Mach service" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :MachServices:dev.agentpass.n3e-qualification' "$DAEMON_DIR/dev.agentpass.native-service.plist")" == "true" ]] || { echo "Missing reserved qualification Mach service" >&2; exit 1; }

if [[ "$ADHOC" -eq 0 ]]; then
  for item in "$SERVICE_APP" "$CLIENT_APP" "$AGENT_HOST_APP" "$QUALIFICATION_CLIENT_APP" "$HELPER_DIR/agentpass-atomic-rename" "$GIT_SIGNING_HELPER" "$MACOS_DIR/agentpass-native-manager" "$MACOS_DIR/agentpass-onboarding" "$APP"; do
    actual_team="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
    [[ "$actual_team" == "$TEAM_ID" ]] || { echo "Unexpected TeamIdentifier on $item" >&2; exit 1; }
  done
fi

/usr/bin/ditto "$APP" "$TARGET_APP"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$TARGET_APP"
echo "$TARGET_APP"

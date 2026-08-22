#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
[[ $# -eq 2 ]] || { echo "Usage: verify-installer-package.sh PACKAGE.pkg EXPECTED_TEAM_ID" >&2; exit 2; }
PACKAGE="$1"
EXPECTED_TEAM_ID="$2"
[[ -f "$PACKAGE" && ! -L "$PACKAGE" ]] || { echo "Installer package must be a real regular file" >&2; exit 1; }
[[ "$(/usr/bin/stat -f '%l' "$PACKAGE")" == "1" ]] || { echo "Installer package must not be hard linked" >&2; exit 1; }
[[ "$EXPECTED_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "Invalid expected Team ID" >&2; exit 2; }
PACKAGE_SHA256="$(/usr/bin/shasum -a 256 "$PACKAGE" | /usr/bin/awk '{print $1}')"
[[ "$PACKAGE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "Unable to compute installer artifact SHA-256" >&2; exit 1; }
if [[ -n "${AGENTPASS_EXPECTED_ARTIFACT_SHA256:-}" ]]; then
  [[ "${AGENTPASS_EXPECTED_ARTIFACT_SHA256}" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid expected artifact SHA-256" >&2; exit 2; }
  [[ "$PACKAGE_SHA256" == "$AGENTPASS_EXPECTED_ARTIFACT_SHA256" ]] || { echo "Installer artifact SHA-256 mismatch" >&2; exit 1; }
fi

SIGNATURE_OUTPUT="$(/usr/sbin/pkgutil --check-signature "$PACKAGE")"
/usr/bin/grep -q 'Status: signed by a certificate trusted by Mac OS X' <<<"$SIGNATURE_OUTPUT" || { echo "Installer signature is not trusted" >&2; exit 1; }
if [[ -n "$EXPECTED_TEAM_ID" ]]; then
  /usr/bin/grep -Eq "Developer ID Installer: .+\(${EXPECTED_TEAM_ID}\)" <<<"$SIGNATURE_OUTPUT" || { echo "Installer Developer ID identity is missing or Team ID mismatched" >&2; exit 1; }
fi

PAYLOAD_FILES="$(/usr/sbin/pkgutil --payload-files "$PACKAGE")"
[[ -n "$PAYLOAD_FILES" ]] || { echo "Installer payload is empty" >&2; exit 1; }
while IFS= read -r path; do
  normalized="${path#./}"
  case "$normalized" in
    .) ;;
    AgentPass.app|AgentPass.app/*) ;;
    *) echo "Installer payload escapes AgentPass.app: $path" >&2; exit 1 ;;
  esac
done <<<"$PAYLOAD_FILES"
if /usr/bin/grep -Eiq '(^|/)(Library/Application Support/AgentPass|key-lifecycle|key-lifecycle-pin|key-lifecycle-outbox|audit|audit-archive|audit-key-rotation-plans)(/|$)' <<<"$PAYLOAD_FILES"; then
  echo "Installer payload contains protected AgentPass state" >&2
  exit 1
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-pkg-verify.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
/usr/sbin/pkgutil --expand-full "$PACKAGE" "$TEMP_DIR/expanded"
[[ "$(/usr/bin/find -P "$TEMP_DIR/expanded" -type f -name PackageInfo | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == "1" ]] || { echo "Installer must contain exactly one PackageInfo" >&2; exit 1; }
PACKAGE_INFO="$(/usr/bin/find -P "$TEMP_DIR/expanded" -type f -name PackageInfo -print -quit)"
[[ "$(/usr/bin/xmllint --xpath 'string(/pkg-info/@install-location)' "$PACKAGE_INFO")" == "/Applications" ]] || { echo "Installer destination is not /Applications" >&2; exit 1; }
[[ "$(/usr/bin/xmllint --xpath 'string(/pkg-info/@identifier)' "$PACKAGE_INFO")" == "dev.agentpass.installer" ]] || { echo "Installer package identifier mismatch" >&2; exit 1; }
[[ "$(/usr/bin/xmllint --xpath 'string(/pkg-info/@auth)' "$PACKAGE_INFO")" == "root" ]] || { echo "Installer does not require root authorization" >&2; exit 1; }
[[ "$(/usr/bin/xmllint --xpath 'string(/pkg-info/@relocatable)' "$PACKAGE_INFO")" == "false" ]] || { echo "Installer is unexpectedly relocatable" >&2; exit 1; }
for expression in \
  'count(/pkg-info/bundle[@path="./AgentPass.app" and @id="dev.agentpass"])' \
  'count(/pkg-info/strict-identifier/bundle[@id="dev.agentpass"])' \
  'count(/pkg-info/upgrade-bundle/bundle[@id="dev.agentpass"])' \
  'count(/pkg-info/scripts/preinstall[@file="./preinstall"])' \
  'count(/pkg-info/scripts/postinstall[@file="./postinstall"])'; do
  [[ "$(/usr/bin/xmllint --xpath "$expression" "$PACKAGE_INFO")" == "1" ]] || { echo "Installer package policy metadata mismatch: $expression" >&2; exit 1; }
done
APP="$(/usr/bin/find -P "$TEMP_DIR/expanded" -type d -name AgentPass.app -print -quit)"
[[ -n "$APP" && -d "$APP" ]] || { echo "Installer does not contain AgentPass.app" >&2; exit 1; }
if /usr/bin/find -P "$APP" -type l -print -quit | /usr/bin/grep -q .; then echo "Packaged app contains a symlink" >&2; exit 1; fi
LAUNCHD_PLIST="$APP/Contents/Library/LaunchDaemons/dev.agentpass.native-service.plist"
[[ -f "$LAUNCHD_PLIST" && ! -L "$LAUNCHD_PLIST" ]] || { echo "Installer is missing the native service launchd plist" >&2; exit 1; }
for mach_service in \
  dev.agentpass.native-service \
  dev.agentpass.agent-session \
  dev.agentpass.agent-host \
  dev.agentpass.agent-host-control \
  dev.agentpass.child-git; do
  [[ "$(/usr/libexec/PlistBuddy -c "Print :MachServices:$mach_service" "$LAUNCHD_PLIST" 2>/dev/null)" == "true" ]] || { echo "Installer launchd plist is missing Mach service: $mach_service" >&2; exit 1; }
done

# A production package is the cross-hardware distribution boundary. Checking
# only the outer signature leaves a single-architecture helper able to pass
# package verification and fail later on the other supported Mac family.
require_universal_binary() {
  local binary="$1" architectures
  [[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] || { echo "Installer is missing executable cross-hardware payload: $binary" >&2; exit 1; }
  architectures="$(/usr/bin/lipo -archs "$binary" 2>/dev/null)" || { echo "Unable to inspect executable architectures: $binary" >&2; exit 1; }
  case "$architectures" in
    "arm64 x86_64"|"x86_64 arm64") ;;
    *) echo "Executable must contain exactly arm64 and x86_64 slices: $binary ($architectures)" >&2; exit 1 ;;
  esac
}

CROSS_HARDWARE_BINARIES=(
  "$APP/Contents/MacOS/agentpass-onboarding"
  "$APP/Contents/MacOS/agentpass-native-manager"
  "$APP/Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service"
  "$APP/Contents/Library/HelperTools/AgentPassNativeClient.app/Contents/MacOS/agentpass-native-client"
  "$APP/Contents/Library/HelperTools/AgentPassNativeAgentHost.app/Contents/MacOS/agentpass-native-agent-host"
  "$APP/Contents/Library/HelperTools/agentpass-atomic-rename"
  "$APP/Contents/Resources/bin/agentpass-git-sign"
  "$APP/Contents/Resources/bin/agentpass-git-session-sign"
  "$APP/Contents/Resources/bin/agentpass-git-sign-xpc"
  "$APP/Contents/Library/HelperTools/agentpass-qualification-grant-client.app/Contents/MacOS/agentpass-qualification-grant-client"
)
for binary in "${CROSS_HARDWARE_BINARIES[@]}"; do
  require_universal_binary "$binary"
done

RESOURCE_BIN="$APP/Contents/Resources/bin"
[[ "$(/usr/bin/find -P "$RESOURCE_BIN" -mindepth 1 -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d '[:space:]')" == "3" ]] || { echo "Packaged Git helper resource directory must contain exactly three files" >&2; exit 1; }
RESOURCE_NAMES="$(/usr/bin/find -P "$RESOURCE_BIN" -mindepth 1 -maxdepth 1 -type f -exec /usr/bin/basename {} \; | /usr/bin/sort | /usr/bin/tr '\n' ' ')"
[[ "$RESOURCE_NAMES" == "agentpass-git-session-sign agentpass-git-sign agentpass-git-sign-xpc " ]] || { echo "Packaged Git helper inventory is not exact: $RESOURCE_NAMES" >&2; exit 1; }
for helper in agentpass-git-sign agentpass-git-session-sign agentpass-git-sign-xpc; do
  [[ "$(/usr/bin/find -P "$APP" -name "$helper" -print | /usr/bin/wc -l | /usr/bin/tr -d '[:space:]')" == "1" ]] || { echo "Packaged Git helper must appear exactly once: $helper" >&2; exit 1; }
done

declare -a EXPECTED_GIT_IDENTITIES=(
  "$APP/Contents/Resources/bin/agentpass-git-sign|dev.agentpass.git-sign"
  "$APP/Contents/Resources/bin/agentpass-git-session-sign|dev.agentpass.git-session-sign"
  "$APP/Contents/Resources/bin/agentpass-git-sign-xpc|dev.agentpass.git-sign-xpc"
)
for binding in "${EXPECTED_GIT_IDENTITIES[@]}"; do
  IFS='|' read -r helper expected_identifier <<< "$binding"
  helper_details="$(/usr/bin/codesign -dv --verbose=4 "$helper" 2>&1)"
  actual_identifier="$(/usr/bin/awk -F= '/^Identifier=/{print $2; exit}' <<< "$helper_details")"
  [[ "$actual_identifier" == "$expected_identifier" ]] || { echo "Packaged Git helper identity mismatch: $helper ($actual_identifier)" >&2; exit 1; }
done

AGENT_HOST_APP="$APP/Contents/Library/HelperTools/AgentPassNativeAgentHost.app"
AGENT_HOST_DETAILS="$(/usr/bin/codesign -dv --verbose=4 "$AGENT_HOST_APP" 2>&1)"
AGENT_HOST_IDENTIFIER="$(/usr/bin/awk -F= '/^Identifier=/{print $2; exit}' <<<"$AGENT_HOST_DETAILS")"
[[ "$AGENT_HOST_IDENTIFIER" == "dev.agentpass.agent-host" ]] || { echo "Agent Host signing identifier mismatch: $AGENT_HOST_IDENTIFIER" >&2; exit 1; }
AGENT_HOST_ENTITLEMENTS="$TEMP_DIR/agent-host-entitlements.plist"
/usr/bin/codesign -d --entitlements :- "$AGENT_HOST_APP" >"$AGENT_HOST_ENTITLEMENTS" 2>/dev/null
[[ "$(/usr/libexec/PlistBuddy -c 'Print :dev.agentpass.agent-session-client' "$AGENT_HOST_ENTITLEMENTS" 2>/dev/null)" == "true" ]] || {
  echo "Agent Host is missing its exact session-client entitlement" >&2
  exit 1
}
if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$AGENT_HOST_ENTITLEMENTS" >/dev/null 2>&1; then
  echo "Agent Host unexpectedly has a keychain access group" >&2
  exit 1
fi

SIGNED_CLI="$APP/Contents/MacOS/agentpass-onboarding"
[[ -f "$SIGNED_CLI" && ! -L "$SIGNED_CLI" && -x "$SIGNED_CLI" ]] || { echo "Installer is missing the signed dev.agentpass CLI helper" >&2; exit 1; }
/usr/bin/codesign --verify --strict --verbose=2 "$SIGNED_CLI"
CLI_DETAILS="$(/usr/bin/codesign -dv --verbose=4 "$SIGNED_CLI" 2>&1)"
CLI_IDENTIFIER="$(/usr/bin/awk -F= '/^Identifier=/{print $2; exit}' <<<"$CLI_DETAILS")"
[[ "$CLI_IDENTIFIER" == "dev.agentpass" ]] || { echo "CLI helper signing identifier mismatch: $CLI_IDENTIFIER" >&2; exit 1; }
grep -q '^Authority=Developer ID Application: ' <<<"$CLI_DETAILS" || { echo "CLI helper is not Developer ID Application signed" >&2; exit 1; }
CLI_TEAM_ID="$(/usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}' <<<"$CLI_DETAILS")"
[[ "$CLI_TEAM_ID" == "$EXPECTED_TEAM_ID" ]] || { echo "CLI helper Team ID mismatch: $CLI_TEAM_ID" >&2; exit 1; }
# PKG files are opaque to the generic release scanner.  At this point the
# component has been expanded, so scan the actual signed payload and package
# scripts before accepting the installer boundary.
if /usr/bin/find -P "$TEMP_DIR/expanded" -type f ! -name Payload -print0 \
  | /usr/bin/xargs -0 /usr/bin/grep -I -n -E -- \
    "-----BEGIN (RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----|AGENTPASS_[A-Z0-9_]*(SECRET|PASSWORD|TOKEN|PRIVATE|P12|KEY)|(^|[^A-Za-z])(aws_secret_access_key|client_secret|api[_-]?key|access[_-]?token)[[:space:]]*[:=]|(^|[^A-Za-z])(password|secret|token|private[_-]?key)[[:space:]]*[:=][[:space:]]*[\"']?[A-Za-z0-9+/=_-]{16,}" \
  >/dev/null; then
  echo "Installer payload or package scripts contain secret material" >&2
  exit 1
fi
for binding in 'preinstall:installer-preinstall.sh' 'postinstall:installer-postinstall.sh' 'validate-preserved-state.sh:validate-preserved-state.sh'; do
  packaged_name="${binding%%:*}"
  source_name="${binding#*:}"
  [[ "$(/usr/bin/find -P "$TEMP_DIR/expanded" -type f -name "$packaged_name" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == "1" ]] || { echo "Installer is missing unique $packaged_name" >&2; exit 1; }
  packaged_script="$(/usr/bin/find -P "$TEMP_DIR/expanded" -type f -name "$packaged_name" -print -quit)"
  /usr/bin/cmp -s "$SCRIPT_DIR/$source_name" "$packaged_script" || { echo "Packaged preservation script differs from reviewed source: $packaged_name" >&2; exit 1; }
done
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"
APP_DETAILS="$(/usr/bin/codesign -dv --verbose=4 "$APP" 2>&1)"
grep -q '^Authority=Developer ID Application: ' <<<"$APP_DETAILS" || { echo "Application is not Developer ID Application signed" >&2; exit 1; }
APP_TEAM_ID="$(/usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}' <<<"$APP_DETAILS")"
[[ "$APP_TEAM_ID" == "$EXPECTED_TEAM_ID" ]] || { echo "Application Team ID mismatch: $APP_TEAM_ID" >&2; exit 1; }
for item in "${CROSS_HARDWARE_BINARIES[@]}" "$APP/Contents/Library/HelperTools/AgentPassNativeService.app" "$APP/Contents/Library/HelperTools/AgentPassNativeClient.app" "$APP/Contents/Library/HelperTools/AgentPassNativeAgentHost.app" "$APP"; do
  details="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1)"
  grep -Eq "^Authority=Developer ID Application: .+\(${EXPECTED_TEAM_ID}\)$" <<<"$details" || { echo "Packaged item has no complete Developer ID Application identity: $item" >&2; exit 1; }
  grep -Eq "^TeamIdentifier=${EXPECTED_TEAM_ID}$" <<<"$details" || { echo "Packaged item Team ID mismatch: $item" >&2; exit 1; }
  grep -Eq '^flags=.*runtime' <<<"$details" || { echo "Packaged item is missing hardened runtime: $item" >&2; exit 1; }
  grep -q '^Timestamp=' <<<"$details" || { echo "Packaged item is missing a secure signing timestamp: $item" >&2; exit 1; }
done
declare -a EXPECTED_IDENTITIES=(
  "${APP}/Contents/MacOS/agentpass-onboarding|dev.agentpass"
  "${APP}/Contents/MacOS/agentpass-native-manager|dev.agentpass.native-manager"
  "${APP}/Contents/Library/HelperTools/AgentPassNativeService.app|dev.agentpass.native-service"
  "${APP}/Contents/Library/HelperTools/AgentPassNativeClient.app|dev.agentpass.native-client"
  "${APP}/Contents/Library/HelperTools/AgentPassNativeAgentHost.app|dev.agentpass.agent-host"
  "${APP}/Contents/Library/HelperTools/agentpass-qualification-grant-client.app|dev.agentpass.qualification-grant-client"
)
for binding in "${EXPECTED_IDENTITIES[@]}"; do
  IFS='|' read -r item expected_identifier <<< "$binding"
  details="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1)"
  actual_identifier="$(/usr/bin/awk -F= '/^Identifier=/{print $2; exit}' <<< "$details")"
  [[ "$actual_identifier" == "$expected_identifier" ]] || { echo "Packaged application identity mismatch: $item ($actual_identifier)" >&2; exit 1; }
done
echo "artifact_sha256=$PACKAGE_SHA256" >&2
echo "Installer package payload and preservation policy verified"

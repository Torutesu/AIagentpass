#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESOURCE_DIR="$PACKAGE_DIR/Resources"
OUTPUT_DIR="$PACKAGE_DIR/dist"
SIGNING_IDENTITY="${AGENTPASS_MIGRATION_SIGNING_IDENTITY:-}"
TEAM_ID="${AGENTPASS_TEAM_ID:-}"
APP_IDENTIFIER_PREFIX="${AGENTPASS_APP_IDENTIFIER_PREFIX:-}"
SERVICE_PROFILE="${AGENTPASS_MIGRATION_SERVICE_PROFILE:-}"
APPROVAL_PROFILE="${AGENTPASS_MIGRATION_APPROVAL_PROFILE:-}"
ADHOC=0
ARCHITECTURES=("$(uname -m)")

usage() {
  echo "Usage: build-legacy-migration.sh [--output-dir DIR] [--identity IDENTITY --team-id TEAMID --app-identifier-prefix PREFIX --service-profile FILE --approval-profile FILE] [--universal] [--adhoc]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) [[ $# -ge 2 ]] || usage; OUTPUT_DIR="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; SIGNING_IDENTITY="$2"; shift 2 ;;
    --team-id) [[ $# -ge 2 ]] || usage; TEAM_ID="$2"; shift 2 ;;
    --app-identifier-prefix) [[ $# -ge 2 ]] || usage; APP_IDENTIFIER_PREFIX="$2"; shift 2 ;;
    --service-profile) [[ $# -ge 2 ]] || usage; SERVICE_PROFILE="$2"; shift 2 ;;
    --approval-profile) [[ $# -ge 2 ]] || usage; APPROVAL_PROFILE="$2"; shift 2 ;;
    --universal) ARCHITECTURES=(arm64 x86_64); shift ;;
    --adhoc) ADHOC=1; shift ;;
    *) usage ;;
  esac
done

SERVICE_ID="dev.agentpass.legacy-service-migration"
APPROVAL_ID="dev.agentpass.legacy-approval-migration"
if [[ "$ADHOC" -eq 1 ]]; then
  [[ -z "$SERVICE_PROFILE" && -z "$APPROVAL_PROFILE" ]] || { echo "Ad-hoc structure builds must not embed profiles" >&2; exit 1; }
  TEAM_ID="ADHOC00000"; APP_IDENTIFIER_PREFIX="ADHOC00000"; SIGNING_IDENTITY="-"
else
  [[ -n "$SIGNING_IDENTITY" ]] || { echo "Production migration build requires --identity" >&2; exit 1; }
  [[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ && "$APP_IDENTIFIER_PREFIX" =~ ^[A-Z0-9]{10}$ ]] || { echo "Production migration build requires exact 10-character team and prefix" >&2; exit 1; }
  [[ "$TEAM_ID" == "$APP_IDENTIFIER_PREFIX" ]] || { echo "Migration Core requires the application identifier prefix to equal Team ID" >&2; exit 1; }
  [[ -f "$SERVICE_PROFILE" && ! -L "$SERVICE_PROFILE" && -f "$APPROVAL_PROFILE" && ! -L "$APPROVAL_PROFILE" ]] || { echo "Two regular non-symlink migration profiles are required" >&2; exit 1; }
  [[ ! "$SERVICE_PROFILE" -ef "$APPROVAL_PROFILE" ]] || { echo "Service and approval migration profiles must be distinct files" >&2; exit 1; }
fi

[[ ! -L "$OUTPUT_DIR" ]] || { echo "Output directory must not be a symlink" >&2; exit 1; }
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
[[ "$OUTPUT_DIR" != "/" ]] || { echo "Refusing filesystem root output" >&2; exit 1; }
[[ ! -L "$OUTPUT_DIR" && -d "$OUTPUT_DIR" && -O "$OUTPUT_DIR" && ! -k "$OUTPUT_DIR" ]] || { echo "Output must be a caller-owned non-symlink directory" >&2; exit 1; }
TARGET="$OUTPUT_DIR/AgentPass-v0.17-Migration"
[[ ! -e "$TARGET" && ! -L "$TARGET" ]] || { echo "$TARGET already exists; migration artifacts are never overwritten" >&2; exit 1; }

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-legacy-migration.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
STAGED="$TEMP_DIR/AgentPass-v0.17-Migration"
SERVICE_APP="$STAGED/AgentPassLegacyServiceMigration.app"
APPROVAL_APP="$STAGED/AgentPassLegacyApprovalMigration.app"
ENTITLEMENTS="$TEMP_DIR/entitlements"
mkdir -p "$SERVICE_APP/Contents/MacOS" "$APPROVAL_APP/Contents/MacOS" "$ENTITLEMENTS"
STAGED_SERVICE_PROFILE="$TEMP_DIR/service.provisionprofile"
STAGED_APPROVAL_PROFILE="$TEMP_DIR/approval.provisionprofile"
if [[ "$ADHOC" -eq 0 ]]; then
  install -m 0400 "$SERVICE_PROFILE" "$STAGED_SERVICE_PROFILE"
  install -m 0400 "$APPROVAL_PROFILE" "$STAGED_APPROVAL_PROFILE"
fi

verify_profile() {
  local profile="$1" bundle_id="$2" group_one="$3" group_two="$4" role="$5" plist
  plist="$TEMP_DIR/$role-profile.plist"
  /usr/bin/security cms -D -i "$profile" >"$plist"
  /usr/bin/plutil -lint "$plist" >/dev/null
  read_profile() { /usr/libexec/PlistBuddy -c "Print $1" "$plist" 2>/dev/null; }
  [[ "$(read_profile :TeamIdentifier:0)" == "$TEAM_ID" ]] || { echo "$role profile TeamIdentifier mismatch" >&2; exit 1; }
  [[ "$(read_profile :ApplicationIdentifierPrefix:0)" == "$APP_IDENTIFIER_PREFIX" ]] || { echo "$role profile prefix mismatch" >&2; exit 1; }
  [[ "$(read_profile :Entitlements:application-identifier)" == "${APP_IDENTIFIER_PREFIX}.${bundle_id}" ]] || { echo "$role profile bundle mismatch" >&2; exit 1; }
  [[ "$(read_profile :Entitlements:com.apple.developer.team-identifier)" == "$TEAM_ID" ]] || { echo "$role profile entitlement team mismatch" >&2; exit 1; }
  [[ "$(read_profile :Entitlements:keychain-access-groups:0)" == "$group_one" && "$(read_profile :Entitlements:keychain-access-groups:1)" == "$group_two" ]] || { echo "$role profile exact groups mismatch" >&2; exit 1; }
  if read_profile :Entitlements:keychain-access-groups:2 >/dev/null; then echo "$role profile has an extra keychain group" >&2; exit 1; fi
  [[ "$(read_profile :Entitlements:get-task-allow || true)" != "true" ]] || { echo "$role profile enables debugging" >&2; exit 1; }
  [[ "$(read_profile :Entitlements:com.apple.security.cs.disable-library-validation || true)" != "true" ]] || { echo "$role profile disables library validation" >&2; exit 1; }
  [[ "$(read_profile :ProvisionsAllDevices)" == "true" ]] || { echo "$role profile is not Developer ID distribution" >&2; exit 1; }
  /usr/bin/ruby -rtime -e 'abort "expired" unless Time.parse(ARGV[0]) > Time.now' "$(read_profile :ExpirationDate)"
}

if [[ "$ADHOC" -eq 0 ]]; then
  verify_profile "$STAGED_SERVICE_PROFILE" "$SERVICE_ID" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" service
  verify_profile "$STAGED_APPROVAL_PROFILE" "$APPROVAL_ID" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys" approval
fi

for architecture in "${ARCHITECTURES[@]}"; do
  MACOSX_DEPLOYMENT_TARGET=14.0 swift build -c release --package-path "$PACKAGE_DIR" --scratch-path "$TEMP_DIR/swift-$architecture" --arch "$architecture" --product agentpass-legacy-service-migration >&2
  MACOSX_DEPLOYMENT_TARGET=14.0 swift build -c release --package-path "$PACKAGE_DIR" --scratch-path "$TEMP_DIR/swift-$architecture" --arch "$architecture" --product agentpass-legacy-approval-migration >&2
done

install_product() {
  local product="$1" destination="$2" slices=() architecture bin_dir
  for architecture in "${ARCHITECTURES[@]}"; do
    bin_dir="$(swift build -c release --package-path "$PACKAGE_DIR" --scratch-path "$TEMP_DIR/swift-$architecture" --arch "$architecture" --show-bin-path)"
    slices+=("$bin_dir/$product")
  done
  if [[ "${#slices[@]}" -eq 1 ]]; then install -m 0755 "${slices[0]}" "$destination"; else xcrun lipo -create "${slices[@]}" -output "$destination"; chmod 0755 "$destination"; fi
}

install_product agentpass-legacy-service-migration "$SERVICE_APP/Contents/MacOS/agentpass-legacy-service-migration"
install_product agentpass-legacy-approval-migration "$APPROVAL_APP/Contents/MacOS/agentpass-legacy-approval-migration"
install -m 0644 "$RESOURCE_DIR/AgentPassLegacyServiceMigration-Info.plist" "$SERVICE_APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassLegacyApprovalMigration-Info.plist" "$APPROVAL_APP/Contents/Info.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassLegacyServiceMigration.entitlements" "$ENTITLEMENTS/service.plist"
install -m 0644 "$RESOURCE_DIR/AgentPassLegacyApprovalMigration.entitlements" "$ENTITLEMENTS/approval.plist"
for file in "$ENTITLEMENTS/service.plist" "$ENTITLEMENTS/approval.plist"; do
  /usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys" "$file"
done
/usr/libexec/PlistBuddy -c "Set :keychain-access-groups:1 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" "$ENTITLEMENTS/service.plist"
/usr/libexec/PlistBuddy -c "Set :keychain-access-groups:1 ${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys" "$ENTITLEMENTS/approval.plist"
if [[ "$ADHOC" -eq 0 ]]; then
  install -m 0644 "$STAGED_SERVICE_PROFILE" "$SERVICE_APP/Contents/embedded.provisionprofile"
  install -m 0644 "$STAGED_APPROVAL_PROFILE" "$APPROVAL_APP/Contents/embedded.provisionprofile"
fi
/usr/bin/plutil -lint "$SERVICE_APP/Contents/Info.plist" "$APPROVAL_APP/Contents/Info.plist" "$ENTITLEMENTS/service.plist" "$ENTITLEMENTS/approval.plist" >/dev/null

sign_helper() {
  local app="$1" identifier="$2" entitlements="$3"
  if [[ "$ADHOC" -eq 1 ]]; then
    /usr/bin/codesign --force --sign - --identifier "$identifier" --entitlements "$entitlements" "$app"
  else
    /usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --identifier "$identifier" --entitlements "$entitlements" --options runtime --timestamp "$app"
  fi
}
sign_helper "$SERVICE_APP" "$SERVICE_ID" "$ENTITLEMENTS/service.plist"
sign_helper "$APPROVAL_APP" "$APPROVAL_ID" "$ENTITLEMENTS/approval.plist"

verify_helper() {
  local app="$1" identifier="$2" first_group="$3" second_group="$4" role="$5" extracted actual_identifier actual_team
  /usr/bin/codesign --verify --strict --verbose=2 "$app"
  actual_identifier="$(/usr/bin/codesign -dv --verbose=4 "$app" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')"
  [[ "$actual_identifier" == "$identifier" ]] || { echo "$role signed identifier mismatch" >&2; exit 1; }
  extracted="$TEMP_DIR/$role-signed-entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$app" >"$extracted" 2>/dev/null
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$extracted")" == "$first_group" ]] || exit 1
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:1' "$extracted")" == "$second_group" ]] || exit 1
  if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:2' "$extracted" >/dev/null 2>&1; then echo "$role has extra signed keychain groups" >&2; exit 1; fi
  /usr/bin/plutil -convert json -o - "$extracted" | /usr/bin/env node -e '
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(0, "utf8"));
    const keys = Object.keys(value);
    if (keys.length !== 1 || keys[0] !== "keychain-access-groups" ||
        JSON.stringify(value[keys[0]]) !== JSON.stringify(process.argv.slice(1))) process.exit(1);
  ' "$first_group" "$second_group" || { echo "$role has unexpected signed entitlements" >&2; exit 1; }
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.get-task-allow' "$extracted" 2>/dev/null || true)" != "true" ]] || exit 1
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.cs.disable-library-validation' "$extracted" 2>/dev/null || true)" != "true" ]] || exit 1
  if [[ "$ADHOC" -eq 0 ]]; then
    actual_team="$(/usr/bin/codesign -dv --verbose=4 "$app" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
    [[ "$actual_team" == "$TEAM_ID" ]] || { echo "$role signed TeamIdentifier mismatch" >&2; exit 1; }
    /usr/bin/codesign -dv --verbose=4 "$app" 2>&1 | /usr/bin/grep -q '^Authority=Developer ID Application:' || { echo "$role is not signed by a Developer ID Application certificate" >&2; exit 1; }
    /usr/bin/codesign -dv --verbose=4 "$app" 2>&1 | /usr/bin/grep -q '^Runtime Version=' || { echo "$role lacks hardened runtime" >&2; exit 1; }
    /usr/bin/codesign -dv --verbose=4 "$app" 2>&1 | /usr/bin/grep -q '^Timestamp=' || { echo "$role lacks a secure timestamp" >&2; exit 1; }
    /usr/bin/codesign --verify --strict --test-requirement "=identifier \"${identifier}\" and anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${TEAM_ID}\"" "$app" || { echo "$role designated requirement mismatch" >&2; exit 1; }
  fi
}
verify_helper "$SERVICE_APP" "$SERVICE_ID" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.service-keys" service
verify_helper "$APPROVAL_APP" "$APPROVAL_ID" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.keys" "${APP_IDENTIFIER_PREFIX}.dev.agentpass.approval-keys" approval

if [[ "$ADHOC" -eq 1 ]]; then
  install -m 0444 /dev/null "$STAGED/ADHOC-STRUCTURE-TEST-ONLY"
else
  printf '%s\n' "This transitional artifact is shipped separately and must never be embedded in AgentPass.app." >"$STAGED/TRANSITIONAL-ARTIFACT"
  chmod 0444 "$STAGED/TRANSITIONAL-ARTIFACT"
fi
mkdir -m 0700 "$TARGET"
/usr/bin/ditto "$STAGED" "$TARGET"
echo "$TARGET"

#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESOURCE_DIR="$PACKAGE_DIR/Resources"
SOURCE_BINARY=""
OUTPUT=""
SIGNING_IDENTITY=""
TEAM_ID=""
IDENTIFIER_PREFIX=""
PROFILE=""
BUNDLE_ID="dev.agentpass.qualification-controller"

check_protected_ancestry() {
  local current="$1"
  local owner mode
  while [[ "$current" != "/" ]]; do
    [[ -d "$current" && ! -L "$current" ]] || { echo "Controller path ancestry is unsafe" >&2; exit 1; }
    owner="$(/usr/bin/stat -f '%u' "$current")"
    [[ "$owner" == "0" || "$owner" == "$(id -u)" ]] || { echo "Controller path ancestry owner is invalid" >&2; exit 1; }
    mode="$(/usr/bin/stat -f '%Lp' "$current")"
    (( (8#$mode & 8#022) == 0 )) || { echo "Controller path ancestry is writable by another user" >&2; exit 1; }
    current="$(dirname "$current")"
  done
}

usage() {
  echo "Usage: build-controller.sh --source-binary FILE --output AgentPassQualificationController.app --identity 'Developer ID Application: ...' --team-id TEAMID --app-identifier-prefix PREFIX --profile FILE" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-binary) [[ $# -ge 2 ]] || usage; SOURCE_BINARY="$2"; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; OUTPUT="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; SIGNING_IDENTITY="$2"; shift 2 ;;
    --team-id) [[ $# -ge 2 ]] || usage; TEAM_ID="$2"; shift 2 ;;
    --app-identifier-prefix) [[ $# -ge 2 ]] || usage; IDENTIFIER_PREFIX="$2"; shift 2 ;;
    --profile) [[ $# -ge 2 ]] || usage; PROFILE="$2"; shift 2 ;;
    --adhoc|--app|--pkg|--service|--entitlements) echo "Unsupported controller build option: $1" >&2; exit 2 ;;
    *) usage ;;
  esac
done

[[ -n "$SOURCE_BINARY" && -n "$OUTPUT" && -n "$SIGNING_IDENTITY" && -n "$TEAM_ID" && -n "$IDENTIFIER_PREFIX" && -n "$PROFILE" ]] || usage
[[ "$SOURCE_BINARY" == /* && "$OUTPUT" == /* && "$PROFILE" == /* ]] || { echo "Controller build paths must be absolute" >&2; exit 2; }
[[ "$(basename "$OUTPUT")" == "AgentPassQualificationController.app" ]] || { echo "Controller output basename is fixed" >&2; exit 2; }
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ && "$IDENTIFIER_PREFIX" =~ ^[A-Z0-9]{10}$ ]] || { echo "Controller signing identifiers are invalid" >&2; exit 2; }
[[ "$SIGNING_IDENTITY" == Developer\ ID\ Application:*"("$TEAM_ID")" ]] || { echo "Controller signing identity is not bound to the expected Team ID" >&2; exit 1; }
[[ -f "$SOURCE_BINARY" && -x "$SOURCE_BINARY" && ! -L "$SOURCE_BINARY" ]] || { echo "Controller source binary is unsafe" >&2; exit 1; }
[[ -f "$PROFILE" && ! -L "$PROFILE" ]] || { echo "Controller profile is unsafe" >&2; exit 1; }
[[ "$(/usr/bin/stat -f '%l' "$SOURCE_BINARY")" == "1" && "$(/usr/bin/stat -f '%l' "$PROFILE")" == "1" ]] || { echo "Controller inputs must be single-link files" >&2; exit 1; }
[[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || { echo "Controller output already exists" >&2; exit 1; }
check_protected_ancestry "$(dirname "$SOURCE_BINARY")"
check_protected_ancestry "$(dirname "$PROFILE")"

OUTPUT_PARENT="$(dirname "$OUTPUT")"
[[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" ]] || { echo "Controller output parent is unsafe" >&2; exit 1; }
[[ "$(/usr/bin/stat -f '%u' "$OUTPUT_PARENT")" == "$(id -u)" ]] || { echo "Controller output parent owner is invalid" >&2; exit 1; }
PARENT_MODE="$(/usr/bin/stat -f '%Lp' "$OUTPUT_PARENT")"
(( (8#$PARENT_MODE & 8#022) == 0 )) || { echo "Controller output parent is writable by another user" >&2; exit 1; }
check_protected_ancestry "$OUTPUT_PARENT"

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-controller.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
PROFILE_PLIST="$TEMP_DIR/profile.plist"
/usr/bin/security cms -D -i "$PROFILE" >"$PROFILE_PLIST" || { echo "Controller profile CMS signature is invalid" >&2; exit 1; }
/usr/bin/plutil -lint "$PROFILE_PLIST" >/dev/null
read_profile() { /usr/libexec/PlistBuddy -c "Print $1" "$PROFILE_PLIST" 2>/dev/null; }

[[ "$(read_profile :TeamIdentifier:0)" == "$TEAM_ID" ]] || { echo "Controller profile TeamIdentifier mismatch" >&2; exit 1; }
[[ "$(read_profile :ApplicationIdentifierPrefix:0)" == "$IDENTIFIER_PREFIX" ]] || { echo "Controller profile prefix mismatch" >&2; exit 1; }
[[ "$(read_profile :Entitlements:application-identifier)" == "${IDENTIFIER_PREFIX}.${BUNDLE_ID}" ]] || { echo "Controller profile application-identifier mismatch" >&2; exit 1; }
[[ "$(read_profile :Entitlements:com.apple.developer.team-identifier)" == "$TEAM_ID" ]] || { echo "Controller profile entitlement Team ID mismatch" >&2; exit 1; }
[[ "$(read_profile :Entitlements:dev.agentpass.qualification-control)" == "true" ]] || { echo "Controller profile is missing qualification-control" >&2; exit 1; }
if read_profile :Entitlements:keychain-access-groups:0 >/dev/null; then echo "Controller profile must not authorize keychain access" >&2; exit 1; fi
[[ "$(read_profile :Entitlements:get-task-allow || true)" != "true" ]] || { echo "Controller profile enables get-task-allow" >&2; exit 1; }
[[ "$(read_profile :ProvisionsAllDevices)" == "true" ]] || { echo "Controller profile is not a Developer ID distribution profile" >&2; exit 1; }
/usr/bin/ruby -rtime -e 'abort "expired" unless Time.parse(ARGV[0]) > Time.now' "$(read_profile :ExpirationDate)" || { echo "Controller profile is expired" >&2; exit 1; }
[[ -n "$(read_profile :UUID)" ]] || { echo "Controller profile has no UUID" >&2; exit 1; }

PROFILE_ENTITLEMENTS="$TEMP_DIR/profile-entitlements.json"
/usr/bin/plutil -extract Entitlements json -o "$PROFILE_ENTITLEMENTS" "$PROFILE_PLIST"
node - "$PROFILE_ENTITLEMENTS" <<'NODE'
const fs = require('node:fs');
const value = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const allowed = [
  'application-identifier',
  'com.apple.developer.team-identifier',
  'dev.agentpass.qualification-control'
];
if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(allowed)) {
  throw new Error('Controller profile entitlement set is not exact');
}
NODE

STAGING="$OUTPUT_PARENT/.AgentPassQualificationController.$$.staging"
[[ ! -e "$STAGING" && ! -L "$STAGING" ]] || { echo "Controller staging path exists" >&2; exit 1; }
APP="$STAGING/AgentPassQualificationController.app"
/bin/mkdir -m 0700 "$STAGING"
/bin/mkdir -m 0755 -p "$APP/Contents/MacOS"
/usr/bin/install -m 0555 "$SOURCE_BINARY" "$APP/Contents/MacOS/agentpass-qualification-controller"
/usr/bin/install -m 0644 "$RESOURCE_DIR/AgentPassQualificationController-Info.plist" "$APP/Contents/Info.plist"
/usr/bin/install -m 0600 "$PROFILE" "$APP/Contents/embedded.provisionprofile"
/usr/bin/install -m 0600 "$RESOURCE_DIR/AgentPassQualificationController.entitlements" "$TEMP_DIR/controller.entitlements"
/usr/libexec/PlistBuddy -c "Set :application-identifier ${IDENTIFIER_PREFIX}.${BUNDLE_ID}" "$TEMP_DIR/controller.entitlements"
/usr/libexec/PlistBuddy -c "Set :com.apple.developer.team-identifier ${TEAM_ID}" "$TEMP_DIR/controller.entitlements"
/usr/bin/plutil -lint "$APP/Contents/Info.plist" "$TEMP_DIR/controller.entitlements" >/dev/null

SOURCE_BEFORE="$(/usr/bin/shasum -a 256 "$SOURCE_BINARY" | /usr/bin/awk '{print $1}')"
/usr/bin/cmp -s "$SOURCE_BINARY" "$APP/Contents/MacOS/agentpass-qualification-controller" || { echo "Controller source changed while staging" >&2; exit 1; }
SOURCE_AFTER="$(/usr/bin/shasum -a 256 "$SOURCE_BINARY" | /usr/bin/awk '{print $1}')"
[[ "$SOURCE_BEFORE" == "$SOURCE_AFTER" ]] || { echo "Controller source changed while staging" >&2; exit 1; }

/usr/bin/codesign --force --strict --options runtime --timestamp \
  --identifier "$BUNDLE_ID" --entitlements "$TEMP_DIR/controller.entitlements" \
  --sign "$SIGNING_IDENTITY" "$APP"
/usr/bin/codesign --verify --strict --verbose=2 "$APP"
REQUIREMENT="anchor apple generic and identifier \"${BUNDLE_ID}\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${TEAM_ID}\" and entitlement[\"dev.agentpass.qualification-control\"] exists"
/usr/bin/codesign --verify --strict --verbose=2 -R="$REQUIREMENT" "$APP"

ACTUAL_ID="$(/usr/bin/codesign -dv --verbose=4 "$APP" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')"
ACTUAL_TEAM="$(/usr/bin/codesign -dv --verbose=4 "$APP" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
[[ "$ACTUAL_ID" == "$BUNDLE_ID" && "$ACTUAL_TEAM" == "$TEAM_ID" ]] || { echo "Controller signed identity mismatch" >&2; exit 1; }
ACTUAL_ENTITLEMENTS="$TEMP_DIR/actual-entitlements.plist"
/usr/bin/codesign -d --entitlements :- "$APP" >"$ACTUAL_ENTITLEMENTS" 2>/dev/null
[[ "$(/usr/libexec/PlistBuddy -c 'Print :application-identifier' "$ACTUAL_ENTITLEMENTS")" == "${IDENTIFIER_PREFIX}.${BUNDLE_ID}" ]] || { echo "Controller signed application-identifier mismatch" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$ACTUAL_ENTITLEMENTS")" == "$TEAM_ID" ]] || { echo "Controller signed Team entitlement mismatch" >&2; exit 1; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :dev.agentpass.qualification-control' "$ACTUAL_ENTITLEMENTS")" == "true" ]] || { echo "Controller signed qualification entitlement missing" >&2; exit 1; }
if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$ACTUAL_ENTITLEMENTS" >/dev/null 2>&1; then echo "Controller unexpectedly has keychain access" >&2; exit 1; fi
[[ "$(/usr/libexec/PlistBuddy -c 'Print :get-task-allow' "$ACTUAL_ENTITLEMENTS" 2>/dev/null || true)" != "true" ]] || { echo "Controller signed with get-task-allow" >&2; exit 1; }
ACTUAL_ENTITLEMENTS_JSON="$TEMP_DIR/actual-entitlements.json"
/usr/bin/plutil -convert json -o "$ACTUAL_ENTITLEMENTS_JSON" "$ACTUAL_ENTITLEMENTS"
node - "$ACTUAL_ENTITLEMENTS_JSON" <<'NODE'
const fs = require('node:fs');
const value = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const allowed = [
  'application-identifier',
  'com.apple.developer.team-identifier',
  'dev.agentpass.qualification-control'
];
if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(allowed)) {
  throw new Error('Controller signed entitlement set is not exact');
}
NODE

/bin/mv "$APP" "$OUTPUT"
/usr/bin/codesign --verify --strict --verbose=2 "$OUTPUT"
/bin/rmdir "$STAGING"
trap - EXIT
/bin/rm -rf -- "$TEMP_DIR"
printf '%s\n' '{"artifact":"AgentPassQualificationController.app","ok":true}'

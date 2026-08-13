#!/bin/bash
set -euo pipefail

fail() { printf '%s\n' 'qualification controller probe signing refused' >&2; exit 1; }
is_absolute() { [[ "$1" == /* ]]; }
is_team_id() { [[ "$1" =~ ^[A-Z0-9]{10}$ ]]; }

: "${AGENTPASS_CONTROLLER_PROBE_SOURCE_BINARY:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_OUTPUT_ROOT:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_TEAM_ID:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_APP_IDENTIFIER_PREFIX:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_ID:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_WRONG_APP_IDENTIFIER_PREFIX:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_APPROVED_SIGNING_IDENTITY:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_MISSING_ENTITLEMENT_SIGNING_IDENTITY:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_SIGNING_IDENTITY:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_APPROVED_PROFILE:?required}"
: "${AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_PROFILE:?required}"

BUNDLE_ID="dev.agentpass.qualification-controller"
EXECUTABLE="agentpass-negative-xpc-probe"
for path in "$AGENTPASS_CONTROLLER_PROBE_SOURCE_BINARY" "$AGENTPASS_CONTROLLER_PROBE_OUTPUT_ROOT" "$AGENTPASS_CONTROLLER_PROBE_APPROVED_PROFILE" "$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_PROFILE"; do
  is_absolute "$path" || fail
done
is_team_id "$AGENTPASS_CONTROLLER_PROBE_TEAM_ID" || fail
is_team_id "$AGENTPASS_CONTROLLER_PROBE_APP_IDENTIFIER_PREFIX" || fail
is_team_id "$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_ID" || fail
is_team_id "$AGENTPASS_CONTROLLER_PROBE_WRONG_APP_IDENTIFIER_PREFIX" || fail
[[ "$AGENTPASS_CONTROLLER_PROBE_TEAM_ID" != "$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_ID" ]] || fail
[[ "$AGENTPASS_CONTROLLER_PROBE_APPROVED_SIGNING_IDENTITY" == Developer\ ID\ Application:*"("$AGENTPASS_CONTROLLER_PROBE_TEAM_ID")" ]] || fail
[[ "$AGENTPASS_CONTROLLER_PROBE_MISSING_ENTITLEMENT_SIGNING_IDENTITY" == Developer\ ID\ Application:*"("$AGENTPASS_CONTROLLER_PROBE_TEAM_ID")" ]] || fail
[[ "$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_SIGNING_IDENTITY" == Developer\ ID\ Application:*"("$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_ID")" ]] || fail
[[ -f "$AGENTPASS_CONTROLLER_PROBE_SOURCE_BINARY" && -x "$AGENTPASS_CONTROLLER_PROBE_SOURCE_BINARY" && ! -L "$AGENTPASS_CONTROLLER_PROBE_SOURCE_BINARY" ]] || fail
for profile in "$AGENTPASS_CONTROLLER_PROBE_APPROVED_PROFILE" "$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_PROFILE"; do
  [[ -f "$profile" && ! -L "$profile" && "$(/usr/bin/stat -f '%l' "$profile")" == "1" ]] || fail
done
[[ "$(/usr/bin/stat -f '%l' "$AGENTPASS_CONTROLLER_PROBE_SOURCE_BINARY")" == "1" ]] || fail
[[ ! -e "$AGENTPASS_CONTROLLER_PROBE_OUTPUT_ROOT" && ! -L "$AGENTPASS_CONTROLLER_PROBE_OUTPUT_ROOT" ]] || fail

output_parent="$(dirname "$AGENTPASS_CONTROLLER_PROBE_OUTPUT_ROOT")"
[[ -d "$output_parent" && ! -L "$output_parent" && "$(/usr/bin/stat -f '%u' "$output_parent")" == "$(id -u)" ]] || fail
output_mode="$(/usr/bin/stat -f '%Lp' "$output_parent")"
(( (8#$output_mode & 8#022) == 0 )) || fail

umask 077
stage="${AGENTPASS_CONTROLLER_PROBE_OUTPUT_ROOT}.staging.$$"
[[ ! -e "$stage" && ! -L "$stage" ]] || fail
trap '/bin/rm -rf -- "$stage"' EXIT HUP INT TERM
/bin/mkdir -m 0700 -p "$stage/probes"

make_bundle() {
  local role="$1"
  local app="$stage/probes/$role-controller.app"
  /bin/mkdir -m 0755 -p "$app/Contents/MacOS"
  /usr/bin/install -m 0555 "$AGENTPASS_CONTROLLER_PROBE_SOURCE_BINARY" "$app/Contents/MacOS/$EXECUTABLE"
  /usr/bin/plutil -create xml1 "$app/Contents/Info.plist"
  /usr/libexec/PlistBuddy \
    -c 'Add :CFBundlePackageType string APPL' \
    -c "Add :CFBundleExecutable string $EXECUTABLE" \
    -c "Add :CFBundleIdentifier string $BUNDLE_ID" \
    -c "Add :CFBundleName string AgentPass Qualification $role Probe" \
    -c 'Add :CFBundleShortVersionString string 1.0.0' \
    -c 'Add :CFBundleVersion string 1' \
    "$app/Contents/Info.plist"
}

make_entitlements() {
  local output="$1"
  local prefix="$2"
  local team="$3"
  /usr/bin/plutil -create xml1 "$output"
  /usr/libexec/PlistBuddy \
    -c "Add :application-identifier string ${prefix}.${BUNDLE_ID}" \
    -c "Add :com.apple.developer.team-identifier string $team" \
    -c 'Add :dev.agentpass.qualification-control bool true' \
    "$output"
}

for role in approved missing-entitlement wrong-team ad-hoc; do make_bundle "$role"; done
make_entitlements "$stage/approved.entitlements.plist" "$AGENTPASS_CONTROLLER_PROBE_APP_IDENTIFIER_PREFIX" "$AGENTPASS_CONTROLLER_PROBE_TEAM_ID"
make_entitlements "$stage/wrong-team.entitlements.plist" "$AGENTPASS_CONTROLLER_PROBE_WRONG_APP_IDENTIFIER_PREFIX" "$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_ID"
/usr/bin/install -m 0600 "$AGENTPASS_CONTROLLER_PROBE_APPROVED_PROFILE" "$stage/probes/approved-controller.app/Contents/embedded.provisionprofile"
/usr/bin/install -m 0600 "$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_PROFILE" "$stage/probes/wrong-team-controller.app/Contents/embedded.provisionprofile"

/usr/bin/codesign --force --strict --options runtime --timestamp --identifier "$BUNDLE_ID" --entitlements "$stage/approved.entitlements.plist" --sign "$AGENTPASS_CONTROLLER_PROBE_APPROVED_SIGNING_IDENTITY" "$stage/probes/approved-controller.app"
/usr/bin/codesign --force --strict --options runtime --timestamp --identifier "$BUNDLE_ID" --sign "$AGENTPASS_CONTROLLER_PROBE_MISSING_ENTITLEMENT_SIGNING_IDENTITY" "$stage/probes/missing-entitlement-controller.app"
/usr/bin/codesign --force --strict --options runtime --timestamp --identifier "$BUNDLE_ID" --entitlements "$stage/wrong-team.entitlements.plist" --sign "$AGENTPASS_CONTROLLER_PROBE_WRONG_TEAM_SIGNING_IDENTITY" "$stage/probes/wrong-team-controller.app"
/usr/bin/codesign --force --strict --identifier "$BUNDLE_ID" --sign - "$stage/probes/ad-hoc-controller.app"

for role in approved missing-entitlement wrong-team ad-hoc; do
  /usr/bin/codesign --verify --strict --verbose=2 "$stage/probes/$role-controller.app"
done
[[ "$(/usr/bin/find "$stage/probes" -mindepth 1 -maxdepth 1 -type d | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == "4" ]] || fail
/bin/mv "$stage" "$AGENTPASS_CONTROLLER_PROBE_OUTPUT_ROOT"
trap - EXIT HUP INT TERM
printf '%s\n' '{"artifact":"qualification-controller-probes","ok":true}'

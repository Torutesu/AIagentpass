#!/bin/sh
set -eu

# This is a release-pipeline helper, not a development fallback. It refuses to
# manufacture a Developer ID identity: the pipeline must provide the two real
# certificate names and the resulting bundles are verified again by the
# physical scenario.
fail() { printf '%s\n' 'negative probe signing refused' >&2; exit 1; }
is_abs() { case "$1" in /*) ;; *) return 1 ;; esac; }
team_re='^[A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]$'

: "${AGENTPASS_PROBE_SOURCE_BINARY:?AGENTPASS_PROBE_SOURCE_BINARY is required}"
: "${AGENTPASS_PROBE_OUTPUT_ROOT:?AGENTPASS_PROBE_OUTPUT_ROOT is required}"
: "${AGENTPASS_PROBE_TEAM_ID:?AGENTPASS_PROBE_TEAM_ID is required}"
: "${AGENTPASS_PROBE_WRONG_TEAM_ID:?AGENTPASS_PROBE_WRONG_TEAM_ID is required}"
: "${AGENTPASS_PROBE_APPROVED_SIGNING_IDENTITY:?AGENTPASS_PROBE_APPROVED_SIGNING_IDENTITY is required}"
: "${AGENTPASS_PROBE_MISSING_ENTITLEMENT_SIGNING_IDENTITY:?AGENTPASS_PROBE_MISSING_ENTITLEMENT_SIGNING_IDENTITY is required}"
: "${AGENTPASS_PROBE_WRONG_TEAM_SIGNING_IDENTITY:?AGENTPASS_PROBE_WRONG_TEAM_SIGNING_IDENTITY is required}"

is_abs "$AGENTPASS_PROBE_SOURCE_BINARY" || fail
is_abs "$AGENTPASS_PROBE_OUTPUT_ROOT" || fail
printf '%s' "$AGENTPASS_PROBE_TEAM_ID" | /usr/bin/grep -Eq "$team_re" || fail
printf '%s' "$AGENTPASS_PROBE_WRONG_TEAM_ID" | /usr/bin/grep -Eq "$team_re" || fail
[ "$AGENTPASS_PROBE_TEAM_ID" != "$AGENTPASS_PROBE_WRONG_TEAM_ID" ] || fail
[ -f "$AGENTPASS_PROBE_SOURCE_BINARY" ] || fail
[ -x "$AGENTPASS_PROBE_SOURCE_BINARY" ] || fail
[ ! -L "$AGENTPASS_PROBE_SOURCE_BINARY" ] || fail
[ ! -e "$AGENTPASS_PROBE_OUTPUT_ROOT" ] || fail

umask 077
stage="${AGENTPASS_PROBE_OUTPUT_ROOT}.staging.$$"
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/probes"

make_info() {
  role="$1"
  directory="$stage/probes/$role-client.app"
  mkdir -p "$directory/Contents/MacOS"
  cp -p "$AGENTPASS_PROBE_SOURCE_BINARY" "$directory/Contents/MacOS/agentpass-negative-xpc-probe"
  chmod 500 "$directory/Contents/MacOS/agentpass-negative-xpc-probe"
  /usr/libexec/PlistBuddy -c 'Add :CFBundlePackageType string APPL' \
    -c 'Add :CFBundleExecutable string agentpass-negative-xpc-probe' \
    -c 'Add :CFBundleIdentifier string dev.agentpass.native-client' \
    -c 'Add :CFBundleName string AgentPass Negative XPC Probe' \
    -c 'Add :CFBundleShortVersionString string 1.0.0' \
    -c 'Add :CFBundleVersion string 1' \
    "$directory/Contents/Info.plist" 2>/dev/null || {
      /usr/bin/plutil -create xml1 "$directory/Contents/Info.plist"
      /usr/libexec/PlistBuddy -c 'Add :CFBundlePackageType string APPL' -c 'Add :CFBundleExecutable string agentpass-negative-xpc-probe' -c 'Add :CFBundleIdentifier string dev.agentpass.native-client' -c 'Add :CFBundleName string AgentPass Negative XPC Probe' -c 'Add :CFBundleShortVersionString string 1.0.0' -c 'Add :CFBundleVersion string 1' "$directory/Contents/Info.plist"
    }
}

make_entitlements() {
  output="$1"
  group="$2"
  /usr/bin/plutil -create xml1 "$output"
  /usr/libexec/PlistBuddy -c 'Add :keychain-access-groups array' -c "Add :keychain-access-groups:0 string $group" "$output"
}

sign_developer_id() {
  role="$1"
  identity="$2"
  entitlements="$3"
  directory="$stage/probes/$role-client.app"
  /usr/bin/codesign --force --strict --options runtime --timestamp --identifier dev.agentpass.native-client --entitlements "$entitlements" --sign "$identity" "$directory"
  /usr/bin/codesign --verify --strict --verbose=2 "$directory"
}

make_info approved
make_info missing-entitlement
make_info wrong-team
make_info ad-hoc
make_entitlements "$stage/approved.entitlements.plist" "$AGENTPASS_PROBE_TEAM_ID.dev.agentpass.approval-keys"
make_entitlements "$stage/wrong-team.entitlements.plist" "$AGENTPASS_PROBE_WRONG_TEAM_ID.dev.agentpass.approval-keys"

sign_developer_id approved "$AGENTPASS_PROBE_APPROVED_SIGNING_IDENTITY" "$stage/approved.entitlements.plist"
/usr/bin/codesign --force --strict --options runtime --timestamp --identifier dev.agentpass.native-client --sign "$AGENTPASS_PROBE_MISSING_ENTITLEMENT_SIGNING_IDENTITY" "$stage/probes/missing-entitlement-client.app"
/usr/bin/codesign --verify --strict --verbose=2 "$stage/probes/missing-entitlement-client.app"
sign_developer_id wrong-team "$AGENTPASS_PROBE_WRONG_TEAM_SIGNING_IDENTITY" "$stage/wrong-team.entitlements.plist"
/usr/bin/codesign --force --strict --sign - "$stage/probes/ad-hoc-client.app"
/usr/bin/codesign --verify --strict --verbose=2 "$stage/probes/ad-hoc-client.app"

# Reject a partial or substituted output before making it visible to the
# runner. The scenario performs the identity and entitlement checks again.
[ "$(find "$stage/probes" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" = 4 ] || fail
mv "$stage" "$AGENTPASS_PROBE_OUTPUT_ROOT"
trap - EXIT HUP INT TERM

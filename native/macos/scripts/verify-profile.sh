#!/bin/bash
set -euo pipefail

[[ $# -eq 6 ]] || { echo "Usage: verify-profile.sh PROFILE TEAM_ID PREFIX BUNDLE_ID KEYCHAIN_GROUP" >&2; exit 2; }
PROFILE="$1"; TEAM_ID="$2"; PREFIX="$3"; BUNDLE_ID="$4"; EXPECTED_GROUP="$5"; : "$6"
# The sixth argument is reserved for an explicit role label to keep diagnostics unambiguous.
ROLE="$6"
[[ -f "$PROFILE" && ! -L "$PROFILE" ]] || { echo "$ROLE profile must be a regular non-symlink file" >&2; exit 1; }
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ && "$PREFIX" =~ ^[A-Z0-9]{10}$ ]] || { echo "$ROLE profile expected identifiers are invalid" >&2; exit 1; }

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-profile.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
PLIST="$TEMP_DIR/profile.plist"
/usr/bin/security cms -D -i "$PROFILE" >"$PLIST" || { echo "$ROLE profile CMS signature is invalid" >&2; exit 1; }
/usr/bin/plutil -lint "$PLIST" >/dev/null

read_plist() { /usr/libexec/PlistBuddy -c "Print $1" "$PLIST" 2>/dev/null; }
[[ "$(read_plist :TeamIdentifier:0)" == "$TEAM_ID" ]] || { echo "$ROLE profile TeamIdentifier mismatch" >&2; exit 1; }
[[ "$(read_plist :ApplicationIdentifierPrefix:0)" == "$PREFIX" ]] || { echo "$ROLE profile ApplicationIdentifierPrefix mismatch" >&2; exit 1; }
[[ "$(read_plist :Entitlements:application-identifier)" == "${PREFIX}.${BUNDLE_ID}" ]] || { echo "$ROLE profile application-identifier mismatch" >&2; exit 1; }
[[ "$(read_plist :Entitlements:com.apple.developer.team-identifier)" == "$TEAM_ID" ]] || { echo "$ROLE profile entitlement Team ID mismatch" >&2; exit 1; }
[[ "$(read_plist :Entitlements:keychain-access-groups:0)" == "$EXPECTED_GROUP" ]] || { echo "$ROLE profile keychain access group mismatch" >&2; exit 1; }
if read_plist :Entitlements:keychain-access-groups:1 >/dev/null; then
  echo "$ROLE profile authorizes unexpected additional keychain groups" >&2
  exit 1
fi
if read_plist :Entitlements:get-task-allow >/dev/null; then
  echo "$ROLE profile enables get-task-allow" >&2
  exit 1
fi
for forbidden in com.apple.security.get-task-allow com.apple.security.cs.disable-library-validation com.apple.security.cs.allow-dyld-environment-variables; do
  if read_plist ":Entitlements:$forbidden" >/dev/null; then
    echo "$ROLE profile enables forbidden entitlement: $forbidden" >&2
    exit 1
  fi
done
[[ "$(read_plist :ProvisionsAllDevices)" == "true" ]] || { echo "$ROLE profile is not a Developer ID distribution profile" >&2; exit 1; }
EXPIRATION="$(read_plist :ExpirationDate)"
/usr/bin/ruby -rtime -e 'abort "expired" unless Time.parse(ARGV[0]) > Time.now' "$EXPIRATION" || { echo "$ROLE profile is expired" >&2; exit 1; }
[[ -n "$(read_plist :UUID)" ]] || { echo "$ROLE profile has no UUID" >&2; exit 1; }
echo "$ROLE provisioning profile verified" >&2

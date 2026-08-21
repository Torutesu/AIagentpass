#!/bin/bash
set -euo pipefail

[[ $# -eq 3 ]] || { echo "Usage: notarize-controller.sh AgentPassQualificationController.app NOTARYTOOL-RESULT.json STAPLER-RESULT.txt" >&2; exit 2; }
CONTROLLER="$1"
NOTARY_RESULT="$2"
STAPLER_RESULT="$3"
for name in AGENTPASS_NOTARY_KEY_ID AGENTPASS_NOTARY_ISSUER_ID AGENTPASS_NOTARY_PRIVATE_KEY_PATH; do
  [[ -n "${!name:-}" ]] || { echo "$name is required" >&2; exit 1; }
done
TEAM_ID="${AGENTPASS_TEAM_ID:-}"
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "AGENTPASS_TEAM_ID is required and must be a 10-character Team ID" >&2; exit 1; }
[[ "$CONTROLLER" == /* && "$NOTARY_RESULT" == /* && "$STAPLER_RESULT" == /* ]] || { echo "Controller and evidence paths must be absolute" >&2; exit 2; }
FAILURE_MARKER="${CONTROLLER}.notarization-failed"
LOCK_DIR="${CONTROLLER}.notarization.lock"
[[ ! -e "$FAILURE_MARKER" && ! -L "$FAILURE_MARKER" ]] || { echo "Controller has a prior notarization failure and must be rebuilt" >&2; exit 1; }
[[ ! -e "$LOCK_DIR" && ! -L "$LOCK_DIR" ]] || { echo "Controller notarization is already in progress" >&2; exit 1; }
if ! /bin/mkdir "$LOCK_DIR"; then echo "Unable to acquire controller notarization lock" >&2; exit 1; fi
notarization_cleanup() {
  status=$?
  if [[ "$status" -ne 0 ]]; then
    # A directory marker is created atomically and cannot follow a symlink.
    # Keep the lock if marker creation fails so the artifact remains blocked.
    if /bin/mkdir "$FAILURE_MARKER" 2>/dev/null; then /bin/rmdir "$LOCK_DIR" 2>/dev/null || true; fi
  else
    /bin/rmdir "$LOCK_DIR" 2>/dev/null || true
  fi
  rm -rf -- "${TEMP_DIR:-}" 2>/dev/null || true
  exit "$status"
}
trap notarization_cleanup EXIT
[[ "$(basename "$CONTROLLER")" == "AgentPassQualificationController.app" && -d "$CONTROLLER" && ! -L "$CONTROLLER" ]] || { echo "Unsafe controller input" >&2; exit 1; }
[[ -f "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH" && ! -L "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH" && "$(/usr/bin/stat -f '%l' "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH")" == "1" ]] || { echo "Unsafe notary private key" >&2; exit 1; }
KEY_MODE="$(/usr/bin/stat -f '%Lp' "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH")"
(( (8#$KEY_MODE & 8#077) == 0 )) || { echo "Notary private key permissions are too broad" >&2; exit 1; }
[[ "$AGENTPASS_NOTARY_KEY_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "Invalid notary key ID" >&2; exit 1; }
[[ "$AGENTPASS_NOTARY_ISSUER_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "Invalid notary issuer ID" >&2; exit 1; }
for output in "$NOTARY_RESULT" "$STAPLER_RESULT"; do
  [[ ! -e "$output" && ! -L "$output" ]] || { echo "Evidence output already exists or is a symlink: $output" >&2; exit 1; }
done
if /usr/bin/find -P "$CONTROLLER" -type l -print -quit | /usr/bin/grep -q .; then echo "Controller contains a symlink" >&2; exit 1; fi
if /usr/bin/find -P "$CONTROLLER" -type f \( -perm -002 -o -perm -020 \) -print -quit | /usr/bin/grep -q .; then echo "Controller contains writable files" >&2; exit 1; fi
/usr/bin/codesign --verify --strict --verbose=4 "$CONTROLLER"
CONTROLLER_DETAILS="$(/usr/bin/codesign -dv --verbose=4 "$CONTROLLER" 2>&1)"
/usr/bin/grep -q '^Authority=Developer ID Application: ' <<<"$CONTROLLER_DETAILS" || { echo "Controller is not Developer ID Application signed" >&2; exit 1; }
/usr/bin/grep -Eq "^TeamIdentifier=${TEAM_ID}$" <<<"$CONTROLLER_DETAILS" || { echo "Controller Developer ID Team ID mismatch" >&2; exit 1; }
/usr/bin/grep -Eq '^flags=.*runtime' <<<"$CONTROLLER_DETAILS" || { echo "Controller is missing hardened runtime" >&2; exit 1; }
/usr/bin/grep -q '^Timestamp=' <<<"$CONTROLLER_DETAILS" || { echo "Controller is missing a secure signing timestamp" >&2; exit 1; }
CONTROLLER_BINARY="$CONTROLLER/Contents/MacOS/agentpass-qualification-controller"
[[ -f "$CONTROLLER_BINARY" && ! -L "$CONTROLLER_BINARY" && -x "$CONTROLLER_BINARY" ]] || { echo "Controller executable is missing" >&2; exit 1; }
CONTROLLER_ARCHITECTURES="$(/usr/bin/lipo -archs "$CONTROLLER_BINARY" 2>/dev/null)" || { echo "Unable to inspect controller architectures" >&2; exit 1; }
case "$CONTROLLER_ARCHITECTURES" in
  "arm64 x86_64"|"x86_64 arm64") ;;
  *) echo "Controller must contain exactly arm64 and x86_64 slices: $CONTROLLER_ARCHITECTURES" >&2; exit 1 ;;
esac

umask 077
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-controller-notary.XXXXXX")"
SUBMISSION="$TEMP_DIR/AgentPassQualificationController.zip"
/usr/bin/ditto -c -k --keepParent --sequesterRsrc "$CONTROLLER" "$SUBMISSION"
/usr/bin/xcrun notarytool submit "$SUBMISSION" --wait --output-format json \
  --key "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH" \
  --key-id "$AGENTPASS_NOTARY_KEY_ID" \
  --issuer "$AGENTPASS_NOTARY_ISSUER_ID" > "$TEMP_DIR/notarytool-result.json"
node -e '
  const fs = require("node:fs");
  const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (value.status !== "Accepted" || !/^[0-9a-f-]{36}$/i.test(value.id || "")) throw new Error("notarytool did not return an accepted controller submission");
' "$TEMP_DIR/notarytool-result.json"

/usr/bin/xcrun stapler staple "$CONTROLLER"
set +e
/usr/bin/xcrun stapler validate "$CONTROLLER" > "$TEMP_DIR/stapler-result.txt" 2>&1
STAPLER_STATUS=$?
set -e
[[ "$STAPLER_STATUS" -eq 0 ]] || { /bin/cat "$TEMP_DIR/stapler-result.txt" >&2; exit 1; }
/usr/bin/grep -Eiq 'The validate action worked!' "$TEMP_DIR/stapler-result.txt" || { echo "Stapler output does not prove successful controller validation" >&2; exit 1; }
/usr/sbin/spctl --assess --type execute --verbose=4 "$CONTROLLER"
/usr/bin/codesign --verify --strict --verbose=4 "$CONTROLLER"

/usr/bin/install -m 0600 "$TEMP_DIR/notarytool-result.json" "$NOTARY_RESULT"
/usr/bin/install -m 0600 "$TEMP_DIR/stapler-result.txt" "$STAPLER_RESULT"
echo "submission_sha256=$(/usr/bin/shasum -a 256 "$SUBMISSION" | /usr/bin/awk '{print $1}')"
echo "Controller notarization accepted and stapled app validated"

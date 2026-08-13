#!/bin/bash
set -euo pipefail

[[ $# -eq 3 ]] || { echo "Usage: notarize-controller.sh AgentPassQualificationController.app NOTARYTOOL-RESULT.json STAPLER-RESULT.txt" >&2; exit 2; }
CONTROLLER="$1"
NOTARY_RESULT="$2"
STAPLER_RESULT="$3"
for name in AGENTPASS_NOTARY_KEY_ID AGENTPASS_NOTARY_ISSUER_ID AGENTPASS_NOTARY_PRIVATE_KEY_PATH; do
  [[ -n "${!name:-}" ]] || { echo "$name is required" >&2; exit 1; }
done
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

umask 077
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-controller-notary.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
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
echo "Controller notarization accepted and stapled app validated"

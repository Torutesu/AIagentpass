#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

[[ $# -eq 3 ]] || { echo "Usage: notarize-installer.sh PACKAGE.pkg NOTARYTOOL-RESULT.json STAPLER-RESULT.txt" >&2; exit 2; }
PACKAGE="$1"
NOTARY_RESULT="$2"
STAPLER_RESULT="$3"
for name in AGENTPASS_NOTARY_KEY_ID AGENTPASS_NOTARY_ISSUER_ID AGENTPASS_NOTARY_PRIVATE_KEY_PATH; do
  [[ -n "${!name:-}" ]] || { echo "$name is required" >&2; exit 1; }
done
TEAM_ID="${AGENTPASS_TEAM_ID:-}"
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "AGENTPASS_TEAM_ID is required and must be a 10-character Team ID" >&2; exit 1; }
[[ "$PACKAGE" == /* && "$NOTARY_RESULT" == /* && "$STAPLER_RESULT" == /* ]] || { echo "Package and evidence paths must be absolute" >&2; exit 2; }
[[ -f "$PACKAGE" && ! -L "$PACKAGE" && "$(/usr/bin/stat -f '%l' "$PACKAGE")" == "1" ]] || { echo "Unsafe package input" >&2; exit 1; }
FAILURE_MARKER="${PACKAGE}.notarization-failed"
LOCK_DIR="${PACKAGE}.notarization.lock"
[[ ! -e "$FAILURE_MARKER" && ! -L "$FAILURE_MARKER" ]] || { echo "Package has a prior notarization failure and must be rebuilt" >&2; exit 1; }
[[ ! -e "$LOCK_DIR" && ! -L "$LOCK_DIR" ]] || { echo "Package notarization is already in progress" >&2; exit 1; }
if ! /bin/mkdir "$LOCK_DIR"; then echo "Unable to acquire package notarization lock" >&2; exit 1; fi
notarization_cleanup() {
  status=$?
  if [[ "$status" -ne 0 ]]; then
    # A directory marker is created atomically and cannot follow a symlink.
    # Keep the lock if marker creation fails so the artifact remains blocked.
    if /bin/mkdir "$FAILURE_MARKER" 2>/dev/null; then /bin/rmdir "$LOCK_DIR" 2>/dev/null || true; fi
  else
    /bin/rmdir "$LOCK_DIR" 2>/dev/null || true
  fi
  rm -f -- "${PKG_SIGNATURE_FILE:-}" 2>/dev/null || true
  rm -rf -- "${TEMP_DIR:-}" 2>/dev/null || true
  exit "$status"
}
trap notarization_cleanup EXIT
PACKAGE_SHA256_BEFORE="$(/usr/bin/shasum -a 256 "$PACKAGE" | /usr/bin/awk '{print $1}')"
[[ "$PACKAGE_SHA256_BEFORE" =~ ^[0-9a-f]{64}$ ]] || { echo "Unable to compute package artifact SHA-256" >&2; exit 1; }
if [[ -n "${AGENTPASS_EXPECTED_ARTIFACT_SHA256:-}" ]]; then
  [[ "${AGENTPASS_EXPECTED_ARTIFACT_SHA256}" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid expected artifact SHA-256" >&2; exit 2; }
  [[ "$PACKAGE_SHA256_BEFORE" == "$AGENTPASS_EXPECTED_ARTIFACT_SHA256" ]] || { echo "Package artifact SHA-256 mismatch" >&2; exit 1; }
fi
[[ -f "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH" && ! -L "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH" && "$(/usr/bin/stat -f '%l' "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH")" == "1" ]] || { echo "Unsafe notary private key" >&2; exit 1; }
KEY_MODE="$(/usr/bin/stat -f '%Lp' "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH")"
(( (8#$KEY_MODE & 8#077) == 0 )) || { echo "Notary private key permissions are too broad" >&2; exit 1; }
[[ "$AGENTPASS_NOTARY_KEY_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "Invalid notary key ID" >&2; exit 1; }
[[ "$AGENTPASS_NOTARY_ISSUER_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "Invalid notary issuer ID" >&2; exit 1; }
PKG_SIGNATURE_FILE="$(mktemp "${TMPDIR:-/tmp}/agentpass-pkg-signature.XXXXXX")"
/usr/sbin/pkgutil --check-signature "$PACKAGE" > "$PKG_SIGNATURE_FILE"
/usr/bin/grep -q 'Status: signed by a certificate trusted by Mac OS X' "$PKG_SIGNATURE_FILE" || { echo "Package is not trusted-signed before notarization" >&2; exit 1; }
/usr/bin/grep -Eq "Developer ID Installer: .*\\(${TEAM_ID}\\)" "$PKG_SIGNATURE_FILE" || { echo "Package Developer ID Installer Team ID mismatch" >&2; exit 1; }
for output in "$NOTARY_RESULT" "$STAPLER_RESULT"; do
  [[ ! -e "$output" && ! -L "$output" ]] || { echo "Evidence output already exists or is a symlink: $output" >&2; exit 1; }
done

umask 077
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-notary.XXXXXX")"
/usr/bin/xcrun notarytool submit "$PACKAGE" --wait --output-format json \
  --key "$AGENTPASS_NOTARY_PRIVATE_KEY_PATH" \
  --key-id "$AGENTPASS_NOTARY_KEY_ID" \
  --issuer "$AGENTPASS_NOTARY_ISSUER_ID" > "$TEMP_DIR/notarytool-result.json"
node -e '
  const fs = require("node:fs");
  const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (value.status !== "Accepted" || !/^[0-9a-f-]{36}$/i.test(value.id || "")) throw new Error("notarytool did not return an accepted submission");
' "$TEMP_DIR/notarytool-result.json"

/usr/bin/xcrun stapler staple "$PACKAGE"
set +e
/usr/bin/xcrun stapler validate "$PACKAGE" > "$TEMP_DIR/stapler-result.txt" 2>&1
STAPLER_STATUS=$?
set -e
[[ "$STAPLER_STATUS" -eq 0 ]] || { /bin/cat "$TEMP_DIR/stapler-result.txt" >&2; exit 1; }
/usr/bin/grep -Eiq 'The validate action worked!' "$TEMP_DIR/stapler-result.txt" || { echo "Stapler output does not prove successful validation" >&2; exit 1; }
/usr/sbin/spctl --assess --type install --verbose=4 "$PACKAGE"

# Stapling changes the package bytes. Re-run the complete package verifier on
# the exact post-staple artifact so a successful ticket/Gatekeeper check cannot
# bypass payload, identity, architecture, or preservation-policy checks.
"$SCRIPT_DIR/../../native/macos/scripts/verify-installer-package.sh" "$PACKAGE" "$TEAM_ID"

PACKAGE_SHA256_AFTER="$(/usr/bin/shasum -a 256 "$PACKAGE" | /usr/bin/awk '{print $1}')"
[[ "$PACKAGE_SHA256_AFTER" =~ ^[0-9a-f]{64}$ && "$PACKAGE_SHA256_AFTER" != "$PACKAGE_SHA256_BEFORE" ]] || { echo "Stapling did not produce a fresh package artifact digest" >&2; exit 1; }

/usr/bin/install -m 0600 "$TEMP_DIR/notarytool-result.json" "$NOTARY_RESULT"
/usr/bin/install -m 0600 "$TEMP_DIR/stapler-result.txt" "$STAPLER_RESULT"
echo "artifact_sha256=$PACKAGE_SHA256_AFTER"
echo "Notarization accepted and stapled package validated"

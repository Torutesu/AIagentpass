#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
[[ $# -eq 1 || $# -eq 2 ]] || { echo "Usage: verify-installer-package.sh PACKAGE.pkg [EXPECTED_TEAM_ID]" >&2; exit 2; }
PACKAGE="$1"
EXPECTED_TEAM_ID="${2:-}"
[[ -f "$PACKAGE" && ! -L "$PACKAGE" ]] || { echo "Installer package must be a real regular file" >&2; exit 1; }
[[ "$(/usr/bin/stat -f '%l' "$PACKAGE")" == "1" ]] || { echo "Installer package must not be hard linked" >&2; exit 1; }
if [[ -n "$EXPECTED_TEAM_ID" ]]; then [[ "$EXPECTED_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "Invalid expected Team ID" >&2; exit 2; }; fi

SIGNATURE_OUTPUT="$(/usr/sbin/pkgutil --check-signature "$PACKAGE")"
/usr/bin/grep -q 'Status: signed by a certificate trusted by Mac OS X' <<<"$SIGNATURE_OUTPUT" || { echo "Installer signature is not trusted" >&2; exit 1; }
if [[ -n "$EXPECTED_TEAM_ID" ]]; then
  /usr/bin/grep -Eq "Developer ID Installer: .*\(${EXPECTED_TEAM_ID}\)" <<<"$SIGNATURE_OUTPUT" || { echo "Installer Team ID mismatch" >&2; exit 1; }
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
for binding in 'preinstall:installer-preinstall.sh' 'postinstall:installer-postinstall.sh' 'validate-preserved-state.sh:validate-preserved-state.sh'; do
  packaged_name="${binding%%:*}"
  source_name="${binding#*:}"
  [[ "$(/usr/bin/find -P "$TEMP_DIR/expanded" -type f -name "$packaged_name" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == "1" ]] || { echo "Installer is missing unique $packaged_name" >&2; exit 1; }
  packaged_script="$(/usr/bin/find -P "$TEMP_DIR/expanded" -type f -name "$packaged_name" -print -quit)"
  /usr/bin/cmp -s "$SCRIPT_DIR/$source_name" "$packaged_script" || { echo "Packaged preservation script differs from reviewed source: $packaged_name" >&2; exit 1; }
done
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"
echo "Installer package payload and preservation policy verified"

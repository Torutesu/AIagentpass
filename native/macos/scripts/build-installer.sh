#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"
VERSION="$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$ROOT_DIR/package.json")"
APP=""
OUTPUT=""
IDENTITY=""

usage() { echo "Usage: AGENTPASS_TEAM_ID=APPLETEAM1 build-installer.sh --app AgentPass.app --output AgentPass.pkg --identity 'Developer ID Installer: ...'" >&2; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) [[ $# -ge 2 ]] || usage; APP="$2"; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; OUTPUT="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; IDENTITY="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$APP" && -n "$OUTPUT" && -n "$IDENTITY" ]] || usage
[[ "$IDENTITY" == "Developer ID Installer:"* ]] || { echo "Installer identity must be a Developer ID Installer identity" >&2; exit 1; }
TEAM_ID="${AGENTPASS_TEAM_ID:-}"
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "AGENTPASS_TEAM_ID must be a 10-character Team ID" >&2; exit 2; }
[[ "$APP" == /* && "$OUTPUT" == /* ]] || { echo "App and output paths must be absolute" >&2; exit 2; }
[[ -d "$APP" && ! -L "$APP" && "$(basename "$APP")" == "AgentPass.app" ]] || { echo "Input must be a real AgentPass.app directory" >&2; exit 1; }
[[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || { echo "Installer output already exists or is a symlink" >&2; exit 1; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] || { echo "Invalid package version" >&2; exit 1; }
if /usr/bin/find -P "$APP" -type l -print -quit | /usr/bin/grep -q .; then echo "App contains a symlink" >&2; exit 1; fi
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-installer.XXXXXX")"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
/bin/mkdir -m 0700 "$TEMP_DIR/package-scripts"
/bin/mkdir -m 0700 "$TEMP_DIR/payload"
/usr/bin/ditto "$APP" "$TEMP_DIR/payload/AgentPass.app"
/usr/bin/install -m 0755 "$SCRIPT_DIR/installer-preinstall.sh" "$TEMP_DIR/package-scripts/preinstall"
/usr/bin/install -m 0755 "$SCRIPT_DIR/installer-postinstall.sh" "$TEMP_DIR/package-scripts/postinstall"
/usr/bin/install -m 0755 "$SCRIPT_DIR/validate-preserved-state.sh" "$TEMP_DIR/package-scripts/validate-preserved-state.sh"
/usr/bin/plutil -create xml1 "$TEMP_DIR/component.plist"
/usr/libexec/PlistBuddy -c 'Clear array' "$TEMP_DIR/component.plist"
/usr/libexec/PlistBuddy -c 'Add :0 dict' "$TEMP_DIR/component.plist"
/usr/libexec/PlistBuddy -c 'Add :0:BundleHasStrictIdentifier bool true' "$TEMP_DIR/component.plist"
/usr/libexec/PlistBuddy -c 'Add :0:BundleIsRelocatable bool false' "$TEMP_DIR/component.plist"
/usr/libexec/PlistBuddy -c 'Add :0:BundleIsVersionChecked bool true' "$TEMP_DIR/component.plist"
/usr/libexec/PlistBuddy -c 'Add :0:BundleOverwriteAction string upgrade' "$TEMP_DIR/component.plist"
/usr/libexec/PlistBuddy -c 'Add :0:RootRelativeBundlePath string AgentPass.app' "$TEMP_DIR/component.plist"

/usr/bin/pkgbuild --root "$TEMP_DIR/payload" \
  --identifier dev.agentpass.installer \
  --version "$VERSION" \
  --install-location /Applications \
  --component-plist "$TEMP_DIR/component.plist" \
  --scripts "$TEMP_DIR/package-scripts" \
  --ownership recommended \
  --sign "$IDENTITY" \
"$OUTPUT"

"$SCRIPT_DIR/verify-installer-package.sh" "$OUTPUT"
INVENTORY_OUTPUT="${OUTPUT}.inventory.json"
[[ ! -e "$INVENTORY_OUTPUT" && ! -L "$INVENTORY_OUTPUT" ]] || { echo "Installer inventory output already exists or is a symlink" >&2; exit 1; }
node "$SCRIPT_DIR/generate-artifact-inventory.mjs" "$APP" "$OUTPUT" "$INVENTORY_OUTPUT" >/dev/null
echo "$OUTPUT"

#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-app-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

APP_PATH="$($SCRIPT_DIR/build-app.sh --adhoc --output-dir "$TEST_DIR/output")"
/usr/bin/codesign --verify --deep --strict "$APP_PATH"

STATUS_JSON="$($APP_PATH/Contents/MacOS/agentpass-native-manager status)"
node -e '
  const fs = require("node:fs");
  const value = JSON.parse(process.argv[1]);
  if (!value.ok || !value.plist_present || fs.realpathSync(value.bundle_path) !== fs.realpathSync(process.argv[2])) process.exit(1);
  if (!["not_found", "not_registered", "enabled", "requires_approval"].includes(value.status)) process.exit(1);
' "$STATUS_JSON" "$APP_PATH"

install -m 0755 "$APP_PATH/Contents/MacOS/agentpass-native-manager" "$TEST_DIR/unbundled-manager"
if "$TEST_DIR/unbundled-manager" status >/dev/null 2>&1; then
  echo "Unbundled manager unexpectedly accepted a status request" >&2
  exit 1
fi

if "$SCRIPT_DIR/build-app.sh" --output-dir "$TEST_DIR/unsigned" >/dev/null 2>&1; then
  echo "Unsigned production build unexpectedly succeeded" >&2
  exit 1
fi
if "$SCRIPT_DIR/build-app.sh" --adhoc --notary-profile invalid --output-dir "$TEST_DIR/notary" >/dev/null 2>&1; then
  echo "Ad-hoc notarization unexpectedly succeeded" >&2
  exit 1
fi
if "$SCRIPT_DIR/build-app.sh" --adhoc --output-dir "$TEST_DIR/output" >/dev/null 2>&1; then
  echo "Existing output was unexpectedly overwritten without --force" >&2
  exit 1
fi

echo "AgentPass app bundle verification passed"

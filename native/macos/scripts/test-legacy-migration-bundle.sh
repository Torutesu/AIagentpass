#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-legacy-migration-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

ARTIFACT="$("$SCRIPT_DIR/build-legacy-migration.sh" --adhoc --output-dir "$TEST_DIR/output")"
SERVICE_APP="$ARTIFACT/AgentPassLegacyServiceMigration.app"
APPROVAL_APP="$ARTIFACT/AgentPassLegacyApprovalMigration.app"
SERVICE_BIN="$SERVICE_APP/Contents/MacOS/agentpass-legacy-service-migration"
APPROVAL_BIN="$APPROVAL_APP/Contents/MacOS/agentpass-legacy-approval-migration"

[[ -d "$SERVICE_APP" && -d "$APPROVAL_APP" && -x "$SERVICE_BIN" && -x "$APPROVAL_BIN" ]] || { echo "migration helper layout is incomplete" >&2; exit 1; }
[[ -f "$ARTIFACT/ADHOC-STRUCTURE-TEST-ONLY" && ! -e "$ARTIFACT/AgentPass.app" ]] || { echo "migration artifact is not clearly isolated" >&2; exit 1; }
[[ ! -e "$SERVICE_APP/Contents/embedded.provisionprofile" && ! -e "$APPROVAL_APP/Contents/embedded.provisionprofile" ]] || { echo "ad-hoc artifact embeds a profile" >&2; exit 1; }

verify_helper() {
  local app="$1" identifier="$2" second_group="$3" role="$4" extracted
  /usr/bin/codesign --verify --strict "$app"
  [[ "$(/usr/bin/codesign -dv --verbose=4 "$app" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')" == "$identifier" ]] || exit 1
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")" == "$identifier" ]] || exit 1
  extracted="$TEST_DIR/$role-entitlements.plist"
  /usr/bin/codesign -d --entitlements :- "$app" >"$extracted" 2>/dev/null
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$extracted")" == "ADHOC00000.dev.agentpass.keys" ]] || exit 1
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:1' "$extracted")" == "$second_group" ]] || exit 1
  if /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:2' "$extracted" >/dev/null 2>&1; then echo "$role has an extra keychain group" >&2; exit 1; fi
  /usr/bin/plutil -convert json -o - "$extracted" | /usr/bin/env node -e '
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(0, "utf8"));
    if (Object.keys(value).length !== 1 || JSON.stringify(value["keychain-access-groups"]) !== JSON.stringify(process.argv.slice(1))) process.exit(1);
  ' "ADHOC00000.dev.agentpass.keys" "$second_group" || { echo "$role has unexpected signed entitlements" >&2; exit 1; }
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.get-task-allow' "$extracted" 2>/dev/null || true)" != "true" ]] || exit 1
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.cs.disable-library-validation' "$extracted" 2>/dev/null || true)" != "true" ]] || exit 1
}
verify_helper "$SERVICE_APP" dev.agentpass.legacy-service-migration ADHOC00000.dev.agentpass.service-keys service
verify_helper "$APPROVAL_APP" dev.agentpass.legacy-approval-migration ADHOC00000.dev.agentpass.approval-keys approval

# macOS intentionally kills ad-hoc binaries carrying fabricated Keychain groups. Exercise command
# dispatch through SwiftPM's unentitled debug products; the app bundles above are structure-only.
swift run --package-path "$SCRIPT_DIR/.." agentpass-legacy-service-migration --help 2>/dev/null | /usr/bin/grep -q 'prepare|prove'
swift run --package-path "$SCRIPT_DIR/.." agentpass-legacy-approval-migration --help 2>/dev/null | /usr/bin/grep -q 'sign-completion'
if swift run --package-path "$SCRIPT_DIR/.." agentpass-legacy-approval-migration unknown --config nowhere >/dev/null 2>&1; then echo "approval helper accepted an unknown command" >&2; exit 1; fi
if [[ "$(id -u)" -ne 0 ]] && swift run --package-path "$SCRIPT_DIR/.." agentpass-legacy-service-migration prepare --config nowhere </dev/null >/dev/null 2>&1; then echo "service helper accepted non-root execution" >&2; exit 1; fi

if "$SCRIPT_DIR/build-legacy-migration.sh" --adhoc --output-dir "$TEST_DIR/output" >/dev/null 2>&1; then echo "build overwrote an existing migration artifact" >&2; exit 1; fi
if "$SCRIPT_DIR/build-legacy-migration.sh" --output-dir "$TEST_DIR/missing-production" >/dev/null 2>&1; then echo "production build accepted missing signing inputs" >&2; exit 1; fi
touch "$TEST_DIR/profile"
ln -s "$TEST_DIR/profile" "$TEST_DIR/profile-link"
if "$SCRIPT_DIR/build-legacy-migration.sh" --identity invalid --team-id ABCDE12345 --app-identifier-prefix ABCDE12345 \
  --service-profile "$TEST_DIR/profile-link" --approval-profile "$TEST_DIR/profile" --output-dir "$TEST_DIR/symlink" >/dev/null 2>&1; then
  echo "production build accepted a symlink profile" >&2; exit 1
fi
if "$SCRIPT_DIR/build-legacy-migration.sh" --adhoc --service-profile "$TEST_DIR/profile" --output-dir "$TEST_DIR/adhoc-profile" >/dev/null 2>&1; then
  echo "ad-hoc build accepted a provisioning profile" >&2; exit 1
fi
mkdir "$TEST_DIR/real-output"
ln -s "$TEST_DIR/real-output" "$TEST_DIR/output-link"
if "$SCRIPT_DIR/build-legacy-migration.sh" --adhoc --output-dir "$TEST_DIR/output-link" >/dev/null 2>&1; then
  echo "build accepted a symlink output directory" >&2; exit 1
fi

NORMAL_APP="$("$SCRIPT_DIR/build-app.sh" --adhoc --output-dir "$TEST_DIR/normal-app")"
if find "$NORMAL_APP" \( -name '*Legacy*Migration*' -o -name 'agentpass-legacy-*-migration' \) -print -quit | /usr/bin/grep -q .; then
  echo "transitional migration helper was embedded in the normal AgentPass app" >&2; exit 1
fi

echo "AgentPass legacy migration bundle verification passed"

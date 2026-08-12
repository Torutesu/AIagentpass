#!/usr/bin/env bash
set -euo pipefail

# Non-destructive installer qualification. Every positive fixture lives below
# a fresh temporary volume. The postinstall positive path is exercised only
# when the caller is already root; this script never asks for elevation.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentpass-installer-preservation.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

OWNER="$(/usr/bin/id -u)"
STATE_ROOT="$TEST_ROOT/Library/Application Support/AgentPass"
STORE="$STATE_ROOT/control-v2-bundles"
STORE_FILE="$STORE/generation-1.bundle"
EXTERNAL="$TEST_ROOT/external-sentinel"

make_fixture() {
  /bin/mkdir -p "$STORE"
  /bin/chmod 700 "$TEST_ROOT" "$TEST_ROOT/Library" "$TEST_ROOT/Library/Application Support" "$STATE_ROOT" "$STORE"
  /usr/bin/printf '%s\n' 'bundle-preserved' >"$STORE_FILE"
  /bin/chmod 600 "$STORE_FILE"
  /usr/bin/printf '%s\n' 'must-survive' >"$EXTERNAL"
  /bin/chmod 600 "$EXTERNAL"
  if [[ "$OWNER" == "0" ]]; then
    /usr/sbin/chown -R 0:0 "$TEST_ROOT"
  fi
}

validate_fixture() {
  "$SCRIPT_DIR/validate-preserved-state.sh" "$1" "$2" >/dev/null
}

expect_rejection() {
  if "$@" >/dev/null 2>&1; then
    echo "expected protected-path rejection" >&2
    exit 1
  fi
}

store_fingerprint() {
  /usr/bin/stat -f '%d:%i:%z:%m:%l:%u:%Lp' "$STATE_ROOT" "$STORE" "$STORE_FILE"
  /usr/bin/shasum -a 256 "$STORE_FILE"
}

make_fixture
before="$(store_fingerprint)"
validate_fixture "$TEST_ROOT" "$OWNER"
after="$(store_fingerprint)"
[[ "$before" == "$after" ]] || { echo "validation mutated a correct bundle store" >&2; exit 1; }

# Wrong owner is tested without changing ownership: validating the fixture
# against a different numeric owner must fail closed on every host.
expect_rejection validate_fixture "$TEST_ROOT" "$((OWNER + 1))"

/bin/chmod 750 "$STORE"
expect_rejection validate_fixture "$TEST_ROOT" "$OWNER"
/bin/chmod 700 "$STORE"

/bin/rm -f "$STORE_FILE"
/bin/ln -s "$EXTERNAL" "$STORE_FILE"
expect_rejection validate_fixture "$TEST_ROOT" "$OWNER"
[[ "$(/bin/cat "$EXTERNAL")" == "must-survive" ]] || { echo "symlink fixture changed its target" >&2; exit 1; }
/bin/rm -f "$STORE_FILE"
/usr/bin/printf '%s\n' 'bundle-preserved' >"$STORE_FILE"
/bin/chmod 600 "$STORE_FILE"

# A dangling protected-root symlink must be rejected too; -e alone is not a
# sufficient existence check for a security boundary.
/bin/rm -rf "$STATE_ROOT"
/bin/ln -s "$TEST_ROOT/missing-state" "$STATE_ROOT"
expect_rejection validate_fixture "$TEST_ROOT" "$OWNER"
[[ "$(/bin/cat "$EXTERNAL")" == "must-survive" ]] || { echo "dangling symlink fixture changed its target" >&2; exit 1; }
/bin/rm -f "$STATE_ROOT"
make_fixture

# A substituted target volume is rejected before any protected path is
# traversed. The real external directory remains byte-for-byte unchanged.
SUBSTITUTED="$TEST_ROOT/substituted-volume"
/bin/mkdir "$SUBSTITUTED"
/usr/bin/printf '%s\n' 'substituted-volume-sentinel' >"$SUBSTITUTED/sentinel"
/bin/ln -s "$SUBSTITUTED" "$TEST_ROOT/volume-link"
substituted_before="$(/usr/bin/shasum -a 256 "$SUBSTITUTED/sentinel")"
expect_rejection validate_fixture "$TEST_ROOT/volume-link" "$OWNER"
substituted_after="$(/usr/bin/shasum -a 256 "$SUBSTITUTED/sentinel")"
[[ "$substituted_before" == "$substituted_after" ]] || { echo "substituted volume was mutated" >&2; exit 1; }

if [[ "$OWNER" == "0" ]]; then
  # Build an ad-hoc, structurally valid app only inside TEST_ROOT, then run the
  # real postinstall twice. The bundle store fingerprint must be identical.
  APP_BUILD="$TEST_ROOT/app-build"
  APP_PATH="$("$SCRIPT_DIR/build-app.sh" --adhoc --output-dir "$APP_BUILD")"
  /bin/mkdir -p "$TEST_ROOT/Applications"
  /usr/bin/ditto "$APP_PATH" "$TEST_ROOT/Applications/AgentPass.app"
  postinstall_args=(package-id package-file "$TEST_ROOT")
  "$SCRIPT_DIR/installer-postinstall.sh" "${postinstall_args[@]}" >/dev/null
  first_postinstall="$(store_fingerprint)"
  "$SCRIPT_DIR/installer-postinstall.sh" "${postinstall_args[@]}" >/dev/null
  second_postinstall="$(store_fingerprint)"
  [[ "$first_postinstall" == "$second_postinstall" ]] || { echo "postinstall is not idempotent" >&2; exit 1; }
  echo "installer preservation qualification: passed (including postinstall idempotence)"
else
  # The production entry point must remain root-only. Do not emulate root or
  # bypass this check; positive postinstall qualification runs in root CI.
  postinstall_args=(package-id package-file "$TEST_ROOT")
  postinstall_before="$(store_fingerprint)"
  expect_rejection "$SCRIPT_DIR/installer-postinstall.sh" "${postinstall_args[@]}"
  postinstall_after="$(store_fingerprint)"
  [[ "$postinstall_before" == "$postinstall_after" ]] || { echo "non-root postinstall rejection mutated state" >&2; exit 1; }
  echo "installer preservation qualification: passed (postinstall positive path skipped; root required)"
fi

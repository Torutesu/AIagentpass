#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TARGET_VOLUME="${3:-/}"
[[ "$(/usr/bin/id -u)" == "0" ]] || { echo "AgentPass installer must run as root" >&2; exit 1; }
"$SCRIPT_DIR/validate-preserved-state.sh" "$TARGET_VOLUME" 0
TARGET_VOLUME="$(cd "$TARGET_VOLUME" && pwd -P)"

if [[ "$TARGET_VOLUME" == "/" ]]; then
  STATE_ROOT="/Library/Application Support/AgentPass"
  APP="/Applications/AgentPass.app"
else
  STATE_ROOT="${TARGET_VOLUME%/}/Library/Application Support/AgentPass"
  APP="${TARGET_VOLUME%/}/Applications/AgentPass.app"
fi

[[ ! -L "$STATE_ROOT" ]] || { echo "Protected AgentPass state root is a symlink" >&2; exit 1; }
if [[ ! -e "$STATE_ROOT" ]]; then
  /bin/mkdir -m 0700 "$STATE_ROOT"
  /usr/sbin/chown 0:0 "$STATE_ROOT"
fi
[[ -d "$STATE_ROOT" && ! -L "$STATE_ROOT" ]] || { echo "Protected AgentPass state root is not a real directory" >&2; exit 1; }
CONTROL_V2_BUNDLE_STORE="$STATE_ROOT/control-v2-bundles"
AGENT_SIGNING_INTENT_STORE="$STATE_ROOT/agent-signing-intents"
ensure_private_store() {
  local store="$1" label="$2"
  [[ ! -L "$store" ]] || { echo "Existing $label is a symlink" >&2; exit 1; }
  if [[ ! -e "$store" ]]; then
    /bin/mkdir -m 0700 "$store"
    /usr/sbin/chown 0:0 "$store"
  else
    [[ -d "$store" && ! -L "$store" ]] || { echo "Existing $label is not a real directory" >&2; exit 1; }
    [[ "$(/usr/bin/stat -f '%u:%Lp' "$store")" == "0:700" ]] || { echo "Existing $label is not root-owned mode 0700" >&2; exit 1; }
  fi
}
ensure_private_store "$CONTROL_V2_BUNDLE_STORE" "ControlBundle store"
ensure_private_store "$AGENT_SIGNING_INTENT_STORE" "Agent signing-intent store"
"$SCRIPT_DIR/validate-preserved-state.sh" "$TARGET_VOLUME" 0
[[ -d "$APP" && ! -L "$APP" ]] || { echo "Installed AgentPass.app is missing or substituted" >&2; exit 1; }
if /usr/bin/find -P "$APP" -type l -print -quit | /usr/bin/grep -q .; then
  echo "Installed AgentPass.app contains a symlink" >&2
  exit 1
fi
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"

# Registration remains an explicit SMAppService operation so an upgrade cannot
# silently replace the user's daemon approval state. The app and its embedded
# LaunchDaemon are one component payload and therefore advance together.
exit 0

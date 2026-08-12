#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TARGET_VOLUME="${3:-/}"
[[ "$(/usr/bin/id -u)" == "0" ]] || { echo "AgentPass installer must run as root" >&2; exit 1; }
"$SCRIPT_DIR/validate-preserved-state.sh" "$TARGET_VOLUME" 0

if [[ "$TARGET_VOLUME" == "/" ]]; then
  STATE_ROOT="/Library/Application Support/AgentPass"
  APP="/Applications/AgentPass.app"
else
  STATE_ROOT="${TARGET_VOLUME%/}/Library/Application Support/AgentPass"
  APP="${TARGET_VOLUME%/}/Applications/AgentPass.app"
fi

if [[ ! -e "$STATE_ROOT" ]]; then
  /bin/mkdir -m 0700 "$STATE_ROOT"
  /usr/sbin/chown 0:0 "$STATE_ROOT"
fi
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

#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
TARGET_VOLUME="${3:-/}"
[[ "$(/usr/bin/id -u)" == "0" ]] || { echo "AgentPass installer must run as root" >&2; exit 1; }
"$SCRIPT_DIR/validate-preserved-state.sh" "$TARGET_VOLUME" 0

# The component payload contains only /Applications/AgentPass.app. Protected
# service state is deliberately neither removed nor copied by this script.
exit 0

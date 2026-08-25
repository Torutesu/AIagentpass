#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
if [[ "$#" -gt 1 || ("${1:-}" != "" && "${1:-}" != "--dry-run") ]]; then
  echo "Usage: require-credentials.sh [--dry-run]" >&2
  exit 2
fi

exec node "$SCRIPT_DIR/validate-signing-inputs.mjs" "$@"

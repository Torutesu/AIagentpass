#!/bin/bash
set -euo pipefail

# Validate the state tree without following links. Installer entry points always
# pass the target volume and uid 0. The uid argument also makes the checker
# testable without weakening the signed installer scripts.
[[ $# -eq 2 ]] || { echo "Usage: validate-preserved-state.sh TARGET_VOLUME EXPECTED_UID" >&2; exit 2; }
TARGET_VOLUME="$1"
EXPECTED_UID="$2"
[[ "$TARGET_VOLUME" == /* && "$EXPECTED_UID" =~ ^[0-9]+$ ]] || { echo "Invalid preservation validation arguments" >&2; exit 2; }
[[ -d "$TARGET_VOLUME" && ! -L "$TARGET_VOLUME" ]] || { echo "Target volume is not a real directory" >&2; exit 1; }

TARGET_VOLUME="$(cd "$TARGET_VOLUME" && pwd -P)"
if [[ "$TARGET_VOLUME" == "/" ]]; then
  STATE_ROOT="/Library/Application Support/AgentPass"
else
  STATE_ROOT="${TARGET_VOLUME}/Library/Application Support/AgentPass"
fi

stat_field() { /usr/bin/stat -f "$1" "$2"; }
validate_ancestor() {
  local path="$1" uid mode type
  [[ -e "$path" ]] || return 0
  [[ ! -L "$path" ]] || { echo "Protected ancestry contains a symlink: $path" >&2; exit 1; }
  type="$(stat_field '%HT' "$path")"
  uid="$(stat_field '%u' "$path")"
  mode="$(stat_field '%Lp' "$path")"
  [[ "$type" == "Directory" && "$uid" == "$EXPECTED_UID" ]] || { echo "Unsafe protected ancestry type or owner: $path" >&2; exit 1; }
  (( (8#$mode & 8#022) == 0 )) || { echo "Protected ancestry is group/world writable: $path" >&2; exit 1; }
}

validate_ancestor "$TARGET_VOLUME"
validate_ancestor "${TARGET_VOLUME%/}/Library"
validate_ancestor "${TARGET_VOLUME%/}/Library/Application Support"
[[ -e "$STATE_ROOT" ]] || exit 0
validate_ancestor "$STATE_ROOT"

ROOT_DEVICE="$(stat_field '%d' "$STATE_ROOT")"
while IFS= read -r -d '' path; do
  type="$(stat_field '%HT' "$path")"
  uid="$(stat_field '%u' "$path")"
  mode="$(stat_field '%Lp' "$path")"
  links="$(stat_field '%l' "$path")"
  device="$(stat_field '%d' "$path")"
  [[ "$device" == "$ROOT_DEVICE" ]] || { echo "Protected state crosses a filesystem boundary: $path" >&2; exit 1; }
  [[ "$uid" == "$EXPECTED_UID" ]] || { echo "Protected state has unsafe ownership: $path" >&2; exit 1; }
  [[ "$type" != "Symbolic Link" ]] || { echo "Protected state contains a symlink: $path" >&2; exit 1; }
  (( (8#$mode & 8#077) == 0 )) || { echo "Protected state grants group/world permissions: $path" >&2; exit 1; }
  case "$type" in
    Directory) ;;
    "Regular File")
      [[ "$links" == "1" ]] || { echo "Protected state contains a hard-linked file: $path" >&2; exit 1; }
      ;;
    *) echo "Protected state contains an unsupported object: $path ($type)" >&2; exit 1 ;;
  esac
done < <(/usr/bin/find -P "$STATE_ROOT" -xdev -print0)

echo "Protected AgentPass state is safe to preserve: $STATE_ROOT"

#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "atomic rename integration test: skipped off macOS"
  exit 0
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
package_dir="$repo_dir/native/macos"
if [[ -n "${AGENTPASS_ATOMIC_RENAME_HELPER:-}" ]]; then
  helper="$AGENTPASS_ATOMIC_RENAME_HELPER"
else
  swift build --package-path "$package_dir" --product agentpass-atomic-rename >/dev/null
  helper="$(swift build --package-path "$package_dir" --show-bin-path)/agentpass-atomic-rename"
fi
[[ "$helper" == /* && -x "$helper" && ! -L "$helper" ]] || { echo "atomic rename helper is unsafe" >&2; exit 1; }

tmp_root="${TMPDIR:-/tmp}"
tmp_root="${tmp_root%/}"
tmp_root="$(cd "$tmp_root" && pwd -P)"
work_dir="$(mktemp -d "$tmp_root/agentpass-atomic-rename.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

boundary="$work_dir/project with spaces"
mkdir -m 700 "$boundary"
source_name="replacement with spaces"
destination_name="editor config"
source="$boundary/$source_name"
destination="$boundary/$destination_name"
outside="$work_dir/must-survive"
printf 'replacement\n' >"$source"
printf 'outside\n' >"$outside"
chmod 600 "$source" "$outside"
touch -t 200001010000.00 "$source"

owner="$(id -u)"
read -r source_dev source_ino source_size source_seconds < <(stat -f '%d %i %z %m' "$source")
source_mtime_ns="$((source_seconds * 1000000000))"

invoke() {
  "$helper" \
    --protocol agentpass.atomic-rename.v1 \
    --operation rename-no-replace \
    --source-parent "$boundary" \
    --source-name "$source_name" \
    --destination-parent "$boundary" \
    --destination-name "$destination_name" \
    --boundary "$boundary" \
    --owner "$owner" \
    --source-dev "$source_dev" \
    --source-ino "$source_ino" \
    --source-size "$source_size" \
    --source-mtime-ns "$source_mtime_ns"
}

success_output="$(invoke)"
[[ "$success_output" == '{"code":"ATOMIC_RENAME_COMPLETE","ok":true,"protocol":"agentpass.atomic-rename.v1"}' ]]
[[ ! -e "$source" ]]
[[ "$(cat "$destination")" == "replacement" ]]
[[ "$(cat "$outside")" == "outside" ]]

printf 'replacement-again\n' >"$source"
chmod 600 "$source"
touch -t 200001010000.00 "$source"
read -r source_dev source_ino source_size source_seconds < <(stat -f '%d %i %z %m' "$source")
source_mtime_ns="$((source_seconds * 1000000000))"
if conflict_output="$(invoke)"; then
  echo "expected RENAME_EXCL conflict" >&2
  exit 1
else
  conflict_status=$?
fi
[[ "$conflict_status" == 17 ]]
[[ "$conflict_output" == '{"code":"ATOMIC_RENAME_DESTINATION_EXISTS","ok":false,"protocol":"agentpass.atomic-rename.v1"}' ]]
[[ "$(cat "$destination")" == "replacement" ]]
[[ -f "$source" ]]

rm -f "$destination"
chmod 777 "$boundary"
if unsafe_output="$(invoke)"; then
  echo "expected private-parent rejection" >&2
  exit 1
else
  unsafe_status=$?
fi
[[ "$unsafe_status" == 77 ]]
[[ "$unsafe_output" == '{"code":"ATOMIC_RENAME_INVALID_INPUT","ok":false,"protocol":"agentpass.atomic-rename.v1"}' ]]
chmod 700 "$boundary"

if operation_output="$("$helper" --protocol agentpass.atomic-rename.v1 --operation replace)"; then
  echo "expected unknown operation rejection" >&2
  exit 1
else
  operation_status=$?
fi
[[ "$operation_status" == 64 ]]
[[ "$operation_output" == '{"code":"ATOMIC_RENAME_INVALID_INPUT","ok":false,"protocol":"agentpass.atomic-rename.v1"}' ]]

echo "atomic rename integration test: passed"

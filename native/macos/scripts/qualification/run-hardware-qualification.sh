#!/bin/bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/../../../../" && pwd -P)"
: "${AGENTPASS_QUALIFICATION_ARTIFACT:?AGENTPASS_QUALIFICATION_ARTIFACT is required}"
: "${AGENTPASS_QUALIFICATION_RELEASE_MANIFEST:?AGENTPASS_QUALIFICATION_RELEASE_MANIFEST is required}"
: "${AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_SIGNATURE:?AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_SIGNATURE is required}"
: "${AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_PUBLIC_KEY:?AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_PUBLIC_KEY is required}"
: "${AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_FINGERPRINT:?AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_FINGERPRINT is required}"
: "${AGENTPASS_QUALIFICATION_SOURCE_COMMIT:?AGENTPASS_QUALIFICATION_SOURCE_COMMIT is required}"
: "${AGENTPASS_QUALIFICATION_SOURCE_TREE:?AGENTPASS_QUALIFICATION_SOURCE_TREE is required}"
: "${AGENTPASS_QUALIFICATION_EXPECTED_TEAM_ID:?AGENTPASS_QUALIFICATION_EXPECTED_TEAM_ID is required}"
: "${AGENTPASS_QUALIFICATION_OUTPUT:?AGENTPASS_QUALIFICATION_OUTPUT is required}"
: "${AGENTPASS_RUNNER_ATTESTATION:?AGENTPASS_RUNNER_ATTESTATION is required}"
: "${AGENTPASS_RUNNER_ATTESTATION_SIGNATURE:?AGENTPASS_RUNNER_ATTESTATION_SIGNATURE is required}"
: "${AGENTPASS_RUNNER_ATTESTATION_PUBLIC_KEY:?AGENTPASS_RUNNER_ATTESTATION_PUBLIC_KEY is required}"
: "${AGENTPASS_RUNNER_ATTESTATION_FINGERPRINT:?AGENTPASS_RUNNER_ATTESTATION_FINGERPRINT is required}"
: "${AGENTPASS_QUALIFICATION_PROBE_STAGING_DIR:?AGENTPASS_QUALIFICATION_PROBE_STAGING_DIR is required}"
: "${AGENTPASS_LAUNCHD_HOST_CHILD_PROBE:?AGENTPASS_LAUNCHD_HOST_CHILD_PROBE is required}"
: "${AGENTPASS_NSXPC_PROBE:?AGENTPASS_NSXPC_PROBE is required}"
: "${AGENTPASS_CRASH_RESTART_PROBE:?AGENTPASS_CRASH_RESTART_PROBE is required}"
: "${AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SHA256:?AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SHA256 is required}"
: "${AGENTPASS_NSXPC_PROBE_SHA256:?AGENTPASS_NSXPC_PROBE_SHA256 is required}"
: "${AGENTPASS_CRASH_RESTART_PROBE_SHA256:?AGENTPASS_CRASH_RESTART_PROBE_SHA256 is required}"
: "${AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SIGNING_IDENTITY:=}"
: "${AGENTPASS_NSXPC_PROBE_SIGNING_IDENTITY:=}"
: "${AGENTPASS_CRASH_RESTART_PROBE_SIGNING_IDENTITY:=}"
: "${AGENTPASS_QUALIFICATION_EXPECTED_ARCHITECTURE:?AGENTPASS_QUALIFICATION_EXPECTED_ARCHITECTURE is required}"

for value in "$AGENTPASS_QUALIFICATION_ARTIFACT" "$AGENTPASS_QUALIFICATION_RELEASE_MANIFEST" "$AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_SIGNATURE" "$AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_PUBLIC_KEY" "$AGENTPASS_QUALIFICATION_OUTPUT" "$AGENTPASS_RUNNER_ATTESTATION" "$AGENTPASS_RUNNER_ATTESTATION_SIGNATURE" "$AGENTPASS_RUNNER_ATTESTATION_PUBLIC_KEY" "$AGENTPASS_QUALIFICATION_PROBE_STAGING_DIR" "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE" "$AGENTPASS_NSXPC_PROBE" "$AGENTPASS_CRASH_RESTART_PROBE"; do
  [[ "$value" == /* && "$value" != *$'\0'* ]] || { echo "qualification paths must be absolute" >&2; exit 1; }
done
[[ ! -e "$AGENTPASS_QUALIFICATION_OUTPUT" && ! -L "$AGENTPASS_QUALIFICATION_OUTPUT" ]] || { echo "qualification output already exists" >&2; exit 1; }
[[ "$AGENTPASS_QUALIFICATION_EXPECTED_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "expected Developer ID Team ID is invalid" >&2; exit 1; }
[[ "$AGENTPASS_QUALIFICATION_EXPECTED_ARCHITECTURE" == arm64 || "$AGENTPASS_QUALIFICATION_EXPECTED_ARCHITECTURE" == x86_64 ]] || { echo "expected architecture is invalid" >&2; exit 1; }

check_acl_free() {
  local value="$1" label="$2" permissions
  permissions="$(/bin/ls -lde "$value" 2>/dev/null | /usr/bin/awk 'NR == 1 { print $1 }')"
  [[ -n "$permissions" && "$permissions" != *+ ]] || { echo "$label has an ACL or could not be inspected" >&2; exit 1; }
}

check_probe_path() {
  local value="$1" label="$2" current mode
  [[ -f "$value" && -x "$value" && ! -L "$value" ]] || { echo "$label must be a regular non-symlink executable" >&2; exit 1; }
  [[ "$(stat -f '%Su' "$value")" == root ]] || { echo "$label must be root-owned" >&2; exit 1; }
  mode="$(stat -f '%Lp' "$value")"
  case "$mode" in [2367][0-7][0-7]|[0-7][2367][0-7]|[0-7][0-7][2367]) echo "$label must not be writable" >&2; exit 1;; esac
  check_acl_free "$value" "$label"
  current="$(dirname "$value")"
  while true; do
    [[ -d "$current" && ! -L "$current" ]] || { echo "$label has an unprotected ancestor directory" >&2; exit 1; }
    [[ "$(stat -f '%Su' "$current")" == root ]] || { echo "$label ancestor directory must be root-owned" >&2; exit 1; }
    mode="$(stat -f '%Lp' "$current")"
    case "$mode" in [2367][0-7][0-7]|[0-7][2367][0-7]|[0-7][0-7][2367]) echo "$label ancestor directory must not be writable" >&2; exit 1;; esac
    check_acl_free "$current" "$label ancestor directory"
    [[ "$current" == / ]] && break
    current="$(dirname "$current")"
  done
}

check_staging_directory() {
  local value="$1" label="$2" current mode
  [[ -d "$value" && ! -L "$value" ]] || { echo "$label must be an existing non-symlink directory" >&2; exit 1; }
  [[ "$(stat -f '%Su' "$value")" == root ]] || { echo "$label must be root-owned" >&2; exit 1; }
  mode="$(stat -f '%Lp' "$value")"
  case "$mode" in [2367][0-7][0-7]|[0-7][2367][0-7]|[0-7][0-7][2367]) echo "$label must not be writable" >&2; exit 1;; esac
  check_acl_free "$value" "$label"
  current="$(dirname "$value")"
  while true; do
    [[ -d "$current" && ! -L "$current" ]] || { echo "$label has an unprotected ancestor directory" >&2; exit 1; }
    [[ "$(stat -f '%Su' "$current")" == root ]] || { echo "$label ancestor directory must be root-owned" >&2; exit 1; }
    mode="$(stat -f '%Lp' "$current")"
    case "$mode" in [2367][0-7][0-7]|[0-7][2367][0-7]|[0-7][0-7][2367]) echo "$label ancestor directory must not be writable" >&2; exit 1;; esac
    check_acl_free "$current" "$label ancestor directory"
    [[ "$current" == / ]] && break
    current="$(dirname "$current")"
  done
}

check_staging_directory "$AGENTPASS_QUALIFICATION_PROBE_STAGING_DIR" "probe staging directory"
for value in "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE" "$AGENTPASS_NSXPC_PROBE" "$AGENTPASS_CRASH_RESTART_PROBE"; do
  check_probe_path "$value" "fixed probe"
done

developer_id_re='^Developer ID Application: [^()]+ \([A-Z0-9]{10}\)$'
check_probe_binding() {
  local digest="$1" identity="$2" label="$3"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo "$label exact expected SHA-256 is required and invalid" >&2; exit 1; }
  [[ -z "$identity" || "$identity" =~ $developer_id_re ]] || { echo "$label expected signing identity is invalid" >&2; exit 1; }
}
check_probe_binding "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SHA256" "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SIGNING_IDENTITY" "launchd host-child probe"
check_probe_binding "$AGENTPASS_NSXPC_PROBE_SHA256" "$AGENTPASS_NSXPC_PROBE_SIGNING_IDENTITY" "NSXPC probe"
check_probe_binding "$AGENTPASS_CRASH_RESTART_PROBE_SHA256" "$AGENTPASS_CRASH_RESTART_PROBE_SIGNING_IDENTITY" "crash/restart probe"

probe_args=(
  --launchd-probe "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE"
  --nsxpc-probe "$AGENTPASS_NSXPC_PROBE"
  --crash-restart-probe "$AGENTPASS_CRASH_RESTART_PROBE"
)
[[ -z "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SHA256" ]] || probe_args+=(--launchd-probe-sha256 "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SHA256")
[[ -z "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SIGNING_IDENTITY" ]] || probe_args+=(--launchd-probe-signing-identity "$AGENTPASS_LAUNCHD_HOST_CHILD_PROBE_SIGNING_IDENTITY")
[[ -z "$AGENTPASS_NSXPC_PROBE_SHA256" ]] || probe_args+=(--nsxpc-probe-sha256 "$AGENTPASS_NSXPC_PROBE_SHA256")
[[ -z "$AGENTPASS_NSXPC_PROBE_SIGNING_IDENTITY" ]] || probe_args+=(--nsxpc-probe-signing-identity "$AGENTPASS_NSXPC_PROBE_SIGNING_IDENTITY")
[[ -z "$AGENTPASS_CRASH_RESTART_PROBE_SHA256" ]] || probe_args+=(--crash-restart-probe-sha256 "$AGENTPASS_CRASH_RESTART_PROBE_SHA256")
[[ -z "$AGENTPASS_CRASH_RESTART_PROBE_SIGNING_IDENTITY" ]] || probe_args+=(--crash-restart-probe-signing-identity "$AGENTPASS_CRASH_RESTART_PROBE_SIGNING_IDENTITY")

exec /usr/bin/env node "$ROOT/native/macos/Qualification/hardware-qualification.mjs" \
  --artifact "$AGENTPASS_QUALIFICATION_ARTIFACT" \
  --release-manifest "$AGENTPASS_QUALIFICATION_RELEASE_MANIFEST" \
  --release-manifest-signature "$AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_SIGNATURE" \
  --release-manifest-public-key "$AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_PUBLIC_KEY" \
  --release-manifest-fingerprint "$AGENTPASS_QUALIFICATION_RELEASE_MANIFEST_FINGERPRINT" \
  --source-commit "$AGENTPASS_QUALIFICATION_SOURCE_COMMIT" \
  --source-tree "$AGENTPASS_QUALIFICATION_SOURCE_TREE" \
  --expected-team-id "$AGENTPASS_QUALIFICATION_EXPECTED_TEAM_ID" \
  --runner-attestation "$AGENTPASS_RUNNER_ATTESTATION" \
  --runner-attestation-signature "$AGENTPASS_RUNNER_ATTESTATION_SIGNATURE" \
  --runner-attestation-public-key "$AGENTPASS_RUNNER_ATTESTATION_PUBLIC_KEY" \
  --runner-attestation-fingerprint "$AGENTPASS_RUNNER_ATTESTATION_FINGERPRINT" \
  --expected-architecture "$AGENTPASS_QUALIFICATION_EXPECTED_ARCHITECTURE" \
  --probe-staging-directory "$AGENTPASS_QUALIFICATION_PROBE_STAGING_DIR" \
  --output "$AGENTPASS_QUALIFICATION_OUTPUT" \
  "${probe_args[@]}"

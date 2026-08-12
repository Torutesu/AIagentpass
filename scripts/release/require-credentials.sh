#!/bin/bash
set -euo pipefail

missing=()
for name in AGENTPASS_SIGNING_CERTIFICATE_P12_BASE64 AGENTPASS_SIGNING_CERTIFICATE_PASSWORD AGENTPASS_SIGNING_IDENTITY AGENTPASS_INSTALLER_SIGNING_IDENTITY AGENTPASS_TEAM_ID AGENTPASS_APP_IDENTIFIER_PREFIX AGENTPASS_SERVICE_PROFILE_BASE64 AGENTPASS_CLIENT_PROFILE_BASE64 AGENTPASS_EPHEMERAL_KEYCHAIN_PASSWORD AGENTPASS_RELEASE_MANIFEST_PRIVATE_KEY_BASE64 AGENTPASS_NOTARY_KEY_ID AGENTPASS_NOTARY_ISSUER_ID AGENTPASS_NOTARY_PRIVATE_KEY_BASE64; do
  [[ -n "${!name:-}" ]] || missing+=("$name")
done
if [[ "${#missing[@]}" -gt 0 ]]; then
  echo "Release candidate credentials are incomplete: ${missing[*]}" >&2
  exit 1
fi
[[ "$AGENTPASS_TEAM_ID" =~ ^[A-Z0-9]{10}$ && "$AGENTPASS_APP_IDENTIFIER_PREFIX" =~ ^[A-Z0-9]{10}$ ]] || { echo "Release candidate Team ID or prefix is invalid" >&2; exit 1; }
echo "Release candidate credential inputs are present; this does not prove signing or notarization success" >&2

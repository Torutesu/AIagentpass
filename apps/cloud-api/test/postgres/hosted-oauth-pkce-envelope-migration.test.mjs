import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const sql = fs.readFileSync(path.join(root, "contracts/postgres/0058_hosted_oauth_pkce_envelope.sql"), "utf8");

test("0058 remains the forward-only encrypted PKCE envelope migration", () => {
  assert.deepEqual(POSTGRES_SCHEMA_HEAD.migrations.find(({ version }) => version === 58)?.name, "0058_hosted_oauth_pkce_envelope.sql");
  assert.match(sql, /^BEGIN;/u);
  assert.match(sql, /COMMIT;\s*$/u);
  assert.match(sql, /CREATE TABLE public\.hosted_identity_oauth_pkce_envelopes/u);
  assert.match(sql, /octet_length\(nonce\) = 12/u);
  assert.match(sql, /octet_length\(auth_tag\) = 16/u);
  assert.doesNotMatch(sql, /pkce_verifier\s+text|client_secret|access_token/iu);
});

test("0058 atomically starts and one-time claims exact state/redirect/code bindings", () => {
  assert.match(sql, /agentpass_hosted_identity_bootstrap_start_v2/u);
  assert.match(sql, /agentpass_hosted_identity_oauth_state_claim_v2/u);
  assert.match(sql, /state_row\.state_hash IS DISTINCT FROM p_state_hash OR state_row\.redirect_uri <> p_redirect_uri/u);
  assert.match(sql, /SET status = 'consuming', code_hash = p_code_hash, consume_started_at = now_value/u);
  assert.match(sql, /DELETE FROM public\.hosted_identity_oauth_pkce_envelopes WHERE oauth_state_id = state_row\.id/u);
  assert.match(sql, /pkce_envelope_missing/u);
  assert.match(sql, /oauth_binding_mismatch/u);
});

test("0058 exposes no deployment role names and revokes PUBLIC only", () => {
  assert.doesNotMatch(sql, /agentpass_app|agentpass_backup|agentpass_signer/u);
  assert.doesNotMatch(sql, /\bGRANT\b/iu);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.hosted_identity_oauth_pkce_envelopes FROM PUBLIC/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_hosted_identity_bootstrap_start_v2\([^;]+\) FROM PUBLIC/u);
});

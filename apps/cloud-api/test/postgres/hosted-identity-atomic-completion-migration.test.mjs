import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("0059 remains the cataloged forward-only atomic identity completion migration", async () => {
  const [sql, catalog] = await Promise.all([
    read("contracts/postgres/0059_hosted_identity_atomic_completion.sql"),
    read("contracts/catalog-v1.json").then(JSON.parse)
  ]);
  assert.ok(POSTGRES_SCHEMA_HEAD.version >= 59);
  assert.match(sql, /^BEGIN;[\s\S]*COMMIT;\s*$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  const entry = catalog.entries.find(({ id }) => id === "migration.0059_hosted_identity_atomic_completion");
  assert.equal(entry?.version, 59);
});

test("0059 serializes immutable subject resolution and prevents orphan members", async () => {
  const sql = await read("contracts/postgres/0059_hosted_identity_atomic_completion.sql");
  assert.match(sql, /agentpass_hosted_identity_oauth_complete_v2\(\s*p_oauth_state_id uuid,\s*p_attempt_id uuid,\s*p_bootstrap_cookie_hash bytea,\s*p_candidate_member_id uuid,\s*p_provider text,\s*p_subject text,\s*p_subject_digest bytea/um);
  assert.match(sql, /pg_advisory_xact_lock\(hashtextextended\(p_provider \|\| chr\(31\) \|\| p_subject, 0\)\)/u);
  assert.match(sql, /FROM public\.upstream_identities AS i[\s\S]*FOR KEY SHARE/u);
  assert.match(sql, /INSERT INTO public\.members[\s\S]*INSERT INTO public\.upstream_identities/u);
  assert.match(sql, /FROM public\.members AS m WHERE m\.id = resolved_member_id FOR UPDATE/u);
  assert.doesNotMatch(sql, /ON CONFLICT[\s\S]*DO NOTHING/iu);
});

test("0059 classifies complete membership history and commits OAuth plus attempt together", async () => {
  const sql = await read("contracts/postgres/0059_hosted_identity_atomic_completion.sql");
  assert.match(sql, /count\(\*\), count\(DISTINCT m\.organization_id\) FILTER \(WHERE m\.status = 'active'\)/u);
  assert.match(sql, /WHEN active_organization_count > 0 THEN 'identity_verified'[\s\S]*WHEN membership_count = 0 THEN 'organization_required'[\s\S]*ELSE 'no_membership'/u);
  assert.match(sql, /SET status = 'consumed', consumed_at = now_value/u);
  assert.match(sql, /SET state = target_state,[\s\S]*bootstrap_cookie_hash = p_bootstrap_cookie_hash[\s\S]*identity_subject_digest = p_subject_digest/u);
  assert.match(sql, /DELETE FROM public\.hosted_identity_oauth_pkce_envelopes WHERE oauth_state_id = oauth_row\.id/u);
  assert.match(sql, /RETURN QUERY SELECT attempt_row\.id, target_state, active_organization_count, attempt_row\.expires_at/u);
});

test("0059 exposes only the v2 function and least-privilege runtime allowlists", async () => {
  const [sql, roles, checker] = await Promise.all([
    read("contracts/postgres/0059_hosted_identity_atomic_completion.sql"),
    read("scripts/postgres/roles.sql"),
    read("scripts/postgres/role-privilege-check.mjs")
  ]);
  const signature = "agentpass_hosted_identity_oauth_complete_v2(uuid,uuid,bytea,uuid,text,text,bytea)";
  assert.doesNotMatch(sql, /agentpass_app|agentpass_backup|agentpass_signer/u);
  assert.doesNotMatch(sql, /\bGRANT\b/iu);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_hosted_identity_oauth_complete_v2\([^;]+\) FROM PUBLIC/u);
  assert.ok(roles.includes(`'${signature}'`));
  assert.ok(checker.includes(`('${signature}')`));
  assert.doesNotMatch(roles, /'agentpass_hosted_identity_oauth_state_complete\(uuid,bytea,uuid,text,bytea\)'/u);
  assert.doesNotMatch(checker, /\('agentpass_hosted_identity_oauth_state_complete\(uuid,bytea,uuid,text,bytea\)'\)/u);
});

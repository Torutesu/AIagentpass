import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("0061 is the cataloged forward-only hosted OAuth output qualification head", async () => {
  const [sql, catalog] = await Promise.all([
    read("contracts/postgres/0061_hosted_oauth_output_qualification.sql"),
    read("contracts/catalog-v1.json").then(JSON.parse)
  ]);
  assert.equal(POSTGRES_SCHEMA_HEAD.version, 61);
  assert.equal(POSTGRES_SCHEMA_HEAD.name, "0061_hosted_oauth_output_qualification.sql");
  assert.match(sql, /^BEGIN;[\s\S]*COMMIT;\s*$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  assert.equal(catalog.entries.at(-1).id, "migration.0061_hosted_oauth_output_qualification");
  assert.equal(catalog.entries.at(-1).version, 61);
});

test("0061 preserves frozen signatures and pins output-column resolution", async () => {
  const sql = await read("contracts/postgres/0061_hosted_oauth_output_qualification.sql");
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_hosted_identity_bootstrap_start_v2\(/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_hosted_identity_oauth_state_claim_v2\(/u);
  assert.equal((sql.match(/#variable_conflict use_column/gu) ?? []).length, 2);
  assert.match(sql, /DELETE FROM public\.hosted_identity_oauth_pkce_envelopes AS e WHERE e\.oauth_state_id = state_row\.id/u);
  assert.doesNotMatch(sql, /access_token|client_secret|pkce_verifier\s+text/iu);
});

test("0061 retains function-only deployment authority", async () => {
  const sql = await read("contracts/postgres/0061_hosted_oauth_output_qualification.sql");
  assert.doesNotMatch(sql, /agentpass_app|agentpass_backup|agentpass_signer/iu);
  assert.doesNotMatch(sql, /\bGRANT\b/iu);
  assert.equal((sql.match(/REVOKE ALL PRIVILEGES ON FUNCTION/gu) ?? []).length, 2);
});

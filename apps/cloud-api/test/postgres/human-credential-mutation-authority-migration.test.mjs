import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migration = new URL("../../../../contracts/postgres/0094_human_credential_mutation_authority.sql", import.meta.url);
const repository = new URL("../../src/postgres/human-repository.mjs", import.meta.url);

test("credential label and revoke mutations are authority-bound CAS operations", async () => {
  const sql = await readFile(migration, "utf8");
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_update_credential_label\(/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_human_revoke_credential\(/u);
  assert.equal((sql.match(/^SECURITY DEFINER$/gmu) ?? []).length, 2);
  assert.equal((sql.match(/SET search_path = pg_catalog, public/g) ?? []).length, 2);
  for (const fragment of ["c.version = p_expected_version", "c.revoked_at IS NULL", "c.clone_detected_at IS NULL", "m.role = s.role", "o.authority_epoch = s.organization_authority_epoch", "m.session_epoch = s.membership_session_epoch", "webauthn_credentials_last_active"]) {
    assert.match(sql, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }
});

test("repository routes label and revoke writes through authority functions", async () => {
  const source = await readFile(repository, "utf8");
  assert.match(source, /agentpass_human_update_credential_label\(\$1::uuid,\$2::uuid,\$3::uuid/u);
  assert.match(source, /agentpass_human_revoke_credential\(\$1::uuid,\$2::uuid,\$3::uuid/u);
});

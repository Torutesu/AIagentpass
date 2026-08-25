import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { defaultContractDirectory, loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0026_owner_recovery_webauthn.sql", import.meta.url);

test("0026 is contiguous and binds WebAuthn only to restricted recovery sessions", async () => {
  const migrations = await loadSqlMigrations(defaultContractDirectory());
  assert.equal(migrations.find((migration) => migration.version === 26)?.name, "0026_owner_recovery_webauthn.sql");
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.match(sql, /FOREIGN KEY \(organization_id, recovery_session_id\)[\s\S]*REFERENCES owner_recovery_sessions/u);
  assert.doesNotMatch(sql, /REFERENCES human_sessions/u);
  assert.match(sql, /human\.recovery\.credential\.register/u);
  assert.match(sql, /human\.recovery\.activate/u);
});

test("0026 stores challenge digests and a one-time activation authorization marker", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /challenge_digest bytea NOT NULL UNIQUE CHECK \(octet_length\(challenge_digest\) = 32\)/u);
  assert.doesNotMatch(sql, /\bchallenge\s+(?:text|bytea)/iu);
  assert.doesNotMatch(sql, /(?:assertion|attestation|client_data|authenticator_data)\s+(?:text|bytea|jsonb)/iu);
  assert.match(sql, /authorization_consumed_at timestamptz/u);
  assert.match(sql, /authorization_consumed_at IS NULL/u);
  assert.match(sql, /owner_recovery_webauthn_one_live_operation/u);
});

test("0026 preserves exact retry identity without persisting verifier material", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /verified_credential_id bytea/u);
  assert.match(sql, /status = 'consumed'[\s\S]*verified_credential_id IS NOT NULL/u);
  assert.match(sql, /PRIMARY KEY \(organization_id, challenge_id\)/u);
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0072_human_webauthn_clone_quarantine.sql", import.meta.url);

test("0072 makes Human WebAuthn clone quarantine monotonic and distinct from revocation", async () => {
  const migration = await readFile(migrationUrl, "utf8");

  assert.match(migration, /^BEGIN;[\s\S]*COMMIT;\s*$/u);
  assert.match(migration, /sign_count_state text NOT NULL[\s\S]*'clone-detected'/u);
  assert.match(migration, /clone_detected_at timestamptz/u);
  assert.match(migration, /CREATE TRIGGER webauthn_credentials_clone_quarantine_monotonic/u);
  assert.match(migration, /WebAuthn clone quarantine is irreversible/u);
  assert.match(migration, /WHERE revoked_at IS NULL AND clone_detected_at IS NULL/u);
  assert.match(migration, /CREATE OR REPLACE FUNCTION agentpass_prevent_last_webauthn_credential_revoke/u);
  assert.match(migration, /cannot revoke the last usable WebAuthn credential/u);
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../../", import.meta.url);
const read = (relativePath) => readFile(new URL(relativePath, root), "utf8");

test("authority relation ACL reconciliation clears stale app writes and restores contract reads", async () => {
  const sql = await read("scripts/postgres/roles.sql");
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.%I FROM agentpass_app, agentpass_backup/u);
  assert.match(sql, /GRANT SELECT ON TABLE public\.%I TO agentpass_app, agentpass_backup/u);
  assert.match(sql, /hosted_identity_/u);
  assert.match(sql, /platform_/u);
  assert.match(sql, /managed_signer_/u);
});

test("privilege checker exposes bounded, relation-only diagnostics without secret-bearing ACL data", async () => {
  const checker = await read("scripts/postgres/role-privilege-check.mjs");
  assert.match(checker, /MAX_TABLE_DIAGNOSTICS = 32/u);
  assert.match(checker, /LIMIT \$\{MAX_TABLE_DIAGNOSTICS\}/u);
  assert.match(checker, /table_privilege_diagnostics/u);
  assert.match(checker, /table_diagnostics=/u);
  assert.match(checker, /left\(relname, \$\{MAX_RELATION_DIAGNOSTIC_NAME\}\)/u);
  assert.match(checker, /cardinality\(failures\)/u);
  assert.doesNotMatch(checker, /table_privilege_diagnostics[\s\S]{0,512}(?:password|secret|token|credential|proacl)/iu);
});

test("authority diagnostics preserve the existing app SELECT contract", async () => {
  const [roles, checker] = await Promise.all([
    read("scripts/postgres/roles.sql"),
    read("scripts/postgres/role-privilege-check.mjs"),
  ]);
  assert.match(roles, /GRANT SELECT ON TABLE public\.%I TO agentpass_app, agentpass_backup/u);
  assert.match(checker, /has_table_privilege\('agentpass_app', t\.oid, 'SELECT'\)/u);
  assert.match(checker, /THEN 'authority'[\s\S]*AS expected_class/u);
  assert.match(checker, /app:insert/u);
  assert.match(checker, /app:update/u);
  assert.match(checker, /app:delete/u);
});

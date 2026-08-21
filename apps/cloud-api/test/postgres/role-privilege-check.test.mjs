import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../../", import.meta.url);
const read = (relativePath) => readFile(new URL(relativePath, root), "utf8");

test("authority ACL reconciliation keeps Hosted runtime function-only and backup-readable", async () => {
  const sql = await read("scripts/postgres/roles.sql");
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE public\.%I FROM agentpass_app, agentpass_backup/u);
  assert.match(sql, /GRANT SELECT ON TABLE public\.%I TO agentpass_app, agentpass_backup/u);
  assert.match(sql, /Hosted bootstrap is function-only[\s\S]*GRANT SELECT ON TABLE public\.%I TO agentpass_backup/u);
  assert.match(sql, /c\.relkind IN \('r', 'p', 'v', 'm', 'f'\)/u);
  assert.match(sql, /hosted_identity_/u);
  assert.match(sql, /platform_/u);
  assert.match(sql, /managed_signer_/u);
});

test("privilege checker exposes bounded, relation-only diagnostics without secret-bearing ACL data", async () => {
  const checker = await read("scripts/postgres/role-privilege-check.mjs");
  assert.match(checker, /SELECT c\.oid, c\.relname, c\.relkind, c\.relowner/u);
  assert.match(checker, /MAX_TABLE_DIAGNOSTICS = 32/u);
  assert.match(checker, /LIMIT \$\{MAX_TABLE_DIAGNOSTICS\}/u);
  assert.match(checker, /table_privilege_diagnostics/u);
  assert.match(checker, /table_diagnostics=/u);
  assert.match(checker, /left\(relname, \$\{MAX_RELATION_DIAGNOSTIC_NAME\}\)/u);
  assert.match(checker, /cardinality\(failures\)/u);
  assert.doesNotMatch(checker, /table_privilege_diagnostics[\s\S]{0,512}(?:password|secret|token|credential|proacl)/iu);
});

test("authority diagnostics enforce function-only app reads for Hosted, Platform, and managed signer tables", async () => {
  const [roles, checker] = await Promise.all([
    read("scripts/postgres/roles.sql"),
    read("scripts/postgres/role-privilege-check.mjs"),
  ]);
  assert.match(roles, /GRANT SELECT ON TABLE public\.%I TO agentpass_app, agentpass_backup/u);
  assert.match(roles, /Hosted bootstrap is function-only[\s\S]*GRANT SELECT ON TABLE public\.%I TO agentpass_backup/u);
  assert.match(checker, /left\(t\.relname, length\('managed_signer_'\)\) = 'managed_signer_'[\s\S]*left\(t\.relname, length\('platform_'\)\) = 'platform_'[\s\S]*left\(t\.relname, length\('hosted_identity_'\)\) = 'hosted_identity_'[\s\S]*NOT has_table_privilege\('agentpass_app', t\.oid, 'SELECT'\)/u);
  assert.match(checker, /THEN 'authority'[\s\S]*AS expected_class/u);
  assert.match(checker, /app:insert/u);
  assert.match(checker, /app:update/u);
  assert.match(checker, /app:delete/u);
});

test("CI service-role login qualification follows the shared PostgreSQL schema head", async () => {
  const workflow = await read(".github/workflows/ci.yml");
  const inlineModules = workflow.split("node --input-type=module <<'NODE'").slice(1).map((value) => value.split("\n          NODE", 1)[0]);
  for (const moduleSource of inlineModules) {
    const imports = moduleSource.match(/import \{ POSTGRES_SCHEMA_HEAD \} from "\.\/apps\/cloud-api\/src\/postgres\/schema-head\.mjs";/gu) ?? [];
    assert.ok(imports.length <= 1, "an inline CI module must not redeclare the schema-head import");
  }
  assert.match(workflow, /Verify actual service-role login boundaries[\s\S]*import \{ POSTGRES_SCHEMA_HEAD \}[\s\S]*assert\.equal\(head\.rows\[0\]\.version, POSTGRES_SCHEMA_HEAD\.version\)/u);
  assert.doesNotMatch(workflow, /assert\.equal\(head\.rows\[0\]\.version, 55\)/u);
});

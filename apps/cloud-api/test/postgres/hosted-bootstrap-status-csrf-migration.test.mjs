import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0064_hosted_bootstrap_status_csrf.sql", import.meta.url);
const rolesUrl = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);
const roleCheckerUrl = new URL("../../../../scripts/postgres/role-privilege-check.mjs", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);
const contractUrl = new URL("../../../../contracts/hosted-identity-bootstrap-v1.contract.json", import.meta.url);
const validatorUrl = new URL("../../../../scripts/validate-hosted-identity-bootstrap.mjs", import.meta.url);

function withoutComments(sql) {
  return sql.replace(/--[^\n]*|\/\*[\s\S]*?\*\//gu, "");
}

function functionBody(sql, name) {
  const start = sql.indexOf(`CREATE FUNCTION public.${name}`);
  assert.notEqual(start, -1, `${name} is missing`);
  const next = sql.indexOf("\nCREATE FUNCTION ", start + 1);
  const revoke = sql.indexOf("\nREVOKE ", start + 1);
  const end = [next, revoke].filter((value) => value >= 0).sort((a, b) => a - b)[0] ?? sql.length;
  return sql.slice(start, end);
}

test("0064 exposes only database-clock status and exact CSRF verification authorities", async () => {
  const sql = withoutComments(await readFile(migrationUrl, "utf8"));
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_guard_hosted_identity_bootstrap_attempt/u);
  assert.match(sql, /CSRF binding is immutable/u);
  assert.match(sql, /OLD\.state = 'no_membership' AND NEW\.state = 'expired'/u);

  const status = functionBody(sql, "agentpass_hosted_identity_bootstrap_status_v2");
  const csrf = functionBody(sql, "agentpass_hosted_identity_bootstrap_csrf_verify_v2");
  for (const body of [status, csrf]) {
    assert.match(body, /SECURITY DEFINER/u);
    assert.match(body, /SET search_path\s*=\s*pg_catalog, public/u);
    assert.match(body, /octet_length\(p_bootstrap_cookie_hash\) IS DISTINCT FROM 32/u);
    assert.match(body, /octet_length\(p_csrf_token_hash\) IS DISTINCT FROM 32/u);
    assert.match(body, /clock_timestamp\(\)/u);
    assert.match(body, /FOR UPDATE/u);
  }
  assert.match(status, /RETURNS TABLE\s*\([\s\S]*state text[\s\S]*organization_count bigint[\s\S]*webauthn_required boolean[\s\S]*can_create_first_organization boolean[\s\S]*expires_at timestamptz/u);
  assert.match(status, /csrf_token_hash IS NULL[\s\S]*SET csrf_token_hash = p_csrf_token_hash/u);
  assert.match(status, /csrf_token_hash IS DISTINCT FROM p_csrf_token_hash/u);
  assert.match(status, /count\(DISTINCT m\.organization_id\) FILTER \(WHERE m\.status = 'active'\)/u);
  assert.match(status, /state = 'organization_required' AND membership_count = 0/u);
  assert.match(status, /IF attempt_row\.state = 'expired'[\s\S]*RETURN QUERY SELECT[\s\S]*'expired'::text[\s\S]*0::bigint[\s\S]*false[\s\S]*false[\s\S]*attempt_row\.expires_at/u);
  assert.match(status, /IF attempt_row\.state = 'completed'[\s\S]*count\(DISTINCT m\.organization_id\) FILTER \(WHERE m\.status = 'active'\)[\s\S]*RETURN QUERY SELECT[\s\S]*'completed'::text[\s\S]*false[\s\S]*false[\s\S]*attempt_row\.expires_at/u);
  assert.match(status, /failure_code = 'bootstrap_expired'[\s\S]*RETURN QUERY SELECT[\s\S]*'expired'::text/u);
  assert.ok(status.indexOf("IF attempt_row.state = 'expired'") < status.indexOf("IF attempt_row.csrf_token_hash IS NULL"), "expired status must not install a CSRF digest");
  assert.ok(status.indexOf("IF attempt_row.state = 'completed'") < status.indexOf("IF attempt_row.csrf_token_hash IS NULL"), "completed status must not install a CSRF digest");
  assert.match(csrf, /RETURNS boolean/u);
  assert.match(csrf, /attempt_row\.csrf_token_hash = p_csrf_token_hash/u);
  assert.match(csrf, /attempt_row\.state NOT IN \([\s\S]*'identity_verified'[\s\S]*'organization_required'[\s\S]*'webauthn_required'[\s\S]*'ready'/u);
  assert.doesNotMatch(csrf, /'completed'/u, "completed must never be CSRF-usable");
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_hosted_identity_bootstrap_status_v2\(bytea, bytea\) FROM PUBLIC/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_hosted_identity_bootstrap_csrf_verify_v2\(bytea, bytea\) FROM PUBLIC/u);
  assert.doesNotMatch(sql, /private_key|client_secret|access_token|refresh_token/iu);
});

test("0064 is cataloged, activated, and granted without app table reads", async () => {
  const [roles, checker, catalog, contract, validator] = await Promise.all([
    readFile(rolesUrl, "utf8"),
    readFile(roleCheckerUrl, "utf8"),
    readFile(catalogUrl, "utf8").then(JSON.parse),
    readFile(contractUrl, "utf8").then(JSON.parse),
    readFile(validatorUrl, "utf8")
  ]);
  const statusSignature = "agentpass_hosted_identity_bootstrap_status_v2(bytea,bytea)";
  const verifySignature = "agentpass_hosted_identity_bootstrap_csrf_verify_v2(bytea,bytea)";
  for (const signature of [statusSignature, verifySignature]) {
    assert.equal(roles.includes(`'${signature}'`), true, signature);
    assert.equal(checker.includes(`('${signature}')`), true, signature);
  }
  assert.doesNotMatch(roles, /GRANT SELECT ON TABLE public\.hosted_identity_[^;]* TO agentpass_app/u);
  assert.equal(roles.includes("'agentpass_hosted_identity_bootstrap_csrf_issue(bytea,bytea)'"), false);
  assert.equal(checker.includes("('agentpass_hosted_identity_bootstrap_csrf_issue(bytea,bytea)')"), false);
  const entry = catalog.entries.find((item) => item.id === "migration.0064_hosted_bootstrap_status_csrf");
  assert.deepEqual(entry, {
    id: "migration.0064_hosted_bootstrap_status_csrf",
    kind: "postgres-migration",
    source: "postgres/0064_hosted_bootstrap_status_csrf.sql",
    version: 64,
    profile: "migration-global",
    purpose: "migration.0064.hosted-bootstrap-status-csrf",
    implementation_status: "implemented",
    tenant_binding: {
      required: true,
      source: "database",
      paths: ["tables.hosted_identity_bootstrap_attempts.bootstrap_cookie_hash", "tables.hosted_identity_bootstrap_attempts.member_id"]
    },
    implementation_refs: [
      "contracts/postgres/0064_hosted_bootstrap_status_csrf.sql",
      "contracts/hosted-identity-bootstrap-v1.contract.json",
      "apps/cloud-api/src/postgres/hosted-identity-bootstrap-repository.mjs",
      "apps/cloud-api/src/hosted-identity/bootstrap-service.mjs",
      "apps/cloud-api/src/hosted-bootstrap/runtime.mjs",
      "apps/cloud-api/src/runtime.mjs",
      "apps/cloud-api/src/server.mjs",
      "scripts/postgres/roles.sql",
      "scripts/postgres/role-privilege-check.mjs",
      "scripts/validate-hosted-identity-bootstrap.mjs"
    ],
    compatibility_fixtures: [
      "apps/cloud-api/test/postgres/hosted-bootstrap-status-csrf-migration.test.mjs",
      "apps/cloud-api/test/postgres/hosted-bootstrap-status-csrf-repository.test.mjs",
      "apps/cloud-api/test/postgres/hosted-bootstrap-status-csrf.integration.test.mjs",
      "apps/cloud-api/test/hosted-identity/bootstrap-service.test.mjs",
      "apps/cloud-api/test/hosted-bootstrap/runtime.test.mjs",
      "apps/cloud-api/test/server-hosted-bootstrap-routing.test.mjs"
    ]
  });
  assert.equal(catalog.entries.filter((item) => item.kind === "postgres-migration").length, 65);
  assert.equal(catalog.entries.length, 176);
  assert.equal(contract.activation.bootstrap_status_csrf_forward_migration, "0064_hosted_bootstrap_status_csrf");
  assert.match(contract.authority.bootstrap_status_csrf_authority, /status_v2/u);
  assert.match(contract.authority.bootstrap_status_csrf_authority, /csrf_verify_v2/u);
  assert.match(validator, /0064_hosted_bootstrap_status_csrf/u);
});

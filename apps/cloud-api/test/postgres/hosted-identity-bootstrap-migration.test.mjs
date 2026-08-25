import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { migrationChecksum } from "../../src/postgres/migration-runner.mjs";

const migrationUrl = new URL("../../../../contracts/postgres/0057_hosted_identity_bootstrap.sql", import.meta.url);
const catalogUrl = new URL("../../../../contracts/catalog-v1.json", import.meta.url);
const rolesUrl = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);

function bodyOf(sql, name) {
  const start = sql.indexOf(`CREATE FUNCTION public.${name}`);
  assert.notEqual(start, -1, `${name} is missing`);
  const end = sql.indexOf("\nCREATE FUNCTION ", start + 1);
  return sql.slice(start, end < 0 ? sql.length : end);
}

test("0057 is transactional, additive, and cataloged as the schema head", async () => {
  const [sql, catalog] = await Promise.all([
    readFile(migrationUrl, "utf8"),
    readFile(catalogUrl, "utf8").then(JSON.parse)
  ]);
  const sha256 = migrationChecksum(sql);
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  assert.doesNotMatch(sql, /ALTER TABLE public\.(?:members|organizations|memberships|human_sessions|webauthn_credentials|webauthn_challenges)/iu);
  assert.doesNotMatch(sql, /agentpass_(?:app|signer|backup|migrator)/u);
  assert.deepEqual(catalog.entries.find((entry) => entry.id === "migration.0057_hosted_identity_bootstrap"), {
    id: "migration.0057_hosted_identity_bootstrap",
    kind: "postgres-migration",
    source: "postgres/0057_hosted_identity_bootstrap.sql",
    version: 57,
    sha256,
    profile: "migration-global",
    purpose: "migration.0057.hosted-identity-bootstrap",
    implementation_status: "implemented",
    tenant_binding: {
      required: true,
      source: "database",
      paths: [
        "tables.hosted_identity_bootstrap_attempts.organization_id",
        "tables.hosted_identity_bootstrap_idempotency.organization_id",
        "tables.hosted_identity_bootstrap_webauthn_challenges.organization_id"
      ]
    },
    implementation_refs: ["contracts/postgres/0057_hosted_identity_bootstrap.sql", "scripts/postgres/roles.sql"],
    compatibility_fixtures: ["apps/cloud-api/test/postgres/hosted-identity-bootstrap-migration.test.mjs"]
  });
});

test("0057 hashes OAuth/cookie/CSRF selectors and binds PKCE plus exact redirect", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /state_hash bytea NOT NULL UNIQUE CHECK \(octet_length\(state_hash\) = 32\)/u);
  assert.match(sql, /code_hash bytea UNIQUE CHECK \(code_hash IS NULL OR octet_length\(code_hash\) = 32\)/u);
  assert.match(sql, /pkce_challenge text NOT NULL[\s\S]*pkce_method text NOT NULL CHECK \(pkce_method = 'S256'\)/u);
  assert.match(sql, /redirect_uri <> p_redirect_uri/u);
  assert.match(bodyOf(sql, "agentpass_hosted_identity_oauth_state_consume"), /failure_code = 'redirect_uri_mismatch'[\s\S]*RETURN;/u);
  assert.match(sql, /bootstrap_cookie_hash bytea CHECK \(bootstrap_cookie_hash IS NULL OR octet_length\(bootstrap_cookie_hash\) = 32\)/u);
  assert.match(sql, /csrf_token_hash bytea CHECK \(csrf_token_hash IS NULL OR octet_length\(csrf_token_hash\) = 32\)/u);
  const oauthTable = sql.slice(sql.indexOf("CREATE TABLE public.hosted_identity_oauth_states"), sql.indexOf("ALTER TABLE public.hosted_identity_bootstrap_attempts"));
  assert.doesNotMatch(oauthTable, /(?:^|,)\s*(?:state|code)\s+(?:text|varchar)/imu);
  assert.doesNotMatch(sql, /(?:raw_)?(?:access|refresh)_token|client_secret|private_key|raw_assertion/iu);
  assert.doesNotMatch(sql, /CREATE TABLE public\.hosted_identity_[^;]*\b(?:email|github_subject|subject)\s+text/iu);
});

test("0057 enforces forward-only consume/failure states and exact first-org replay", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /state text NOT NULL CHECK \(state IN \([\s\S]*'completed', 'expired'/u);
  assert.match(sql, /status text NOT NULL CHECK \(status IN \('pending', 'consuming', 'consumed', 'failed', 'expired'\)\)/u);
  assert.match(sql, /hosted_identity_bootstrap_attempts_member_first_org[\s\S]*WHERE organization_id IS NOT NULL/u);
  assert.match(sql, /PRIMARY KEY \(member_id, operation, idempotency_key\)/u);
  assert.match(sql, /request_hash bytea NOT NULL CHECK \(octet_length\(request_hash\) = 32\)/u);
  assert.match(sql, /response_json - 'version' - 'organization' - 'onboarding' = '\{\}'::jsonb/u);
  assert.match(sql, /response_json->'onboarding'->>'state' = 'webauthn_required'/u);
  assert.match(bodyOf(sql, "agentpass_hosted_identity_bootstrap_organization_commit"), /prior_row\.request_hash IS DISTINCT FROM p_request_hash/u);
  assert.match(bodyOf(sql, "agentpass_hosted_identity_bootstrap_organization_commit"), /RETURN QUERY SELECT 200, prior_row\.response_json, true/u);
  assert.match(bodyOf(sql, "agentpass_guard_hosted_identity_bootstrap_attempt"), /OLD\.state = 'oauth_started' AND NEW\.state IN \('identity_verified', 'expired'\)/u);
  assert.match(bodyOf(sql, "agentpass_guard_hosted_identity_oauth_state"), /OLD\.status = 'pending' AND NEW\.status IN \('consuming', 'failed', 'expired'\)/u);
  assert.match(bodyOf(sql, "agentpass_hosted_identity_oauth_state_complete"), /i\.provider = 'github' AND i\.subject = p_subject AND i\.member_id = p_member_id/u);
});

test("0057 binds bootstrap WebAuthn to the server-derived member/org and consumes once", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /CREATE TABLE public\.hosted_identity_bootstrap_webauthn_challenges[\s\S]*attempt_id uuid NOT NULL REFERENCES public\.hosted_identity_bootstrap_attempts\(id\)[\s\S]*member_id uuid NOT NULL REFERENCES public\.members\(id\)[\s\S]*organization_id uuid NOT NULL REFERENCES public\.organizations\(id\)/u);
  assert.match(sql, /user_verification text NOT NULL CHECK \(user_verification = 'required'\)/u);
  assert.match(sql, /hosted_identity_bootstrap_webauthn_live_operation[\s\S]*WHERE status IN \('pending', 'consuming'\)/u);
  assert.match(bodyOf(sql, "agentpass_guard_hosted_identity_bootstrap_webauthn_challenge"), /attempt_member_id IS DISTINCT FROM NEW\.member_id[\s\S]*attempt_organization_id IS DISTINCT FROM NEW\.organization_id/u);
  assert.match(bodyOf(sql, "agentpass_hosted_identity_bootstrap_challenge_consume"), /c\.challenge_hash = p_challenge_hash[\s\S]*challenge_row\.status <> 'pending'/u);
  assert.match(bodyOf(sql, "agentpass_hosted_identity_bootstrap_challenge_consume"), /failure_code = 'challenge_expired'[\s\S]*RETURN;/u);
  assert.match(bodyOf(sql, "agentpass_hosted_identity_bootstrap_challenge_complete"), /c\.status = 'consuming' AND a\.state = 'webauthn_required'/u);
});

test("0057 keeps owner-based guards while current roles expose only hardened bootstrap functions", async () => {
  const [sql, roles] = await Promise.all([readFile(migrationUrl, "utf8"), readFile(rolesUrl, "utf8")]);
  for (const name of [
    "agentpass_guard_hosted_identity_bootstrap_attempt",
    "agentpass_guard_hosted_identity_oauth_state",
    "agentpass_guard_hosted_identity_bootstrap_idempotency",
    "agentpass_guard_hosted_identity_bootstrap_webauthn_challenge"
  ]) {
    assert.match(bodyOf(sql, name), /current_user <> pg_get_userbyid\(\(SELECT relowner FROM pg_catalog\.pg_class WHERE oid = TG_RELID\)\)/u);
  }
  assert.match(sql, /REVOKE ALL PRIVILEGES ON TABLE[\s\S]*FROM PUBLIC;/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_hosted_identity_bootstrap_start\([^;]+\) FROM PUBLIC;/u);
  assert.doesNotMatch(sql, /GRANT\s/iu);
  assert.doesNotMatch(sql, /FROM PUBLIC,|TO agentpass_/u);
  assert.match(roles, /left\(c\.relname, length\('hosted_identity_'\)\) = 'hosted_identity_'/u);
  assert.match(roles, /REVOKE ALL PRIVILEGES ON TABLE public\.%I FROM agentpass_app, agentpass_backup/u);
  for (const signature of [
    "agentpass_hosted_identity_bootstrap_start_v2(uuid,uuid,bytea,text,text,text,text,bytea,bytea,bytea,timestamptz)",
    "agentpass_hosted_identity_oauth_state_claim_v2(uuid,bytea,bytea,text)",
    "agentpass_hosted_identity_oauth_complete_v2(uuid,uuid,bytea,uuid,text,text,bytea)",
    "agentpass_hosted_identity_bootstrap_status_v2(bytea,bytea)",
    "agentpass_hosted_identity_bootstrap_csrf_verify_v2(bytea,bytea)",
    "agentpass_hosted_identity_bootstrap_organization_commit_v2(bytea,text,bytea,text,uuid,uuid,uuid)",
    "agentpass_hosted_identity_bootstrap_challenge_create(bytea,uuid,bytea,text,text,timestamptz)"
  ]) assert.ok(roles.includes(`'${signature}'`), `${signature} app grant`);
  assert.equal(roles.includes("'agentpass_hosted_identity_bootstrap_start(uuid,uuid,bytea,text,text,text)'"), false);
  assert.equal(roles.includes("'agentpass_hosted_identity_oauth_state_consume(uuid,bytea,text)'"), false);
  assert.equal(roles.includes("'agentpass_hosted_identity_oauth_state_complete(uuid,bytea,uuid,text,bytea)'"), false);
  assert.equal(roles.includes("'agentpass_hosted_identity_bootstrap_organization_commit(bytea,text,bytea,uuid,uuid,jsonb)'"), false);
});

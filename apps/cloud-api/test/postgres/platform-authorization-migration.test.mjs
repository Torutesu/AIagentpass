import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0054_platform_authorization.sql", import.meta.url);

function definitions(sql) {
  const starts = [...sql.matchAll(/CREATE FUNCTION public\.([a-z0-9_]+)\(([^)]*)\)/gu)];
  return starts.map((match, index) => {
    const end = starts[index + 1]?.index ?? sql.indexOf("-- No table DML is granted", match.index);
    return { name: match[1], signature: match[2].replace(/\s+/gu, " ").trim(), body: sql.slice(match.index, end < 0 ? sql.length : end) };
  });
}

function bodyOf(sql, name) { return definitions(sql).find((item) => item.name === name)?.body ?? ""; }

test("0054 is transactional, forward-only, hash-only, and request-bound", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  for (const table of ["platform_session_challenges", "platform_authorization_proofs"]) {
    assert.match(sql, new RegExp(`CREATE TABLE public\\.${table} \\(`, "u"));
    assert.match(sql, new RegExp(`CREATE TRIGGER ${table}_forward_only`, "u"));
  }
  assert.match(sql, /csrf_token_hash bytea[\s\S]*request_digest_sha256 bytea[\s\S]*allowed_webauthn_credential_ids bytea\[\]/u);
  assert.match(sql, /platform_sessions_csrf_token_hash_unique/u);
  assert.match(sql, /request_digest_sha256 bytea NOT NULL CHECK \(octet_length\(request_digest_sha256\) = 32\)/u);
  assert.match(sql, /allowed_webauthn_credential_ids bytea\[\] NOT NULL/u);
  assert.match(sql, /webauthn_credential_id bytea NOT NULL REFERENCES public\.webauthn_credentials\(id\)/u);
  assert.match(sql, /platform_credential_id uuid NOT NULL REFERENCES public\.platform_credentials\(credential_id\)/u);
  assert.doesNotMatch(sql.replace(/--[^\n]*$/gmu, ""), /(?:raw|plain)[ _]?(?:challenge|jti|bearer|csrf|claim|proof)\s+(?:text|bytea)/iu);
});

test("0054 uses DB-clock one-use challenge transitions and constant-loop token checks", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const constantTime = bodyOf(sql, "agentpass_platform_bytea_equal");
  assert.match(constantTime, /FOR index_value IN/u);
  assert.match(constantTime, /get_byte\(p_left/u);
  assert.match(constantTime, /difference := difference \|/u);
  for (const name of [
    "agentpass_platform_session_challenge_create",
    "agentpass_platform_session_challenge_claim",
    "agentpass_platform_session_challenge_fail",
    "agentpass_platform_session_challenge_complete",
    "agentpass_platform_session_complete_and_issue",
    "agentpass_consume_platform_authorization_and_reserve"
  ]) {
    assert.match(bodyOf(sql, name), /SECURITY DEFINER/u, `${name} must be SECURITY DEFINER`);
    assert.match(bodyOf(sql, name), /SET search_path = pg_catalog, public/u, `${name} search_path`);
  }
  assert.match(bodyOf(sql, "agentpass_platform_session_challenge_create"), /clock_timestamp\(\)/u);
  assert.match(bodyOf(sql, "agentpass_platform_session_challenge_claim"), /FOR UPDATE/u);
  assert.match(bodyOf(sql, "agentpass_platform_session_challenge_fail"), /status = 'failed'/u);
  assert.match(bodyOf(sql, "agentpass_platform_session_challenge_complete"), /platform_authorization_proofs/u);
  assert.match(bodyOf(sql, "agentpass_platform_session_complete_and_issue"), /session_issue[\s\S]*challenge_complete/u);
  assert.match(bodyOf(sql, "agentpass_platform_session_complete_and_issue"), /SECURITY DEFINER/u);
});

test("0054 replaces unsafe session signatures and reserves promotion only through proof consume", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql, /DROP FUNCTION public\.agentpass_platform_session_issue\(uuid, bytea, uuid, uuid, uuid, uuid, uuid, text, text, integer, integer\)/u);
  assert.match(sql, /DROP FUNCTION public\.agentpass_platform_session_touch\(bytea, uuid, text, text\)/u);
  assert.match(sql, /DROP FUNCTION public\.agentpass_platform_session_revoke\(uuid, text\)/u);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_platform_promotion_issuance_reserve\([^;]+\) FROM agentpass_app/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_consume_platform_authorization_and_reserve\([^;]+\) TO agentpass_app/u);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_platform_session_issue\([^;]+\) TO agentpass_app/u);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_platform_session_challenge_complete\([^;]+\) TO agentpass_app/u);
  assert.match(bodyOf(sql, "agentpass_consume_platform_authorization_and_reserve"), /agentpass_platform_promotion_issuance_reserve/u);
  assert.match(bodyOf(sql, "agentpass_consume_platform_authorization_and_reserve"), /platform_authorization_proofs[\s\S]*status = 'consumed'/u);
  assert.ok(
    bodyOf(sql, "agentpass_consume_platform_authorization_and_reserve").indexOf("FROM public.platform_sessions")
      < bodyOf(sql, "agentpass_consume_platform_authorization_and_reserve").indexOf("FROM public.platform_authorization_proofs"),
    "atomic function must lock session before proof"
  );
});

test("0054 enforces generation/version/tenant/request/candidate/environment replay fences", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const atomic = bodyOf(sql, "agentpass_consume_platform_authorization_and_reserve");
  for (const fragment of [
    "authority_generation = session_row.principal_authority_generation",
    "version = session_row.assignment_version",
    "platform_credential_id <> session_row.credential_id",
    "organization_id <> session_row.organization_id",
    "request_digest_sha256 IS DISTINCT FROM session_row.request_digest_sha256",
    "environment <> p_environment",
    "candidate_id <> p_candidate_id",
    "idempotency_key <> p_idempotency_key",
    "consumed_promotion_id <> p_promotion_id"
  ]) assert.match(atomic, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"), fragment);
  assert.match(atomic, /agentpass_platform_authorization_request_digest/u);
  assert.match(atomic, /status <> 'available'/u);
  assert.match(atomic, /FOR UPDATE/u);
});

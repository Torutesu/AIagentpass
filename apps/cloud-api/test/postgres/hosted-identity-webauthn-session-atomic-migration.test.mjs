import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0062_hosted_webauthn_session_atomic.sql", import.meta.url);
const rolesUrl = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);
const FUNCTION = "agentpass_hosted_identity_bootstrap_webauthn_complete_v2";
const RECEIPT_TABLE = "hosted_identity_bootstrap_completions";

function functionBody(sql, name = FUNCTION) {
  const start = sql.indexOf(`CREATE FUNCTION public.${name}`);
  assert.notEqual(start, -1, `${name} is missing`);
  const nextFunction = sql.indexOf("\nCREATE FUNCTION ", start + 1);
  const revoke = sql.indexOf("\nREVOKE ", start + 1);
  const end = [nextFunction, revoke].filter((value) => value >= 0).sort((a, b) => a - b)[0] ?? -1;
  return sql.slice(start, end < 0 ? sql.length : end);
}

function withoutComments(sql) {
  return sql.replace(/--[^\n]*|\/\*[\s\S]*?\*\//gu, "");
}

test("0062 is a forward-only transaction and adds a one-use response-loss receipt", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const body = withoutComments(sql);

  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(body, /DROP\s+(?:TABLE|COLUMN|INDEX)|TRUNCATE\s+TABLE/iu);
  assert.match(body, new RegExp(`CREATE TABLE public\\.${RECEIPT_TABLE} \\(`, "u"));
  assert.match(body, /attempt_id uuid PRIMARY KEY REFERENCES public\.hosted_identity_bootstrap_attempts\(id\)/u);
  assert.match(body, /challenge_id uuid NOT NULL UNIQUE REFERENCES public\.hosted_identity_bootstrap_webauthn_challenges\(id\)/u);
  assert.match(body, /session_id uuid NOT NULL UNIQUE REFERENCES public\.human_sessions\(id\)/u);
  assert.match(body, /request_hash bytea NOT NULL CHECK \(octet_length\(request_hash\) = 32\)/u);
  assert.match(body, /replay_expires_at timestamptz NOT NULL/u);
  assert.match(body, /replayed_at timestamptz/u);
  assert.match(body, /OLD\.replayed_at IS NULL AND NEW\.replayed_at IS NOT NULL/u);
  assert.doesNotMatch(body, /\b(?:raw_)?(?:cookie|token|challenge|assertion)\s+(?:text|varchar|bytea)\b/iu);
  assert.doesNotMatch(body, /private_key|client_secret|access_token|refresh_token/iu);
});

test("0062 accepts only verified WebAuthn material and never a caller-selected session id", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const body = functionBody(withoutComments(sql));
  const declaration = body.slice(0, body.indexOf(")\nRETURNS"));

  for (const parameter of [
    "p_attempt_id uuid",
    "p_bootstrap_cookie_hash bytea",
    "p_challenge_id uuid",
    "p_challenge_hash bytea",
    "p_request_hash bytea",
    "p_credential_id bytea",
    "p_public_key bytea",
    "p_sign_count bigint",
    "p_transports text[]",
    "p_label text",
    "p_backup_eligible boolean",
    "p_backup_state boolean",
    "p_session_token_hash bytea",
    "p_session_csrf_token_hash bytea"
  ]) assert.match(declaration, new RegExp(parameter.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"), parameter);

  assert.doesNotMatch(declaration, /\bp_session_id\b|\bp_member_id\b|\bp_organization_id\b|\bp_membership_id\b|\bp_authority_epoch\b|\bp_session_epoch\b/iu);
  assert.match(body, /RETURNS TABLE\s*\([\s\S]*session_id uuid[\s\S]*member_id uuid[\s\S]*organization_id uuid[\s\S]*membership_id uuid[\s\S]*role text[\s\S]*created_at timestamptz[\s\S]*expires_at timestamptz[\s\S]*replayed boolean/u);
  assert.doesNotMatch(body, /RETURNS TABLE\s*\([\s\S]*\b(?:token|cookie|csrf|challenge)\b\s+(?:text|varchar|bytea)/iu);
  assert.match(body, /SECURITY DEFINER/u);
  assert.match(body, /SET search_path\s*=\s*pg_catalog, public/u);
  assert.match(body, /INSERT INTO public\.human_sessions/u);
  assert.match(body, /gen_random_uuid\(\)/u);
  assert.match(body, /session_expiry := now_value \+ interval '8 hours'/u);
  assert.match(body, /session_idle_expiry := now_value \+ interval '30 minutes'/u);
  assert.match(body, /position >= 5/u);
  assert.match(body, /agentpass:human:sessions:/u);
  assert.doesNotMatch(body, /VALUES\s*\(\s*p_session_id\b/iu, "session id must be database-generated, not copied from a caller parameter");
});

test("0062 locks and rechecks the exact attempt, challenge, membership, and epoch binding", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const body = functionBody(withoutComments(sql));

  assert.match(body, /FROM public\.hosted_identity_bootstrap_attempts[\s\S]*p_attempt_id[\s\S]*FOR UPDATE/u);
  assert.match(body, /FROM public\.hosted_identity_bootstrap_webauthn_challenges[\s\S]*p_challenge_id[\s\S]*FOR UPDATE/u);
  assert.match(body, /c\.attempt_id\s*=\s*attempt_row\.id/u);
  assert.match(body, /c\.member_id\s*=\s*attempt_row\.member_id/u);
  assert.match(body, /c\.organization_id\s*=\s*attempt_row\.organization_id/u);
  assert.match(body, /c\.challenge_hash\s*=\s*p_challenge_hash/u);
  assert.match(body, /challenge_row\.status\s*(?:=|<>)\s*'consuming'/u);
  assert.match(body, /m\.id\s*=\s*attempt_row\.membership_id/u);
  assert.match(body, /m\.member_id\s*=\s*attempt_row\.member_id/u);
  assert.match(body, /m\.organization_id\s*=\s*attempt_row\.organization_id/u);
  assert.match(body, /m\.status\s*=\s*'active'/u);
  assert.doesNotMatch(body, /SELECT\s+m\s*,\s*o\.authority_epoch\s+INTO\s+membership_row\s*,/iu,
    "a %ROWTYPE target cannot share a PL/pgSQL INTO list with a scalar");
  assert.match(body, /o\.authority_epoch\s*=\s*session_row\.organization_authority_epoch|organization_authority_epoch\s*:=\s*organization_row\.authority_epoch|organization_epoch\b/u);
  assert.match(body, /m\.session_epoch\s*=\s*session_row\.membership_session_epoch|membership_row\.session_epoch/u);
  assert.match(body, /FOR (?:SHARE|UPDATE) OF organization|FOR UPDATE/u);
});

test("0062 consumes the challenge once and completes the attempt atomically", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const body = functionBody(withoutComments(sql));

  assert.match(body, /UPDATE public\.hosted_identity_bootstrap_webauthn_challenges[\s\S]*status\s*=\s*'consumed'[\s\S]*WHERE[\s\S]*status\s*=\s*'consuming'/u);
  assert.match(body, /UPDATE public\.hosted_identity_bootstrap_attempts[\s\S]*state\s*=\s*'completed'/u);
  assert.match(body, new RegExp(`INSERT INTO public\\.${RECEIPT_TABLE}`, "u"));
  assert.match(body, /replay_expires_at\s*<=\s*now_value/u);
  assert.match(body, /SET replayed_at = now_value[\s\S]*replayed_at IS NULL/u);
  assert.doesNotMatch(body, /COMMIT;|ROLLBACK;/iu);
});

test("0062 keeps its atomic function private after the 0063 claim-bound upgrade", async () => {
  const [sql, roles] = await Promise.all([readFile(migrationUrl, "utf8"), readFile(rolesUrl, "utf8")]);
  const signature = `${FUNCTION}(uuid,bytea,uuid,bytea,bytea,bytea,bytea,bigint,text[],text,boolean,boolean,bytea,bytea)`;
  const legacy = [
    "agentpass_hosted_identity_bootstrap_challenge_complete(bytea,uuid,bytea)"
  ];

  assert.match(sql, new RegExp(`REVOKE ALL PRIVILEGES ON FUNCTION public\\.${FUNCTION}\\([^;]+\\) FROM PUBLIC`, "u"));
  assert.equal(roles.includes(`'${signature}'`), false, "0062 entry point must be hidden behind the 0063 claim-bound wrapper");
  for (const oldSignature of legacy) assert.equal(roles.includes(`'${oldSignature}'`), false, oldSignature);
});

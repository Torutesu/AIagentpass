import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL("../../../../contracts/postgres/0063_hosted_webauthn_claim_lease.sql", import.meta.url);
const rolesUrl = new URL("../../../../scripts/postgres/roles.sql", import.meta.url);

function functionBody(sql, name) {
  const start = sql.indexOf(`CREATE FUNCTION public.${name}`);
  assert.notEqual(start, -1, `${name} is missing`);
  const next = sql.indexOf("\nCREATE FUNCTION ", start + 1);
  const revoke = sql.indexOf("\nREVOKE ", start + 1);
  const end = [next, revoke].filter((value) => value >= 0).sort((a, b) => a - b)[0] ?? sql.length;
  return sql.slice(start, end);
}

function withoutComments(sql) {
  return sql.replace(/--[^\n]*|\/\*[\s\S]*?\*\//gu, "");
}

test("0063 adds a digest-only database-clock claim lease without raw authority", async () => {
  const sql = withoutComments(await readFile(migrationUrl, "utf8"));

  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.match(sql, /ADD COLUMN claim_token_hash bytea/u);
  assert.match(sql, /ADD COLUMN claim_expires_at timestamptz/u);
  assert.match(sql, /ADD COLUMN claim_generation bigint NOT NULL DEFAULT 0/u);
  assert.match(sql, /octet_length\(claim_token_hash\) = 32/u);
  assert.match(sql, /claim_expires_at > consume_started_at/u);
  assert.match(sql, /claim_generation >= 1/u);
  assert.match(sql, /CREATE TABLE public\.hosted_identity_bootstrap_webauthn_claim_events/u);
  assert.match(sql, /event_type IN \([\s\S]*'claimed'[\s\S]*'takeover'[\s\S]*'completed'[\s\S]*'replayed'[\s\S]*'failed'[\s\S]*'expired'/u);
  assert.match(sql, /claim events are append-only/u);
  assert.match(sql, /WHERE status = 'consuming'/u, "pre-lease consuming rows must be made terminal during upgrade");
  assert.doesNotMatch(sql, /\bclaim_token\s+(?:text|varchar|bytea)\b/iu);
  assert.doesNotMatch(sql, /private_key|client_secret|access_token|refresh_token/iu);
});

test("0063 claim takes locks in attempt/challenge order and permits takeover only after expiry", async () => {
  const sql = withoutComments(await readFile(migrationUrl, "utf8"));
  const body = functionBody(sql, "agentpass_hosted_identity_bootstrap_webauthn_claim_v2");
  const attemptLock = body.indexOf("FROM public.hosted_identity_bootstrap_attempts");
  const challengeLock = body.indexOf("FROM public.hosted_identity_bootstrap_webauthn_challenges");

  assert.ok(attemptLock >= 0 && challengeLock > attemptLock, "lock order must be attempt then challenge");
  assert.match(body, /FOR UPDATE/u);
  assert.match(body, /now_value \+ interval '30 seconds'/u);
  assert.match(body, /challenge_row\.claim_token_hash = p_claim_token_hash[\s\S]*claim_expires_at > now_value/u);
  assert.match(body, /challenge_row\.claim_expires_at <= now_value[\s\S]*claim_generation = claim_generation \+ 1/u);
  assert.match(body, /completion\.replay_expires_at > now_value[\s\S]*completion\.replayed_at IS NULL/u);
  assert.match(body, /challenge_row\.claim_token_hash IS DISTINCT FROM p_claim_token_hash/u);
  assert.match(body, /claim_generation bigint/u);
  assert.match(body, /'takeover'/u);
  assert.ok(body.indexOf("now_value := clock_timestamp()") > challengeLock, "lease time must be sampled after both locks");
});

test("0063 failure and atomic completion require the exact claim digest", async () => {
  const sql = withoutComments(await readFile(migrationUrl, "utf8"));
  const failure = functionBody(sql, "agentpass_hosted_identity_bootstrap_webauthn_fail_v3");
  const completion = functionBody(sql, "agentpass_hosted_identity_bootstrap_webauthn_complete_v3");

  assert.match(failure, /c\.claim_token_hash = p_claim_token_hash/u);
  assert.match(failure, /c\.claim_generation = p_claim_generation/u);
  assert.match(failure, /claim_expires_at > now_value/u);
  assert.match(failure, /status = 'failed'/u);
  assert.match(completion, /claim_hash IS DISTINCT FROM p_claim_token_hash/u);
  assert.match(completion, /claim_generation_value IS DISTINCT FROM p_claim_generation/u);
  assert.match(completion, /challenge_status <> 'consuming' OR claim_expiry <= now_value/u);
  assert.match(completion, /agentpass_hosted_identity_bootstrap_webauthn_complete_v2/u);
  assert.doesNotMatch(completion, /COMMIT;|ROLLBACK;/iu);
});

test("application role receives only claim-bound Hosted WebAuthn mutation functions", async () => {
  const roles = await readFile(rolesUrl, "utf8");
  const allowed = [
    "agentpass_hosted_identity_bootstrap_challenge_create(bytea,uuid,bytea,text,text,timestamptz)",
    "agentpass_hosted_identity_bootstrap_webauthn_claim_v2(bytea,uuid,bytea,bytea)",
    "agentpass_hosted_identity_bootstrap_webauthn_complete_v3(uuid,bytea,uuid,bytea,bytea,bigint,bytea,bytea,bytea,bigint,text[],text,boolean,boolean,bytea,bytea)",
    "agentpass_hosted_identity_bootstrap_webauthn_fail_v3(bytea,uuid,bytea,bytea,bigint,text)"
  ];
  const forbidden = [
    "agentpass_hosted_identity_bootstrap_challenge_consume(bytea,uuid,bytea)",
    "agentpass_hosted_identity_bootstrap_challenge_complete(bytea,uuid,bytea)",
    "agentpass_hosted_identity_bootstrap_challenge_fail(bytea,uuid,bytea,text)",
    "agentpass_hosted_identity_bootstrap_webauthn_replay_context(bytea,uuid,bytea)",
    "agentpass_hosted_identity_bootstrap_webauthn_complete_v2(uuid,bytea,uuid,bytea,bytea,bytea,bytea,bigint,text[],text,boolean,boolean,bytea,bytea)",
    "agentpass_hosted_identity_bootstrap_webauthn_fail_v2(bytea,uuid,bytea,bytea,text)"
  ];

  for (const signature of allowed) assert.ok(roles.includes(`'${signature}'`), signature);
  for (const signature of forbidden) assert.equal(roles.includes(`'${signature}'`), false, signature);
});

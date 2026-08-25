import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL(
  "../../../../contracts/postgres/0051_managed_signer_lifecycle_signing_authority.sql",
  import.meta.url
);

const ENTRY_SIGNATURES = Object.freeze({
  agentpass_managed_signer_lifecycle_snapshot: "text",
  agentpass_managed_signer_lifecycle_initialize: "text,text,jsonb,integer,bigint",
  agentpass_managed_signer_lifecycle_apply: "text,text,bytea,bigint,jsonb,bigint",
  agentpass_managed_signer_signing_reserve: "text,text,bytea,text,bigint,bytea,bigint,bigint",
  agentpass_managed_signer_signing_start: "text,text,bytea,text,bigint,bytea",
  agentpass_managed_signer_signing_commit: "text,text,bytea,text,bigint,bytea,bytea,text,text",
  agentpass_managed_signer_signing_uncertain: "text,text,bytea,text,bigint,bytea",
  agentpass_managed_signer_signing_reconcile: "text,text,bytea,text,bigint,bytea,text,text",
  agentpass_managed_signer_signing_lookup: "text,text",
  agentpass_managed_signer_signing_prune: "text,timestamptz,integer",
  agentpass_managed_signer_lifecycle_operation_prune: "text,timestamptz,integer"
});

const CLOSED_OUTCOMES = new Set([
  "ok", "absent", "conflict", "pending", "uncertain", "claim_lost",
  "configuration_conflict", "not_initialized", "not_active"
]);

test("0051 exposes the exact closed lifecycle/signing authority API", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.doesNotMatch(sql, /\bGRANT\b[\s\S]*\bPUBLIC\b/iu);

  const definitions = functionDefinitions(sql);
  assert.deepEqual(
    Object.fromEntries(definitions.filter(({ name }) => Object.hasOwn(ENTRY_SIGNATURES, name)).map(({ name, signature }) => [name, signature])),
    ENTRY_SIGNATURES
  );

  for (const [name, signature] of Object.entries(ENTRY_SIGNATURES)) {
    const definition = definitions.find((candidate) => candidate.name === name && candidate.signature === signature);
    assert.ok(definition, `missing ${name}(${signature})`);
    assert.match(definition.body, /RETURNS jsonb/u);
    assert.match(definition.body, /SECURITY DEFINER/u);
    assert.match(definition.body, /SET search_path = pg_catalog, public/u);
    assert.match(definition.body, /agentpass_managed_signer_envelope\(/u);
    assert.match(sql, new RegExp(
      `REVOKE ALL ON FUNCTION public\\.${escapeRegex(name)}\\(${signaturePattern(signature)}\\) FROM PUBLIC`,
      "u"
    ));
  }

  for (const definition of definitions) {
    assert.match(definition.body, /SECURITY (?:INVOKER|DEFINER)/u);
    assert.match(definition.body, /SET search_path = pg_catalog, public/u);
    assert.match(sql, new RegExp(
      `REVOKE ALL ON FUNCTION public\\.${escapeRegex(definition.name)}\\(${signaturePattern(definition.signature)}\\) FROM PUBLIC`,
      "u"
    ));
  }

  const outcomes = [...sql.matchAll(/agentpass_managed_signer_envelope\(\s*'([^']+)'/gu)].map((match) => match[1]);
  assert.ok(outcomes.length > 0);
  assert.ok(outcomes.every((outcome) => CLOSED_OUTCOMES.has(outcome)));
  assert.match(sql, /p_outcome IN \([\s\S]*'not_active'/u);
  assert.doesNotMatch(functionBody(sql, "agentpass_managed_signer_signing_record_json"), /claim_token_digest/iu);
  assert.doesNotMatch(sql, /\b(?:FROM|JOIN|UPDATE|INSERT INTO|DELETE FROM)\s+(?!public\.)managed_signer_/iu);
});

test("0051 validates transitions, bindings, leases, and database-clock pruning", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const transition = functionBody(sql, "agentpass_managed_signer_transition_kind");
  assert.match(transition, /single-key/u);
  assert.match(transition, /rotate/u);
  assert.match(transition, /emergency-disable-all/u);
  assert.match(transition, /restore-new-key/u);
  assert.match(transition, /agentpass_managed_signer_key_identity/u);
  assert.match(transition, /target_key->>'state' <> 'emergency-disabled'[\s\S]*IF non_emergency_count > 0 THEN\s*RETURN 'emergency-disable-all';[\s\S]*A single-key transition/u);
  assert.match(sql, /p_target_snapshot[\s\S]*agentpass_managed_signer_snapshot_is_valid/u);
  assert.match(sql, /(?:p_request_digest IS DISTINCT FROM signing_row\.request_digest|signing_row\.request_digest IS DISTINCT FROM p_request_digest)/u);
  assert.match(sql, /(?:p_key_id IS DISTINCT FROM signing_row\.key_id|signing_row\.key_id IS DISTINCT FROM p_key_id)/u);
  assert.match(sql, /(?:p_key_version IS DISTINCT FROM signing_row\.key_version|signing_row\.key_version IS DISTINCT FROM p_key_version)/u);
  assert.match(sql, /claim_token_digest = p_claim_token_digest/u);
  assert.match(sql, /claim_expires_at > now_at/u);
  assert.match(sql, /FOR UPDATE SKIP LOCKED/u);
  assert.match(sql, /expires_at <= now_at/u);
  assert.match(sql, /octet_length\(p_signature\) <> 64/u);
  assert.match(sql, /provider_started_at IS NOT NULL/u);
  assert.match(sql, /status = 'committed'/u);
  assert.match(sql, /status = 'uncertain'/u);
  assert.match(sql, /status = 'pending'/u);
  assert.match(sql, /pg_catalog\.clock_timestamp\(\)/u);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.agentpass_guard_managed_signer_key\(\)/u);
  assert.match(sql, /terminal_epoch_refresh := NOT changed_state[\s\S]*OLD\.state = 'emergency-disabled'[\s\S]*NEW\.state_version = lifecycle_version[\s\S]*NEW\.state_version > OLD\.state_version/u);
  assert.match(sql, /REVOKE ALL ON FUNCTION public\.agentpass_guard_managed_signer_key\(\) FROM PUBLIC/u);

  const reserve = functionBody(sql, "agentpass_managed_signer_signing_reserve");
  assert.match(reserve, /status = 'aborted'[\s\S]*reserved_lifecycle_version = lifecycle_row\.version;\s*IF NOT FOUND THEN\s*RETURN public\.agentpass_managed_signer_envelope\('not_active'/u);
  assert.match(reserve, /claim_expires_at <= now_at;\s*END IF;\s*SELECT \* INTO signing_row/u);
  assert.match(reserve, /status = 'pending'[\s\S]*expires_at = now_at \+ \(p_retention_ms::double precision \* interval '1 millisecond'\)/u);
  const lookup = functionBody(sql, "agentpass_managed_signer_signing_lookup");
  assert.match(lookup, /agentpass_managed_signer_envelope\('absent', '\{\}'::jsonb\)/u);
  assert.doesNotMatch(lookup, /FOR (?:SHARE|UPDATE)/u);
  assert.match(functionBody(sql, "agentpass_managed_signer_receipt_is_valid"), /WHEN p_provider IS NULL OR p_receipt_id IS NULL THEN false/u);
});

function functionDefinitions(sql) {
  const starts = [...sql.matchAll(/CREATE FUNCTION public\.([a-z0-9_]+)\(([^)]*)\)/gu)];
  return starts.map((match, index) => {
    const end = starts[index + 1]?.index ?? sql.indexOf("REVOKE ALL ON FUNCTION", match.index);
    const body = sql.slice(match.index, end < 0 ? sql.length : end);
    const signature = match[2].trim() === ""
      ? ""
      : match[2].split(",").map((argument) => argument.trim().split(/\s+/u).at(-1)).join(",");
    return { name: match[1], signature, body };
  });
}

function functionBody(sql, name) {
  return functionDefinitions(sql).find((definition) => definition.name === name)?.body ?? "";
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function signaturePattern(value) {
  return value.split(",").map(escapeRegex).join("\\s*,\\s*");
}

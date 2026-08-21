import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const migrationUrl = new URL(
  "../../../../contracts/postgres/0074_agent_session_signing_capability_reservations.sql",
  import.meta.url,
);
const rolesUrl = new URL(
  "../../../../scripts/postgres/roles.sql",
  import.meta.url,
);
const capabilitySchemaUrl = new URL(
  "../../../../contracts/schemas/agent-signing-capability-v1.schema.json",
  import.meta.url,
);
const responseSchemaUrl = new URL(
  "../../../../contracts/schemas/agent-session-signing-capability-response-v1.schema.json",
  import.meta.url,
);

async function migration() {
  return readFile(migrationUrl, "utf8");
}

async function roles() {
  return readFile(rolesUrl, "utf8");
}

async function json(url) {
  return JSON.parse(await readFile(url, "utf8"));
}

function tableBody(sql) {
  const start = sql.indexOf("CREATE TABLE public.agent_session_signing_capability_reservations (");
  assert.notEqual(start, -1);
  const end = sql.indexOf("\n);", start);
  assert.notEqual(end, -1);
  return sql.slice(start, end);
}

function functionBody(sql, name) {
  const start = sql.indexOf(`CREATE FUNCTION public.${name}(`);
  assert.notEqual(start, -1, `missing function ${name}`);
  const bodyStart = sql.indexOf("AS $$", start);
  assert.notEqual(bodyStart, -1, `missing function body ${name}`);
  const bodyEnd = sql.indexOf("$$;", bodyStart);
  assert.notEqual(bodyEnd, -1, `unterminated function ${name}`);
  return sql.slice(start, bodyEnd + 3);
}

function before(sql, marker) {
  const end = sql.indexOf(marker);
  assert.notEqual(end, -1, `missing marker ${marker}`);
  return sql.slice(0, end);
}

test("0074 is a forward-only transactional migration", async () => {
  const sql = await migration();
  assert.match(sql.trim(), /^BEGIN;[\s\S]*COMMIT;$/u);
  assert.match(sql, /CREATE TABLE public\.agent_session_signing_capability_reservations/u);
  assert.doesNotMatch(sql, /\b(?:DROP|TRUNCATE)\s+(?:TABLE|COLUMN|INDEX|FUNCTION)/iu);
  assert.match(sql, /ALTER TABLE public\.capabilities[\s\S]*ADD COLUMN issued_by_session_id uuid/u);
  assert.doesNotMatch(sql, /ALTER TABLE\s+(?:public\.)?(?:agent_sessions|agent_session_grants)\b/iu);
});

test("0074 binds tenant, Device, Agent Session, Grant, sequence, and authority generation", async () => {
  const sql = await migration();
  const table = tableBody(sql);
  for (const column of [
    "organization_id", "reservation_id", "request_id", "request_digest",
    "capability_id", "session_id", "grant_id", "device_id", "agent_id",
    "grant_hash", "sequence", "scope_json", "control_sequence",
    "authority_generation", "key_purpose", "key_id", "claim_token_hash",
  ]) assert.match(table, new RegExp(`\\b${column}\\b`, "u"));
  for (const fragment of [
    "UNIQUE (organization_id, request_id)",
    "UNIQUE (organization_id, capability_id)",
    "UNIQUE (organization_id, agent_id, sequence)",
    "FOREIGN KEY (organization_id, session_id, grant_id, device_id)",
    "REFERENCES public.agent_sessions(organization_id, session_id, grant_id, device_id)",
    "REFERENCES public.agent_session_grants(organization_id, grant_id, device_id, agent_id, grant_hash)",
    "REFERENCES public.control_plane_authority_generations(organization_id, generation)",
    "REFERENCES public.managed_signer_keys(purpose, key_id, key_version)",
  ]) assert.ok(table.includes(fragment), fragment);
});

test("0074 keeps agent_sessions as the sole two-signature budget authority", async () => {
  const sql = await migration();
  const table = tableBody(sql);
  assert.doesNotMatch(table, /session_signature_budget|remaining_session_signatures|used_signatures|reserved_signatures/u);
  assert.match(sql, /session_row\.max_signatures <> 2/u);
  assert.match(sql, /used_signatures \+ session_row\.reserved_signatures >= session_row\.max_signatures/u);
  assert.match(sql, /session_row\.status = 'signed'[\s\S]*?session_row\.used_signatures \+ session_row\.reserved_signatures < session_row\.max_signatures[\s\S]*?SET status = 'active'/u);
  assert.match(sql, /FROM public\.agent_sessions AS s[\s\S]*FOR UPDATE/u);
  assert.match(sql, /status = 'request_reserved'[\s\S]*reserved_signatures = reserved_signatures \+ 1/u);
  assert.match(sql, /status = 'signing_intent'/u);
  assert.match(sql, /status = 'signed'[\s\S]*used_signatures = used_signatures \+ 1[\s\S]*reserved_signatures = reserved_signatures - 1/u);
  assert.match(sql, /status = 'outcome_unknown'[\s\S]*used_signatures = used_signatures \+ 1[\s\S]*reserved_signatures = reserved_signatures - 1/u);
  assert.match(sql, /CREATE TABLE public\.agent_capability_sequence_heads/u);
  assert.match(sql, /CREATE TRIGGER capabilities_sequence_allocator/u);
  assert.match(sql, /FROM public\.agent_capability_sequence_heads[\s\S]*FOR UPDATE/u);
  assert.match(sql, /SET sequence = next_sequence/u);
  assert.match(sql, /REFERENCES public\.managed_signer_provider_operations\(purpose, operation_id\)/u);
});

test("0074 supports exact committed replay without retaining clear claim tokens", async () => {
  const sql = await migration();
  const table = tableBody(sql);
  assert.match(table, /claim_token_hash bytea NOT NULL CHECK \(octet_length\(claim_token_hash\) = 32\)/u);
  assert.doesNotMatch(table, /\bclaim_token\s+(?:text|bytea|jsonb)/iu);
  assert.match(table, /response_json jsonb/u);
  assert.match(sql, /'state', 'committed', 'capability', p_row\.response_json/u);
  assert.match(sql, /state = 'expired'[\s\S]*response_json = NULL/u);
  assert.match(sql, /capability_statement_hash = (?:p_statement_hash|expected_statement_hash)/u);
  assert.match(sql, /capability_signature_hash = (?:p_signature_hash|sha256\(provider_row\.signature\))/u);
  assert.match(sql, /reservation_row\.claim_token_hash IS DISTINCT FROM p_claim_token_hash/u);
});

test("0074 derives fixed authority and rejects substituted Capability statements", async () => {
  const sql = await migration();
  const reserve = functionBody(sql, "agentpass_agent_signing_capability_reserve");
  const commit = functionBody(sql, "agentpass_agent_signing_capability_commit");
  for (const body of [reserve, commit]) {
    assert.match(body, /convert_to\('AgentPass-Agent-Signing-Capability-v1', 'UTF8'\)\s*\|\|\s*decode\('00', 'hex'\)\s*\|\|\s*convert_to\(statement_text, 'UTF8'\)/u);
    assert.doesNotMatch(body, /chr\(0\)/u, "PostgreSQL text cannot contain a NUL byte");
  }
  assert.match(sql, /p_operation IS DISTINCT FROM 'git\.commit\.sign'/u);
  assert.match(sql, /p_key_purpose IS DISTINCT FROM 'git\.commit\.sign'/u);
  assert.match(sql, /p_one_use IS DISTINCT FROM true/u);
  assert.match(sql, /p_max_signatures IS DISTINCT FROM 1/u);
  assert.match(sql, /WHERE k\.purpose = p_key_purpose AND k\.state = 'active'/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_agent_signing_capability_statement_canonical_json\(/u);
  assert.match(commit, /expected_statement_hash := sha256\(convert_to\(statement_text, 'UTF8'\)\)/u);
  assert.doesNotMatch(commit, /p_capability|p_statement_hash|p_signature_hash/u);
  assert.match(commit, /expected_capability := jsonb_build_object\([\s\S]*'statement', statement_text::jsonb/u);
  assert.match(sql, /(?:generation|g)\.generation = reservation_row\.authority_generation[\s\S]*(?:generation|g)\.superseded_at IS NULL/u);
});

test("0074 exposes only function-owned app authority with tenant RLS", async () => {
  const sql = await migration();
  assert.match(sql, /ENABLE ROW LEVEL SECURITY/u);
  assert.match(sql, /FORCE ROW LEVEL SECURITY/u);
  assert.match(sql, /organization_id = public\.agentpass_current_organization_id\(\)/u);
  assert.match(sql, /tenant_insert[\s\S]*FOR INSERT[\s\S]*WITH CHECK/u);
  assert.match(sql, /tenant_update[\s\S]*FOR UPDATE[\s\S]*WITH CHECK/u);
  assert.doesNotMatch(sql, /set_config\('agentpass\.organization_id',\s*p_organization_id::text/u);
  assert.match(sql, /REVOKE ALL ON TABLE public\.agent_session_signing_capability_reservations[\s\S]*FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup/u);
  assert.match(sql, /GRANT SELECT ON TABLE public\.agent_session_signing_capability_reservations TO agentpass_backup/u);
  assert.match(sql, /CREATE POLICY agent_capability_sequence_heads_migrator_authority[\s\S]*TO agentpass_migrator[\s\S]*USING \(true\) WITH CHECK \(true\)/u);
  assert.match(sql, /CREATE POLICY agent_session_signing_reservations_migrator_authority[\s\S]*TO agentpass_migrator[\s\S]*USING \(true\) WITH CHECK \(true\)/u);
  assert.match(sql, /CREATE POLICY agent_sessions_signing_capability_migrator_authority[\s\S]*ON public\.agent_sessions[\s\S]*TO agentpass_migrator/u);
  for (const name of ["reserve", "commit", "replay", "uncertain"]) {
    assert.match(sql, new RegExp(`CREATE FUNCTION public\\.agentpass_agent_signing_capability_${name}\\(`, "u"));
    assert.match(sql, new RegExp(`GRANT EXECUTE ON FUNCTION public\\.agentpass_agent_signing_capability_${name}\\([\\s\\S]*?TO agentpass_app`, "u"));
  }
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE).*TO agentpass_app/iu);
});

test("0074 capability listing reads the tenant-qualified authority table", async () => {
  const sql = await migration();
  const list = functionBody(sql, "agentpass_capability_reservation_list");
  assert.match(list, /FROM public\.capabilities AS capability/u);
  assert.match(list, /capability\.organization_id = p_organization_id/u);
  assert.ok(
    list.indexOf("FROM public.capabilities AS capability") < list.indexOf("capability.organization_id = p_organization_id"),
    "the table alias must be introduced before its tenant predicate",
  );
});

test("0074 rechecks every authority boundary immediately before capability commit", async () => {
  const sql = await migration();
  const commit = functionBody(sql, "agentpass_agent_signing_capability_commit");
  const commitBeforeInsert = before(commit, "INSERT INTO public.capabilities");

  // The session row is locked again at commit time and cannot be trusted merely
  // because it was valid when the reservation was created.
  assert.match(commitBeforeInsert, /FROM public\.agent_sessions AS s[\s\S]*FOR UPDATE/u);
  for (const field of [
    "device_id", "agent_id", "grant_id", "grant_hash", "control_sequence", "authority_generation",
  ]) {
    assert.match(
      commitBeforeInsert,
      new RegExp(`session_row\\.${field}\\s+IS DISTINCT FROM\\s+reservation_row\\.${field}`, "u"),
      `commit must recheck session ${field}`,
    );
  }

  // A consumed grant, live device/agent, current generation, and absence of
  // active revocation are all required in the same transaction as the insert.
  assert.match(commitBeforeInsert, /FROM public\.agent_session_grants[\s\S]*FOR SHARE/u);
  assert.match(commitBeforeInsert, /grant_row\.status\s+<>\s+'consumed'/u);
  assert.match(commitBeforeInsert, /FROM public\.devices[\s\S]*d\.id\s*=\s*reservation_row\.device_id/u);
  assert.match(commitBeforeInsert, /d\.status\s*=\s*'active'/u);
  assert.match(commitBeforeInsert, /FROM public\.agents[\s\S]*a\.id\s*=\s*reservation_row\.agent_id/u);
  assert.match(commitBeforeInsert, /a\.status\s*=\s*'active'/u);
  assert.match(commitBeforeInsert, /FROM public\.control_plane_authority_generations[\s\S]*g\.generation\s*=\s*reservation_row\.authority_generation/u);
  assert.match(commitBeforeInsert, /g\.superseded_at\s+IS\s+NULL/u);
  assert.match(commitBeforeInsert, /FROM public\.revocations AS r[\s\S]*r\.status\s*=\s*'active'/u);
  for (const target of ["organization", "device", "agent"]) {
    assert.match(commitBeforeInsert, new RegExp(`target_type\\s*=\\s*'${target}'`, "u"));
  }

  // The key may be disabled or rotated while the provider is signing.
  assert.match(commitBeforeInsert, /FROM public\.managed_signer_keys[\s\S]*k\.purpose\s*=\s*reservation_row\.key_purpose/u);
  assert.match(commitBeforeInsert, /k\.key_id\s*=\s*reservation_row\.key_id/u);
  assert.match(commitBeforeInsert, /k\.state\s*=\s*'active'/u);
  assert.match(commitBeforeInsert, /k\.algorithm\s*=\s*reservation_row\.algorithm/u);
});

test("0074 binds commit to one immutable managed-signer provider operation", async () => {
  const sql = await migration();
  const table = tableBody(sql);
  const commit = functionBody(sql, "agentpass_agent_signing_capability_commit");
  const commitBeforeInsert = before(commit, "INSERT INTO public.capabilities");

  for (const column of ["planned_provider_operation_id", "provider_operation_id", "provider_request_digest", "provider_bytes_length", "signing_bytes_digest"]) {
    assert.match(table, new RegExp(`\\b${column}\\b`, "u"), `missing ${column}`);
  }
  assert.match(
    table,
    /FOREIGN KEY \(key_purpose, provider_operation_id\)\s+REFERENCES public\.managed_signer_provider_operations\(purpose, operation_id\)/u,
  );
  assert.match(commitBeforeInsert, /FROM public\.managed_signer_provider_operations AS provider/u);
  for (const predicate of [
    "provider.purpose = reservation_row.key_purpose",
    "provider.operation_id = reservation_row.planned_provider_operation_id",
    "provider_row.algorithm IS DISTINCT FROM reservation_row.algorithm",
    "provider_row.key_id IS DISTINCT FROM reservation_row.key_id",
    "provider_row.key_version IS DISTINCT FROM reservation_row.key_version",
    "provider_row.request_digest IS DISTINCT FROM expected_provider_request_digest",
    "provider_row.bytes_length IS DISTINCT FROM octet_length(signing_bytes)",
    "provider_row.public_key_der IS NULL",
  ]) {
    assert.match(commitBeforeInsert, new RegExp(predicate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"), predicate);
  }
  assert.match(commitBeforeInsert, /provider_row\.state\s*(?:<>|IS DISTINCT FROM)\s*'committed'/u);
  assert.match(commitBeforeInsert, /provider_row\.signature\s+IS\s+NULL/u);
});

test("0074 enforces exact capability and public response JSON cardinality", async () => {
  const sql = await migration();
  const [capabilitySchema, responseSchema] = await Promise.all([
    json(capabilitySchemaUrl),
    json(responseSchemaUrl),
  ]);
  const commit = functionBody(sql, "agentpass_agent_signing_capability_commit");
  const statement = functionBody(sql, "agentpass_agent_signing_capability_statement_canonical_json");

  assert.equal(capabilitySchema.maxProperties, Object.keys(capabilitySchema.properties).length);
  assert.equal(capabilitySchema.maxProperties, capabilitySchema.required.length);
  assert.equal(capabilitySchema.$defs.statement.maxProperties, capabilitySchema.$defs.statement.required.length);
  assert.equal(responseSchema.maxProperties, Object.keys(responseSchema.properties).length);
  assert.equal(responseSchema.maxProperties, responseSchema.required.length);
  assert.equal(responseSchema.$defs.metadata.maxProperties, responseSchema.$defs.metadata.required.length);

  assert.match(commit, /SELECT count\(\*\) FROM jsonb_object_keys\(expected_capability\)[\s\S]{0,80}(?:<>|IS DISTINCT FROM)\s*5/u);
  assert.match(commit, /SELECT count\(\*\) FROM jsonb_object_keys\(expected_capability->'statement'\)[\s\S]{0,100}(?:<>|IS DISTINCT FROM)\s*21/u);
  for (const field of capabilitySchema.$defs.statement.required) {
    assert.match(
      statement,
      new RegExp(`(?:'|")${field}(?:'|")`, "u"),
      `the server-built statement must contain key ${field}`,
    );
  }
  for (const field of capabilitySchema.required) {
    if (field === "statement") continue;
    assert.match(commit, new RegExp(`(?:'|")${field}(?:'|")`, "u"), `the server-built envelope must contain key ${field}`);
  }
  assert.match(commit, /response_json\s*=\s*expected_capability/u);
  assert.doesNotMatch(commit, /p_capability|p_statement_hash|p_signature_hash/u);
});

test("0074 has bounded expiry recovery for abandoned reservations", async () => {
  const sql = await migration();
  const recovery = functionBody(sql, "agentpass_agent_signing_capability_recover_expired");

  assert.match(recovery, /state\s*=\s*'reserved'/u);
  assert.match(recovery, /claim_expires_at\s*<=/u);
  assert.match(recovery, /FOR UPDATE SKIP LOCKED/u);
  assert.match(recovery, /state\s*=\s*'outcome_unknown'/u);
  assert.match(recovery, /reserved_signatures\s*=\s*reserved_signatures\s*-\s*1/u);
  assert.match(recovery, /used_signatures\s*=\s*used_signatures\s*\+\s*1/u);
  assert.match(recovery, /response_json\s*=\s*NULL/u);
  assert.match(recovery, /LIMIT\s+p_batch_size/u);
  assert.match(sql, /CREATE FUNCTION public\.agentpass_agent_signing_capability_recover_expired\(\s*p_batch_size integer/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_agent_signing_capability_recover_expired\(integer\)[\s\S]*?TO agentpass_maintenance/u);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_agent_signing_capability_recover_expired\(integer\)\s+TO agentpass_app;/u);
  assert.doesNotMatch(recovery, /p_organization_id|agentpass_current_organization_id/u);
  assert.match(recovery, /FROM public\.agent_session_signing_capability_reservations AS reservation[\s\S]*WHERE \(/u);
});

test("0074 never derives the tenant GUC directly from a caller argument", async () => {
  const sql = await migration();
  for (const name of [
    "agentpass_agent_signing_capability_reserve",
    "agentpass_agent_signing_capability_commit",
    "agentpass_agent_signing_capability_replay",
    "agentpass_agent_signing_capability_uncertain",
  ]) {
    const body = functionBody(sql, name);
    const setConfig = body.match(/set_config\(\s*'agentpass\.organization_id'\s*,\s*([^,]+),/u);
    if (setConfig) assert.doesNotMatch(setConfig[1], /p_organization_id/u, `${name} must not trust caller organization_id`);
    assert.match(body, /public\.agentpass_current_organization_id\(\)\s+IS DISTINCT FROM\s+p_organization_id/u);
  }
  assert.doesNotMatch(functionBody(sql, "agentpass_agent_signing_capability_recover_expired"), /p_organization_id|agentpass_current_organization_id/u);
  assert.doesNotMatch(sql, /set_config\(\s*'agentpass\.organization_id'\s*,\s*p_organization_id::text/u);
});

test("0074 fixes SECURITY DEFINER search paths and RLS for every authority table", async () => {
  const sql = await migration();
  for (const name of [
    "agentpass_allocate_capability_sequence_on_insert",
    "agentpass_agent_signing_capability_reserve",
    "agentpass_agent_signing_capability_commit",
    "agentpass_agent_signing_capability_replay",
    "agentpass_agent_signing_capability_uncertain",
  ]) {
    const definition = functionBody(sql, name);
    assert.match(definition, /SECURITY DEFINER/u, `${name} must be definer-owned`);
    assert.match(definition, /SET search_path\s*=\s*pg_catalog,\s*public/u, `${name} must pin search_path`);
  }

  for (const table of [
    "capabilities",
    "agent_capability_sequence_heads",
    "agent_session_signing_capability_reservations",
  ]) {
    assert.match(sql, new RegExp(`ALTER TABLE public\\.${table} ENABLE ROW LEVEL SECURITY`, "u"), `${table} RLS enabled`);
    assert.match(sql, new RegExp(`ALTER TABLE public\\.${table} FORCE ROW LEVEL SECURITY`, "u"), `${table} RLS forced`);
    const policy = new RegExp(`CREATE POLICY[\\s\\S]*?ON public\\.${table}[\\s\\S]*?organization_id\\s*=\\s*public\\.agentpass_current_organization_id\\(\\)`, "u");
    assert.match(sql, policy, `${table} tenant policy`);
  }
});

test("0074 leaves signing authority function-only for agentpass_app", async () => {
  const [sql, roleSql] = await Promise.all([migration(), roles()]);
  assert.doesNotMatch(roleSql, /GRANT\s+SELECT,\s*INSERT,\s*UPDATE,\s*DELETE\s+ON\s+ALL\s+TABLES[\s\S]*?TO\s+agentpass_app/iu);
  for (const table of [
    "capabilities",
    "managed_signer_keys",
    "managed_signer_provider_operations",
    "agent_session_signing_capability_reservations",
    "agent_capability_sequence_heads",
  ]) {
    assert.match(roleSql, new RegExp(`['"]${table}['"]`, "u"), `${table} must be in the authority classification`);
    assert.match(
      roleSql,
      new RegExp(`(?:REVOKE ALL PRIVILEGES ON TABLE public\\.${table}|${table})[\\s\\S]*?agentpass_app`, "u"),
      `${table} must be classified as function-only authority`,
    );
    assert.doesNotMatch(
      roleSql,
      new RegExp(`GRANT\\s+(?:SELECT|INSERT|UPDATE|DELETE)[^\\n]*public\\.${table}[^\\n]*TO\\s+agentpass_app`, "iu"),
    );
  }
  assert.doesNotMatch(sql, /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE).*TO\s+agentpass_app/iu);
});

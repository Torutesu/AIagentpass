import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const checkerPath = new URL('./role-privilege-check.mjs', import.meta.url);

test('signing capability role qualification is an explicit catalog contract', async () => {
  const checker = await readFile(checkerPath, 'utf8');

  for (const table of [
    'capabilities',
    'agent_session_signing_capability_reservations',
    'agent_capability_sequence_heads',
  ]) {
    assert.match(checker, new RegExp(`'${table}'`, 'u'));
  }

  for (const signature of [
    'agentpass_agent_signing_capability_reserve(uuid,uuid,uuid,uuid,bytea,uuid,uuid,bytea,text,text,boolean,integer,bigint)',
    'agentpass_agent_signing_capability_commit(uuid,uuid,uuid,uuid,bytea,bytea)',
    'agentpass_agent_signing_capability_replay(uuid,uuid,uuid,uuid,bytea)',
    'agentpass_agent_signing_capability_uncertain(uuid,uuid,uuid,uuid,bytea,bytea,text)',
    'agentpass_agent_signing_capability_recover_expired(integer)',
    'agentpass_capability_authority_issue(uuid,uuid,uuid,uuid,bigint,text,timestamptz,uuid,bigint)',
    'agentpass_capability_authority_revoke_member(uuid,uuid,timestamptz)',
    'agentpass_capability_authority_list_revoked(uuid,timestamptz,integer)',
    'agentpass_capability_reservation_issue(uuid,uuid,uuid,uuid,bigint,text,timestamptz,uuid,text,text,jsonb,timestamptz,bytea)',
    'agentpass_capability_reservation_list(uuid,integer)',
  ]) {
    assert.match(checker, new RegExp(`'${signature.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}'`, 'u'));
  }

  assert.match(checker, /relrowsecurity/u);
  assert.match(checker, /relforcerowsecurity/u);
  assert.match(checker, /pg_policy/u);
  assert.match(checker, /pg_get_expr\(p\.polqual, p\.polrelid\)/u);
  assert.match(checker, /pg_get_expr\(p\.polwithcheck, p\.polrelid\)/u);
  assert.doesNotMatch(checker, /btrim\(regexp_replace\(pg_get_expr/u);
  assert.match(checker, /'\(\^\[\(\]\|\[\)\]\$\)', '', 'g'/u);
  assert.match(checker, /'public\.agentpass_current_organization_id\(\)', 'agentpass_current_organization_id\(\)'/u);
  assert.match(checker, /p\.polroles IS DISTINCT FROM ARRAY\[0::oid\]/u);
  assert.match(checker, /p\.polpermissive IS DISTINCT FROM true/u);
  assert.match(checker, /SET search_path = pg_catalog;/u);

  for (const policy of [
    'agent_session_signing_capability_reservations_tenant_select',
    'agent_session_signing_capability_reservations_tenant_insert',
    'agent_session_signing_capability_reservations_tenant_update',
    'agent_capability_sequence_heads_tenant_select',
    'agent_capability_sequence_heads_tenant_insert',
    'agent_capability_sequence_heads_tenant_update',
    'agent_capability_sequence_heads_migrator_authority',
  ]) {
    assert.match(checker, new RegExp(`'${policy}'`, 'u'));
  }

  assert.match(checker, /organization_id=agentpass_current_organization_id\(\)/gu);
  assert.match(checker, /p\.prosecdef IS DISTINCT FROM true/u);
  assert.match(checker, /p\.proconfig\[1\] IS DISTINCT FROM 'search_path=pg_catalog, public'/u);
  assert.match(checker, /p\.proowner IS DISTINCT FROM \(SELECT oid FROM role_ids WHERE rolname = 'agentpass_migrator'\)/u);

  for (const privilege of ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) {
    assert.match(
      checker,
      new RegExp(`has_table_privilege\\('agentpass_app', t\\.oid, '${privilege}'\\)`, 'u'),
      `missing direct app privilege check for ${privilege}`,
    );
  }

  assert.match(checker, /signing_capability_boundary_ok/u);
  assert.match(checker, /signing_capability_table_diagnostics/u);
  assert.match(checker, /signing_capability_function_diagnostics/u);
  assert.match(checker, /agentpass_maintenance/u);
  assert.match(checker, /maintenance_function_allowlist/u);
  assert.match(checker, /device_audit_boundary_ok/u);
  assert.match(checker, /device_audit_events_tenant_select/u);
  assert.match(checker, /agentpass_record_device_audit_head\(\)/u);
  assert.match(checker, /expected_migrations\(version, checksum\)/u);
  assert.match(checker, /actual\.checksum IS DISTINCT FROM expected\.checksum/u);
  assert.match(checker, /policy:tenant_predicate_mismatch/u);
  assert.match(checker, /maintenance_function_oids/u);
  assert.match(checker, /policy_mismatches/u);
  assert.match(checker, /actual_with_check/u);
});

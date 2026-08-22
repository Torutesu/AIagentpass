import { access, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const root = new URL('../../../../', import.meta.url);
const read = async (relativePath) => readFile(new URL(relativePath, root), 'utf8');

const PLATFORM_AUTHORITY_RELATIONS = Object.freeze([
  'platform_credentials',
  'platform_sessions',
  'platform_session_challenges',
  'platform_authorization_proofs',
  'platform_principals',
  'platform_operator_assignments',
  'platform_operator_assignment_approvals',
  'platform_promotion_approvals',
  'platform_promotion_deployments',
  'platform_promotion_issuances',
]);
const HUMAN_AUTHORITY_RELATIONS = Object.freeze([
  "organizations", "memberships",
  "human_sessions", "webauthn_credentials", "webauthn_challenges",
  "owner_recovery_requests", "owner_recovery_approvals", "owner_recovery_exchanges",
  "owner_recovery_sessions", "owner_recovery_webauthn_challenges",
  "owner_recovery_idempotency_records", "owner_recovery_outbox",
  "owner_recovery_outbox_retention_ledger", "owner_recovery_outbox_transition_heads",
  "owner_recovery_outbox_transition_ledger"
]);

const PLATFORM_APP_FUNCTIONS = Object.freeze([
  'agentpass_platform_operator_assignment_find_active(uuid,uuid,uuid,text,text)',
  'agentpass_platform_session_challenge_create(uuid,uuid,bytea,bytea,bytea,bytea,bytea[],uuid,uuid,uuid,uuid,bigint,text,text,text,text,text,integer)',
  'agentpass_platform_session_challenge_find(uuid)',
  'agentpass_platform_session_challenge_claim(uuid,bytea,bytea,bytea,bytea)',
  'agentpass_platform_session_challenge_fail(uuid,bytea,bytea,bytea,bytea,text)',
  'agentpass_platform_session_credential_find(uuid,bytea,bytea)',
  'agentpass_platform_credential_advance_verified(uuid,bytea,uuid,bytea,bigint,bigint,bigint,boolean,boolean)',
  'agentpass_platform_session_find_active(bytea,uuid,text,text)',
  'agentpass_platform_session_touch(bytea,bytea,uuid,text,text)',
  'agentpass_platform_session_revoke(bytea,bytea,text)',
  'agentpass_platform_session_complete_and_issue(uuid,bytea,bytea,uuid,bytea,bytea,bytea,bytea,bytea,integer,integer)',
  'agentpass_consume_platform_authorization_and_reserve(bytea,bytea,uuid,bytea,bytea,uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint)',
  'agentpass_platform_session_bootstrap_context(bytea,uuid,text,text)',
]);

const SHARED_CONTROL_APP_FUNCTIONS = Object.freeze([
  'agentpass_consume_device_request_nonce(uuid,uuid,bytea,integer)',
  'agentpass_consume_human_identity_assertion(bytea,timestamptz)',
  'agentpass_valid_webauthn_transports(text[])',
  'agentpass_acquire_rate_limit(uuid,text,uuid,integer,numeric,integer,integer)',
  'agentpass_acquire_anonymous_rate_limit(text,uuid,integer,numeric,integer,integer)',
  'agentpass_prune_shared_control_expired(integer)',
  'agentpass_prune_anonymous_rate_limits(integer)',
  'agentpass_prune_human_identity_assertion_replays(integer)',
  'agentpass_request_device_refresh(uuid,uuid,uuid,bigint,text,bytea,timestamptz)',
]);

const LEGACY_PLATFORM_PROMOTION_MUTATIONS = Object.freeze([
  'agentpass_platform_promotion_issuance_reserve(uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint)',
  'agentpass_platform_promotion_issuance_replay(uuid,text,text,text,text)',
  'agentpass_platform_promotion_issuance_commit(uuid,text,text,text,text,bytea,bytea,bytea,bytea,bytea)',
  'agentpass_platform_promotion_issuance_uncertain(uuid,text,text,text,text,bytea,text)',
]);

const PLATFORM_SIGNER_FINALIZE_FUNCTIONS = Object.freeze([
  'agentpass_platform_promotion_issuance_commit(uuid,text,text,text,text,bytea,bytea,bytea,bytea,bytea)',
  'agentpass_platform_promotion_issuance_uncertain(uuid,text,text,text,text,bytea,text)',
]);

const PLATFORM_MIGRATION_FILES = Object.freeze([
  'contracts/postgres/0044_platform_promotion_approvals.sql',
  'contracts/postgres/0047_platform_promotion_issuance.sql',
  'contracts/postgres/0048_platform_promotion_authority_boundary.sql',
  'contracts/postgres/0052_platform_operator_authority.sql',
  'contracts/postgres/0053_platform_sessions.sql',
  'contracts/postgres/0054_platform_authorization.sql',
  'contracts/postgres/0055_platform_session_bootstrap.sql',
]);

function escapedRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

test('role SQL is idempotent, credential-free, and PUBLIC is revoked', async () => {
  const sql = await read('scripts/postgres/roles.sql');
  const migrations = await Promise.all(PLATFORM_MIGRATION_FILES.map(read));
  const platformSql = migrations.join('\n');

  assert.match(sql, /CREATE ROLE %I LOGIN/);
  for (const role of ['agentpass_app', 'agentpass_signer', 'agentpass_migrator', 'agentpass_backup', 'agentpass_maintenance']) assert.match(sql, new RegExp(`\\b${role}\\b`));
  assert.doesNotMatch(sql, /PASSWORD\s+['"]/i);
  assert.doesNotMatch(sql, /postgres(?:ql)?:\/\/[^\s]*:[^\s@]+@/i);
  assert.match(sql, /REVOKE agentpass_migrator FROM agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance/);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON DATABASE/);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC/);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC/);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC/);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC/);
  assert.match(sql, /schema_migrations/);
  assert.match(sql, /schema_migration_attempts/);
  assert.match(sql, /to_regclass\('public\.organizations'\)[\s\S]*to_regclass\('public\.memberships'\)[\s\S]*GRANT SELECT ON TABLE public\.organizations, public\.memberships/u);
  for (const relation of ['release_candidates', 'platform_promotion_approvals', 'platform_promotion_deployments', 'platform_promotion_issuances', 'platform_principals', 'platform_operator_assignments', 'platform_operator_assignment_approvals', 'managed_signer_key_lifecycles', 'managed_signer_keys']) assert.match(sql, new RegExp(`\\b${relation}\\b`));
  for (const relation of PLATFORM_AUTHORITY_RELATIONS) {
    assert.match(platformSql, new RegExp(`CREATE TABLE (?:public\\.)?${relation} \\(`, 'u'), `migration relation missing: ${relation}`);
  }
  assert.match(sql, /Platform mutation is issue-only for the application role/);
  assert.match(sql, /managed_signer_provider_operations/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.%s TO agentpass_app/);
  assert.match(sql, /agentpass_agent_signing_capability_recover_expired\(integer\)/u);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION public\.%s TO agentpass_maintenance/u);
  assert.doesNotMatch(sql, /agentpass_agent_signing_capability_recover_expired\(uuid,integer\)/u);
  assert.match(sql, /agentpass_platform_operator_assignment_find_active\(uuid,uuid,uuid,text,text\)/u);
  assert.match(sql, /agentpass_platform_session_find_active\(bytea,uuid,text,text\)/u);
  assert.match(sql, /agentpass_platform_session_touch\(bytea,bytea,uuid,text,text\)/u);
  assert.match(sql, /agentpass_platform_session_revoke\(bytea,bytea,text\)/u);
  assert.match(sql, /agentpass_platform_session_complete_and_issue\(uuid,bytea,bytea,uuid,bytea,bytea,bytea,bytea,bytea,integer,integer\)/u);
  assert.match(sql, /agentpass_consume_platform_authorization_and_reserve\(bytea,bytea,uuid,bytea,bytea,uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint\)/u);
  assert.match(sql, /agentpass_platform_session_bootstrap_context\(bytea,uuid,text,text\)/u);
  for (const signature of PLATFORM_APP_FUNCTIONS) {
    assert.match(sql, new RegExp(`'${escapedRegExp(signature)}'`, 'u'), `application function missing: ${signature}`);
    const functionName = signature.slice(0, signature.indexOf('('));
    assert.match(platformSql, new RegExp(`CREATE FUNCTION (?:public\\.)?${escapedRegExp(functionName)}\\(`, 'u'), `migration function missing: ${functionName}`);
  }
  for (const signature of SHARED_CONTROL_APP_FUNCTIONS) {
    assert.match(sql, new RegExp(`'${escapedRegExp(signature)}'`, 'u'), `shared-control application function missing: ${signature}`);
  }
  for (const signature of LEGACY_PLATFORM_PROMOTION_MUTATIONS) {
    const occurrences = sql.split(`'${signature}'`).length - 1;
    assert.equal(occurrences, PLATFORM_SIGNER_FINALIZE_FUNCTIONS.includes(signature) ? 1 : 0, `unexpected promotion grant count: ${signature}`);
  }
  assert.match(sql, /ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public/);
  assert.match(sql, /ON TABLES/);
  assert.match(sql, /ON SEQUENCES/);
  assert.match(sql, /ON FUNCTIONS/);
});

test('platform authority matrix is function-only for app and purpose-scoped for signer', async () => {
  const [rolesSql, ...migrations] = await Promise.all([
    read('scripts/postgres/roles.sql'),
    ...PLATFORM_MIGRATION_FILES.map(read),
  ]);
  const platformSql = migrations.join('\n');
  const authorization = await read('contracts/postgres/0054_platform_authorization.sql');

  assert.match(rolesSql, /GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public\.%I TO agentpass_app/u);
  assert.match(rolesSql, /c\.relname NOT IN \([\s\S]*'capabilities'[\s\S]*'agent_session_signing_capability_reservations'/u);
  assert.match(rolesSql, /c\.relname NOT IN \([\s\S]*'device_audit_inbox'/u);
  assert.match(rolesSql, /'managed_signer_provider_operations', 'device_audit_inbox'/u);
  assert.match(rolesSql, /REVOKE ALL PRIVILEGES ON TABLE public\.%I FROM agentpass_app, agentpass_backup/u);
  assert.match(rolesSql, /GRANT SELECT ON TABLE public\.%I TO agentpass_app, agentpass_backup/u);
  assert.match(rolesSql, /left\(c\.relname, length\('platform_'\)\) = 'platform_'/u);
  assert.ok(rolesSql.indexOf("c.relname NOT IN (") < rolesSql.indexOf('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO agentpass_app'));
  for (const relation of HUMAN_AUTHORITY_RELATIONS) {
    assert.match(rolesSql, new RegExp(`'${escapedRegExp(relation)}'`, 'u'), `human authority relation is missing from app DML exclusion: ${relation}`);
  }

  assert.match(authorization, /CREATE FUNCTION public\.agentpass_consume_platform_authorization_and_reserve\([\s\S]*?SECURITY DEFINER[\s\S]*?SET search_path = pg_catalog, public/u);
  assert.match(authorization, /REVOKE ALL PRIVILEGES ON FUNCTION public\.agentpass_platform_promotion_issuance_reserve\([^;]+\) FROM agentpass_app/u);
  assert.doesNotMatch(authorization, /GRANT EXECUTE ON FUNCTION public\.agentpass_platform_promotion_issuance_reserve\([^;]+\) TO agentpass_app/u);

  for (const signature of PLATFORM_APP_FUNCTIONS) {
    assert.match(rolesSql, new RegExp(`'${escapedRegExp(signature)}'`, 'u'), `app allowlist missing: ${signature}`);
  }
  for (const signature of LEGACY_PLATFORM_PROMOTION_MUTATIONS) {
    const occurrences = rolesSql.split(`'${signature}'`).length - 1;
    assert.equal(occurrences, PLATFORM_SIGNER_FINALIZE_FUNCTIONS.includes(signature) ? 1 : 0, `unexpected promotion grant count: ${signature}`);
    const functionName = signature.slice(0, signature.indexOf('('));
    assert.match(platformSql, new RegExp(`CREATE FUNCTION (?:public\\.)?${escapedRegExp(functionName)}\\(`, 'u'), `migration function missing: ${functionName}`);
  }

  assert.match(rolesSql, /GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO agentpass_migrator/u);
  assert.match(rolesSql, /GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO agentpass_migrator/u);
  assert.match(rolesSql, /GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO agentpass_migrator/u);
  assert.match(rolesSql, /GRANT EXECUTE ON FUNCTION public\.%s TO agentpass_signer/u);
  assert.match(rolesSql, /left\(c\.relname, length\('managed_signer_'\)\) = 'managed_signer_'/u);
  for (const signature of PLATFORM_SIGNER_FINALIZE_FUNCTIONS) {
    assert.match(rolesSql, new RegExp(`'${escapedRegExp(signature)}'`, 'u'), `signer finalization allowlist missing: ${signature}`);
  }
});

test('app is DML-only, migrator owns migration authority, and backup is read-only', async () => {
  const sql = await read('scripts/postgres/roles.sql');

  assert.match(sql, /GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public\.%I TO agentpass_app/);
  assert.doesNotMatch(sql, /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agentpass_app/);
  assert.match(sql, /'agentpass_signer'/);
  assert.doesNotMatch(sql, /GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public\.%I TO agentpass_signer/);
  assert.match(sql, /left\(c\.relname, length\('managed_signer_'\)\) = 'managed_signer_'/u);
  assert.match(sql, /left\(c\.relname, length\('platform_'\)\) = 'platform_'/u);
  assert.match(sql, /agentpass_managed_signer_provider_operation_reserve\(text,text,text,integer,bytea,text,bigint,bytea,integer,integer\)/u);
  assert.match(sql, /agentpass_maintain_managed_signer_provider_operations\(integer\)/u);
  for (const signature of [
    'agentpass_managed_signer_lifecycle_snapshot(text)',
    'agentpass_managed_signer_lifecycle_initialize(text,text,jsonb,integer,bigint)',
    'agentpass_managed_signer_lifecycle_apply(text,text,bytea,bigint,jsonb,bigint)',
    'agentpass_managed_signer_signing_reserve(text,text,bytea,text,bigint,bytea,bigint,bigint)',
    'agentpass_managed_signer_signing_start(text,text,bytea,text,bigint,bytea)',
    'agentpass_managed_signer_signing_commit(text,text,bytea,text,bigint,bytea,bytea,text,text)',
    'agentpass_managed_signer_signing_uncertain(text,text,bytea,text,bigint,bytea)',
    'agentpass_managed_signer_signing_reconcile(text,text,bytea,text,bigint,bytea,text,text)',
    'agentpass_managed_signer_signing_lookup(text,text)',
    'agentpass_managed_signer_signing_prune(text,timestamptz,integer)',
    'agentpass_managed_signer_lifecycle_operation_prune(text,timestamptz,integer)'
  ]) assert.equal(sql.includes(signature), true);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_quarantine_expired_managed_signer_provider_operations/u);
  assert.match(sql, /left\(c\.relname, length\('platform_'\)\) = 'platform_'/u);
  assert.match(sql, /GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agentpass_app/);
  assert.match(sql, /GRANT USAGE, CREATE ON SCHEMA public TO agentpass_migrator/);
  assert.match(sql, /OWNER TO agentpass_migrator/);
  assert.match(sql, /GRANT SELECT ON ALL TABLES IN SCHEMA public TO agentpass_backup/);
  assert.match(sql, /GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO agentpass_backup/);
  assert.match(sql, /REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance/);
  assert.doesNotMatch(sql, /GRANT .* ON SCHEMA public TO agentpass_app[^\n]*CREATE/i);
  assert.doesNotMatch(sql, /GRANT .* ON SCHEMA public TO agentpass_signer[^\n]*CREATE/i);
  assert.doesNotMatch(sql, /ALTER DEFAULT PRIVILEGES[\s\S]{0,160}GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agentpass_app/u);
  assert.doesNotMatch(sql, /ALTER DEFAULT PRIVILEGES[\s\S]{0,160}GRANT USAGE, SELECT ON SEQUENCES TO agentpass_app/u);
});

test('checker reads the URL from the environment, enforces verify-full, and measures opaque evidence', async () => {
  const checker = await read('scripts/postgres/role-privilege-check.mjs');

  assert.match(checker, /process\.env\[DATABASE_URL_ENV\]/);
  assert.doesNotMatch(checker, /process\.argv\[[^]]+\].*(?:URL|DATABASE)/i);
  assert.match(checker, /sslmode.*verify-full/);
  assert.match(checker, /process\.argv\.length !== 2/);
  assert.match(checker, /current_user/);
  assert.match(checker, /current_user = 'agentpass_migrator'/);
  assert.match(checker, /left\(t\.relname, length\('platform_'\)\)/u);
  for (const privilegeFunction of ['has_schema_privilege', 'has_table_privilege', 'has_sequence_privilege', 'has_function_privilege']) assert.match(checker, new RegExp(privilegeFunction));
  assert.match(checker, /agentpass_signer/);
  assert.match(checker, /managed_signer_provider_operations/);
  assert.match(checker, /migration_head_ok/u);
  assert.match(checker, /POSTGRES_SCHEMA_HEAD/u);
  assert.match(checker, /const EXPECTED_MIGRATION_VERSION = POSTGRES_SCHEMA_HEAD\.version/u);
  assert.match(checker, /count\(\*\) = \$\{EXPECTED_MIGRATION_VERSION\}[\s\S]*?min\(version\) = 1[\s\S]*?max\(version\) = \$\{EXPECTED_MIGRATION_VERSION\}/u);
  assert.match(checker, /signer_function_allowlist/u);
  assert.match(checker, /app_function_allowlist/u);
  assert.match(checker, /to_regprocedure\('public\.' \|\| routine_signature\) AS routine_oid/u);
  assert.match(checker, /NOT EXISTS \(SELECT 1 FROM signer_function_oids WHERE routine_oid IS NULL\)/u);
  for (const signature of PLATFORM_APP_FUNCTIONS) {
    assert.match(checker, new RegExp(`\\('${escapedRegExp(signature)}'\\)`, 'u'), `checker app allowlist missing: ${signature}`);
  }
  for (const signature of LEGACY_PLATFORM_PROMOTION_MUTATIONS) {
    const occurrences = checker.split(`('${signature}')`).length - 1;
    assert.equal(occurrences, PLATFORM_SIGNER_FINALIZE_FUNCTIONS.includes(signature) ? 1 : 0, `checker promotion allowlist mismatch: ${signature}`);
  }
  assert.match(checker, /a\.routine_oid = functions\.oid/u);
  assert.match(checker, /createHash\('sha256'\)/);
  assert.match(checker, /failed_checks=/u);
  assert.match(checker, /REPORT_CHECKS\.filter/u);
  assert.match(checker, /AGENTPASS_PRIVILEGE_EVIDENCE_OUTPUT/u);
  assert.match(checker, /writeFileSync\(evidenceOutput/u);
  assert.match(checker, /spawnSync\(\s*'psql'/);
  assert.match(checker, /'--command'/);
  assert.doesNotMatch(checker, /sql,\s*databaseUrl/);
  for (const variable of ['PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD', 'PGDATABASE', 'PGSSLMODE']) assert.match(checker, new RegExp(variable));
});

test('real role qualification removes database URLs before spawning psql', async () => {
  const integration = await read('apps/cloud-api/test/postgres/least-privilege-role.integration.test.mjs');

  assert.match(integration, /AGENTPASS_TEST_DATABASE_URL:\s*_testDatabaseUrl/);
  assert.match(integration, /AGENTPASS_TEST_POSTGRES_URL:\s*_testPostgresUrl/);
  assert.match(integration, /AGENTPASS_DATABASE_URL:\s*_databaseUrl/);
  assert.match(integration, /DATABASE_URL:\s*_genericDatabaseUrl/);
  assert.match(integration, /spawnSync\(\s*"psql"/);
  assert.doesNotMatch(integration, /env:\s*process\.env/);
});

test('real role qualification uses independent TLS-authenticated connections', async () => {
  const integration = await read('apps/cloud-api/test/postgres/least-privilege-role.integration.test.mjs');

  for (const variable of [
    'AGENTPASS_TEST_POSTGRES_ADMIN_URL',
    'AGENTPASS_TEST_APP_DATABASE_URL',
    'AGENTPASS_TEST_SIGNER_DATABASE_URL',
    'AGENTPASS_TEST_MIGRATION_DATABASE_URL',
    'AGENTPASS_TEST_BACKUP_DATABASE_URL',
  ]) assert.match(integration, new RegExp(variable, 'u'));
  assert.match(integration, /async function withRoleConnection/u);
  assert.match(integration, /SELECT session_user, current_user,[\s\S]*pg_stat_ssl/u);
  assert.match(integration, /assert\.equal\(principal\.rows\[0\]\.ssl, true/u);
  assert.doesNotMatch(integration, /SET SESSION AUTHORIZATION/u);
  assert.doesNotMatch(integration, /SET LOCAL ROLE/u);
  assert.match(integration, /cleanup left rows or objects behind/u);
});

test('existing operational docs contain the role boundary', async () => {
  const [cutover, backup] = await Promise.all([
    read('docs/POSTGRES_CUTOVER_RUNBOOK.md'),
    read('docs/POSTGRES_BACKUP_RESTORE.md'),
  ]);
  for (const document of [cutover, backup]) {
    assert.match(document, /agentpass_app/);
    assert.match(document, /agentpass_signer/);
    assert.match(document, /agentpass_migrator/);
    assert.match(document, /agentpass_backup/);
    assert.match(document, /verify-full/);
    assert.match(document, /secret|credential/i);
  }
  assert.match(cutover, /roles\.sql/);
  assert.match(cutover, /role-privilege-check\.mjs/);
  assert.match(backup, /read-only/i);
});

test('all requested artifacts exist in the allowed paths', async () => {
  await Promise.all([
    'scripts/postgres/roles.sql',
    'scripts/postgres/role-privilege-check.mjs',
    'apps/cloud-api/test/postgres/least-privilege-role-contract.test.mjs',
    'apps/cloud-api/test/postgres/least-privilege-role.integration.test.mjs',
    'docs/POSTGRES_CUTOVER_RUNBOOK.md',
    'docs/POSTGRES_BACKUP_RESTORE.md',
  ].map((relativePath) => access(new URL(relativePath, root))));
});

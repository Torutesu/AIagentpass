import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { POSTGRES_SCHEMA_HEAD } from '../../apps/cloud-api/src/postgres/schema-head.mjs';

const DATABASE_URL_ENV = 'AGENTPASS_DATABASE_URL';
const EVIDENCE_OUTPUT_ENV = 'AGENTPASS_PRIVILEGE_EVIDENCE_OUTPUT';
const SCHEMA = 'public';
const EXPECTED_MIGRATION_VERSION = POSTGRES_SCHEMA_HEAD.version;
const MAX_TABLE_DIAGNOSTICS = 32;
const MAX_RELATION_DIAGNOSTIC_NAME = 128;
const MAX_DIAGNOSTIC_OUTPUT = 4096;
const ROLES = ['agentpass_app', 'agentpass_signer', 'agentpass_migrator', 'agentpass_backup'];
const REPORT_CHECKS = [
  'role_attributes_ok',
  'role_memberships_ok',
  'schema_privileges_ok',
  'database_privileges_ok',
  'migration_head_ok',
  'table_privileges_ok',
  'sequence_privileges_ok',
  'function_privileges_ok',
  'default_privileges_ok',
];

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 2;
}

function boundedTableDiagnostics(value) {
  if (!Array.isArray(value)) return '[]';
  const diagnostics = value.slice(0, MAX_TABLE_DIAGNOSTICS).map((item) => ({
    relation: typeof item?.relation === 'string'
      ? item.relation.slice(0, MAX_RELATION_DIAGNOSTIC_NAME).replace(/[^A-Za-z0-9_]/gu, '?')
      : 'unknown',
    kind: typeof item?.kind === 'string' ? item.kind.slice(0, 1) : '?',
    class: typeof item?.class === 'string' ? item.class.slice(0, 16) : 'unknown',
    failures: Array.isArray(item?.failures)
      ? item.failures.filter((failure) => typeof failure === 'string').slice(0, 16)
      : [],
  }));
  const encoded = JSON.stringify(diagnostics);
  return encoded.length <= MAX_DIAGNOSTIC_OUTPUT
    ? encoded
    : `${encoded.slice(0, MAX_DIAGNOSTIC_OUTPUT - 32)}...(truncated)`;
}

if (process.argv.length !== 2) {
  fail('role privilege check accepts no arguments');
} else {
  const databaseUrl = process.env[DATABASE_URL_ENV];

  if (!databaseUrl) {
    fail(`missing ${DATABASE_URL_ENV}`);
  } else {
    let parsedUrl;
    try {
      parsedUrl = new URL(databaseUrl);
    } catch {
      fail('invalid database URL');
    }

    if (parsedUrl) {
      const queryEntries = [...parsedUrl.searchParams.entries()];
      const onlyVerifyFull = queryEntries.length === 1
        && queryEntries[0][0] === 'sslmode'
        && queryEntries[0][1] === 'verify-full';

      if (parsedUrl.protocol !== 'postgresql:' || !parsedUrl.hostname || !parsedUrl.username || !parsedUrl.password
        || !parsedUrl.pathname || parsedUrl.pathname === '/' || parsedUrl.hash) {
        fail('database URL must use the postgresql scheme');
      } else if (!onlyVerifyFull) {
        fail('database URL must contain only sslmode=verify-full');
      } else {
        const sql = String.raw`
WITH target_schema AS (
  SELECT n.oid
  FROM pg_namespace AS n
  WHERE n.nspname = '${SCHEMA}'
),
role_ids AS (
  SELECT oid, rolname, rolsuper, rolcreaterole, rolcreatedb,
         rolcanlogin, rolreplication, rolbypassrls
  FROM pg_roles
  WHERE rolname IN ('${ROLES.join("', '")}')
),
tables AS (
  SELECT c.oid, c.relname, c.relkind, c.relowner
  FROM pg_class AS c
  JOIN target_schema AS s ON s.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
),
sequences AS (
  SELECT c.oid, c.relowner
  FROM pg_class AS c
  JOIN target_schema AS s ON s.oid = c.relnamespace
  WHERE c.relkind = 'S'
),
functions AS (
  SELECT p.oid, p.proowner, p.proacl
  FROM pg_proc AS p
  JOIN target_schema AS s ON s.oid = p.pronamespace
),
signer_function_allowlist(routine_signature) AS (
  VALUES
    ('agentpass_managed_signer_provider_operation_reserve(text,text,text,integer,bytea,text,bigint,bytea,integer,integer)'),
    ('agentpass_managed_signer_provider_operation_reserve(text,text,text,integer,bytea,text,bigint,bytea,integer,bigint)'),
    ('agentpass_managed_signer_provider_operation_claim(text,text,text,integer,bytea,text,bigint,bytea,integer)'),
    ('agentpass_managed_signer_provider_operation_start(text,text,text,integer,bytea,text,bigint,bytea)'),
    ('agentpass_managed_signer_provider_operation_accept(text,text,text,integer,bytea,text,bigint,bytea,bytea,bytea,text,text,text,text,text)'),
    ('agentpass_managed_signer_provider_operation_commit(text,text,text,integer,bytea,text,bigint,bytea)'),
    ('agentpass_managed_signer_provider_operation_reconcile(text,text,text,integer,bytea,text,bigint)'),
    ('agentpass_managed_signer_provider_operation_uncertain(text,text,text,integer,bytea,text,bigint,bytea,text)'),
    ('agentpass_managed_signer_provider_operation_get(text,text,text,integer,bytea,text,bigint)'),
    ('agentpass_managed_signer_provider_operation_health(text,text,bigint,text)'),
    ('agentpass_managed_signer_provider_operation_prune(text,text,bigint,text,timestamptz,integer)'),
    ('agentpass_maintain_managed_signer_provider_operations(integer)'),
    ('agentpass_health_managed_signer_provider_operations()'),
    ('agentpass_managed_signer_lifecycle_snapshot(text)'),
    ('agentpass_managed_signer_lifecycle_initialize(text,text,jsonb,integer,bigint)'),
    ('agentpass_managed_signer_lifecycle_apply(text,text,bytea,bigint,jsonb,bigint)'),
    ('agentpass_managed_signer_signing_reserve(text,text,bytea,text,bigint,bytea,bigint,bigint)'),
    ('agentpass_managed_signer_signing_start(text,text,bytea,text,bigint,bytea)'),
    ('agentpass_managed_signer_signing_commit(text,text,bytea,text,bigint,bytea,bytea,text,text)'),
    ('agentpass_managed_signer_signing_uncertain(text,text,bytea,text,bigint,bytea)'),
    ('agentpass_managed_signer_signing_reconcile(text,text,bytea,text,bigint,bytea,text,text)'),
    ('agentpass_managed_signer_signing_lookup(text,text)'),
    ('agentpass_managed_signer_signing_prune(text,timestamptz,integer)'),
    ('agentpass_managed_signer_lifecycle_operation_prune(text,timestamptz,integer)'),
    ('agentpass_platform_promotion_issuance_commit(uuid,text,text,text,text,bytea,bytea,bytea,bytea,bytea)'),
    ('agentpass_platform_promotion_issuance_uncertain(uuid,text,text,text,text,bytea,text)')
),
app_function_allowlist(routine_signature) AS (
  VALUES
    ('agentpass_consume_device_request_nonce(uuid,uuid,bytea,integer)'),
    ('agentpass_acquire_rate_limit(uuid,text,uuid,integer,numeric,integer,integer)'),
    ('agentpass_acquire_anonymous_rate_limit(text,uuid,integer,numeric,integer,integer)'),
    ('agentpass_prune_shared_control_expired(integer)'),
    ('agentpass_prune_anonymous_rate_limits(integer)'),
    ('agentpass_prune_human_identity_assertion_replays(integer)'),
    ('agentpass_platform_operator_assignment_find_active(uuid,uuid,uuid,text,text)'),
    ('agentpass_platform_session_challenge_create(uuid,uuid,bytea,bytea,bytea,bytea,bytea[],uuid,uuid,uuid,uuid,bigint,text,text,text,text,text,integer)'),
    ('agentpass_platform_session_challenge_find(uuid)'),
    ('agentpass_platform_session_challenge_claim(uuid,bytea,bytea,bytea,bytea)'),
    ('agentpass_platform_session_challenge_fail(uuid,bytea,bytea,bytea,bytea,text)'),
    ('agentpass_platform_session_credential_find(uuid,bytea,bytea)'),
    ('agentpass_platform_credential_advance_verified(uuid,bytea,uuid,bytea,bigint,bigint,bigint,boolean,boolean)'),
    ('agentpass_platform_session_find_active(bytea,uuid,text,text)'),
    ('agentpass_platform_session_touch(bytea,bytea,uuid,text,text)'),
    ('agentpass_platform_session_revoke(bytea,bytea,text)'),
    ('agentpass_platform_session_complete_and_issue(uuid,bytea,bytea,uuid,bytea,bytea,bytea,bytea,bytea,integer,integer)'),
    ('agentpass_consume_platform_authorization_and_reserve(bytea,bytea,uuid,bytea,bytea,uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint)'),
    ('agentpass_platform_session_bootstrap_context(bytea,uuid,text,text)'),
    ('agentpass_hosted_identity_bootstrap_start_v2(uuid,uuid,bytea,text,text,text,text,bytea,bytea,bytea,timestamptz)'),
    ('agentpass_hosted_identity_oauth_state_claim_v2(uuid,bytea,bytea,text)'),
    ('agentpass_hosted_identity_oauth_complete_v2(uuid,uuid,bytea,uuid,text,text,bytea)'),
    ('agentpass_hosted_identity_oauth_state_fail(uuid,text)'),
    ('agentpass_hosted_identity_bootstrap_status_v2(bytea,bytea)'),
    ('agentpass_hosted_identity_bootstrap_csrf_verify_v2(bytea,bytea)'),
    ('agentpass_hosted_identity_bootstrap_organization_commit_v2(bytea,text,bytea,text,uuid,uuid,uuid)'),
    ('agentpass_hosted_identity_bootstrap_challenge_create(bytea,uuid,bytea,text,text,timestamptz)'),
    ('agentpass_hosted_identity_bootstrap_webauthn_claim_v2(bytea,uuid,bytea,bytea)'),
    ('agentpass_hosted_identity_bootstrap_webauthn_complete_v3(uuid,bytea,uuid,bytea,bytea,bigint,bytea,bytea,bytea,bigint,text[],text,boolean,boolean,bytea,bytea)'),
    ('agentpass_hosted_identity_bootstrap_webauthn_fail_v3(bytea,uuid,bytea,bytea,bigint,text)')
),
signer_function_oids AS (
  SELECT routine_signature, to_regprocedure('public.' || routine_signature) AS routine_oid
  FROM signer_function_allowlist
),
app_function_oids AS (
  SELECT routine_signature, to_regprocedure('public.' || routine_signature) AS routine_oid
  FROM app_function_allowlist
),
default_acl AS (
  SELECT d.defaclobjtype AS object_type, r.rolname AS grantee,
         x.privilege_type
  FROM pg_default_acl AS d
  CROSS JOIN LATERAL aclexplode(d.defaclacl) AS x
  LEFT JOIN pg_roles AS r ON r.oid = x.grantee
  JOIN target_schema AS s ON s.oid = d.defaclnamespace
  WHERE d.defaclrole = (SELECT oid FROM role_ids WHERE rolname = 'agentpass_migrator')
),
role_attributes_ok AS (
  SELECT count(*) = ${ROLES.length}
    AND bool_and(
      NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
      AND NOT rolreplication AND NOT rolbypassrls AND rolcanlogin
    ) AS value
  FROM role_ids
),
role_memberships_ok AS (
  SELECT NOT EXISTS (
    SELECT 1
    FROM pg_auth_members AS m
    JOIN role_ids AS granted ON granted.oid = m.roleid
    JOIN role_ids AS member ON member.oid = m.member
  ) AS value
),
schema_privileges_ok AS (
  SELECT EXISTS (SELECT 1 FROM target_schema)
    AND has_schema_privilege('agentpass_app', '${SCHEMA}', 'USAGE')
    AND NOT has_schema_privilege('agentpass_app', '${SCHEMA}', 'CREATE')
    AND has_schema_privilege('agentpass_signer', '${SCHEMA}', 'USAGE')
    AND NOT has_schema_privilege('agentpass_signer', '${SCHEMA}', 'CREATE')
    AND has_schema_privilege('agentpass_migrator', '${SCHEMA}', 'USAGE')
    AND has_schema_privilege('agentpass_migrator', '${SCHEMA}', 'CREATE')
    AND has_schema_privilege('agentpass_backup', '${SCHEMA}', 'USAGE')
    AND NOT has_schema_privilege('agentpass_backup', '${SCHEMA}', 'CREATE') AS value
),
database_privileges_ok AS (
  SELECT has_database_privilege('agentpass_app', current_database(), 'CONNECT')
    AND NOT has_database_privilege('agentpass_app', current_database(), 'CREATE')
    AND NOT has_database_privilege('agentpass_app', current_database(), 'TEMP')
    AND has_database_privilege('agentpass_signer', current_database(), 'CONNECT')
    AND NOT has_database_privilege('agentpass_signer', current_database(), 'CREATE')
    AND NOT has_database_privilege('agentpass_signer', current_database(), 'TEMP')
    AND has_database_privilege('agentpass_migrator', current_database(), 'CONNECT')
    AND has_database_privilege('agentpass_backup', current_database(), 'CONNECT')
    AND NOT has_database_privilege('agentpass_backup', current_database(), 'CREATE')
    AND NOT has_database_privilege('agentpass_backup', current_database(), 'TEMP') AS value
),
migration_head_ok AS (
  SELECT to_regclass('public.schema_migrations') IS NOT NULL
    AND (SELECT count(*) = ${EXPECTED_MIGRATION_VERSION} AND min(version) = 1 AND max(version) = ${EXPECTED_MIGRATION_VERSION}
         FROM public.schema_migrations) AS value
),
table_privilege_observations AS (
  SELECT t.relname,
    t.relkind,
    CASE WHEN t.relname IN ('schema_migrations', 'schema_migration_attempts', 'release_candidates')
        OR left(t.relname, length('managed_signer_')) = 'managed_signer_'
        OR left(t.relname, length('platform_')) = 'platform_'
        OR left(t.relname, length('hosted_identity_')) = 'hosted_identity_' THEN 'authority'
      ELSE 'application' END AS expected_class,
    array_remove(ARRAY[
      CASE WHEN left(t.relname, length('managed_signer_')) = 'managed_signer_'
          OR left(t.relname, length('platform_')) = 'platform_'
          OR left(t.relname, length('hosted_identity_')) = 'hosted_identity_'
        THEN CASE WHEN NOT has_table_privilege('agentpass_app', t.oid, 'SELECT') THEN NULL ELSE 'app:select' END
        ELSE CASE WHEN has_table_privilege('agentpass_app', t.oid, 'SELECT') THEN NULL ELSE 'app:select_missing' END END,
      CASE WHEN (t.relname IN ('schema_migrations', 'schema_migration_attempts', 'release_candidates')
          OR left(t.relname, length('managed_signer_')) = 'managed_signer_'
          OR left(t.relname, length('platform_')) = 'platform_'
          OR left(t.relname, length('hosted_identity_')) = 'hosted_identity_')
          THEN CASE WHEN NOT has_table_privilege('agentpass_app', t.oid, 'INSERT') THEN NULL ELSE 'app:insert' END
          ELSE CASE WHEN has_table_privilege('agentpass_app', t.oid, 'INSERT') THEN NULL ELSE 'app:insert_missing' END END,
      CASE WHEN (t.relname IN ('schema_migrations', 'schema_migration_attempts', 'release_candidates')
          OR left(t.relname, length('managed_signer_')) = 'managed_signer_'
          OR left(t.relname, length('platform_')) = 'platform_'
          OR left(t.relname, length('hosted_identity_')) = 'hosted_identity_')
          THEN CASE WHEN NOT has_table_privilege('agentpass_app', t.oid, 'UPDATE') THEN NULL ELSE 'app:update' END
          ELSE CASE WHEN has_table_privilege('agentpass_app', t.oid, 'UPDATE') THEN NULL ELSE 'app:update_missing' END END,
      CASE WHEN (t.relname IN ('schema_migrations', 'schema_migration_attempts', 'release_candidates')
          OR left(t.relname, length('managed_signer_')) = 'managed_signer_'
          OR left(t.relname, length('platform_')) = 'platform_'
          OR left(t.relname, length('hosted_identity_')) = 'hosted_identity_')
          THEN CASE WHEN NOT has_table_privilege('agentpass_app', t.oid, 'DELETE') THEN NULL ELSE 'app:delete' END
          ELSE CASE WHEN has_table_privilege('agentpass_app', t.oid, 'DELETE') THEN NULL ELSE 'app:delete_missing' END END,
      CASE WHEN NOT has_table_privilege('agentpass_app', t.oid, 'TRUNCATE') THEN NULL ELSE 'app:truncate' END,
      CASE WHEN NOT has_table_privilege('agentpass_app', t.oid, 'REFERENCES') THEN NULL ELSE 'app:references' END,
      CASE WHEN NOT has_table_privilege('agentpass_app', t.oid, 'TRIGGER') THEN NULL ELSE 'app:trigger' END,
      CASE WHEN NOT has_table_privilege('agentpass_signer', t.oid, 'SELECT') THEN NULL ELSE 'signer:select' END,
      CASE WHEN NOT has_table_privilege('agentpass_signer', t.oid, 'INSERT') THEN NULL ELSE 'signer:insert' END,
      CASE WHEN NOT has_table_privilege('agentpass_signer', t.oid, 'UPDATE') THEN NULL ELSE 'signer:update' END,
      CASE WHEN NOT has_table_privilege('agentpass_signer', t.oid, 'DELETE') THEN NULL ELSE 'signer:delete' END,
      CASE WHEN NOT has_table_privilege('agentpass_signer', t.oid, 'TRUNCATE') THEN NULL ELSE 'signer:truncate' END,
      CASE WHEN NOT has_table_privilege('agentpass_signer', t.oid, 'REFERENCES') THEN NULL ELSE 'signer:references' END,
      CASE WHEN NOT has_table_privilege('agentpass_signer', t.oid, 'TRIGGER') THEN NULL ELSE 'signer:trigger' END,
      CASE WHEN has_table_privilege('agentpass_backup', t.oid, 'SELECT') THEN NULL ELSE 'backup:select' END,
      CASE WHEN NOT has_table_privilege('agentpass_backup', t.oid, 'INSERT') THEN NULL ELSE 'backup:insert' END,
      CASE WHEN NOT has_table_privilege('agentpass_backup', t.oid, 'UPDATE') THEN NULL ELSE 'backup:update' END,
      CASE WHEN NOT has_table_privilege('agentpass_backup', t.oid, 'DELETE') THEN NULL ELSE 'backup:delete' END,
      CASE WHEN NOT has_table_privilege('agentpass_backup', t.oid, 'TRUNCATE') THEN NULL ELSE 'backup:truncate' END,
      CASE WHEN NOT has_table_privilege('agentpass_backup', t.oid, 'REFERENCES') THEN NULL ELSE 'backup:references' END,
      CASE WHEN NOT has_table_privilege('agentpass_backup', t.oid, 'TRIGGER') THEN NULL ELSE 'backup:trigger' END,
      CASE WHEN t.relowner = (SELECT oid FROM role_ids WHERE rolname = 'agentpass_migrator') THEN NULL ELSE 'owner:not_migrator' END
    ]::text[], NULL::text) AS failures
  FROM tables AS t
),
table_privileges_ok AS (
  SELECT NOT EXISTS (
    SELECT 1 FROM table_privilege_observations
    WHERE cardinality(failures) > 0
  ) AS value
),
sequence_privileges_ok AS (
  SELECT COALESCE((SELECT bool_and(
      has_sequence_privilege('agentpass_app', oid, 'USAGE')
      AND has_sequence_privilege('agentpass_app', oid, 'SELECT')
      AND NOT has_sequence_privilege('agentpass_app', oid, 'UPDATE')
    ) FROM sequences), true)
    AND COALESCE((SELECT bool_and(relowner = (SELECT oid FROM role_ids WHERE rolname = 'agentpass_migrator')) FROM sequences), true)
    AND COALESCE((SELECT bool_and(has_sequence_privilege('agentpass_backup', oid, 'SELECT')
      AND NOT has_sequence_privilege('agentpass_backup', oid, 'USAGE')
      AND NOT has_sequence_privilege('agentpass_backup', oid, 'UPDATE')) FROM sequences), true)
    AND COALESCE((SELECT bool_and(
      NOT has_sequence_privilege('agentpass_signer', oid, 'USAGE')
      AND NOT has_sequence_privilege('agentpass_signer', oid, 'SELECT')
      AND NOT has_sequence_privilege('agentpass_signer', oid, 'UPDATE')
    ) FROM sequences), true) AS value
),
function_privileges_ok AS (
  SELECT COALESCE((SELECT bool_and(proowner = (SELECT oid FROM role_ids WHERE rolname = 'agentpass_migrator')) FROM functions), true)
    AND NOT EXISTS (SELECT 1 FROM signer_function_oids WHERE routine_oid IS NULL)
    AND NOT EXISTS (SELECT 1 FROM app_function_oids WHERE routine_oid IS NULL)
    AND NOT EXISTS (SELECT 1 FROM functions
      CROSS JOIN LATERAL aclexplode(COALESCE(proacl, acldefault('f', proowner))) AS acl
      WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE')
    AND NOT EXISTS (SELECT 1 FROM functions
      WHERE has_function_privilege('agentpass_backup', oid, 'EXECUTE')
         OR (has_function_privilege('agentpass_signer', oid, 'EXECUTE')
           AND NOT EXISTS (SELECT 1 FROM signer_function_oids AS a WHERE a.routine_oid = functions.oid))
         OR (NOT has_function_privilege('agentpass_signer', oid, 'EXECUTE')
           AND EXISTS (SELECT 1 FROM signer_function_oids AS a WHERE a.routine_oid = functions.oid))
         OR (has_function_privilege('agentpass_app', oid, 'EXECUTE')
           AND NOT EXISTS (SELECT 1 FROM app_function_oids AS a WHERE a.routine_oid = functions.oid))
         OR (NOT has_function_privilege('agentpass_app', oid, 'EXECUTE')
           AND EXISTS (SELECT 1 FROM app_function_oids AS a WHERE a.routine_oid = functions.oid))) AS value
),
default_privileges_ok AS (
  SELECT
    NOT EXISTS (SELECT 1 FROM default_acl
      WHERE object_type IN ('r', 'S') AND grantee = 'agentpass_app')
    AND (SELECT count(*) = 1 FROM default_acl
      WHERE object_type = 'r' AND grantee = 'agentpass_backup' AND privilege_type = 'SELECT')
    AND (SELECT count(*) = 1 FROM default_acl
      WHERE object_type = 'S' AND grantee = 'agentpass_backup' AND privilege_type = 'SELECT')
    AND NOT EXISTS (SELECT 1 FROM default_acl
      WHERE object_type = 'f' AND grantee IN ('agentpass_app', 'agentpass_signer', 'agentpass_backup'))
    AND NOT EXISTS (SELECT 1 FROM default_acl
      WHERE grantee = 'agentpass_signer') AS value
),
checks AS (
  SELECT current_user = 'agentpass_migrator'
    AND (SELECT value FROM migration_head_ok)
    AND (SELECT value FROM role_attributes_ok)
    AND (SELECT value FROM role_memberships_ok)
    AND (SELECT value FROM schema_privileges_ok)
    AND (SELECT value FROM database_privileges_ok)
    AND (SELECT value FROM table_privileges_ok)
    AND (SELECT value FROM sequence_privileges_ok)
    AND (SELECT value FROM function_privileges_ok)
    AND (SELECT value FROM default_privileges_ok) AS ok
)
SELECT json_build_object(
  'ok', (SELECT ok FROM checks),
  'current_user', current_user,
  'role_attributes_ok', (SELECT value FROM role_attributes_ok),
  'role_memberships_ok', (SELECT value FROM role_memberships_ok),
  'schema_privileges_ok', (SELECT value FROM schema_privileges_ok),
  'database_privileges_ok', (SELECT value FROM database_privileges_ok),
  'migration_head_ok', (SELECT value FROM migration_head_ok),
  'table_privileges_ok', (SELECT value FROM table_privileges_ok),
  'table_privilege_diagnostics', COALESCE((SELECT json_agg(json_build_object(
      'relation', left(relname, ${MAX_RELATION_DIAGNOSTIC_NAME}),
      'kind', relkind,
      'class', expected_class,
      'failures', failures
    ) ORDER BY relname)
    FROM (SELECT relname, relkind, expected_class, failures
      FROM table_privilege_observations
      WHERE cardinality(failures) > 0
      ORDER BY relname
      LIMIT ${MAX_TABLE_DIAGNOSTICS}) AS bounded_table_failures), '[]'::json),
  'sequence_privileges_ok', (SELECT value FROM sequence_privileges_ok),
  'function_privileges_ok', (SELECT value FROM function_privileges_ok),
  'default_privileges_ok', (SELECT value FROM default_privileges_ok),
  'table_count', (SELECT count(*) FROM tables),
  'sequence_count', (SELECT count(*) FROM sequences),
  'function_count', (SELECT count(*) FROM functions)
)::text;
`;

        const { AGENTPASS_DATABASE_URL: _databaseUrl, ...inheritedEnvironment } = process.env;
        const result = spawnSync(
          'psql',
          [
            '--no-psqlrc',
            '--quiet',
            '--tuples-only',
            '--no-align',
            '--set=ON_ERROR_STOP=1',
            '--command',
            sql,
          ],
          {
            env: {
              ...inheritedEnvironment,
              PGHOST: parsedUrl.hostname,
              PGPORT: parsedUrl.port || '5432',
              PGUSER: decodeURIComponent(parsedUrl.username),
              PGPASSWORD: decodeURIComponent(parsedUrl.password),
              PGDATABASE: decodeURIComponent(parsedUrl.pathname.slice(1)),
              PGSSLMODE: 'verify-full',
            },
            encoding: 'utf8',
            maxBuffer: 1024 * 1024,
          },
        );

        if (result.error || result.status !== 0) {
          fail('database privilege check failed');
        } else {
          try {
            const report = JSON.parse(result.stdout.trim());
            const evidence = createHash('sha256')
              .update(JSON.stringify(report))
              .digest('hex');
            if (report.ok !== true) {
              const failedChecks = [
                ...(report.current_user === 'agentpass_migrator' ? [] : ['current_user']),
                ...REPORT_CHECKS.filter((name) => report[name] !== true),
              ];
              const tableDiagnostics = report.table_privileges_ok === true
                ? ''
                : ` table_diagnostics=${boundedTableDiagnostics(report.table_privilege_diagnostics)}`;
              fail(`database privilege contract failed: failed_checks=${failedChecks.join(',') || 'unknown'} evidence=${evidence}${tableDiagnostics}`);
            } else {
              const evidenceOutput = process.env[EVIDENCE_OUTPUT_ENV];
              if (evidenceOutput !== undefined) {
                if (!path.isAbsolute(evidenceOutput) || evidenceOutput.length > 4096) {
                  fail('database privilege evidence output is invalid');
                } else {
                  writeFileSync(evidenceOutput, `${JSON.stringify(report)}\n`, { flag: 'wx', mode: 0o600 });
                }
              }
              process.stdout.write(`ok evidence=${evidence}\n`);
            }
          } catch {
            fail('database privilege check returned invalid evidence');
          }
        }
      }
    }
  }
}

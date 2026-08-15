import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import path from 'node:path';

const DATABASE_URL_ENV = 'AGENTPASS_DATABASE_URL';
const EVIDENCE_OUTPUT_ENV = 'AGENTPASS_PRIVILEGE_EVIDENCE_OUTPUT';
const SCHEMA = 'public';
const ROLES = ['agentpass_app', 'agentpass_signer', 'agentpass_migrator', 'agentpass_backup'];

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 2;
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
  SELECT c.oid, c.relname, c.relowner
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
    ('agentpass_managed_signer_lifecycle_operation_prune(text,timestamptz,integer)')
),
app_function_allowlist(routine_signature) AS (
  VALUES
    ('agentpass_platform_promotion_issuance_replay(uuid,text,text,text,text)'),
    ('agentpass_platform_promotion_issuance_commit(uuid,text,text,text,text,bytea,bytea,bytea,bytea,bytea)'),
    ('agentpass_platform_promotion_issuance_uncertain(uuid,text,text,text,text,bytea,text)'),
    ('agentpass_platform_promotion_issuance_get(uuid,text,text,text,text,boolean)'),
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
    ('agentpass_platform_session_bootstrap_context(bytea,uuid,text,text)')
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
    AND (SELECT count(*) = 55 AND min(version) = 1 AND max(version) = 55
         FROM public.schema_migrations) AS value
),
table_privileges_ok AS (
  SELECT COALESCE((SELECT bool_and(
      has_table_privilege('agentpass_app', oid, 'SELECT')
      AND CASE WHEN relname IN ('schema_migrations', 'schema_migration_attempts', 'release_candidates')
          OR left(relname, length('managed_signer_')) = 'managed_signer_'
          OR left(relname, length('platform_')) = 'platform_' THEN
        NOT has_table_privilege('agentpass_app', oid, 'INSERT')
        AND NOT has_table_privilege('agentpass_app', oid, 'UPDATE')
        AND NOT has_table_privilege('agentpass_app', oid, 'DELETE')
      ELSE
        has_table_privilege('agentpass_app', oid, 'INSERT')
        AND has_table_privilege('agentpass_app', oid, 'UPDATE')
        AND has_table_privilege('agentpass_app', oid, 'DELETE')
      END
      AND NOT has_table_privilege('agentpass_app', oid, 'TRUNCATE')
      AND NOT has_table_privilege('agentpass_app', oid, 'REFERENCES')
      AND NOT has_table_privilege('agentpass_app', oid, 'TRIGGER')
    ) FROM tables), true)
    AND COALESCE((SELECT bool_and(
      NOT has_table_privilege('agentpass_signer', oid, 'SELECT')
      AND NOT has_table_privilege('agentpass_signer', oid, 'INSERT')
      AND NOT has_table_privilege('agentpass_signer', oid, 'UPDATE')
      AND NOT has_table_privilege('agentpass_signer', oid, 'DELETE')
      AND NOT has_table_privilege('agentpass_signer', oid, 'TRUNCATE')
      AND NOT has_table_privilege('agentpass_signer', oid, 'REFERENCES')
      AND NOT has_table_privilege('agentpass_signer', oid, 'TRIGGER')
    ) FROM tables), true)
    AND COALESCE((SELECT bool_and(relowner = (SELECT oid FROM role_ids WHERE rolname = 'agentpass_migrator')) FROM tables), true)
    AND COALESCE((SELECT bool_and(has_table_privilege('agentpass_backup', oid, 'SELECT')
      AND NOT has_table_privilege('agentpass_backup', oid, 'INSERT')
      AND NOT has_table_privilege('agentpass_backup', oid, 'UPDATE')
      AND NOT has_table_privilege('agentpass_backup', oid, 'DELETE')
      AND NOT has_table_privilege('agentpass_backup', oid, 'TRUNCATE')
      AND NOT has_table_privilege('agentpass_backup', oid, 'REFERENCES')
      AND NOT has_table_privilege('agentpass_backup', oid, 'TRIGGER')) FROM tables), true)
    AND NOT EXISTS (SELECT 1 FROM tables
      WHERE relowner = (SELECT oid FROM role_ids WHERE rolname = 'agentpass_app')) AS value
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
              fail(`database privilege contract failed: evidence=${evidence}`);
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

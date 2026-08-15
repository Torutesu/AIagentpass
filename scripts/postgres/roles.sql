\set ON_ERROR_STOP on

-- AgentPass PostgreSQL role boundary for the public-schema migration set.
-- Authentication is supplied by the deployment (IAM, mTLS, or a secret
-- manager). This file intentionally contains no passwords or credentials.

BEGIN;

DO $$
DECLARE
  role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'agentpass_app',
    'agentpass_migrator',
    'agentpass_backup'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format('CREATE ROLE %I LOGIN', role_name);
    END IF;
  END LOOP;
END
$$;

-- External authentication remains enabled, but no server-level authority is
-- inherited by any of the three service identities.
ALTER ROLE agentpass_app
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE agentpass_migrator
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE agentpass_backup
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Prevent an existing role membership from becoming a privilege-escalation
-- path through SET ROLE, even though these roles are NOINHERIT.
REVOKE agentpass_app FROM agentpass_migrator, agentpass_backup;
REVOKE agentpass_migrator FROM agentpass_app, agentpass_backup;
REVOKE agentpass_backup FROM agentpass_app, agentpass_migrator;

-- Revoke database-wide PUBLIC access, then grant connection only to the
-- identities that are explicitly part of this contract.
DO $$
DECLARE
  database_name text := current_database();
BEGIN
  EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM PUBLIC', database_name);
  EXECUTE format(
    'GRANT CONNECT ON DATABASE %I TO agentpass_app, agentpass_migrator, agentpass_backup',
    database_name
  );
END
$$;

-- The existing migration set uses public. The migration role receives schema
-- CREATE; app and backup receive USAGE only.
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM agentpass_app, agentpass_backup;
GRANT USAGE ON SCHEMA public TO agentpass_app, agentpass_backup;
GRANT USAGE, CREATE ON SCHEMA public TO agentpass_migrator;

-- Make the migration identity the owner of existing migration objects. This
-- is idempotent and gives it ALTER/DROP authority without giving that power to
-- the application or backup identity.
DO $$
DECLARE
  object_record record;
BEGIN
  FOR object_record IN
    SELECT n.nspname, c.relname, c.relkind
    FROM pg_class AS c
    JOIN pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  LOOP
    IF object_record.relkind = 'S' THEN
      EXECUTE format(
        'ALTER SEQUENCE %I.%I OWNER TO agentpass_migrator',
        object_record.nspname, object_record.relname
      );
    ELSIF object_record.relkind = 'v' THEN
      EXECUTE format('ALTER VIEW %I.%I OWNER TO agentpass_migrator', object_record.nspname, object_record.relname);
    ELSIF object_record.relkind = 'm' THEN
      EXECUTE format('ALTER MATERIALIZED VIEW %I.%I OWNER TO agentpass_migrator', object_record.nspname, object_record.relname);
    ELSIF object_record.relkind = 'f' THEN
      EXECUTE format('ALTER FOREIGN TABLE %I.%I OWNER TO agentpass_migrator', object_record.nspname, object_record.relname);
    ELSE
      EXECUTE format(
        'ALTER TABLE %I.%I OWNER TO agentpass_migrator',
        object_record.nspname, object_record.relname
      );
    END IF;
  END LOOP;

  FOR object_record IN
    SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) AS arguments
    FROM pg_proc AS p
    JOIN pg_namespace AS n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.prokind <> 'a'
  LOOP
    EXECUTE format(
      'ALTER ROUTINE %I.%I(%s) OWNER TO agentpass_migrator',
      object_record.nspname, object_record.proname, object_record.arguments
    );
  END LOOP;
END
$$;

-- Clear grants on objects already present before applying the exact contract.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM agentpass_app, agentpass_backup;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM agentpass_app, agentpass_backup;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM agentpass_app, agentpass_backup;

-- app: DML only, plus sequence consumption required by inserts.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agentpass_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agentpass_app;

-- backup: read-only table and sequence-state access. It cannot consume or
-- mutate sequences and cannot execute functions.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO agentpass_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO agentpass_backup;

-- migrator owns the objects and retains the explicit object privileges needed
-- by migration tooling.
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO agentpass_migrator;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO agentpass_migrator;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO agentpass_migrator;

-- Migration bookkeeping is control-plane metadata, not application data.
-- Keep its SELECT visibility for the read-only backup identity, but never let
-- app or backup mutate the migration history or attempt ledger. These tables
-- may not exist on the bootstrap invocation, so this is conditional.
DO $$
DECLARE
  relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'schema_migrations', 'schema_migration_attempts',
    'release_candidates', 'platform_promotion_approvals',
    'platform_promotion_deployments', 'platform_promotion_issuances',
    'managed_signer_key_lifecycles', 'managed_signer_keys',
    'managed_signer_key_lifecycle_operations', 'managed_signer_signing_idempotency'
  ] LOOP
    IF to_regclass(format('public.%I', relation_name)) IS NOT NULL THEN
      EXECUTE format(
        'REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.%I FROM agentpass_app, agentpass_backup',
        relation_name
      );
    END IF;
  END LOOP;
END
$$;

-- Promotion issuance and signer authority are not generic application DML.
-- The current repository path must run through a reviewed authority/procedure
-- role before hosted deployment; these explicit revokes keep a compromised
-- agentpass_app session from mutating the authority tables directly while
-- that SECURITY DEFINER procedure path is completed.

-- Future objects created by the migration identity preserve the same boundary.
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, agentpass_app, agentpass_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agentpass_app;
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  GRANT SELECT ON TABLES TO agentpass_backup;

ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, agentpass_app, agentpass_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO agentpass_app;
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  GRANT SELECT ON SEQUENCES TO agentpass_backup;

ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC, agentpass_app, agentpass_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO agentpass_migrator;

COMMIT;

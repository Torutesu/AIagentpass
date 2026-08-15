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
    'agentpass_signer',
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
-- inherited by any of the four service identities.
ALTER ROLE agentpass_app
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE agentpass_signer
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE agentpass_migrator
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE agentpass_backup
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Prevent an existing role membership from becoming a privilege-escalation
-- path through SET ROLE, even though these roles are NOINHERIT.
REVOKE agentpass_app FROM agentpass_signer, agentpass_migrator, agentpass_backup;
REVOKE agentpass_signer FROM agentpass_app, agentpass_migrator, agentpass_backup;
REVOKE agentpass_migrator FROM agentpass_app, agentpass_signer, agentpass_backup;
REVOKE agentpass_backup FROM agentpass_app, agentpass_signer, agentpass_migrator;

-- Revoke database-wide PUBLIC access, then grant connection only to the
-- identities that are explicitly part of this contract.
DO $$
DECLARE
  database_name text := current_database();
BEGIN
  EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM PUBLIC', database_name);
  EXECUTE format(
    'GRANT CONNECT ON DATABASE %I TO agentpass_app, agentpass_signer, agentpass_migrator, agentpass_backup',
    database_name
  );
END
$$;

-- The existing migration set uses public. The migration role receives schema
-- CREATE; app and backup receive USAGE only.
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM agentpass_app, agentpass_signer, agentpass_backup;
GRANT USAGE ON SCHEMA public TO agentpass_app, agentpass_signer, agentpass_backup;
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
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM agentpass_app, agentpass_signer, agentpass_backup;

-- app: DML only, plus sequence consumption required by inserts.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agentpass_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agentpass_app;

-- signer: all managed-signer state is function-only after migration 0051.
-- The signer identity receives no table or sequence privileges. Every state
-- transition is routed through the exact SECURITY DEFINER entry-point list
-- below; no organization, policy, session, audit, promotion, or ledger table
-- is directly reachable.

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
    'platform_principals', 'platform_operator_assignments',
    'platform_operator_assignment_approvals',
    'managed_signer_key_lifecycles', 'managed_signer_keys',
    'managed_signer_key_lifecycle_operations', 'managed_signer_signing_idempotency',
    'managed_signer_provider_operations'
  ] LOOP
    IF to_regclass(format('public.%I', relation_name)) IS NOT NULL THEN
      EXECUTE format(
        'REVOKE ALL PRIVILEGES ON TABLE public.%I FROM agentpass_app, agentpass_backup',
        relation_name
      );
      -- Existing authority-table contracts intentionally retain read access for
      -- the app and backup identities. Re-grant it after the full revoke so a
      -- stale table ACL cannot leave any write privilege behind.
      EXECUTE format(
        'GRANT SELECT ON TABLE public.%I TO agentpass_app, agentpass_backup',
        relation_name
      );
    END IF;
  END LOOP;

  -- Future managed-signer, Platform, and Hosted identity ledgers are authority tables by
  -- default. A new migration cannot silently inherit the broad application
  -- DML defaults merely because this reviewed array has not yet been
  -- extended.
  FOR relation_name IN
    SELECT c.relname
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND (
        left(c.relname, length('managed_signer_')) = 'managed_signer_'
        OR left(c.relname, length('platform_')) = 'platform_'
        OR left(c.relname, length('hosted_identity_')) = 'hosted_identity_'
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON TABLE public.%I FROM agentpass_app, agentpass_backup',
      relation_name
    );
    EXECUTE format(
      'GRANT SELECT ON TABLE public.%I TO agentpass_app, agentpass_backup',
      relation_name
    );
  END LOOP;

END
$$;

-- Provider operations and deployment-wide maintenance are reachable only
-- through the reviewed SECURITY DEFINER entry points. Helpers, triggers, the
-- legacy quarantine function, and every unrelated routine remain denied.
DO $$
DECLARE
  routine_signature text;
BEGIN
  FOREACH routine_signature IN ARRAY ARRAY[
    'agentpass_managed_signer_provider_operation_reserve(text,text,text,integer,bytea,text,bigint,bytea,integer,integer)',
    'agentpass_managed_signer_provider_operation_claim(text,text,text,integer,bytea,text,bigint,bytea,integer)',
    'agentpass_managed_signer_provider_operation_start(text,text,text,integer,bytea,text,bigint,bytea)',
    'agentpass_managed_signer_provider_operation_accept(text,text,text,integer,bytea,text,bigint,bytea,bytea,bytea,text,text,text,text,text)',
    'agentpass_managed_signer_provider_operation_commit(text,text,text,integer,bytea,text,bigint,bytea)',
    'agentpass_managed_signer_provider_operation_reconcile(text,text,text,integer,bytea,text,bigint)',
    'agentpass_managed_signer_provider_operation_uncertain(text,text,text,integer,bytea,text,bigint,bytea,text)',
    'agentpass_managed_signer_provider_operation_get(text,text,text,integer,bytea,text,bigint)',
    'agentpass_managed_signer_provider_operation_health(text,text,bigint,text)',
    'agentpass_managed_signer_provider_operation_prune(text,text,bigint,text,timestamptz,integer)',
    'agentpass_maintain_managed_signer_provider_operations(integer)',
    'agentpass_health_managed_signer_provider_operations()',
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
  ] LOOP
    IF to_regprocedure('public.' || routine_signature) IS NOT NULL THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO agentpass_signer', routine_signature);
    END IF;
  END LOOP;
END
$$;

-- Platform mutation is issue-only for the application role. Promotion replay,
-- commit, uncertain, and legacy reserve remain unavailable even though their
-- internal functions still support the purpose-scoped signer workflow.
-- The reviewed 0054 function is the sole online proof-consuming mutation.
DO $$
DECLARE
  routine_signature text;
BEGIN
  FOREACH routine_signature IN ARRAY ARRAY[
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
    'agentpass_hosted_identity_bootstrap_start_v2(uuid,uuid,bytea,text,text,text,text,bytea,bytea,bytea,timestamptz)',
    'agentpass_hosted_identity_oauth_state_claim_v2(uuid,bytea,bytea,text)',
    'agentpass_hosted_identity_oauth_state_complete(uuid,bytea,uuid,text,bytea)',
    'agentpass_hosted_identity_oauth_state_fail(uuid,text)',
    'agentpass_hosted_identity_bootstrap_csrf_issue(bytea,bytea)',
    'agentpass_hosted_identity_bootstrap_organization_commit(bytea,text,bytea,uuid,uuid,jsonb)',
    'agentpass_hosted_identity_bootstrap_challenge_create(bytea,uuid,bytea,text,text,timestamptz)',
    'agentpass_hosted_identity_bootstrap_challenge_consume(bytea,uuid,bytea)',
    'agentpass_hosted_identity_bootstrap_challenge_complete(bytea,uuid,bytea)',
    'agentpass_hosted_identity_bootstrap_challenge_fail(bytea,uuid,bytea,text)'
  ] LOOP
    IF to_regprocedure('public.' || routine_signature) IS NOT NULL THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO agentpass_app', routine_signature);
    END IF;
  END LOOP;
END
$$;

-- After 0054 has atomically consumed the browser proof and reserved one
-- issuance, only the signer identity may finalize that exact claim. It has no
-- platform table privileges and receives neither reserve, replay, nor get.
DO $$
DECLARE
  routine_signature text;
BEGIN
  FOREACH routine_signature IN ARRAY ARRAY[
    'agentpass_platform_promotion_issuance_commit(uuid,text,text,text,text,bytea,bytea,bytea,bytea,bytea)',
    'agentpass_platform_promotion_issuance_uncertain(uuid,text,text,text,text,bytea,text)'
  ] LOOP
    IF to_regprocedure('public.' || routine_signature) IS NOT NULL THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO agentpass_signer', routine_signature);
    END IF;
  END LOOP;
END
$$;

-- Future objects created by the migration identity preserve the same boundary.
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  GRANT SELECT ON TABLES TO agentpass_backup;

ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  GRANT SELECT ON SEQUENCES TO agentpass_backup;

ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE agentpass_migrator IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO agentpass_migrator;

COMMIT;

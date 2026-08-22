BEGIN;

-- Lock-order bridge for the human authority paths.
--
-- The 0087/0096/0094 bodies are retained under private legacy names and are
-- called only after this migration has acquired the locks.  Renaming instead
-- of copying their complete PL/pgSQL bodies keeps the old validation and
-- return contracts byte-for-byte intact while making the lock boundary
-- reviewable in one place.
--
-- Canonical application order:
--   human-authority(member) -> organization(organization ids in ascending
--   order where more than one is involved) -> human-session-set(member) ->
--   webauthn-credential-set(member) -> authority rows.
--
-- The human-authority lock prevents a credential revoke from discovering a
-- newly-created membership after it has started waiting on the session lock.
-- Membership mutation callers acquire the same lock in the repository.

ALTER FUNCTION public.agentpass_human_session_create(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz
) RENAME TO agentpass_human_session_create_legacy_0105;
ALTER FUNCTION public.agentpass_human_session_create_with_ceiling(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz
) RENAME TO agentpass_human_session_create_with_ceiling_legacy_0105;
ALTER FUNCTION public.agentpass_human_session_rotate(
  uuid,bytea,uuid,uuid,uuid,uuid,text,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) RENAME TO agentpass_human_session_rotate_legacy_0105;
ALTER FUNCTION public.agentpass_human_update_credential_label(
  uuid,uuid,uuid,bytea,text,bigint
) RENAME TO agentpass_human_update_credential_label_legacy_0105;
ALTER FUNCTION public.agentpass_human_revoke_credential(
  uuid,uuid,uuid,bytea,bigint,timestamptz,text
) RENAME TO agentpass_human_revoke_credential_legacy_0105;

CREATE FUNCTION public.agentpass_human_session_create(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_membership_id uuid,
  p_role text,
  p_token_hash bytea,
  p_csrf_token_hash bytea,
  p_created_at timestamptz,
  p_expires_at timestamptz,
  p_last_seen_at timestamptz,
  p_idle_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );
  RETURN public.agentpass_human_session_create_legacy_0105(
    p_session_id, p_member_id, p_organization_id, p_membership_id, p_role,
    p_token_hash, p_csrf_token_hash, p_created_at, p_expires_at,
    p_last_seen_at, p_idle_expires_at
  );
END;
$$;

CREATE FUNCTION public.agentpass_human_session_create_with_ceiling(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_membership_id uuid,
  p_role text,
  p_token_hash bytea,
  p_csrf_token_hash bytea,
  p_created_at timestamptz,
  p_expires_at timestamptz,
  p_last_seen_at timestamptz,
  p_idle_expires_at timestamptz,
  p_max_concurrent_sessions integer,
  p_revoke_reason text,
  p_issued_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );
  RETURN public.agentpass_human_session_create_with_ceiling_legacy_0105(
    p_session_id, p_member_id, p_organization_id, p_membership_id, p_role,
    p_token_hash, p_csrf_token_hash, p_created_at, p_expires_at,
    p_last_seen_at, p_idle_expires_at, p_max_concurrent_sessions,
    p_revoke_reason, p_issued_at
  );
END;
$$;

CREATE FUNCTION public.agentpass_human_session_rotate(
  p_old_session_id uuid,
  p_old_token_hash bytea,
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_membership_id uuid,
  p_role text,
  p_token_hash bytea,
  p_csrf_token_hash bytea,
  p_created_at timestamptz,
  p_expires_at timestamptz,
  p_last_seen_at timestamptz,
  p_idle_expires_at timestamptz,
  p_rotated_at timestamptz,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );
  RETURN public.agentpass_human_session_rotate_legacy_0105(
    p_old_session_id, p_old_token_hash, p_session_id, p_member_id,
    p_organization_id, p_membership_id, p_role, p_token_hash,
    p_csrf_token_hash, p_created_at, p_expires_at, p_last_seen_at,
    p_idle_expires_at, p_rotated_at, p_reason
  );
END;
$$;

CREATE FUNCTION public.agentpass_human_update_credential_label(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_credential_id bytea,
  p_label text,
  p_expected_version bigint
)
RETURNS TABLE (
  id bytea,
  member_id uuid,
  label text,
  transports text[],
  backup_eligible boolean,
  backup_state boolean,
  created_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  version bigint
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:webauthn:credentials:' || p_member_id::text, 0)
  );
  RETURN QUERY
  SELECT * FROM public.agentpass_human_update_credential_label_legacy_0105(
    p_session_id, p_member_id, p_organization_id, p_credential_id,
    p_label, p_expected_version
  );
END;
$$;

CREATE FUNCTION public.agentpass_human_revoke_credential(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_credential_id bytea,
  p_expected_version bigint,
  p_revoked_at timestamptz,
  p_revoke_reason text DEFAULT NULL
)
RETURNS TABLE (
  id bytea,
  member_id uuid,
  label text,
  transports text[],
  backup_eligible boolean,
  backup_state boolean,
  created_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  version bigint
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  scoped_organization_id uuid;
BEGIN
  -- Credential invalidation can fan out to every organization in which the
  -- member has a membership or platform session.  The member authority lock
  -- freezes that scope while the advisory organization locks are acquired in
  -- UUID order, so the AFTER credential trigger cannot discover a new scope
  -- after this transaction has taken the session lock.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_member_id::text, 0)
  );
  FOR scoped_organization_id IN
    SELECT scopes.organization_id
    FROM (
      SELECT m.organization_id
      FROM public.memberships AS m
      WHERE m.member_id = p_member_id
      UNION
      SELECT s.organization_id
      FROM public.platform_sessions AS s
      WHERE s.member_id = p_member_id
      UNION
      SELECT p_organization_id
    ) AS scopes
    ORDER BY scopes.organization_id
  LOOP
    PERFORM pg_advisory_xact_lock(
      hashtextextended('agentpass:organization:' || scoped_organization_id::text, 0)
    );
  END LOOP;
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:webauthn:credentials:' || p_member_id::text, 0)
  );
  RETURN QUERY
  SELECT * FROM public.agentpass_human_revoke_credential_legacy_0105(
    p_session_id, p_member_id, p_organization_id, p_credential_id,
    p_expected_version, p_revoked_at, p_revoke_reason
  );
END;
$$;

ALTER FUNCTION public.agentpass_human_session_create(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_session_create_with_ceiling(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_session_rotate(
  uuid,bytea,uuid,uuid,uuid,uuid,text,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_update_credential_label(
  uuid,uuid,uuid,bytea,text,bigint
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_revoke_credential(
  uuid,uuid,uuid,bytea,bigint,timestamptz,text
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_create_legacy_0105(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_create_with_ceiling_legacy_0105(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_rotate_legacy_0105(
  uuid,bytea,uuid,uuid,uuid,uuid,text,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_update_credential_label_legacy_0105(
  uuid,uuid,uuid,bytea,text,bigint
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_revoke_credential_legacy_0105(
  uuid,uuid,uuid,bytea,bigint,timestamptz,text
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_create(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_create_with_ceiling(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_session_rotate(
  uuid,bytea,uuid,uuid,uuid,uuid,text,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_update_credential_label(
  uuid,uuid,uuid,bytea,text,bigint
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_revoke_credential(
  uuid,uuid,uuid,bytea,bigint,timestamptz,text
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;

GRANT EXECUTE ON FUNCTION public.agentpass_human_session_create(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_create_with_ceiling(
  uuid,uuid,uuid,uuid,text,bytea,bytea,timestamptz,timestamptz,timestamptz,timestamptz,integer,text,timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_session_rotate(
  uuid,bytea,uuid,uuid,uuid,uuid,text,bytea,bytea,
  timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,text
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_update_credential_label(
  uuid,uuid,uuid,bytea,text,bigint
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_revoke_credential(
  uuid,uuid,uuid,bytea,bigint,timestamptz,text
) TO agentpass_app;

COMMIT;

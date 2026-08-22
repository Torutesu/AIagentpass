BEGIN;

-- Management credential metadata is an authority-scoped read.  The session
-- binding is repeated in the same statement as the credential projection so
-- an application caller cannot widen the result to another member or tenant.
-- Revoked and clone-quarantined rows remain visible to management; clone
-- quarantine is represented by the same revoked_at field as the repository
-- API, without exposing the underlying authentication state.
CREATE FUNCTION public.agentpass_human_list_credential_metadata_for_session(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_after_created_at timestamptz DEFAULT NULL,
  p_after_id uuid DEFAULT NULL,
  p_limit integer DEFAULT 25
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
  now_value timestamptz;
BEGIN
  IF p_session_id IS NULL
     OR p_member_id IS NULL
     OR p_organization_id IS NULL
     OR p_limit IS NULL
     OR p_limit NOT BETWEEN 1 AND 100
     OR ((p_after_created_at IS NULL) <> (p_after_id IS NULL)) THEN
    RAISE EXCEPTION 'invalid human credential metadata listing input'
      USING ERRCODE = '22023';
  END IF;

  -- Use one database observation for the complete lifetime check.  The
  -- organization and membership epochs are the immutable authority snapshot
  -- captured when the session was issued.
  now_value := pg_catalog.clock_timestamp();

  RETURN QUERY
  SELECT c.id,
         c.member_id,
         c.label,
         c.transports,
         c.backup_eligible,
         c.backup_state,
         c.created_at,
         c.last_used_at,
         COALESCE(c.revoked_at, c.clone_detected_at) AS revoked_at,
         c.version
  FROM public.webauthn_credentials AS c
  JOIN public.human_sessions AS s
    ON s.member_id = c.member_id
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.id = p_session_id
    AND s.member_id = p_member_id
    AND s.organization_id = p_organization_id
    AND s.revoked_at IS NULL
    AND s.expires_at > now_value
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
    AND (
      p_after_created_at IS NULL
      OR (
        EXISTS (
          SELECT 1
          FROM public.webauthn_credentials AS anchor
          WHERE anchor.member_id = p_member_id
            AND (
              substr(encode(sha256(anchor.id), 'hex'), 1, 8)
              || '-' || substr(encode(sha256(anchor.id), 'hex'), 9, 4)
              || '-4' || substr(encode(sha256(anchor.id), 'hex'), 14, 3)
              || '-8' || substr(encode(sha256(anchor.id), 'hex'), 18, 3)
              || '-' || substr(encode(sha256(anchor.id), 'hex'), 21, 12)
            )::uuid = p_after_id
            AND date_trunc('milliseconds', anchor.created_at)
                = date_trunc('milliseconds', p_after_created_at)
        )
        AND (date_trunc('milliseconds', c.created_at), c.id) > (
          SELECT date_trunc('milliseconds', anchor.created_at), anchor.id
          FROM public.webauthn_credentials AS anchor
          WHERE anchor.member_id = p_member_id
            AND (
              substr(encode(sha256(anchor.id), 'hex'), 1, 8)
              || '-' || substr(encode(sha256(anchor.id), 'hex'), 9, 4)
              || '-4' || substr(encode(sha256(anchor.id), 'hex'), 14, 3)
              || '-8' || substr(encode(sha256(anchor.id), 'hex'), 18, 3)
              || '-' || substr(encode(sha256(anchor.id), 'hex'), 21, 12)
            )::uuid = p_after_id
            AND date_trunc('milliseconds', anchor.created_at)
                = date_trunc('milliseconds', p_after_created_at)
          LIMIT 1
        )
      )
    )
  ORDER BY date_trunc('milliseconds', c.created_at) ASC, c.id ASC
  LIMIT (p_limit + 1);
END;
$$;

ALTER FUNCTION public.agentpass_human_list_credential_metadata_for_session(
  uuid, uuid, uuid, timestamptz, uuid, integer
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_list_credential_metadata_for_session(
  uuid, uuid, uuid, timestamptz, uuid, integer
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_migrator,
     agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_list_credential_metadata_for_session(
  uuid, uuid, uuid, timestamptz, uuid, integer
) TO agentpass_app;

COMMIT;

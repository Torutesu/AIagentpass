BEGIN;

-- Recompile the 0092 authority with an explicit PL/pgSQL conflict policy. The
-- RETURNS TABLE column `id` otherwise collides with the composite projection
-- returned by `created`, which PostgreSQL reports as an ambiguous reference
-- when the function is executed on a fresh 16/17 cluster.
CREATE OR REPLACE FUNCTION public.agentpass_human_register_credential(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_credential_id bytea,
  p_public_key bytea,
  p_sign_count bigint,
  p_transports text[],
  p_label text,
  p_backup_eligible boolean,
  p_backup_state boolean
)
RETURNS TABLE (
  id bytea,
  member_id uuid,
  public_key bytea,
  sign_count bigint,
  transports text[],
  label text,
  backup_eligible boolean,
  backup_state boolean,
  created_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
#variable_conflict use_column
DECLARE
  now_value timestamptz;
  session_row public.human_sessions%ROWTYPE;
  created public.webauthn_credentials%ROWTYPE;
BEGIN
  IF p_session_id IS NULL
     OR p_member_id IS NULL
     OR p_organization_id IS NULL
     OR p_credential_id IS NULL
     OR octet_length(p_credential_id) NOT BETWEEN 16 AND 1024
     OR p_public_key IS NULL
     OR octet_length(p_public_key) NOT BETWEEN 32 AND 4096
     OR p_sign_count IS NULL
     OR p_sign_count < 0
     OR p_transports IS NULL
     OR NOT COALESCE(public.agentpass_valid_webauthn_transports(p_transports), false)
     OR p_label IS NULL
     OR char_length(p_label) NOT BETWEEN 1 AND 128
     OR p_label ~ '[[:cntrl:]]'
     OR p_backup_eligible IS NULL
     OR p_backup_state IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'WebAuthn credential registration input is invalid';
  END IF;
  IF p_backup_state IS TRUE AND p_backup_eligible IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'webauthn_credentials_backup_state_valid', MESSAGE = 'backup_state requires backup_eligible';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:webauthn:credentials:' || p_member_id::text, 0));
  now_value := pg_catalog.clock_timestamp();
  SELECT s.* INTO session_row
  FROM public.human_sessions AS s
  JOIN public.memberships AS m ON m.organization_id = s.organization_id AND m.member_id = s.member_id AND m.id = s.membership_id
  JOIN public.organizations AS o ON o.id = s.organization_id
  WHERE s.id = p_session_id AND s.member_id = p_member_id AND s.organization_id = p_organization_id
    AND s.revoked_at IS NULL AND s.expires_at > now_value
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
    AND m.status = 'active' AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  FOR UPDATE OF s, m, o;
  IF NOT FOUND THEN RETURN; END IF;
  INSERT INTO public.webauthn_credentials (id, member_id, public_key, sign_count, transports, label, backup_eligible, backup_state, sign_count_state)
  VALUES (p_credential_id, session_row.member_id, p_public_key, p_sign_count, p_transports, p_label, p_backup_eligible, p_backup_state,
          CASE WHEN p_sign_count = 0 THEN 'zero-counter' ELSE 'monotonic' END)
  ON CONFLICT (id) DO NOTHING
  RETURNING * INTO created;
  IF NOT FOUND THEN RETURN; END IF;
  RETURN QUERY SELECT created.id AS id, created.member_id AS member_id, created.public_key AS public_key,
    created.sign_count AS sign_count, created.transports AS transports, created.label AS label,
    created.backup_eligible AS backup_eligible, created.backup_state AS backup_state,
    created.created_at AS created_at, created.last_used_at AS last_used_at, created.revoked_at AS revoked_at;
END;
$$;

COMMIT;

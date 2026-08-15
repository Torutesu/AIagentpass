BEGIN;

-- 0055 makes the human session the only online bootstrap selector.  The
-- caller supplies a SHA-256 digest of the HttpOnly session bearer, the
-- organization requested by the route, and the closed operation/capability
-- pair.  Principal, member, assignment, generation, and WebAuthn allow-list
-- values are resolved and rechecked here under one SECURITY DEFINER call.
-- No bearer, CSRF value, WebAuthn assertion, or private credential material is
-- stored or returned by this boundary.

-- Resolve the complete trusted bootstrap context from the human session
-- bearer digest.  The function returns zero rows for every failed or
-- ambiguous resolution; it never returns a partial context.  Lock order is
-- deliberate and must remain stable across future bootstrap callers:
--
--   human session -> organization -> member -> membership -> principal
--   -> assignment -> platform credential -> WebAuthn credential
--
-- The first assignment scan identifies the principal without trusting that
-- identifier.  After the principal row is locked, a second assignment scan
-- locks and rechecks every current candidate.  This closes both stale
-- authority and multiple-assignment races without allowing the caller to
-- select any authority identity.
CREATE FUNCTION public.agentpass_platform_session_bootstrap_context(
  p_human_session_token_hash bytea,
  p_organization_id uuid,
  p_operation text,
  p_capability text
)
RETURNS TABLE (
  human_session_id uuid,
  organization_id uuid,
  member_id uuid,
  membership_id uuid,
  role text,
  organization_authority_epoch bigint,
  membership_session_epoch bigint,
  assignment_id uuid,
  principal_id uuid,
  principal_authority_generation bigint,
  assignment_version bigint,
  operation text,
  capability text,
  allowed_webauthn_credential_ids bytea[],
  platform_credentials jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_value timestamptz := clock_timestamp();
  session_row public.human_sessions%ROWTYPE;
  organization_row public.organizations%ROWTYPE;
  member_row public.members%ROWTYPE;
  membership_row public.memberships%ROWTYPE;
  principal_row public.platform_principals%ROWTYPE;
  assignment_row public.platform_operator_assignments%ROWTYPE;
  locked_assignment public.platform_operator_assignments%ROWTYPE;
  credential_row record;
  candidate_principal_id uuid;
  candidate_count integer := 0;
  credential_count integer := 0;
  usable_credential_count integer := 0;
  allowed_ids bytea[] := ARRAY[]::bytea[];
  credentials_json jsonb := '[]'::jsonb;
BEGIN
  -- Only fixed-width digests and a closed scope may enter the authority
  -- resolver.  Invalid input is indistinguishable from absent authority.
  IF p_human_session_token_hash IS NULL
     OR octet_length(p_human_session_token_hash) <> 32
     OR p_organization_id IS NULL
     OR p_operation IS NULL
     OR p_capability IS NULL
     OR p_operation <> p_capability
     OR p_operation !~ '^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+){0,15}$'
     OR p_capability NOT IN (
       'platform.assignment.manage',
       'platform.promotion.issue',
       'platform.promotion.replay',
       'platform.promotion.verify',
       'platform.promotion.reconcile'
     )
  THEN
    RETURN;
  END IF;

  -- The token hash is the sole human-session selector.  Lock the row before
  -- checking lifecycle state so a concurrent revoke/expiry update cannot be
  -- observed half-way through this bootstrap decision.
  SELECT session_value.*
    INTO session_row
  FROM public.human_sessions AS session_value
  WHERE session_value.token_hash = p_human_session_token_hash
    AND session_value.organization_id = p_organization_id
  FOR UPDATE;
  IF NOT FOUND
     OR NOT public.agentpass_platform_bytea_equal(
       session_row.token_hash, p_human_session_token_hash
     )
     OR session_row.revoked_at IS NOT NULL
     OR session_row.expires_at <= now_value
     OR (session_row.idle_expires_at IS NOT NULL AND session_row.idle_expires_at <= now_value)
     OR session_row.organization_id IS DISTINCT FROM p_organization_id
     OR session_row.membership_id IS NULL
  THEN
    RETURN;
  END IF;

  -- Lock tenant and identity rows before reading their current authority
  -- epochs.  The member row has no mutable authority epoch today, but its
  -- lock makes the identity boundary explicit and future-proof.
  SELECT organization_value.*
    INTO organization_row
  FROM public.organizations AS organization_value
  WHERE organization_value.id = session_row.organization_id
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT member_value.*
    INTO member_row
  FROM public.members AS member_value
  WHERE member_value.id = session_row.member_id
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT membership_value.*
    INTO membership_row
  FROM public.memberships AS membership_value
  WHERE membership_value.organization_id = session_row.organization_id
    AND membership_value.id = session_row.membership_id
    AND membership_value.member_id = session_row.member_id
  FOR SHARE;
  IF NOT FOUND
     OR membership_row.status <> 'active'
     OR membership_row.role IS DISTINCT FROM session_row.role
     OR organization_row.authority_epoch IS DISTINCT FROM session_row.organization_authority_epoch
     OR membership_row.session_epoch IS DISTINCT FROM session_row.membership_session_epoch
  THEN
    RETURN;
  END IF;

  -- This scan intentionally does not accept a principal or assignment from
  -- the caller.  The durable assignment is member-scoped; the validated
  -- Human session supplies only organization and member context.  This first
  -- scan is only a candidate hint used to establish the lock order; the
  -- locked scan below is authoritative.
  SELECT count(*)::integer,
         (array_agg(candidate.principal_id ORDER BY candidate.assignment_id))[1]
    INTO candidate_count, candidate_principal_id
  FROM public.platform_operator_assignments AS candidate
  WHERE candidate.organization_id = session_row.organization_id
    AND candidate.member_id = session_row.member_id
    AND candidate.operation = p_operation
    AND candidate.capability = p_capability
    AND candidate.status = 'active'
    AND candidate.issued_at IS NOT NULL
    AND candidate.issued_at <= now_value
    AND candidate.expires_at > now_value;
  IF candidate_count <> 1 OR candidate_principal_id IS NULL THEN
    RETURN;
  END IF;

  SELECT principal_value.*
    INTO principal_row
  FROM public.platform_principals AS principal_value
  WHERE principal_value.principal_id = candidate_principal_id
    AND principal_value.member_id = session_row.member_id
  FOR SHARE;
  IF NOT FOUND OR principal_row.status <> 'active' THEN RETURN; END IF;

  -- Re-scan and lock all current candidates after the principal lock.  Any
  -- assignment count other than exactly one is fail-closed, including a
  -- concurrent replacement or an authority row that became stale.
  candidate_count := 0;
  FOR locked_assignment IN
    SELECT candidate.*
    FROM public.platform_operator_assignments AS candidate
    WHERE candidate.organization_id = session_row.organization_id
      AND candidate.member_id = session_row.member_id
      AND candidate.operation = p_operation
      AND candidate.capability = p_capability
      AND candidate.status = 'active'
      AND candidate.issued_at IS NOT NULL
      AND candidate.issued_at <= now_value
      AND candidate.expires_at > now_value
    ORDER BY candidate.assignment_id
    FOR SHARE
  LOOP
    candidate_count := candidate_count + 1;
    IF candidate_count = 1 THEN
      assignment_row := locked_assignment;
    END IF;
  END LOOP;
  IF candidate_count <> 1
     OR assignment_row.assignment_id IS NULL
     OR assignment_row.principal_id IS DISTINCT FROM candidate_principal_id
     OR assignment_row.principal_id IS DISTINCT FROM principal_row.principal_id
     OR assignment_row.organization_id IS DISTINCT FROM session_row.organization_id
     OR assignment_row.member_id IS DISTINCT FROM session_row.member_id
     OR assignment_row.operation IS DISTINCT FROM p_operation
     OR assignment_row.capability IS DISTINCT FROM p_capability
     OR assignment_row.issued_at IS NULL
     OR assignment_row.issued_at > now_value
     OR assignment_row.expires_at <= now_value
  THEN
    RETURN;
  END IF;

  -- Lock every active platform credential and its underlying WebAuthn row in
  -- deterministic public-ID order.  Active platform rows whose WebAuthn
  -- credential is revoked or whose platform counter is clone-detected remain
  -- visible as state, but never enter the usable allow-list.
  FOR credential_row IN
    SELECT platform_credential.credential_id AS platform_credential_id,
           platform_credential.webauthn_credential_id,
           platform_credential.status AS platform_status,
           platform_credential.sign_count AS platform_sign_count,
           platform_credential.sign_count_state AS platform_sign_count_state,
           platform_credential.backup_eligible AS platform_backup_eligible,
           platform_credential.backup_state AS platform_backup_state,
           platform_credential.version AS platform_version,
           platform_credential.clone_detected_at AS platform_clone_detected_at,
           webauthn_credential.revoked_at AS webauthn_revoked_at,
           webauthn_credential.sign_count AS webauthn_sign_count,
           webauthn_credential.backup_eligible AS webauthn_backup_eligible,
           webauthn_credential.backup_state AS webauthn_backup_state,
           webauthn_credential.version AS webauthn_version
    FROM public.platform_credentials AS platform_credential
    JOIN public.webauthn_credentials AS webauthn_credential
      ON webauthn_credential.id = platform_credential.webauthn_credential_id
     AND webauthn_credential.member_id = platform_credential.member_id
    WHERE platform_credential.principal_id = principal_row.principal_id
      AND platform_credential.member_id = session_row.member_id
      AND platform_credential.status = 'active'
    ORDER BY platform_credential.webauthn_credential_id
    FOR UPDATE OF platform_credential, webauthn_credential
  LOOP
    credential_count := credential_count + 1;
    credentials_json := credentials_json || jsonb_build_array(jsonb_build_object(
      'platform_credential_id', credential_row.platform_credential_id,
      'webauthn_credential_id', rtrim(translate(replace(encode(credential_row.webauthn_credential_id, 'base64'), chr(10), ''), '+/', '-_'), '='),
      'platform_status', credential_row.platform_status,
      'platform_sign_count', credential_row.platform_sign_count,
      'platform_sign_count_state', credential_row.platform_sign_count_state,
      'platform_backup_eligible', credential_row.platform_backup_eligible,
      'platform_backup_state', credential_row.platform_backup_state,
      'platform_version', credential_row.platform_version,
      'platform_clone_detected_at', credential_row.platform_clone_detected_at,
      'webauthn_revoked_at', credential_row.webauthn_revoked_at,
      'webauthn_sign_count', credential_row.webauthn_sign_count,
      'webauthn_backup_eligible', credential_row.webauthn_backup_eligible,
      'webauthn_backup_state', credential_row.webauthn_backup_state,
      'webauthn_version', credential_row.webauthn_version
    ));

    IF credential_row.webauthn_revoked_at IS NULL
       AND credential_row.platform_sign_count_state <> 'clone-detected'
       AND credential_row.platform_clone_detected_at IS NULL
    THEN
      usable_credential_count := usable_credential_count + 1;
      allowed_ids := array_append(allowed_ids, credential_row.webauthn_credential_id);
    END IF;
  END LOOP;

  -- Canonicalize in the database after all credential rows are locked.  The
  -- platform credential schema is unique by WebAuthn ID, but DISTINCT is kept
  -- here as a defense-in-depth invariant for future schema changes.
  SELECT ARRAY(
    SELECT DISTINCT allowed_id
    FROM unnest(allowed_ids) AS allowed_id
    ORDER BY allowed_id
  )
    INTO allowed_ids;
  IF credential_count < 1
     OR usable_credential_count < 1
     OR cardinality(allowed_ids) NOT BETWEEN 1 AND 16
  THEN
    RETURN;
  END IF;

  human_session_id := session_row.id;
  organization_id := organization_row.id;
  member_id := member_row.id;
  membership_id := membership_row.id;
  role := membership_row.role;
  organization_authority_epoch := organization_row.authority_epoch;
  membership_session_epoch := membership_row.session_epoch;
  assignment_id := assignment_row.assignment_id;
  principal_id := principal_row.principal_id;
  principal_authority_generation := principal_row.authority_generation;
  assignment_version := assignment_row.version;
  operation := assignment_row.operation;
  capability := assignment_row.capability;
  allowed_webauthn_credential_ids := allowed_ids;
  platform_credentials := credentials_json;
  RETURN NEXT;
  RETURN;
END;
$$;

-- No table DML is added for the application role.  This resolver is the sole
-- new online entry point and its result is trusted only after the database
-- has performed every lock and epoch check above.
REVOKE ALL PRIVILEGES ON FUNCTION
  public.agentpass_platform_session_bootstrap_context(bytea, uuid, text, text)
FROM PUBLIC, agentpass_signer, agentpass_backup;

GRANT EXECUTE ON FUNCTION
  public.agentpass_platform_session_bootstrap_context(bytea, uuid, text, text)
TO agentpass_app;

COMMIT;

BEGIN;

-- 0052 establishes the deployment-global platform-operator authority.  A
-- principal is bound to exactly one member, while an assignment binds that
-- principal to one organization, operation, and closed capability.  No row
-- is seeded here: platform principals and their assignments are provisioned
-- explicitly by the migration authority after this transaction is applied.
-- This migration intentionally does not read or backfill the legacy 0044
-- platform_promotion_approvals.platform_principal_ids array.  Legacy approval
-- evidence is not identity proof for this authority boundary.

CREATE TABLE platform_principals (
  principal_id uuid PRIMARY KEY,
  member_id uuid NOT NULL UNIQUE REFERENCES members(id),
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  status_reason text CHECK (
    status_reason IS NULL
    OR (char_length(status_reason) BETWEEN 1 AND 256 AND status_reason !~ '[[:cntrl:]]')
  ),
  authority_generation bigint NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (principal_id <> member_id),
  UNIQUE (principal_id, member_id)
);

CREATE INDEX platform_principals_active_member
  ON platform_principals (member_id, principal_id)
  WHERE status = 'active';

CREATE FUNCTION agentpass_guard_platform_principal()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'restrict_violation',
      CONSTRAINT = 'platform_principals_forward_only',
      MESSAGE = 'platform principals cannot be deleted';
  END IF;

  IF NEW.principal_id IS DISTINCT FROM OLD.principal_id
     OR NEW.member_id IS DISTINCT FROM OLD.member_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_principals_immutable_identity',
      MESSAGE = 'platform principal identity is immutable';
  END IF;

  IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_principals_version_forward_only',
      MESSAGE = 'platform principal version must advance by one';
  END IF;

  IF NEW.authority_generation < OLD.authority_generation
     OR NEW.authority_generation > OLD.authority_generation + 1
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_principals_generation_forward_only',
      MESSAGE = 'platform principal authority generation must advance monotonically';
  END IF;

  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_principals_revoked_terminal',
      MESSAGE = 'revoked platform principals cannot be restored';
  END IF;

  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_principals_forward_only
  BEFORE UPDATE OR DELETE ON platform_principals
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_platform_principal();

CREATE TABLE platform_operator_assignments (
  assignment_id uuid PRIMARY KEY,
  principal_id uuid NOT NULL,
  member_id uuid NOT NULL REFERENCES members(id),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  operation text NOT NULL CHECK (
    char_length(operation) BETWEEN 1 AND 128
    AND operation ~ '^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+){0,15}$'
  ),
  capability text NOT NULL CHECK (
    capability IN (
      'platform.assignment.manage',
      'platform.promotion.issue',
      'platform.promotion.replay',
      'platform.promotion.verify',
      'platform.promotion.reconcile'
    )
  ),
  status text NOT NULL CHECK (status IN ('pending', 'active', 'suspended', 'revoked', 'replaced')),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  requested_authority_generation bigint NOT NULL CHECK (requested_authority_generation > 0),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  issued_at timestamptz,
  expires_at timestamptz NOT NULL,
  activated_at timestamptz,
  suspended_at timestamptz,
  revoked_at timestamptz,
  replaced_at timestamptz,
  suspend_reason text CHECK (
    suspend_reason IS NULL
    OR (char_length(suspend_reason) BETWEEN 1 AND 256 AND suspend_reason !~ '[[:cntrl:]]')
  ),
  revoke_reason text CHECK (
    revoke_reason IS NULL
    OR (char_length(revoke_reason) BETWEEN 1 AND 256 AND revoke_reason !~ '[[:cntrl:]]')
  ),
  replace_reason text CHECK (
    replace_reason IS NULL
    OR (char_length(replace_reason) BETWEEN 1 AND 256 AND replace_reason !~ '[[:cntrl:]]')
  ),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (principal_id, member_id)
    REFERENCES platform_principals(principal_id, member_id),
  CHECK (expires_at > requested_at),
  CHECK (operation = capability),
  CHECK (issued_at IS NULL OR issued_at >= requested_at),
  CHECK (status <> 'active' OR issued_at IS NOT NULL),
  CHECK (status <> 'active' OR activated_at IS NOT NULL),
  CHECK (status <> 'suspended' OR suspended_at IS NOT NULL),
  CHECK (status <> 'suspended' OR suspend_reason IS NOT NULL),
  CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
  CHECK (status <> 'revoked' OR revoke_reason IS NOT NULL),
  CHECK (status <> 'replaced' OR replaced_at IS NOT NULL),
  CHECK (status <> 'replaced' OR replace_reason IS NOT NULL)
);

-- A replacement needs one pending row beside the currently effective row.
-- Separate partial indexes permit that pair while still rejecting duplicate
-- pending or effective authority for an exact scope.
CREATE UNIQUE INDEX platform_operator_assignments_one_effective
  ON platform_operator_assignments (organization_id, principal_id, operation, capability)
  WHERE status IN ('active', 'suspended');

CREATE UNIQUE INDEX platform_operator_assignments_one_pending
  ON platform_operator_assignments (organization_id, principal_id, operation, capability)
  WHERE status = 'pending';

CREATE INDEX platform_operator_assignments_active_lookup
  ON platform_operator_assignments
    (organization_id, member_id, operation, capability, principal_id, assignment_id)
  WHERE status = 'active';

CREATE FUNCTION agentpass_guard_platform_operator_assignment()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'restrict_violation',
      CONSTRAINT = 'platform_operator_assignments_forward_only',
      MESSAGE = 'platform operator assignments cannot be deleted';
  END IF;

  IF NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
     OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
     OR NEW.member_id IS DISTINCT FROM OLD.member_id
     OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.operation IS DISTINCT FROM OLD.operation
     OR NEW.capability IS DISTINCT FROM OLD.capability
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.requested_authority_generation IS DISTINCT FROM OLD.requested_authority_generation
     OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignments_immutable_binding',
      MESSAGE = 'platform operator assignment binding is immutable';
  END IF;

  IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignments_version_forward_only',
      MESSAGE = 'platform operator assignment version must advance by one';
  END IF;

  IF OLD.status IN ('revoked', 'replaced') AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignments_terminal',
      MESSAGE = 'terminal platform operator assignments cannot change state';
  END IF;

  IF OLD.status = 'pending' AND NEW.status NOT IN ('pending', 'active', 'suspended', 'revoked', 'replaced') THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid pending assignment transition';
  END IF;
  IF OLD.status = 'active' AND NEW.status NOT IN ('active', 'suspended', 'revoked', 'replaced') THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid active assignment transition';
  END IF;
  IF OLD.status = 'suspended' AND NEW.status NOT IN ('suspended', 'revoked', 'replaced') THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid suspended assignment transition';
  END IF;

  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_operator_assignments_forward_only
  BEFORE UPDATE OR DELETE ON platform_operator_assignments
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_platform_operator_assignment();

CREATE TABLE platform_operator_assignment_approvals (
  approval_id uuid PRIMARY KEY,
  assignment_id uuid NOT NULL REFERENCES platform_operator_assignments(assignment_id),
  approver_principal_id uuid NOT NULL REFERENCES platform_principals(principal_id),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  approver_authority_generation bigint NOT NULL CHECK (approver_authority_generation > 0),
  approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (assignment_id, approver_principal_id)
);

CREATE INDEX platform_operator_assignment_approvals_active_lookup
  ON platform_operator_assignment_approvals (assignment_id, approver_principal_id, approved_at);

CREATE FUNCTION agentpass_guard_platform_operator_assignment_approval()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  assignment_row record;
  approver_row record;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'restrict_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_forward_only',
      MESSAGE = 'platform operator assignment approvals cannot be deleted';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'restrict_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_immutable',
      MESSAGE = 'platform operator assignment approvals are immutable';
  END IF;

  SELECT assignment_id, principal_id, member_id, request_digest,
    requested_authority_generation, status
    INTO assignment_row
  FROM platform_operator_assignments
  WHERE assignment_id = NEW.assignment_id
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'assignment was not found';
  END IF;
  IF assignment_row.principal_id = NEW.approver_principal_id THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_no_self_approval',
      MESSAGE = 'assignment target cannot approve itself';
  END IF;
  IF assignment_row.request_digest IS DISTINCT FROM NEW.request_digest THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_digest_binding',
      MESSAGE = 'approval request digest does not match assignment';
  END IF;
  IF assignment_row.status <> 'pending' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_pending_only',
      MESSAGE = 'only pending assignments may receive approvals';
  END IF;

  SELECT status, member_id, authority_generation
    INTO approver_row
  FROM platform_principals
  WHERE principal_id = NEW.approver_principal_id
  FOR SHARE;
  IF approver_row.status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_active_approver',
      MESSAGE = 'approval requires an active platform principal';
  END IF;
  IF approver_row.member_id = assignment_row.member_id THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_no_target_member',
      MESSAGE = 'assignment target member cannot approve itself';
  END IF;
  IF NEW.approver_authority_generation IS DISTINCT FROM approver_row.authority_generation THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_generation_binding',
      MESSAGE = 'approval authority generation does not match the assignment request';
  END IF;

  IF NEW.approved_at > clock_timestamp() THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_db_clock',
      MESSAGE = 'approval time cannot be in the future';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_operator_assignment_approvals_forward_only
  BEFORE INSERT OR UPDATE OR DELETE ON platform_operator_assignment_approvals
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_platform_operator_assignment_approval();

CREATE FUNCTION agentpass_platform_principal_json(
  p_principal platform_principals
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object(
    'principal_id', p_principal.principal_id,
    'member_id', p_principal.member_id,
    'status', p_principal.status,
    'status_reason', p_principal.status_reason,
    'authority_generation', p_principal.authority_generation,
    'version', p_principal.version
  )
$$;

CREATE FUNCTION agentpass_platform_operator_assignment_json(
  p_assignment platform_operator_assignments,
  p_authority_generation bigint
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object(
    'assignment_id', p_assignment.assignment_id,
    'principal_id', p_assignment.principal_id,
    'member_id', p_assignment.member_id,
    'organization_id', p_assignment.organization_id,
    'operation', p_assignment.operation,
    'capability', p_assignment.capability,
    'status', p_assignment.status,
    'request_digest', encode(p_assignment.request_digest, 'hex'),
    'requested_authority_generation', p_assignment.requested_authority_generation,
    'version', p_assignment.version,
    'requested_at', p_assignment.requested_at,
    'issued_at', p_assignment.issued_at,
    'expires_at', p_assignment.expires_at,
    'activated_at', p_assignment.activated_at,
    'suspended_at', p_assignment.suspended_at,
    'revoked_at', p_assignment.revoked_at,
    'replaced_at', p_assignment.replaced_at,
    'authority_generation', p_authority_generation
  )
$$;

CREATE FUNCTION agentpass_platform_principal_provision(
  p_principal_id uuid,
  p_member_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  principal_row platform_principals;
BEGIN
  SELECT * INTO principal_row
  FROM platform_principals
  WHERE member_id = p_member_id
  FOR UPDATE;
  IF FOUND AND principal_row.principal_id IS DISTINCT FROM p_principal_id THEN
    RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'member already has a platform principal';
  END IF;
  IF FOUND THEN
    RETURN agentpass_platform_principal_json(principal_row);
  END IF;

  INSERT INTO platform_principals (principal_id, member_id, status)
  VALUES (p_principal_id, p_member_id, 'active')
  ON CONFLICT (principal_id) DO NOTHING;

  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = p_principal_id
  FOR UPDATE;
  IF principal_row.member_id IS DISTINCT FROM p_member_id THEN
    RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'principal is bound to another member';
  END IF;
  RETURN agentpass_platform_principal_json(principal_row);
END;
$$;

CREATE FUNCTION agentpass_platform_operator_assignment_request(
  p_assignment_id uuid,
  p_principal_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_operation text,
  p_capability text,
  p_request_digest bytea,
  p_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  principal_row platform_principals;
  assignment_row platform_operator_assignments;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = p_principal_id
    AND member_id = p_member_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'platform principal/member binding was not found';
  END IF;
  IF principal_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'assignment requires an active platform principal';
  END IF;
  IF p_expires_at <= now_value THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'assignment expiry must be in the future';
  END IF;

  INSERT INTO platform_operator_assignments (
    assignment_id, principal_id, member_id, organization_id,
    operation, capability, status, request_digest,
    requested_authority_generation, requested_at, expires_at
  ) VALUES (
    p_assignment_id, p_principal_id, p_member_id, p_organization_id,
    p_operation, p_capability, 'pending', p_request_digest,
    principal_row.authority_generation, now_value, p_expires_at
  )
  RETURNING * INTO assignment_row;

  RETURN agentpass_platform_operator_assignment_json(
    assignment_row, principal_row.authority_generation
  );
END;
$$;

CREATE FUNCTION agentpass_platform_operator_assignment_approve(
  p_approval_id uuid,
  p_assignment_id uuid,
  p_approver_principal_id uuid,
  p_request_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  assignment_row platform_operator_assignments;
  approver_row platform_principals;
  approval_row platform_operator_assignment_approvals;
BEGIN
  SELECT * INTO assignment_row
  FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'assignment was not found';
  END IF;
  IF assignment_row.request_digest IS DISTINCT FROM p_request_digest THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_digest_binding',
      MESSAGE = 'approval request digest does not match assignment';
  END IF;

  SELECT * INTO approval_row
  FROM platform_operator_assignment_approvals
  WHERE assignment_id = p_assignment_id
    AND approver_principal_id = p_approver_principal_id;
  IF FOUND THEN
    IF approval_row.approval_id IS DISTINCT FROM p_approval_id
       OR approval_row.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION USING
        ERRCODE = 'unique_violation',
        CONSTRAINT = 'platform_operator_assignment_approvals_assignment_id_approver_principal_id_key',
        MESSAGE = 'approver already recorded a different approval for this assignment';
    END IF;
    RETURN jsonb_build_object(
      'approval_id', approval_row.approval_id,
      'assignment_id', approval_row.assignment_id,
      'approver_principal_id', approval_row.approver_principal_id,
      'request_digest', encode(approval_row.request_digest, 'hex'),
      'approver_authority_generation', approval_row.approver_authority_generation,
      'approved_at', approval_row.approved_at
    );
  END IF;
  IF assignment_row.status <> 'pending' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'only pending assignments may receive approvals';
  END IF;
  IF assignment_row.principal_id = p_approver_principal_id THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_no_self_approval',
      MESSAGE = 'assignment target cannot approve itself';
  END IF;

  SELECT * INTO approver_row
  FROM platform_principals
  WHERE principal_id = p_approver_principal_id
  FOR SHARE;
  IF NOT FOUND OR approver_row.status <> 'active' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_active_approver',
      MESSAGE = 'approval requires an active platform principal';
  END IF;
  IF approver_row.member_id = assignment_row.member_id THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignment_approvals_no_target_member',
      MESSAGE = 'assignment target member cannot approve itself';
  END IF;
  INSERT INTO platform_operator_assignment_approvals (
    approval_id, assignment_id, approver_principal_id, request_digest,
    approver_authority_generation, approved_at
  ) VALUES (
    p_approval_id, p_assignment_id, p_approver_principal_id,
    p_request_digest, approver_row.authority_generation, clock_timestamp()
  )
  RETURNING * INTO approval_row;

  RETURN jsonb_build_object(
    'approval_id', approval_row.approval_id,
    'assignment_id', approval_row.assignment_id,
    'approver_principal_id', approval_row.approver_principal_id,
    'request_digest', encode(approval_row.request_digest, 'hex'),
    'approver_authority_generation', approval_row.approver_authority_generation,
    'approved_at', approval_row.approved_at
  );
END;
$$;

CREATE FUNCTION agentpass_platform_operator_assignment_activate(
  p_assignment_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  assignment_row platform_operator_assignments;
  principal_row platform_principals;
  principal_id_value uuid;
  approver_row record;
  active_approvals integer := 0;
  active_approver_members uuid[] := ARRAY[]::uuid[];
  now_value timestamptz := clock_timestamp();
BEGIN
  -- All mutators acquire the principal lock before any assignment lock.  This
  -- order is shared with suspend/revoke and prevents a principal-wide stop
  -- from deadlocking against activation.
  SELECT principal_id INTO principal_id_value
  FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'assignment was not found';
  END IF;
  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = principal_id_value
  FOR UPDATE;
  SELECT * INTO assignment_row
  FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id
  FOR UPDATE;
  IF assignment_row.status = 'active' THEN
    RETURN agentpass_platform_operator_assignment_json(assignment_row, principal_row.authority_generation);
  END IF;
  IF assignment_row.status <> 'pending' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'only pending assignments may be activated';
  END IF;
  IF assignment_row.expires_at <= now_value THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'expired assignments cannot be activated';
  END IF;

  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = assignment_row.principal_id
    AND member_id = assignment_row.member_id
  FOR UPDATE;
  IF NOT FOUND OR principal_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'assignment target principal is not active';
  END IF;
  IF principal_row.authority_generation IS DISTINCT FROM assignment_row.requested_authority_generation THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignments_generation_binding',
      MESSAGE = 'assignment target principal authority generation is stale';
  END IF;
  IF principal_row.authority_generation = 9223372036854775807::bigint THEN
    RAISE EXCEPTION USING ERRCODE = 'numeric_value_out_of_range', MESSAGE = 'principal authority generation exhausted';
  END IF;

  FOR approver_row IN
    SELECT approval.approver_principal_id,
      approver.member_id, approver.authority_generation
    FROM platform_operator_assignment_approvals AS approval
    JOIN platform_principals AS approver
      ON approver.principal_id = approval.approver_principal_id
    WHERE approval.assignment_id = assignment_row.assignment_id
      AND approval.request_digest = assignment_row.request_digest
      AND approver.status = 'active'
      AND approver.principal_id <> assignment_row.principal_id
      AND approver.member_id <> assignment_row.member_id
      AND approval.approver_authority_generation = approver.authority_generation
    ORDER BY approver.principal_id
    FOR SHARE OF approver
  LOOP
    IF NOT (approver_row.member_id = ANY(active_approver_members)) THEN
      active_approver_members := array_append(active_approver_members, approver_row.member_id);
      active_approvals := active_approvals + 1;
    END IF;
  END LOOP;
  IF active_approvals < 2 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignments_two_active_approvals',
      MESSAGE = 'assignment activation requires two distinct active approver principals';
  END IF;

  UPDATE platform_principals
  SET authority_generation = authority_generation + 1,
      version = version + 1,
      updated_at = now_value
  WHERE principal_id = principal_row.principal_id;

  UPDATE platform_operator_assignments
  SET status = 'active',
      issued_at = now_value,
      activated_at = now_value,
      version = version + 1,
      updated_at = now_value
  WHERE assignment_id = assignment_row.assignment_id
  RETURNING * INTO assignment_row;

  principal_row.authority_generation := principal_row.authority_generation + 1;
  principal_row.version := principal_row.version + 1;
  RETURN agentpass_platform_operator_assignment_json(
    assignment_row, principal_row.authority_generation
  );
END;
$$;

CREATE FUNCTION agentpass_platform_operator_assignment_suspend(
  p_assignment_id uuid,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  assignment_row platform_operator_assignments;
  principal_row platform_principals;
  principal_id_value uuid;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT principal_id INTO principal_id_value
  FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'assignment was not found';
  END IF;
  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = principal_id_value
  FOR UPDATE;
  SELECT * INTO assignment_row
  FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id
  FOR UPDATE;
  IF assignment_row.status <> 'active' THEN
    IF assignment_row.status = 'pending' THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'pending assignments must be revoked rather than suspended';
    END IF;
    RETURN agentpass_platform_operator_assignment_json(assignment_row, principal_row.authority_generation);
  END IF;
  IF p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 256 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'assignment suspension reason is invalid';
  END IF;
  IF principal_row.authority_generation = 9223372036854775807::bigint THEN
    RAISE EXCEPTION USING ERRCODE = 'numeric_value_out_of_range', MESSAGE = 'principal authority generation exhausted';
  END IF;
  UPDATE platform_principals
  SET authority_generation = authority_generation + 1,
      version = version + 1,
      updated_at = now_value
  WHERE principal_id = principal_row.principal_id
  RETURNING * INTO principal_row;
  UPDATE platform_operator_assignments
  SET status = 'suspended',
      suspended_at = now_value,
      suspend_reason = p_reason,
      version = version + 1,
      updated_at = now_value
  WHERE assignment_id = p_assignment_id
  RETURNING * INTO assignment_row;
  RETURN agentpass_platform_operator_assignment_json(assignment_row, principal_row.authority_generation);
END;
$$;

CREATE FUNCTION agentpass_platform_operator_assignment_revoke(
  p_assignment_id uuid,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  assignment_row platform_operator_assignments;
  principal_row platform_principals;
  principal_id_value uuid;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT principal_id INTO principal_id_value
  FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'assignment was not found';
  END IF;
  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = principal_id_value
  FOR UPDATE;
  SELECT * INTO assignment_row
  FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'assignment was not found';
  END IF;
  IF assignment_row.status NOT IN ('pending', 'active', 'suspended') THEN
    RETURN agentpass_platform_operator_assignment_json(assignment_row, principal_row.authority_generation);
  END IF;
  IF p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 256 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'assignment revocation reason is invalid';
  END IF;
  IF principal_row.authority_generation = 9223372036854775807::bigint THEN
    RAISE EXCEPTION USING ERRCODE = 'numeric_value_out_of_range', MESSAGE = 'principal authority generation exhausted';
  END IF;
  UPDATE platform_principals
  SET authority_generation = authority_generation + 1,
      version = version + 1,
      updated_at = now_value
  WHERE principal_id = principal_row.principal_id
  RETURNING * INTO principal_row;
  UPDATE platform_operator_assignments
  SET status = 'revoked',
      revoked_at = now_value,
      revoke_reason = p_reason,
      version = version + 1,
      updated_at = now_value
  WHERE assignment_id = p_assignment_id
  RETURNING * INTO assignment_row;
  RETURN agentpass_platform_operator_assignment_json(assignment_row, principal_row.authority_generation);
END;
$$;

CREATE FUNCTION agentpass_platform_principal_suspend(
  p_principal_id uuid,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  principal_row platform_principals;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = p_principal_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'principal was not found';
  END IF;
  IF principal_row.status = 'revoked' THEN
    RETURN agentpass_platform_principal_json(principal_row);
  END IF;
  IF principal_row.status = 'active' THEN
    IF p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 256 OR p_reason ~ '[[:cntrl:]]' THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'principal suspension reason is invalid';
    END IF;
    IF principal_row.authority_generation = 9223372036854775807::bigint THEN
      RAISE EXCEPTION USING ERRCODE = 'numeric_value_out_of_range', MESSAGE = 'principal authority generation exhausted';
    END IF;
    UPDATE platform_principals
    SET status = 'suspended',
        status_reason = p_reason,
        authority_generation = authority_generation + 1,
        version = version + 1,
        updated_at = now_value
    WHERE principal_id = p_principal_id
    RETURNING * INTO principal_row;
    -- Pending replacements are not effective authority and cannot coexist as
    -- suspended rows with the effective assignment's unique scope. Cancel
    -- them first; then suspend only currently active authority.
    UPDATE platform_operator_assignments
    SET status = 'revoked',
        revoked_at = now_value,
        revoke_reason = p_reason,
        version = version + 1,
        updated_at = now_value
    WHERE principal_id = p_principal_id
      AND status = 'pending';
    UPDATE platform_operator_assignments
    SET status = 'suspended',
        suspended_at = now_value,
        suspend_reason = p_reason,
        version = version + 1,
        updated_at = now_value
    WHERE principal_id = p_principal_id
      AND status = 'active';
  END IF;
  RETURN agentpass_platform_principal_json(principal_row);
END;
$$;

CREATE FUNCTION agentpass_platform_principal_revoke(
  p_principal_id uuid,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  principal_row platform_principals;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = p_principal_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'principal was not found';
  END IF;
  IF principal_row.status <> 'revoked' THEN
    IF p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 256 OR p_reason ~ '[[:cntrl:]]' THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'principal revocation reason is invalid';
    END IF;
    IF principal_row.authority_generation = 9223372036854775807::bigint THEN
      RAISE EXCEPTION USING ERRCODE = 'numeric_value_out_of_range', MESSAGE = 'principal authority generation exhausted';
    END IF;
    UPDATE platform_principals
    SET status = 'revoked',
        status_reason = p_reason,
        authority_generation = authority_generation + 1,
        version = version + 1,
        updated_at = now_value
    WHERE principal_id = p_principal_id
    RETURNING * INTO principal_row;
    UPDATE platform_operator_assignments
    SET status = 'revoked',
        revoked_at = now_value,
        revoke_reason = p_reason,
        version = version + 1,
        updated_at = now_value
    WHERE principal_id = p_principal_id
      AND status IN ('pending', 'active', 'suspended');
  END IF;
  RETURN agentpass_platform_principal_json(principal_row);
END;
$$;

CREATE FUNCTION agentpass_platform_operator_assignment_replace(
  p_assignment_id uuid,
  p_replacement_assignment_id uuid,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  old_assignment platform_operator_assignments;
  replacement_assignment platform_operator_assignments;
  principal_row platform_principals;
  principal_id_value uuid;
  approver_row record;
  active_approvals integer := 0;
  active_approver_members uuid[] := ARRAY[]::uuid[];
  now_value timestamptz := clock_timestamp();
BEGIN
  IF p_assignment_id = p_replacement_assignment_id THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'an assignment cannot replace itself';
  END IF;
  IF p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 256 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'assignment replacement reason is invalid';
  END IF;

  SELECT principal_id INTO principal_id_value
  FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'replacement assignment was not found';
  END IF;
  SELECT * INTO principal_row
  FROM platform_principals
  WHERE principal_id = principal_id_value
  FOR UPDATE;

  -- Lock both rows in UUID order so concurrent replacement requests cannot
  -- deadlock by taking the two assignment locks in opposite orders.
  PERFORM 1
  FROM platform_operator_assignments
  WHERE assignment_id IN (p_assignment_id, p_replacement_assignment_id)
  ORDER BY assignment_id
  FOR UPDATE;
  SELECT * INTO old_assignment FROM platform_operator_assignments
  WHERE assignment_id = p_assignment_id FOR UPDATE;
  SELECT * INTO replacement_assignment FROM platform_operator_assignments
  WHERE assignment_id = p_replacement_assignment_id FOR UPDATE;
  IF NOT FOUND OR old_assignment.assignment_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'replacement assignment was not found';
  END IF;
  IF old_assignment.status NOT IN ('active', 'suspended')
     OR replacement_assignment.status <> 'pending'
     OR old_assignment.principal_id IS DISTINCT FROM replacement_assignment.principal_id
     OR old_assignment.member_id IS DISTINCT FROM replacement_assignment.member_id
     OR old_assignment.organization_id IS DISTINCT FROM replacement_assignment.organization_id
     OR old_assignment.operation IS DISTINCT FROM replacement_assignment.operation
     OR old_assignment.capability IS DISTINCT FROM replacement_assignment.capability
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'assignment replacement binding is invalid';
  END IF;
  IF replacement_assignment.expires_at <= now_value THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'expired replacement assignments cannot be activated';
  END IF;

  IF principal_row.member_id IS DISTINCT FROM replacement_assignment.member_id
     OR principal_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'replacement target principal is not active';
  END IF;
  IF principal_row.authority_generation IS DISTINCT FROM replacement_assignment.requested_authority_generation THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_operator_assignments_generation_binding',
      MESSAGE = 'replacement target principal authority generation is stale';
  END IF;
  IF principal_row.authority_generation = 9223372036854775807::bigint THEN
    RAISE EXCEPTION USING ERRCODE = 'numeric_value_out_of_range', MESSAGE = 'principal authority generation exhausted';
  END IF;

  FOR approver_row IN
    SELECT approval.approver_principal_id,
      approver.member_id, approver.authority_generation
    FROM platform_operator_assignment_approvals AS approval
    JOIN platform_principals AS approver
      ON approver.principal_id = approval.approver_principal_id
    WHERE approval.assignment_id = replacement_assignment.assignment_id
      AND approval.request_digest = replacement_assignment.request_digest
      AND approver.status = 'active'
      AND approver.principal_id <> replacement_assignment.principal_id
      AND approver.member_id <> replacement_assignment.member_id
      AND approval.approver_authority_generation = approver.authority_generation
    ORDER BY approver.principal_id
    FOR SHARE OF approver
  LOOP
    IF NOT (approver_row.member_id = ANY(active_approver_members)) THEN
      active_approver_members := array_append(active_approver_members, approver_row.member_id);
      active_approvals := active_approvals + 1;
    END IF;
  END LOOP;
  IF active_approvals < 2 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'replacement requires two distinct active approver principals';
  END IF;

  UPDATE platform_operator_assignments
  SET status = 'replaced',
      replaced_at = now_value,
      replace_reason = p_reason,
      version = version + 1,
      updated_at = now_value
  WHERE assignment_id = old_assignment.assignment_id;
  UPDATE platform_operator_assignments
  SET status = 'active',
      issued_at = now_value,
      activated_at = now_value,
      version = version + 1,
      updated_at = now_value
  WHERE assignment_id = replacement_assignment.assignment_id
  RETURNING * INTO replacement_assignment;
  UPDATE platform_principals
  SET authority_generation = authority_generation + 1,
      version = version + 1,
      updated_at = now_value
  WHERE principal_id = principal_row.principal_id
  RETURNING * INTO principal_row;
  RETURN agentpass_platform_operator_assignment_json(
    replacement_assignment, principal_row.authority_generation
  );
END;
$$;

-- This lookup is a non-locking precheck, never the final authorization point.
-- requested_authority_generation fences request activation only: changing one
-- assignment must not invalidate a principal's unrelated active assignments.
-- N3 sessions/proofs snapshot the returned current principal generation, and
-- the atomic N3/N4 consume path must compare that snapshot with the principal.
CREATE FUNCTION agentpass_platform_operator_assignment_find_active(
  p_organization_id uuid,
  p_member_id uuid,
  p_session_id uuid,
  p_operation text,
  p_capability text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_value timestamptz := clock_timestamp();
  assignment jsonb;
BEGIN
  SELECT jsonb_build_object(
    'assignment_id', operator_assignment.assignment_id,
    'capability', operator_assignment.capability,
    'expires_at', operator_assignment.expires_at,
    'issued_at', operator_assignment.issued_at,
    'member_id', operator_assignment.member_id,
    'principal_id', principal.principal_id,
    'operation', operator_assignment.operation,
    'organization_id', operator_assignment.organization_id,
    'role', 'platform_operator',
    'session_id', human_session.id,
    'status', operator_assignment.status,
    'authority_generation', principal.authority_generation,
    'assignment_version', operator_assignment.version
  )
  INTO assignment
  FROM human_sessions AS human_session
  JOIN organizations AS organization
    ON organization.id = human_session.organization_id
   AND organization.authority_epoch = human_session.organization_authority_epoch
  JOIN memberships AS membership
    ON membership.organization_id = human_session.organization_id
   AND membership.id = human_session.membership_id
   AND membership.member_id = human_session.member_id
   AND membership.status = 'active'
   AND membership.session_epoch = human_session.membership_session_epoch
  JOIN platform_principals AS principal
    ON principal.member_id = human_session.member_id
   AND principal.status = 'active'
  JOIN platform_operator_assignments AS operator_assignment
    ON operator_assignment.principal_id = principal.principal_id
   AND operator_assignment.member_id = human_session.member_id
   AND operator_assignment.organization_id = membership.organization_id
   AND operator_assignment.operation = p_operation
   AND operator_assignment.capability = p_capability
   AND operator_assignment.status = 'active'
   AND operator_assignment.issued_at <= now_value
   AND operator_assignment.expires_at > now_value
  WHERE human_session.id = p_session_id
    AND human_session.member_id = p_member_id
    AND human_session.organization_id = p_organization_id
    AND human_session.created_at <= now_value
    AND human_session.expires_at > now_value
    AND (human_session.idle_expires_at IS NULL OR human_session.idle_expires_at > now_value)
    AND human_session.revoked_at IS NULL
  ;

  RETURN assignment;
END;
$$;

-- Functions are executable by nobody by default in this contract.  The
-- migrator owns the mutation boundary; the application receives only the
-- read-only, session-bound lookup.  Revoke PUBLIC on tables and every helper
-- or trigger function as well, so no implicit PostgreSQL default remains.
REVOKE ALL PRIVILEGES ON TABLE
  platform_principals,
  platform_operator_assignments,
  platform_operator_assignment_approvals
FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

REVOKE ALL PRIVILEGES ON FUNCTION agentpass_guard_platform_principal() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_guard_platform_operator_assignment() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_guard_platform_operator_assignment_approval() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_principal_json(platform_principals) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_operator_assignment_json(platform_operator_assignments, bigint) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_principal_provision(uuid, uuid) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_operator_assignment_request(uuid, uuid, uuid, uuid, text, text, bytea, timestamptz) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_operator_assignment_approve(uuid, uuid, uuid, bytea) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_operator_assignment_activate(uuid) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_operator_assignment_suspend(uuid, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_operator_assignment_revoke(uuid, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_operator_assignment_replace(uuid, uuid, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_principal_suspend(uuid, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_principal_revoke(uuid, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION agentpass_platform_operator_assignment_find_active(uuid, uuid, uuid, text, text) FROM PUBLIC, agentpass_signer, agentpass_backup;

GRANT EXECUTE ON FUNCTION agentpass_platform_principal_provision(uuid, uuid) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_operator_assignment_request(uuid, uuid, uuid, uuid, text, text, bytea, timestamptz) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_operator_assignment_approve(uuid, uuid, uuid, bytea) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_operator_assignment_activate(uuid) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_operator_assignment_suspend(uuid, text) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_operator_assignment_revoke(uuid, text) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_operator_assignment_replace(uuid, uuid, text) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_principal_suspend(uuid, text) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_principal_revoke(uuid, text) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION agentpass_platform_operator_assignment_find_active(uuid, uuid, uuid, text, text) TO agentpass_migrator, agentpass_app;

COMMIT;

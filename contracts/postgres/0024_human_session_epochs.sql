BEGIN;

-- Human sessions carry the authority observations that were true when they
-- were issued.  Epochs are deliberately positive, tenant-qualified values;
-- they are not timestamps and must never be reset during a rollout.
ALTER TABLE organizations
  ADD COLUMN authority_epoch bigint NOT NULL DEFAULT 1,
  ADD CONSTRAINT organizations_authority_epoch_positive
    CHECK (authority_epoch > 0);

ALTER TABLE memberships
  ADD COLUMN session_epoch bigint NOT NULL DEFAULT 1,
  ADD CONSTRAINT memberships_session_epoch_positive
    CHECK (session_epoch > 0);

-- These columns preserve the exact authority revision observed at issuance.
-- The existing organization/membership identity constraints remain in force;
-- the insert trigger below rejects any new unbound session.
ALTER TABLE human_sessions
  ADD COLUMN organization_authority_epoch bigint NOT NULL DEFAULT 1,
  ADD COLUMN membership_session_epoch bigint NOT NULL DEFAULT 1,
  ADD CONSTRAINT human_sessions_organization_authority_epoch_positive
    CHECK (organization_authority_epoch > 0),
  ADD CONSTRAINT human_sessions_membership_session_epoch_positive
    CHECK (membership_session_epoch > 0);

-- Epoch values are historical snapshots, not foreign-key identities. Making
-- them part of a foreign key would prevent the referenced organization or
-- membership epoch from advancing while any old session still exists. The
-- existing tenant-qualified organization/membership foreign keys preserve
-- identity; the insert trigger below captures the current epoch under locks.

CREATE INDEX memberships_active_session_epoch_lookup
  ON memberships (organization_id, member_id, session_epoch, id)
  WHERE status = 'active';

CREATE INDEX human_sessions_current_epoch_lookup
  ON human_sessions (organization_id, organization_authority_epoch,
                     membership_id, membership_session_epoch, member_id, id)
  WHERE revoked_at IS NULL;

CREATE INDEX human_sessions_membership_epoch_lookup
  ON human_sessions (organization_id, membership_id,
                     membership_session_epoch, member_id, id)
  WHERE revoked_at IS NULL;

-- A newly issued session must observe the rows it is bound to after taking a
-- share lock on both rows. This closes the race where an epoch reduction and
-- a session insert run on different Cloud instances.
CREATE FUNCTION agentpass_bind_human_session_epochs()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  current_authority_epoch bigint;
  current_session_epoch bigint;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.organization_id IS NULL OR NEW.membership_id IS NULL THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'human_sessions_epoch_binding_complete',
        MESSAGE = 'new human sessions require an organization and membership';
    END IF;

    SELECT organization.authority_epoch, membership.session_epoch
      INTO current_authority_epoch, current_session_epoch
    FROM organizations AS organization
    JOIN memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.id = NEW.membership_id
    WHERE organization.id = NEW.organization_id
      AND membership.member_id = NEW.member_id
      AND membership.status = 'active'
    FOR SHARE OF organization, membership;

    IF NOT FOUND THEN
      RAISE EXCEPTION USING
        ERRCODE = 'foreign_key_violation',
        CONSTRAINT = 'human_sessions_epoch_binding_complete',
        MESSAGE = 'human session membership is not active in its organization';
    END IF;

    NEW.organization_authority_epoch := current_authority_epoch;
    NEW.membership_session_epoch := current_session_epoch;
    RETURN NEW;
  END IF;

  -- A snapshot describes issuance and is never rewritten in place.  Moving a
  -- session to another tenant/membership would also defeat the composite FK
  -- boundary, so reject both identity and snapshot changes together.
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.membership_id IS DISTINCT FROM OLD.membership_id
     OR NEW.member_id IS DISTINCT FROM OLD.member_id
     OR NEW.role IS DISTINCT FROM OLD.role
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
     OR NEW.csrf_token_hash IS DISTINCT FROM OLD.csrf_token_hash
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.organization_authority_epoch IS DISTINCT FROM OLD.organization_authority_epoch
     OR NEW.membership_session_epoch IS DISTINCT FROM OLD.membership_session_epoch THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'human_sessions_epoch_snapshot_immutable',
      MESSAGE = 'human session authority snapshots are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER human_sessions_bind_epochs
  BEFORE INSERT OR UPDATE OF id, organization_id, membership_id, member_id, role,
    token_hash, csrf_token_hash, created_at, expires_at,
    organization_authority_epoch, membership_session_epoch ON human_sessions
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_bind_human_session_epochs();

-- Every role/status transition advances exactly the target membership's
-- session epoch, including a widening, so a session
-- issued under the old membership state can never survive a state change.
-- The assignment is made to NEW in the existing BEFORE trigger path:
-- PostgreSQL therefore runs the last-owner trigger against the same proposed
-- role/status row and no second UPDATE (or recursive trigger) is introduced.
CREATE FUNCTION agentpass_bump_membership_session_epoch()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  authority_changed boolean;
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RETURN NEW;
  END IF;

  IF NEW.session_epoch IS DISTINCT FROM OLD.session_epoch
     AND NEW.session_epoch IS DISTINCT FROM OLD.session_epoch + 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'memberships_session_epoch_forward_only',
      MESSAGE = 'membership session epoch may only advance by one';
  END IF;

  authority_changed :=
    (NEW.status IS DISTINCT FROM OLD.status)
    OR (NEW.role IS DISTINCT FROM OLD.role)
    OR (NEW.organization_id IS DISTINCT FROM OLD.organization_id);

  IF authority_changed THEN
    IF OLD.session_epoch = 9223372036854775807::bigint THEN
      RAISE EXCEPTION USING
        ERRCODE = 'numeric_value_out_of_range',
        CONSTRAINT = 'memberships_session_epoch_positive',
        MESSAGE = 'membership session epoch cannot advance beyond bigint';
    END IF;
    NEW.session_epoch := OLD.session_epoch + 1;
  ELSIF NEW.session_epoch IS DISTINCT FROM OLD.session_epoch THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'memberships_session_epoch_forward_only',
      MESSAGE = 'membership session epoch is managed by the authority trigger';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER memberships_bump_session_epoch
  BEFORE UPDATE OF organization_id, role, status, session_epoch ON memberships
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_bump_membership_session_epoch();

-- Organization-wide invalidation is an explicit operation because the base
-- organization table has no other authority-bearing state column.  The row
-- lock and single UPDATE make the increment atomic with the caller's audit,
-- outbox, and protected mutation transaction.  It is intentionally scoped by
-- organization_id and never accepts an arbitrary epoch value.
CREATE FUNCTION agentpass_bump_organization_authority_epoch(
  request_organization_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public
AS $$
DECLARE
  next_epoch bigint;
BEGIN
  PERFORM 1
  FROM organizations
  WHERE id = request_organization_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'foreign_key_violation',
      CONSTRAINT = 'organizations_authority_epoch_positive',
      MESSAGE = 'organization was not found';
  END IF;

  UPDATE organizations
  SET authority_epoch = authority_epoch + 1,
      updated_at = clock_timestamp()
  WHERE id = request_organization_id
  RETURNING authority_epoch INTO next_epoch;

  RETURN next_epoch;
END;
$$;

-- Direct writes may be used by a tightly controlled emergency-stop caller, but
-- they can only move the epoch forward by one.  Ordinary organization edits
-- leave authority_epoch unchanged.  The trigger is separate from the helper
-- so it does not interfere with membership role/status or last-owner checks.
CREATE FUNCTION agentpass_guard_organization_authority_epoch()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.authority_epoch < OLD.authority_epoch
     OR NEW.authority_epoch > OLD.authority_epoch + 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'organizations_authority_epoch_forward_only',
      MESSAGE = 'organization authority epoch must advance monotonically by one';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER organizations_authority_epoch_forward_only
  BEFORE UPDATE OF authority_epoch ON organizations
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_organization_authority_epoch();

COMMIT;

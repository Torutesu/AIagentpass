BEGIN;

-- Grant control_sequence identifies a device bundle revision.  The separate
-- organization authority generation is the epoch that invalidates every
-- previously issued Grant after a narrowing or revocation.  This is a new
-- forward migration so released 0018-0020 checksums remain immutable.
ALTER TABLE agent_session_grants
  ADD COLUMN authority_generation bigint;

UPDATE agent_session_grants grant_record
SET authority_generation = statement.authority_generation
FROM control_bundle_statements statement
WHERE statement.organization_id = grant_record.organization_id
  AND statement.device_id = grant_record.device_id
  AND statement.format_epoch = 2
  AND statement.sequence = grant_record.control_sequence;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM agent_session_grants WHERE authority_generation IS NULL) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session Grant authority generation backfill is incomplete',
      CONSTRAINT = 'agent_session_grants_authority_generation_backfill';
  END IF;
END;
$$;

ALTER TABLE agent_session_grants
  ALTER COLUMN authority_generation SET NOT NULL,
  ADD CONSTRAINT agent_session_grants_authority_generation_positive
    CHECK (authority_generation > 0),
  ADD CONSTRAINT agent_session_grants_authority_generation_fk
    FOREIGN KEY (organization_id, authority_generation)
    REFERENCES control_plane_authority_generations(organization_id, generation);

ALTER TABLE agent_sessions
  ADD COLUMN authority_generation bigint;

UPDATE agent_sessions session_record
SET authority_generation = grant_record.authority_generation
FROM agent_session_grants grant_record
WHERE grant_record.organization_id = session_record.organization_id
  AND grant_record.grant_id = session_record.grant_id;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM agent_sessions WHERE authority_generation IS NULL) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session authority generation backfill is incomplete',
      CONSTRAINT = 'agent_sessions_authority_generation_backfill';
  END IF;
END;
$$;

ALTER TABLE agent_sessions
  ALTER COLUMN authority_generation SET NOT NULL,
  ADD CONSTRAINT agent_sessions_authority_generation_positive
    CHECK (authority_generation > 0),
  ADD CONSTRAINT agent_sessions_authority_generation_fk
    FOREIGN KEY (organization_id, authority_generation)
    REFERENCES control_plane_authority_generations(organization_id, generation);

CREATE FUNCTION agentpass_guard_agent_session_authority_generation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  grant_generation bigint;
BEGIN
  IF TG_TABLE_NAME = 'agent_session_grants' THEN
    IF TG_OP = 'UPDATE' AND NEW.authority_generation <> OLD.authority_generation THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'agent session Grant authority generation is immutable',
        CONSTRAINT = 'agent_session_grants_authority_generation_immutable';
    END IF;
    RETURN NEW;
  END IF;

  SELECT authority_generation INTO grant_generation
  FROM agent_session_grants
  WHERE organization_id = NEW.organization_id AND grant_id = NEW.grant_id
  FOR UPDATE;
  IF grant_generation IS NULL OR NEW.authority_generation <> grant_generation THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session authority generation must match its Grant',
      CONSTRAINT = 'agent_sessions_authority_generation_binding';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.authority_generation <> OLD.authority_generation THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session authority generation is immutable',
      CONSTRAINT = 'agent_sessions_authority_generation_immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER agent_session_grants_authority_generation_immutable
  BEFORE UPDATE ON agent_session_grants
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_agent_session_authority_generation();

CREATE TRIGGER agent_sessions_authority_generation_binding
  BEFORE INSERT OR UPDATE ON agent_sessions
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_agent_session_authority_generation();

COMMIT;

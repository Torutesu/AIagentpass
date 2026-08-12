BEGIN;

-- NOTIFY is delivered only after the surrounding transaction commits. The
-- payload is deliberately limited to public routing metadata; listeners must
-- always re-query authoritative state and never trust this as the refresh.
CREATE FUNCTION agentpass_notify_device_refresh_hint()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_notify('agentpass_refresh_hint_v1', json_build_object(
    'organization_id', NEW.organization_id,
    'device_id', NEW.device_id,
    'desired_generation', NEW.desired_generation
  )::text);
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_refresh_outbox_notify_hint
  AFTER INSERT ON device_refresh_outbox
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_notify_device_refresh_hint();

COMMIT;

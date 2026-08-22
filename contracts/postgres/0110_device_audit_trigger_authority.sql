BEGIN;

-- Device audit head advancement is trigger-owned state.  The online
-- application may insert an event, but must not inherit direct privileges on
-- the head/gap projections.  Run the trigger under the migration owner so
-- FORCE RLS and projection ACLs remain a real authority boundary.
ALTER FUNCTION public.agentpass_record_device_audit_head()
  OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_record_device_audit_head()
  SECURITY DEFINER;
ALTER FUNCTION public.agentpass_record_device_audit_head()
  SET search_path = pg_catalog, public;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_record_device_audit_head()
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;

COMMIT;

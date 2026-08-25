BEGIN;

-- Device audit rows are application-visible evidence, but their organization
-- key is an authorization boundary.  Keep the policies explicit even though
-- the runtime ACLs below are narrower than CRUD: this prevents any future
-- DML grant from turning into a cross-tenant path.
ALTER TABLE public.device_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.device_audit_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_audit_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE public.device_audit_gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_audit_gaps FORCE ROW LEVEL SECURITY;

CREATE POLICY device_audit_events_tenant_select
  ON public.device_audit_events FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_events_tenant_insert
  ON public.device_audit_events FOR INSERT
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_events_tenant_update
  ON public.device_audit_events FOR UPDATE
  USING (organization_id = public.agentpass_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_events_tenant_delete
  ON public.device_audit_events FOR DELETE
  USING (organization_id = public.agentpass_current_organization_id());

CREATE POLICY device_audit_heads_tenant_select
  ON public.device_audit_heads FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_heads_tenant_insert
  ON public.device_audit_heads FOR INSERT
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_heads_tenant_update
  ON public.device_audit_heads FOR UPDATE
  USING (organization_id = public.agentpass_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_heads_tenant_delete
  ON public.device_audit_heads FOR DELETE
  USING (organization_id = public.agentpass_current_organization_id());

CREATE POLICY device_audit_gaps_tenant_select
  ON public.device_audit_gaps FOR SELECT
  USING (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_gaps_tenant_insert
  ON public.device_audit_gaps FOR INSERT
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_gaps_tenant_update
  ON public.device_audit_gaps FOR UPDATE
  USING (organization_id = public.agentpass_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_current_organization_id());
CREATE POLICY device_audit_gaps_tenant_delete
  ON public.device_audit_gaps FOR DELETE
  USING (organization_id = public.agentpass_current_organization_id());

-- The existing append trigger is the only writer for heads and gaps in the
-- online path.  It must retain its state-transition writes after runtime DML
-- is narrowed, but it must not inherit a mutable caller search_path.
ALTER FUNCTION public.agentpass_record_device_audit_head()
  SECURITY DEFINER
  SET search_path = pg_catalog, public;

-- SECURITY DEFINER trigger execution is not an online callable API.
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_record_device_audit_head()
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

-- SECURITY DEFINER execution uses the migration owner and therefore needs an
-- explicit deployment-wide policy under FORCE RLS.  Backup is read-only and
-- intentionally retains complete evidence visibility for restoration.
CREATE POLICY device_audit_events_migrator_authority
  ON public.device_audit_events FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY device_audit_heads_migrator_authority
  ON public.device_audit_heads FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY device_audit_gaps_migrator_authority
  ON public.device_audit_gaps FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY device_audit_events_backup_select
  ON public.device_audit_events FOR SELECT TO agentpass_backup
  USING (true);
CREATE POLICY device_audit_heads_backup_select
  ON public.device_audit_heads FOR SELECT TO agentpass_backup
  USING (true);
CREATE POLICY device_audit_gaps_backup_select
  ON public.device_audit_gaps FOR SELECT TO agentpass_backup
  USING (true);

-- Remove the inherited broad DML path.  The online repository only needs to
-- ingest/read events and read the trigger-maintained head/gap projections.
REVOKE ALL PRIVILEGES ON TABLE
  public.device_audit_events,
  public.device_audit_heads,
  public.device_audit_gaps
FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
GRANT SELECT, INSERT ON TABLE public.device_audit_events TO agentpass_app;
GRANT SELECT ON TABLE public.device_audit_heads, public.device_audit_gaps TO agentpass_app;
GRANT SELECT ON TABLE
  public.device_audit_events,
  public.device_audit_heads,
  public.device_audit_gaps
TO agentpass_backup;

COMMENT ON TABLE public.device_audit_events IS
  'Tenant-isolated device audit evidence; online writes are append-only ingestion.';
COMMENT ON TABLE public.device_audit_heads IS
  'Tenant-isolated trigger-maintained device audit chain heads.';
COMMENT ON TABLE public.device_audit_gaps IS
  'Tenant-isolated trigger-maintained device audit gap evidence.';

COMMIT;

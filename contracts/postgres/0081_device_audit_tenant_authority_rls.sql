BEGIN;

-- 0079 used the caller-settable agentpass.organization_id GUC as the RLS
-- tenant selector.  That is not an authority boundary: an agentpass_app
-- connection can change the value with SET LOCAL or set_config().  Keep the
-- tenant assertion transaction-bound, but make its durable source a
-- SECURITY DEFINER membership check owned by the migration authority.
CREATE TABLE public.platform_device_audit_tenant_context (
  backend_pid integer NOT NULL CHECK (backend_pid > 0),
  transaction_id bigint NOT NULL CHECK (transaction_id > 0),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  member_id uuid REFERENCES public.members(id),
  device_id uuid REFERENCES public.devices(id),
  authorized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (backend_pid, transaction_id),
  CHECK ((member_id IS NOT NULL) <> (device_id IS NOT NULL))
);

CREATE INDEX platform_device_audit_tenant_context_transaction
  ON public.platform_device_audit_tenant_context (transaction_id, backend_pid);

COMMENT ON TABLE public.platform_device_audit_tenant_context IS
  'Transaction-bound device-audit tenant authority; only the SECURITY DEFINER membership assertion may write it.';

CREATE OR REPLACE FUNCTION public.agentpass_authorize_device_audit_tenant(
  p_organization_id uuid,
  p_member_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  current_transaction_id bigint := txid_current();
  existing_context public.platform_device_audit_tenant_context%ROWTYPE;
  asserted_organization_id uuid;
BEGIN
  IF p_organization_id IS NULL OR p_member_id IS NULL THEN
    RETURN NULL;
  END IF;

  -- The membership row is the database-side authority assertion.  The
  -- caller supplies only the identity already authenticated by the service;
  -- this function rechecks that the identity is still an active member of
  -- the requested organization before installing any transaction context.
  SELECT membership.organization_id
    INTO asserted_organization_id
    FROM public.memberships AS membership
   WHERE membership.organization_id = p_organization_id
     AND membership.member_id = p_member_id
     AND membership.status = 'active'
   FOR SHARE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  -- A backend can be reused, so discard only its completed transaction
  -- contexts.  The transaction id remains the authority key; a caller-set
  -- GUC cannot manufacture a matching row in this migration-owned table.
  DELETE FROM public.platform_device_audit_tenant_context
   WHERE backend_pid = pg_backend_pid()
     AND transaction_id <> current_transaction_id;

  SELECT context.*
    INTO existing_context
    FROM public.platform_device_audit_tenant_context AS context
   WHERE context.backend_pid = pg_backend_pid()
     AND context.transaction_id = current_transaction_id
   FOR UPDATE;
  IF FOUND THEN
    IF existing_context.organization_id IS DISTINCT FROM asserted_organization_id
       OR existing_context.member_id IS DISTINCT FROM p_member_id
       OR existing_context.device_id IS NOT NULL
    THEN
      RETURN NULL;
    END IF;
    RETURN asserted_organization_id;
  END IF;

  INSERT INTO public.platform_device_audit_tenant_context (
    backend_pid, transaction_id, organization_id, member_id
  ) VALUES (
    pg_backend_pid(), current_transaction_id, asserted_organization_id, p_member_id, NULL
  );
  RETURN asserted_organization_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.agentpass_authorize_device_audit_device(
  p_organization_id uuid,
  p_device_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  current_transaction_id bigint := txid_current();
  existing_context public.platform_device_audit_tenant_context%ROWTYPE;
  asserted_organization_id uuid;
BEGIN
  SELECT devices.organization_id INTO asserted_organization_id
    FROM public.devices AS devices
   WHERE devices.organization_id = p_organization_id
     AND devices.id = p_device_id
     AND devices.status = 'active'
   FOR SHARE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT context.* INTO existing_context
    FROM public.platform_device_audit_tenant_context AS context
   WHERE context.backend_pid = pg_backend_pid() AND context.transaction_id = current_transaction_id
   FOR UPDATE;
  IF FOUND THEN
    IF existing_context.organization_id IS DISTINCT FROM asserted_organization_id
       OR existing_context.device_id IS DISTINCT FROM p_device_id
       OR existing_context.member_id IS NOT NULL THEN RETURN NULL; END IF;
    RETURN asserted_organization_id;
  END IF;
  INSERT INTO public.platform_device_audit_tenant_context (backend_pid, transaction_id, organization_id, member_id, device_id)
  VALUES (pg_backend_pid(), current_transaction_id, asserted_organization_id, NULL, p_device_id);
  RETURN asserted_organization_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.agentpass_device_audit_current_organization_id()
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  current_organization_id uuid;
  current_transaction_id bigint := txid_current_if_assigned();
BEGIN
  IF current_transaction_id IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT context.organization_id
    INTO current_organization_id
    FROM public.platform_device_audit_tenant_context AS context
   WHERE context.backend_pid = pg_backend_pid()
     AND context.transaction_id = current_transaction_id;
  RETURN current_organization_id;
END;
$$;

ALTER TABLE public.platform_device_audit_tenant_context OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_authorize_device_audit_tenant(uuid, uuid) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_authorize_device_audit_device(uuid, uuid) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_device_audit_current_organization_id() OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON TABLE public.platform_device_audit_tenant_context
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT ALL PRIVILEGES ON TABLE public.platform_device_audit_tenant_context TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_authorize_device_audit_tenant(uuid, uuid)
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_authorize_device_audit_device(uuid, uuid)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_device_audit_current_organization_id()
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_authorize_device_audit_tenant(uuid, uuid) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_authorize_device_audit_device(uuid, uuid) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_device_audit_current_organization_id()
  TO agentpass_app, agentpass_backup, agentpass_migrator;

DROP POLICY device_audit_events_tenant_select ON public.device_audit_events;
DROP POLICY device_audit_events_tenant_insert ON public.device_audit_events;
DROP POLICY device_audit_events_tenant_update ON public.device_audit_events;
DROP POLICY device_audit_events_tenant_delete ON public.device_audit_events;
DROP POLICY device_audit_heads_tenant_select ON public.device_audit_heads;
DROP POLICY device_audit_heads_tenant_insert ON public.device_audit_heads;
DROP POLICY device_audit_heads_tenant_update ON public.device_audit_heads;
DROP POLICY device_audit_heads_tenant_delete ON public.device_audit_heads;
DROP POLICY device_audit_gaps_tenant_select ON public.device_audit_gaps;
DROP POLICY device_audit_gaps_tenant_insert ON public.device_audit_gaps;
DROP POLICY device_audit_gaps_tenant_update ON public.device_audit_gaps;
DROP POLICY device_audit_gaps_tenant_delete ON public.device_audit_gaps;

CREATE POLICY device_audit_events_tenant_select
  ON public.device_audit_events FOR SELECT
  USING (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_events_tenant_insert
  ON public.device_audit_events FOR INSERT
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_events_tenant_update
  ON public.device_audit_events FOR UPDATE
  USING (organization_id = public.agentpass_device_audit_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_events_tenant_delete
  ON public.device_audit_events FOR DELETE
  USING (organization_id = public.agentpass_device_audit_current_organization_id());

CREATE POLICY device_audit_heads_tenant_select
  ON public.device_audit_heads FOR SELECT
  USING (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_heads_tenant_insert
  ON public.device_audit_heads FOR INSERT
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_heads_tenant_update
  ON public.device_audit_heads FOR UPDATE
  USING (organization_id = public.agentpass_device_audit_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_heads_tenant_delete
  ON public.device_audit_heads FOR DELETE
  USING (organization_id = public.agentpass_device_audit_current_organization_id());

CREATE POLICY device_audit_gaps_tenant_select
  ON public.device_audit_gaps FOR SELECT
  USING (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_gaps_tenant_insert
  ON public.device_audit_gaps FOR INSERT
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_gaps_tenant_update
  ON public.device_audit_gaps FOR UPDATE
  USING (organization_id = public.agentpass_device_audit_current_organization_id())
  WITH CHECK (organization_id = public.agentpass_device_audit_current_organization_id());
CREATE POLICY device_audit_gaps_tenant_delete
  ON public.device_audit_gaps FOR DELETE
  USING (organization_id = public.agentpass_device_audit_current_organization_id());

COMMENT ON FUNCTION public.agentpass_authorize_device_audit_tenant(uuid, uuid) IS
  'Installs one transaction-bound device-audit tenant only after rechecking active database membership; caller-settable tenant GUCs are ignored.';
COMMENT ON FUNCTION public.agentpass_device_audit_current_organization_id() IS
  'Returns only the organization authorized by the current transaction-bound SECURITY DEFINER membership assertion.';

COMMIT;

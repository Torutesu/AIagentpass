BEGIN;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_reserve_app(
  p_organization_id uuid, p_owner_member_id uuid, p_slug text, p_name text, p_project_binding_digest bytea
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_id uuid;
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id OR p_slug IS NULL OR p_slug !~ '^[a-z0-9][a-z0-9-]{0,62}$' THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='small software tenant or app input is invalid'; END IF;
  PERFORM 1 FROM public.memberships m WHERE m.organization_id=p_organization_id AND m.member_id=p_owner_member_id AND m.status='active' AND m.role IN ('owner','admin');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='small software app reservation is not allowed'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:small-software:app:'||p_organization_id::text,0));
  INSERT INTO public.small_software_apps(organization_id,owner_member_id,slug,name,project_binding_digest) VALUES(p_organization_id,p_owner_member_id,p_slug,p_name,p_project_binding_digest) RETURNING id INTO v_id;
  RETURN v_id;
END; $$;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_reserve_release(
  p_organization_id uuid, p_app_id uuid, p_member_id uuid, p_source_digest bytea, p_build_digest bytea, p_artifact_digest bytea
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_id uuid;
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='small software tenant is invalid'; END IF;
  PERFORM 1 FROM public.memberships m WHERE m.organization_id=p_organization_id AND m.member_id=p_member_id AND m.status='active' AND m.role IN ('owner','admin');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='release reservation is not allowed'; END IF;
  PERFORM 1 FROM public.small_software_apps a WHERE a.organization_id=p_organization_id AND a.id=p_app_id AND a.lifecycle_state NOT IN ('deleted','deleting');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='foreign_key_violation', MESSAGE='app was not found'; END IF;
  INSERT INTO public.small_software_releases(organization_id,app_id,requested_by_member_id,source_digest,build_digest,artifact_digest,state) VALUES(p_organization_id,p_app_id,p_member_id,p_source_digest,p_build_digest,p_artifact_digest,'requested') RETURNING id INTO v_id;
  RETURN v_id;
END; $$;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_reserve_provider_operation(
  p_organization_id uuid,p_app_id uuid,p_release_id uuid,p_operation_kind text,p_operation_key text,p_request_digest bytea,p_provider text
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_id uuid;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:small-software:operation:'||p_organization_id::text||':'||p_operation_key,0));
  SELECT id INTO v_id FROM public.small_software_provider_operations WHERE organization_id=p_organization_id AND operation_key=p_operation_key AND request_digest=p_request_digest;
  IF v_id IS NOT NULL THEN RETURN v_id; END IF;
  IF EXISTS (SELECT 1 FROM public.small_software_provider_operations WHERE organization_id=p_organization_id AND operation_key=p_operation_key) THEN RAISE EXCEPTION USING ERRCODE='unique_violation', MESSAGE='provider operation key is bound to different bytes'; END IF;
  INSERT INTO public.small_software_provider_operations(organization_id,app_id,release_id,operation_kind,operation_key,request_digest,provider) VALUES(p_organization_id,p_app_id,p_release_id,p_operation_kind,p_operation_key,p_request_digest,p_provider) RETURNING id INTO v_id;
  RETURN v_id;
END; $$;
ALTER FUNCTION public.agentpass_small_software_reserve_app(uuid,uuid,text,text,bytea) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_small_software_reserve_release(uuid,uuid,uuid,bytea,bytea,bytea) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_small_software_reserve_provider_operation(uuid,uuid,uuid,text,text,bytea,text) OWNER TO agentpass_migrator;
REVOKE ALL ON FUNCTION public.agentpass_small_software_reserve_app(uuid,uuid,text,text,bytea), public.agentpass_small_software_reserve_release(uuid,uuid,uuid,bytea,bytea,bytea), public.agentpass_small_software_reserve_provider_operation(uuid,uuid,uuid,text,text,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.agentpass_small_software_reserve_app(uuid,uuid,text,text,bytea), public.agentpass_small_software_reserve_release(uuid,uuid,uuid,bytea,bytea,bytea), public.agentpass_small_software_reserve_provider_operation(uuid,uuid,uuid,text,text,bytea,text) TO agentpass_app;
COMMIT;

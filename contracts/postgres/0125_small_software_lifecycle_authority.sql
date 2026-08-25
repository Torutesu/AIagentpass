BEGIN;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_activate_route(p_organization_id uuid,p_app_id uuid,p_release_id uuid,p_deployment_id uuid,p_expected_generation bigint) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_generation bigint; v_state text;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:small-software:route:'||p_organization_id::text||':'||p_app_id::text,0));
 SELECT state INTO v_state FROM public.small_software_deployments WHERE organization_id=p_organization_id AND id=p_deployment_id AND app_id=p_app_id AND release_id=p_release_id;
 IF v_state IS DISTINCT FROM 'reconciled' THEN RAISE EXCEPTION USING ERRCODE='check_violation',MESSAGE='deployment is not reconciled'; END IF;
 INSERT INTO public.small_software_routes(organization_id,app_id,release_id,route,active_generation,state,deployment_id,activated_at) VALUES(p_organization_id,p_app_id,p_release_id,'app-'||p_app_id::text,1,'active',p_deployment_id,clock_timestamp()) ON CONFLICT (organization_id,app_id) DO UPDATE SET release_id=EXCLUDED.release_id,deployment_id=EXCLUDED.deployment_id,active_generation=public.small_software_routes.active_generation+1,state='active',activated_at=clock_timestamp(),updated_at=clock_timestamp() WHERE public.small_software_routes.active_generation=p_expected_generation RETURNING active_generation INTO v_generation;
 IF v_generation IS NULL THEN RAISE EXCEPTION USING ERRCODE='serialization_failure',MESSAGE='route generation is stale'; END IF;
 UPDATE public.small_software_apps SET lifecycle_state='active',updated_at=clock_timestamp() WHERE organization_id=p_organization_id AND id=p_app_id;
 UPDATE public.small_software_releases SET state='active',activated_at=clock_timestamp() WHERE organization_id=p_organization_id AND id=p_release_id;
 RETURN v_generation;
END; $$;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_suspend(p_organization_id uuid,p_app_id uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 UPDATE public.small_software_apps SET lifecycle_state='suspended',updated_at=clock_timestamp() WHERE organization_id=p_organization_id AND id=p_app_id AND lifecycle_state <> 'deleted';
 UPDATE public.small_software_routes SET state='suspended',updated_at=clock_timestamp() WHERE organization_id=p_organization_id AND app_id=p_app_id;
 RETURN FOUND;
END; $$;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_expire(p_organization_id uuid,p_app_id uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN RETURN public.agentpass_small_software_suspend(p_organization_id,p_app_id); END; $$;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_rollback(p_organization_id uuid,p_app_id uuid,p_release_id uuid,p_expected_generation bigint) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_deployment uuid;
BEGIN SELECT deployment_id INTO v_deployment FROM public.small_software_deployments WHERE organization_id=p_organization_id AND app_id=p_app_id AND release_id=p_release_id AND state='reconciled' ORDER BY reconciled_at DESC LIMIT 1; IF v_deployment IS NULL THEN RAISE EXCEPTION USING ERRCODE='foreign_key_violation',MESSAGE='approved reconciled deployment was not found'; END IF; RETURN public.agentpass_small_software_activate_route(p_organization_id,p_app_id,p_release_id,v_deployment,p_expected_generation); END; $$;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_delete_reservation(p_organization_id uuid,p_app_id uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN UPDATE public.small_software_apps SET lifecycle_state='deleting',updated_at=clock_timestamp() WHERE organization_id=p_organization_id AND id=p_app_id AND lifecycle_state NOT IN ('deleted','deleting'); UPDATE public.small_software_routes SET state='deleted',updated_at=clock_timestamp() WHERE organization_id=p_organization_id AND app_id=p_app_id; RETURN FOUND; END; $$;
ALTER FUNCTION public.agentpass_small_software_activate_route(uuid,uuid,uuid,uuid,bigint) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_small_software_suspend(uuid,uuid) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_small_software_expire(uuid,uuid) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_small_software_rollback(uuid,uuid,uuid,bigint) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_small_software_delete_reservation(uuid,uuid) OWNER TO agentpass_migrator;
REVOKE ALL ON FUNCTION public.agentpass_small_software_activate_route(uuid,uuid,uuid,uuid,bigint),public.agentpass_small_software_suspend(uuid,uuid),public.agentpass_small_software_expire(uuid,uuid),public.agentpass_small_software_rollback(uuid,uuid,uuid,bigint),public.agentpass_small_software_delete_reservation(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.agentpass_small_software_activate_route(uuid,uuid,uuid,uuid,bigint),public.agentpass_small_software_suspend(uuid,uuid),public.agentpass_small_software_expire(uuid,uuid),public.agentpass_small_software_rollback(uuid,uuid,uuid,bigint),public.agentpass_small_software_delete_reservation(uuid,uuid) TO agentpass_app;
COMMIT;

BEGIN;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_approve(
 p_organization_id uuid,p_release_id uuid,p_plan_id uuid,p_plan_digest bytea,p_artifact_digest bytea,p_approver_member_id uuid,p_session_operation_id uuid,p_assertion_digest bytea
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_id uuid; v_plan public.small_software_publish_plans%ROWTYPE; v_release public.small_software_releases%ROWTYPE;
BEGIN
 IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege',MESSAGE='approval tenant is invalid'; END IF;
 SELECT * INTO v_plan FROM public.small_software_publish_plans WHERE organization_id=p_organization_id AND id=p_plan_id FOR UPDATE;
 SELECT * INTO v_release FROM public.small_software_releases WHERE organization_id=p_organization_id AND id=p_release_id FOR UPDATE;
 IF NOT FOUND OR v_plan.release_id IS DISTINCT FROM p_release_id OR v_plan.plan_digest IS DISTINCT FROM p_plan_digest OR v_release.artifact_digest IS DISTINCT FROM p_artifact_digest THEN RAISE EXCEPTION USING ERRCODE='check_violation',MESSAGE='approval binding does not match exact plan and artifact'; END IF;
 PERFORM 1 FROM public.memberships WHERE organization_id=p_organization_id AND member_id=p_approver_member_id AND status='active' AND role IN ('owner','admin');
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege',MESSAGE='approval is not allowed'; END IF;
 INSERT INTO public.small_software_approvals(organization_id,app_id,release_id,plan_id,plan_digest,artifact_digest,approver_member_id,session_operation_id,assertion_digest) VALUES(p_organization_id,v_release.app_id,p_release_id,p_plan_id,p_plan_digest,p_artifact_digest,p_approver_member_id,p_session_operation_id,p_assertion_digest) ON CONFLICT (organization_id,release_id,plan_digest) DO UPDATE SET state='approved' RETURNING id INTO v_id;
 UPDATE public.small_software_releases SET plan_digest=p_plan_digest,state='approved',approved_at=clock_timestamp() WHERE organization_id=p_organization_id AND id=p_release_id AND state IN ('awaiting_approval','preview_ready');
 RETURN v_id;
END; $$;
CREATE OR REPLACE FUNCTION public.agentpass_small_software_reconcile_deployment(p_organization_id uuid,p_deployment_id uuid,p_state text,p_provider_deployment_id text,p_receipt_json jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF p_state NOT IN ('reconciled','failed','unknown') THEN RAISE EXCEPTION USING ERRCODE='invalid_parameter_value',MESSAGE='deployment state is invalid'; END IF;
 UPDATE public.small_software_deployments SET state=p_state,provider_deployment_id=COALESCE(provider_deployment_id,p_provider_deployment_id),receipt_json=CASE WHEN p_state='reconciled' THEN p_receipt_json ELSE receipt_json END,reconciled_at=CASE WHEN p_state='reconciled' THEN clock_timestamp() ELSE reconciled_at END WHERE organization_id=p_organization_id AND id=p_deployment_id;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='foreign_key_violation',MESSAGE='deployment was not found'; END IF;
 RETURN true;
END; $$;
ALTER FUNCTION public.agentpass_small_software_approve(uuid,uuid,uuid,bytea,bytea,uuid,uuid,bytea) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_small_software_reconcile_deployment(uuid,uuid,text,text,jsonb) OWNER TO agentpass_migrator;
REVOKE ALL ON FUNCTION public.agentpass_small_software_approve(uuid,uuid,uuid,bytea,bytea,uuid,uuid,bytea),public.agentpass_small_software_reconcile_deployment(uuid,uuid,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.agentpass_small_software_approve(uuid,uuid,uuid,bytea,bytea,uuid,uuid,bytea),public.agentpass_small_software_reconcile_deployment(uuid,uuid,text,text,jsonb) TO agentpass_app;
COMMIT;

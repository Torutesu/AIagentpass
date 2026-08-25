BEGIN;

-- The application never receives table DML. These JSONB authority functions
-- are the only write path for durable maintenance jobs/results/PR metadata.
CREATE FUNCTION public.agentpass_reserve_maintenance_job(p_input jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog, public AS $$
DECLARE v_job public.maintenance_jobs;
BEGIN
  IF p_input IS NULL OR public.agentpass_current_organization_id() IS DISTINCT FROM (p_input->>'organization_id')::uuid THEN
    RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='maintenance job tenant is invalid';
  END IF;
  INSERT INTO public.maintenance_jobs(job_id, organization_id, provider_id, advisory_id, snapshot_id, policy_generation, status, plan_digest)
  VALUES ((p_input->>'job_id')::uuid, (p_input->>'organization_id')::uuid, (p_input->>'provider_id')::uuid, (p_input->>'advisory_id')::uuid, (p_input->>'snapshot_id')::uuid, (p_input->>'policy_generation')::bigint, 'reserved', decode(p_input->>'plan_digest','hex'))
  ON CONFLICT (job_id) DO UPDATE SET plan_digest=EXCLUDED.plan_digest, updated_at=clock_timestamp()
  WHERE public.maintenance_jobs.organization_id=EXCLUDED.organization_id AND public.maintenance_jobs.plan_digest=EXCLUDED.plan_digest
  RETURNING * INTO v_job;
  IF v_job.job_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='unique_violation', MESSAGE='maintenance job binding differs'; END IF;
  RETURN to_jsonb(v_job);
END $$;

CREATE FUNCTION public.agentpass_get_maintenance_job(p_organization_id uuid, p_job_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
DECLARE v_result jsonb;
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='maintenance job tenant is invalid'; END IF;
  SELECT to_jsonb(j) INTO v_result FROM public.maintenance_jobs j WHERE j.organization_id=p_organization_id AND j.job_id=p_job_id;
  IF v_result IS NULL THEN RAISE EXCEPTION USING ERRCODE='no_data_found', MESSAGE='maintenance job was not found'; END IF;
  RETURN v_result;
END $$;

CREATE FUNCTION public.agentpass_update_maintenance_job(p_organization_id uuid, p_job_id uuid, p_patch jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog, public AS $$
DECLARE v_job public.maintenance_jobs; v_status text;
BEGIN
  IF public.agentpass_current_organization_id() IS DISTINCT FROM p_organization_id OR p_patch IS NULL THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='maintenance job update is invalid'; END IF;
  v_status := p_patch->>'status';
  IF v_status IS NULL OR v_status NOT IN ('reserved','running','completed','cancelled','failed','uncertain') THEN RAISE EXCEPTION USING ERRCODE='invalid_parameter_value', MESSAGE='maintenance job status is invalid'; END IF;
  UPDATE public.maintenance_jobs SET status=v_status, updated_at=clock_timestamp() WHERE organization_id=p_organization_id AND job_id=p_job_id AND status NOT IN ('completed','cancelled','failed');
  SELECT * INTO v_job FROM public.maintenance_jobs WHERE organization_id=p_organization_id AND job_id=p_job_id;
  IF v_job.job_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='no_data_found', MESSAGE='maintenance job was not found'; END IF;
  RETURN to_jsonb(v_job);
END $$;

CREATE FUNCTION public.agentpass_record_maintenance_result(p_input jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog, public AS $$
DECLARE v_result public.maintenance_results; v_org uuid := (p_input->>'organization_id')::uuid; v_job uuid := (p_input->>'job_id')::uuid;
BEGIN
  IF p_input IS NULL OR public.agentpass_current_organization_id() IS DISTINCT FROM v_org OR NOT EXISTS (SELECT 1 FROM public.maintenance_jobs WHERE job_id=v_job AND organization_id=v_org) THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='maintenance result binding is invalid'; END IF;
  INSERT INTO public.maintenance_results(job_id, organization_id, result_commit, result_tree, patch_digest, evidence, status)
  VALUES (v_job, v_org, NULLIF(p_input->>'result_commit',''), NULLIF(p_input->>'result_tree',''), CASE WHEN p_input->>'patch_digest' IS NULL THEN NULL ELSE decode(p_input->>'patch_digest','hex') END, p_input, COALESCE(p_input->>'status','uncertain')) RETURNING * INTO v_result;
  RETURN to_jsonb(v_result);
END $$;

CREATE FUNCTION public.agentpass_record_maintenance_pull_request(p_input jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog, public AS $$
DECLARE v_pr public.maintenance_pull_requests; v_org uuid := (p_input->>'organization_id')::uuid; v_job uuid := (p_input->>'job_id')::uuid;
BEGIN
  IF p_input IS NULL OR public.agentpass_current_organization_id() IS DISTINCT FROM v_org OR NOT EXISTS (SELECT 1 FROM public.maintenance_jobs WHERE job_id=v_job AND organization_id=v_org) OR (p_input->>'external_number')::bigint < 1 THEN RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='maintenance PR binding is invalid'; END IF;
  INSERT INTO public.maintenance_pull_requests(job_id, organization_id, repository_id, external_number, head_commit, base_commit, state)
  VALUES (v_job, v_org, p_input->>'repository_id', (p_input->>'external_number')::bigint, p_input->>'head_commit', p_input->>'base_commit', COALESCE(p_input->>'state','draft'))
  ON CONFLICT (repository_id, external_number) DO UPDATE SET state=EXCLUDED.state
  RETURNING * INTO v_pr;
  RETURN to_jsonb(v_pr);
END $$;

ALTER FUNCTION public.agentpass_reserve_maintenance_job(jsonb) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_get_maintenance_job(uuid,uuid) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_update_maintenance_job(uuid,uuid,jsonb) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_record_maintenance_result(jsonb) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_record_maintenance_pull_request(jsonb) OWNER TO agentpass_migrator;
REVOKE ALL ON FUNCTION public.agentpass_reserve_maintenance_job(jsonb), public.agentpass_get_maintenance_job(uuid,uuid), public.agentpass_update_maintenance_job(uuid,uuid,jsonb), public.agentpass_record_maintenance_result(jsonb), public.agentpass_record_maintenance_pull_request(jsonb) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
GRANT EXECUTE ON FUNCTION public.agentpass_reserve_maintenance_job(jsonb), public.agentpass_get_maintenance_job(uuid,uuid), public.agentpass_update_maintenance_job(uuid,uuid,jsonb), public.agentpass_record_maintenance_result(jsonb), public.agentpass_record_maintenance_pull_request(jsonb) TO agentpass_maintenance;

COMMIT;

BEGIN;

CREATE FUNCTION public.agentpass_record_maintenance_receipt(p_input jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog, public AS $$
DECLARE v_receipt public.maintenance_receipts; v_org uuid := (p_input->>'organization_id')::uuid; v_job uuid := (p_input->>'job_id')::uuid;
BEGIN
  IF p_input IS NULL OR public.agentpass_current_organization_id() IS DISTINCT FROM v_org OR NOT EXISTS (SELECT 1 FROM public.maintenance_jobs WHERE job_id=v_job AND organization_id=v_org) OR p_input->>'receipt_digest' IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='insufficient_privilege', MESSAGE='maintenance receipt binding is invalid';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_object_keys(p_input) AS key WHERE key NOT IN ('schema_version','kind','receipt_id','organization_id','job_id','source_commit','patch_digest','verification_status','created_at','uncertainty','receipt_digest')) THEN RAISE EXCEPTION USING ERRCODE='invalid_parameter_value', MESSAGE='maintenance receipt contains unknown fields'; END IF;
  INSERT INTO public.maintenance_receipts(job_id, organization_id, receipt_digest, receipt)
  VALUES (v_job, v_org, decode(p_input->>'receipt_digest','hex'), jsonb_strip_nulls(jsonb_build_object('schema_version',p_input->'schema_version','kind',p_input->'kind','receipt_id',p_input->'receipt_id','organization_id',p_input->'organization_id','job_id',p_input->'job_id','source_commit',p_input->'source_commit','patch_digest',p_input->'patch_digest','verification_status',p_input->'verification_status','created_at',p_input->'created_at','uncertainty',p_input->'uncertainty')))
  ON CONFLICT (receipt_digest) DO NOTHING
  RETURNING * INTO v_receipt;
  IF v_receipt.receipt_id IS NULL THEN SELECT * INTO v_receipt FROM public.maintenance_receipts WHERE receipt_digest=decode(p_input->>'receipt_digest','hex'); END IF;
  RETURN to_jsonb(v_receipt);
END $$;

ALTER FUNCTION public.agentpass_record_maintenance_receipt(jsonb) OWNER TO agentpass_migrator;
REVOKE ALL ON FUNCTION public.agentpass_record_maintenance_receipt(jsonb) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
GRANT EXECUTE ON FUNCTION public.agentpass_record_maintenance_receipt(jsonb) TO agentpass_maintenance;

COMMIT;

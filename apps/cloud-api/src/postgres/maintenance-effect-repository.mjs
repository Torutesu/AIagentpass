export function createMaintenanceEffectRepository({ db }) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  return Object.freeze({
    reserve: (input) => db.query("SELECT public.agentpass_reserve_maintenance_effect($1,$2,$3,$4,$5) AS effect_id", [input.job_id, input.organization_id, input.effect_kind, input.idempotency_key, input.request_digest]),
    cancel: (id) => db.query("SELECT public.agentpass_cancel_maintenance_effect($1)", [id]),
    complete: (id, digest) => db.query("SELECT public.agentpass_complete_maintenance_effect($1,$2)", [id, digest]),
    reconcile: (id, state, digest = null) => db.query("SELECT public.agentpass_reconcile_maintenance_effect($1,$2,$3)", [id, state, digest])
  });
}

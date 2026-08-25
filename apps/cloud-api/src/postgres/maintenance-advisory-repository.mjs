export function createMaintenanceAdvisoryRepository({ db }) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  return Object.freeze({
    publish: (input) => db.query("SELECT public.agentpass_publish_maintenance_advisory($1,$2,$3,$4,$5,$6) AS advisory_id", [input.advisory, input.payload_digest, input.signature, input.provider_id, input.key_id, input.version]),
    supersede: (oldId, newId) => db.query("SELECT public.agentpass_supersede_maintenance_advisory($1,$2)", [oldId, newId]),
    withdraw: (id, reason) => db.query("SELECT public.agentpass_withdraw_maintenance_advisory($1,$2)", [id, reason])
  });
}

/** Usage index/classification authority adapter; raw source and payloads are out of scope. */
export function createMaintenanceUsageRepository({ db } = {}) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  const call = (name, values) => db.query(`SELECT public.${name}(${values.map((_, index) => `$${index + 1}`).join(",")}) AS result`, values);
  return Object.freeze({
    saveAttestation: (input) => call("agentpass_record_maintenance_usage_attestation", [input]),
    getAttestation: (organizationId, attestationId) => call("agentpass_get_maintenance_usage_attestation", [organizationId, attestationId])
  });
}

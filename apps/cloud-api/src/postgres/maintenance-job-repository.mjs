/** Job lifecycle authority adapter. All state transitions remain database-owned. */
export function createMaintenanceJobRepository({ db } = {}) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  const call = (name, values) => db.query(`SELECT public.${name}(${values.map((_, index) => `$${index + 1}`).join(",")}) AS result`, values);
  return Object.freeze({
    reserveJob: (input) => call("agentpass_reserve_maintenance_job", [input]),
    getJob: (organizationId, jobId) => call("agentpass_get_maintenance_job", [organizationId, jobId]),
    updateJob: (organizationId, jobId, patch) => call("agentpass_update_maintenance_job", [organizationId, jobId, patch])
  });
}

/** Job lifecycle authority adapter. All state transitions remain database-owned. */
export function createMaintenanceJobRepository({ db } = {}) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  const call = async (name, values) => {
    const { rows } = await db.query(`SELECT public.${name}(${values.map((_, index) => `$${index + 1}`).join(",")}) AS result`, values);
    return rows?.[0]?.result ?? null;
  };
  const subject = (value) => {
    if (!value || typeof value !== "object") throw new TypeError("organization_id and job_id are required");
    const organizationId = value.organization_id ?? value.organizationId;
    const jobId = value.job_id ?? value.jobId;
    if (typeof organizationId !== "string" || typeof jobId !== "string") throw new TypeError("organization_id and job_id are required");
    return [organizationId, jobId];
  };
  return Object.freeze({
    reserveJob: (input) => call("agentpass_reserve_maintenance_job", [input]),
    getJob: (value) => call("agentpass_get_maintenance_job", subject(value)),
    updateJob: (value, patch = undefined) => {
      const [organizationId, jobId] = subject(value);
      return call("agentpass_update_maintenance_job", [organizationId, jobId, patch ?? value.patch]);
    }
  });
}

export function createMaintenanceResultRepository({ db } = {}) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  return Object.freeze({
    saveResult: (input) => db.query("SELECT public.agentpass_record_maintenance_result($1) AS result", [input])
  });
}

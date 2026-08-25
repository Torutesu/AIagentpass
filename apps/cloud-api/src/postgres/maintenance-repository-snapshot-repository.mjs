/** Repository snapshot authority adapter. Snapshot bytes stay in the connector. */
export function createMaintenanceRepositorySnapshotRepository({ db } = {}) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  const call = (name, values) => db.query(`SELECT public.${name}(${values.map((_, index) => `$${index + 1}`).join(",")}) AS result`, values);
  return Object.freeze({
    saveInstallation: (input) => call("agentpass_save_maintenance_repository_installation", [input]),
    saveSnapshot: (input) => call("agentpass_capture_maintenance_repository_snapshot", [input]),
    getSnapshot: (organizationId, repositoryId, baseCommit) => call("agentpass_get_maintenance_repository_snapshot", [organizationId, repositoryId, baseCommit])
  });
}

/** Pull request metadata authority; the connector, not the agent, owns tokens. */
export function createMaintenancePullRequestRepository({ db } = {}) {
  if (!db || typeof db.query !== "function") throw new TypeError("db.query is required");
  return Object.freeze({
    savePullRequest: (input) => db.query("SELECT public.agentpass_record_maintenance_pull_request($1) AS result", [input])
  });
}

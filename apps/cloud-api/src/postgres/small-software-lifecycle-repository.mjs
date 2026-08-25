/** Lifecycle mutations remain narrow database authority calls. */
export function createSmallSoftwareLifecycleRepository({ db }) {
  const call = async (name, values) => {
    const { rows } = await db.query(`SELECT public.${name}(${values.map((_, i) => `$${i + 1}`).join(', ')}) AS result`, values);
    return rows[0]?.result ?? null;
  };
  return {
    activateRoute: (input) => call('agentpass_small_software_activate_route', [input.organizationId, input.appId, input.releaseId, input.deploymentId, input.expectedGeneration]),
    suspend: (organizationId, appId) => call('agentpass_small_software_suspend', [organizationId, appId]),
    expire: (organizationId, appId) => call('agentpass_small_software_expire', [organizationId, appId]),
    rollback: (input) => call('agentpass_small_software_rollback', [input.organizationId, input.appId, input.releaseId, input.expectedGeneration]),
    deleteReservation: (organizationId, appId) => call('agentpass_small_software_delete_reservation', [organizationId, appId]),
  };
}

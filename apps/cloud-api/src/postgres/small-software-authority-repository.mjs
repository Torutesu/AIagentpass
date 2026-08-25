/** PostgreSQL authority adapters for Small Software Wave 1.
 * All writes use fixed SECURITY DEFINER entry points; callers never receive
 * table DML capability. The transaction caller must bind tenant context first.
 */
export function createSmallSoftwareAuthorityRepository({ db }) {
  const call = async (name, values) => {
    const { rows } = await db.query(`SELECT public.${name}(${values.map((_, i) => `$${i + 1}`).join(', ')}) AS result`, values);
    return rows[0]?.result ?? null;
  };
  return {
    reserveApp: (input) => call('agentpass_small_software_reserve_app', [input.organizationId, input.ownerMemberId, input.slug, input.name, input.projectBindingDigest]),
    reserveRelease: (input) => call('agentpass_small_software_reserve_release', [input.organizationId, input.appId, input.memberId, input.sourceDigest, input.buildDigest, input.artifactDigest]),
    reserveProviderOperation: (input) => call('agentpass_small_software_reserve_provider_operation', [input.organizationId, input.appId, input.releaseId, input.operationKind, input.operationKey, input.requestDigest, input.provider]),
    approve: (input) => call('agentpass_small_software_approve', [input.organizationId, input.releaseId, input.planId, input.planDigest, input.artifactDigest, input.approverMemberId, input.sessionOperationId, input.assertionDigest]),
    reconcileDeployment: (input) => call('agentpass_small_software_reconcile_deployment', [input.organizationId, input.deploymentId, input.state, input.providerDeploymentId, input.receiptJson]),
  };
}

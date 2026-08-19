import {
  assertAgentLaunchAuthorityHandoffBinding,
  AgentLaunchAuthorityHandoffContractError
} from "../agent-launch-authority-handoff-contract.mjs";

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_INPUT",
  NATIVE_PROOF_UNAVAILABLE: "ERR_NATIVE_AGENT_AUTHORITY_PROOF_UNAVAILABLE"
});

export class AgentLaunchAuthorityHandoffRepositoryError extends Error {
  constructor(code) {
    super(code === AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.INVALID_INPUT
      ? "Agent launch authority handoff input is invalid"
      : "Native Agent launch authority proof is unavailable");
    this.name = "AgentLaunchAuthorityHandoffRepositoryError";
    this.code = code;
  }
}

/**
 * Explicitly fail-closed repository boundary.
 *
 * The existing Cloud authority can issue signed Grants, consume them into
 * Session Leases, and issue one-use signing Capabilities. It cannot mint or
 * independently verify the opaque native bootstrap/session proof carried by
 * NativeAgentLaunchAuthorityHandoff. There is also no migration-owned,
 * atomic one-time handoff record in the current schema. Keeping this adapter
 * present makes the missing contract observable without turning a Grant,
 * Lease, Capability, nonce, or digest into a generic bearer token.
 */
export function createPostgresAgentLaunchAuthorityHandoffRepository() {
  async function issueAgentLaunchAuthorityHandoff(input = {}) {
    try {
      assertAgentLaunchAuthorityHandoffBinding(input);
    } catch (error) {
      if (error instanceof AgentLaunchAuthorityHandoffContractError) {
        throw new AgentLaunchAuthorityHandoffRepositoryError(
          AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.INVALID_INPUT
        );
      }
      throw error;
    }
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE
    );
  }

  return Object.freeze({
    issueAgentLaunchAuthorityHandoff,
    createAgentLaunchAuthorityHandoff: issueAgentLaunchAuthorityHandoff
  });
}

export const createAgentLaunchAuthorityHandoffRepository = createPostgresAgentLaunchAuthorityHandoffRepository;
export default createPostgresAgentLaunchAuthorityHandoffRepository;

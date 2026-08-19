import {
  assertAgentLaunchAuthorityHandoffBinding,
  AgentLaunchAuthorityHandoffContractError,
  normalizeAgentLaunchAuthoritySignedGrant
} from "../agent-launch-authority-handoff-contract.mjs";

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_CONFIG",
  INVALID_INPUT: "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_INPUT",
  RESULT: "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_RESULT",
  REPLAYED: "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_REPLAYED",
  NATIVE_PROOF_UNAVAILABLE: "ERR_NATIVE_AGENT_AUTHORITY_PROOF_UNAVAILABLE"
});

export class AgentLaunchAuthorityHandoffRepositoryError extends Error {
  constructor(code) {
    super(code === AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.CONFIG
      ? "Agent launch authority handoff repository configuration is invalid"
      : code === AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.INVALID_INPUT
        ? "Agent launch authority handoff input is invalid"
        : code === AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.RESULT
          ? "Agent launch authority handoff repository returned an invalid result"
          : code === AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.REPLAYED
            ? "Agent launch authority handoff was already returned"
            : "Native Agent launch authority proof is unavailable");
    this.name = "AgentLaunchAuthorityHandoffRepositoryError";
    this.code = code;
  }
}

/**
 * The optional callback is the production PostgreSQL seam. It must perform
 * the one-time state transition atomically in the same authority boundary as
 * the Session/Lease row and receive only public bindings plus the Grant
 * digest. The default has no such SQL function and remains fail-closed.
 */
export function createPostgresAgentLaunchAuthorityHandoffRepository({ atomicHandoff } = {}) {
  if (atomicHandoff !== undefined && typeof atomicHandoff !== "function") {
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.CONFIG
    );
  }

  async function issueAgentLaunchAuthorityHandoff(input = {}) {
    try {
      assertAgentLaunchAuthorityHandoffBinding(input);
      normalizeAgentLaunchAuthoritySignedGrant(input.grant, { allowExpired: true });
    } catch (error) {
      if (error instanceof AgentLaunchAuthorityHandoffContractError) {
        throw new AgentLaunchAuthorityHandoffRepositoryError(
          AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.INVALID_INPUT
        );
      }
      throw error;
    }
    if (!atomicHandoff) {
      throw new AgentLaunchAuthorityHandoffRepositoryError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE
      );
    }

    let outcome;
    try {
      // Never pass the signed envelope to the persistence seam. The already
      // issued Grant remains transient; only its exact digest is durable.
      outcome = await atomicHandoff(Object.freeze({
        version: input.version,
        type: input.type,
        request_id: input.request_id,
        grant_id: input.grant_id,
        organization_id: input.organization_id,
        device_id: input.device_id,
        agent_id: input.agent_id,
        agent_kind: input.agent_kind,
        adapter_id: input.adapter_id,
        adapter_version: input.adapter_version,
        session_id: input.session_id,
        worktree_binding_sha256: input.worktree_binding_sha256,
        not_before: input.not_before,
        expires_at: input.expires_at,
        control_sequence: input.control_sequence,
        authority_generation: input.authority_generation,
        nonce_sha256: input.nonce_sha256,
        lease_sha256: input.lease_sha256,
        grant_hash: input.grant_hash
      }));
    } catch (error) {
      if (error instanceof AgentLaunchAuthorityHandoffRepositoryError) throw error;
      throw new AgentLaunchAuthorityHandoffRepositoryError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE
      );
    }
    if (!outcome || typeof outcome !== "object" || Array.isArray(outcome)
      || Object.keys(outcome).some((key) => key !== "state")
      || !["issued", "already_returned"].includes(outcome.state)) {
      throw new AgentLaunchAuthorityHandoffRepositoryError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.RESULT
      );
    }
    if (outcome.state === "already_returned") {
      throw new AgentLaunchAuthorityHandoffRepositoryError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.REPLAYED
      );
    }
    return Object.freeze({ state: "issued", grant: input.grant });
  }

  return Object.freeze({
    issueAgentLaunchAuthorityHandoff,
    createAgentLaunchAuthorityHandoff: issueAgentLaunchAuthorityHandoff
  });
}

export const createAgentLaunchAuthorityHandoffRepository = createPostgresAgentLaunchAuthorityHandoffRepository;
export default createPostgresAgentLaunchAuthorityHandoffRepository;

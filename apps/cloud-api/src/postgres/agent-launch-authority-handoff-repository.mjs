import {
  assertAgentLaunchAuthorityHandoffBinding,
  AgentLaunchAuthorityHandoffContractError,
  normalizeAgentLaunchAuthoritySignedGrant
} from "../agent-launch-authority-handoff-contract.mjs";
import { withTransaction } from "./repository.mjs";

/**
 * This function is intentionally a deployment-owned SQL boundary. The
 * SQL/role contract that owns it must atomically validate the current
 * Session/Lease authority and insert the one-time handoff marker. The
 * application adapter never falls back to table DML or an application-side
 * check-then-insert sequence.
 */
export const AGENT_LAUNCH_AUTHORITY_HANDOFF_SQL = `SELECT public.agentpass_agent_launch_authority_handoff(
  $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::text,$7::uuid,$8::text,
  $9::uuid,$10::bytea,$11::timestamptz,$12::timestamptz,$13::bigint,$14::bigint,
  $15::bytea,$16::bytea,$17::bytea
) AS result`;

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_FUNCTION =
  "public.agentpass_agent_launch_authority_handoff";

export const AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_CONFIG",
  INVALID_INPUT: "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_INPUT",
  DATABASE: "ERR_AGENT_LAUNCH_AUTHORITY_HANDOFF_DATABASE",
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
        : code === AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.DATABASE
          ? "Agent launch authority handoff storage is unavailable"
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
 * The default has no SQL adapter and remains fail-closed. A client-backed
 * instance is enabled only by explicit composition and calls the fixed
 * deployment-owned function above inside one checked-out transaction. The
 * callback remains an explicit DI seam for a separately reviewed transaction
 * adapter; it receives the same typed, digest-only projection as SQL.
 */
export function createPostgresAgentLaunchAuthorityHandoffRepository(options = {}) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.CONFIG
    );
  }
  const { client, atomicHandoff, transaction = withTransaction } = options;
  if (client !== undefined && (!client || typeof client.query !== "function")) {
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.CONFIG
    );
  }
  if (atomicHandoff !== undefined && typeof atomicHandoff !== "function") {
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.CONFIG
    );
  }
  if (client !== undefined && atomicHandoff !== undefined) {
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.CONFIG
    );
  }
  if (typeof transaction !== "function") {
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.CONFIG
    );
  }

  const persistence = atomicHandoff ?? (client === undefined ? undefined : createSqlHandoff({ client, transaction }));

  async function issueAgentLaunchAuthorityHandoff(input = {}) {
    const durableInput = normalizeDurableInput(input);
    if (!persistence) {
      throw new AgentLaunchAuthorityHandoffRepositoryError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE
      );
    }

    let outcome;
    try {
      outcome = await persistence(durableInput);
    } catch (error) {
      if (error instanceof AgentLaunchAuthorityHandoffRepositoryError) throw error;
      throw new AgentLaunchAuthorityHandoffRepositoryError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE
      );
    }
    const state = normalizePersistenceOutcome(outcome);
    if (state === "unavailable") {
      throw new AgentLaunchAuthorityHandoffRepositoryError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE
      );
    }
    if (state === "already_returned") {
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

function createSqlHandoff({ client, transaction }) {
  return async function sqlHandoff(input) {
    try {
      const raw = await transaction(client, async (tx) => {
        const configured = await tx.query(
          "SELECT set_config('agentpass.organization_id',$1,true) AS organization_id",
          [input.organization_id]
        );
        if (rowCount(configured) !== 1 || configured.rows?.[0]?.organization_id !== input.organization_id) {
          throw new AgentLaunchAuthorityHandoffRepositoryError(
            AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.DATABASE
          );
        }
        const result = await tx.query(AGENT_LAUNCH_AUTHORITY_HANDOFF_SQL, [
          input.request_id,
          input.grant_id,
          input.organization_id,
          input.device_id,
          input.agent_id,
          input.agent_kind,
          input.adapter_id,
          input.adapter_version,
          input.session_id,
          digestBytes(input.worktree_binding_sha256),
          input.not_before,
          input.expires_at,
          input.control_sequence,
          input.authority_generation,
          digestBytes(input.nonce_sha256),
          digestBytes(input.lease_sha256),
          digestBytes(input.grant_hash)
        ]);
        if (rowCount(result) !== 1 || !Object.hasOwn(result.rows?.[0] ?? {}, "result")) {
          throw new AgentLaunchAuthorityHandoffRepositoryError(
            AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.DATABASE
          );
        }
        return Object.freeze({
          state: normalizePersistenceOutcome(result.rows[0].result, { allowUnavailable: true })
        });
      });
      return raw;
    } catch (error) {
      if (error instanceof AgentLaunchAuthorityHandoffRepositoryError
        && [
          AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.DATABASE,
          AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.RESULT
        ].includes(error.code)) {
        throw error;
      }
      throw new AgentLaunchAuthorityHandoffRepositoryError(
        AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE
      );
    }
  };
}

function normalizeDurableInput(input) {
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
  return Object.freeze({
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
  });
}

function normalizePersistenceOutcome(value, { allowUnavailable = true } = {}) {
  try {
    const outcome = typeof value === "string" ? JSON.parse(value) : value;
    if (!outcome || typeof outcome !== "object" || Array.isArray(outcome)
      || Object.keys(outcome).length !== 1 || typeof outcome.state !== "string") throw new Error("result");
    const states = allowUnavailable
      ? new Set(["issued", "already_returned", "unavailable"])
      : new Set(["issued", "already_returned"]);
    if (!states.has(outcome.state)) throw new Error("state");
    return outcome.state;
  } catch {
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.RESULT
    );
  }
}

function digestBytes(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new AgentLaunchAuthorityHandoffRepositoryError(
      AGENT_LAUNCH_AUTHORITY_HANDOFF_REPOSITORY_ERROR_CODES.INVALID_INPUT
    );
  }
  return Buffer.from(value, "hex");
}

function rowCount(result) {
  const value = Number(result?.rowCount ?? result?.rows?.length ?? 0);
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

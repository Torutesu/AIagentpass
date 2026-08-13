import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createAgentSessionAuthorityRepository } from "./agent-session-authority-repository.mjs";
import { createPostgresCloudAgentAuditRepository } from "./cloud-agent-audit-repository.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";

/** Lease creation and Cloud consume evidence share one caller-owned transaction. */
export function createPostgresAgentSessionConsumptionRepository({ client, authorityRepository, auditRepository, sharedControls } = {}) {
  assertMethod(client, "query");
  const authority = authorityRepository ?? createAgentSessionAuthorityRepository({ client });
  const audit = auditRepository ?? createPostgresCloudAgentAuditRepository();
  const controls = sharedControls ?? createSharedControlRepository({ client });
  assertMethod(authority, "consumeAgentSessionGrantInTransaction");
  assertMethod(audit, "appendAgentSessionGrantConsumedInTransaction");
  assertMethod(controls, "withTransaction");

  async function consumeAgentSessionGrant(input = {}) {
    const grant = input.grant;
    if (!grant || typeof grant !== "object" || Array.isArray(grant) || !grant.statement) throw new TypeError("agent session grant is required");
    return controls.withTransaction(async (tx) => {
      const consumed = await authority.consumeAgentSessionGrantInTransaction({ tx, ...input });
      const lease = consumed?.lease;
      if (!lease || typeof lease !== "object" || Array.isArray(lease)) throw new TypeError("agent session lease is invalid");
      await audit.appendAgentSessionGrantConsumedInTransaction({
        tx,
        organization_id: lease.organization_id,
        grant_id: lease.grant_id,
        session_id: lease.session_id,
        device_id: lease.device_id,
        agent_id: lease.agent_id,
        grant_hash: crypto.createHash("sha256").update(canonicalJson(grant), "utf8").digest("hex"),
        statement_hash: grant.statement_hash,
        signer_key_id: grant.statement.key_id,
        process_binding_sha256: lease.process_binding_sha256,
        ancestry_binding_sha256: lease.ancestry_binding_sha256,
        worktree_binding_sha256: lease.worktree_binding_sha256,
        control_sequence: lease.control_sequence,
        authority_generation: lease.authority_generation
      });
      return consumed;
    });
  }

  return Object.freeze({ consumeAgentSessionGrant, consumeGrant: consumeAgentSessionGrant });
}

function assertMethod(value, method) {
  if (!value || typeof value[method] !== "function") throw new TypeError(`${method}() is required`);
}

export default createPostgresAgentSessionConsumptionRepository;

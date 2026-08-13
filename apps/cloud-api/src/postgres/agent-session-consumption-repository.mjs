import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createAgentSessionAuthorityRepository } from "./agent-session-authority-repository.mjs";
import { createPostgresCloudAgentAuditRepository } from "./cloud-agent-audit-repository.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";

/** Lease creation and Cloud consume evidence share one caller-owned transaction. */
export function createPostgresAgentSessionConsumptionRepository({ client, authorityRepository, auditRepository, sharedControls, metrics } = {}) {
  assertMethod(client, "query");
  const authority = authorityRepository ?? createAgentSessionAuthorityRepository({ client });
  const audit = auditRepository ?? createPostgresCloudAgentAuditRepository();
  const controls = sharedControls ?? createSharedControlRepository({ client });
  assertMethod(authority, "consumeAgentSessionGrantInTransaction");
  assertMethod(audit, "appendAgentSessionGrantConsumedInTransaction");
  assertMethod(controls, "withTransaction");
  assertMetrics(metrics);

  async function consumeAgentSessionGrant(input = {}) {
    let phase = "validation";
    try {
      const grant = input.grant;
      if (!grant || typeof grant !== "object" || Array.isArray(grant) || !grant.statement) throw new TypeError("agent session grant is required");
      phase = "consume";
      const consumed = await controls.withTransaction(async (tx) => {
        const result = await authority.consumeAgentSessionGrantInTransaction({ tx, ...input });
        phase = "audit";
        const lease = result?.lease;
        if (!lease || typeof lease !== "object" || Array.isArray(lease)) throw new TypeError("agent session lease is invalid");
        const auditEvent = await audit.appendAgentSessionGrantConsumedInTransaction({
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
        phase = "outbox";
        await publishConsumption(tx, lease.organization_id, auditEvent);
        return result;
      });
      recordMetric("recordCloudAuditAppend");
      if (consumed.replayed === true) recordMetric("recordAgentSessionConsumeReplay");
      else recordMetric("recordAgentSessionConsumeSuccess");
      return consumed;
    } catch (error) {
      if (phase !== "validation") recordMetric("recordAgentSessionConsumeRollback");
      if (phase === "audit" || phase === "outbox") recordMetric("recordCloudAuditFailure");
      if (/CONFLICT|BINDING|SESSION_CONFLICT/iu.test(String(error?.code ?? ""))) recordMetric("recordAgentSessionConsumeConflict");
      else if (/STALE|UNAVAILABLE|EXPIRED|NOT_YET_VALID/iu.test(String(error?.code ?? ""))) recordMetric("recordAgentSessionConsumeStale");
      else recordMetric("recordAgentSessionConsumeFailure");
      throw error;
    }
  }

  function recordMetric(method) {
    try { metrics?.[method](); } catch { /* Metrics never alter durable consumption outcomes. */ }
  }

  return Object.freeze({ consumeAgentSessionGrant, consumeGrant: consumeAgentSessionGrant });
}

async function publishConsumption(tx, organizationId, event) {
  if (!event || typeof event !== "object" || typeof event.event_id !== "string" || typeof event.event_hash !== "string") {
    throw new TypeError("cloud consume audit event is invalid");
  }
  const id = deterministicUuid(event.event_id);
  const payload = Object.freeze({
    version: 1,
    audit_event_id: event.event_id,
    audit_event_hash: event.event_hash,
    grant_id: event.grant_id,
    session_id: event.session_id,
    device_id: event.device_id,
    agent_id: event.agent_id,
    grant_hash: event.grant_hash,
    statement_hash: event.statement_hash,
    consumed_at: event.consumed_at
  });
  const inserted = await tx.query(`INSERT INTO outbox_events
    (organization_id,id,aggregate,action,payload,status)
    VALUES ($1,$2,'agent-session-grant','agent_session_grant.consumed',$3::jsonb,'pending')
    ON CONFLICT (organization_id,id) DO NOTHING
    RETURNING id`, [organizationId, id, JSON.stringify(payload)]);
  if (Number(inserted?.rowCount ?? inserted?.rows?.length ?? 0) === 1 && inserted.rows[0]?.id === id) return;
  const existing = await tx.query(`SELECT id,aggregate,action,payload,status
    FROM outbox_events WHERE organization_id=$1 AND id=$2 FOR SHARE`, [organizationId, id]);
  if (Number(existing?.rowCount ?? existing?.rows?.length ?? 0) !== 1
    || existing.rows[0]?.id !== id
    || existing.rows[0]?.aggregate !== "agent-session-grant"
    || existing.rows[0]?.action !== "agent_session_grant.consumed"
    || !["pending", "published"].includes(existing.rows[0]?.status)
    || canonicalJson(existing.rows[0]?.payload) !== canonicalJson(payload)) {
    throw new TypeError("cloud consume publication is unavailable");
  }
}

function deterministicUuid(eventId) {
  const bytes = crypto.createHash("sha256")
    .update("AgentPass-Agent-Session-Consume-Outbox-v1\0")
    .update(eventId, "utf8").digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function assertMethod(value, method) {
  if (!value || typeof value[method] !== "function") throw new TypeError(`${method}() is required`);
}

function assertMetrics(metrics) {
  if (metrics === undefined) return;
  for (const method of ["recordAgentSessionConsumeSuccess", "recordAgentSessionConsumeReplay", "recordAgentSessionConsumeConflict", "recordAgentSessionConsumeStale", "recordAgentSessionConsumeFailure", "recordAgentSessionConsumeRollback", "recordCloudAuditAppend", "recordCloudAuditFailure"]) assertMethod(metrics, method);
}

export default createPostgresAgentSessionConsumptionRepository;

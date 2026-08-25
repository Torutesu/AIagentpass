import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const MUTATION_KEY = /^[A-Za-z0-9._~-]{8,240}$/u;
const SOURCE = new Set(["admin_api", "organization_api", "management_api", "system"]);
const SAFE_TEXT = /^[^\u0000-\u001f\u007f]+$/u;

const EVENT_RULES = Object.freeze({
  "member.role_reduced": Object.freeze({ targetType: "member", metadata: Object.freeze(["previous_role", "new_role"]) }),
  "member.removed": Object.freeze({ targetType: "member", metadata: Object.freeze([]) }),
  "policy.scope_reduced": Object.freeze({ targetType: "policy", metadata: Object.freeze(["policy_version"]) }),
  "policy.disabled": Object.freeze({ targetType: "policy", metadata: Object.freeze(["policy_version"]) }),
  "capability.revoked": Object.freeze({ targetType: "member", metadata: Object.freeze(["revoked_count", "generation"]) }),
  "credential.revoked": Object.freeze({ targetType: "member", metadata: Object.freeze(["generation"]) }),
  "session.revoked": Object.freeze({ targetType: "member", metadata: Object.freeze(["generation"]) }),
  "device.revoked": Object.freeze({ targetType: "device", metadata: Object.freeze([]) })
});

export class AuthorityReductionAuditError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "AuthorityReductionAuditError";
    this.code = code;
  }
}

/**
 * Build the only audit append path used by an authority-reducing mutation.
 * This adapter deliberately has no database client: the caller owns the
 * transaction and the underlying repository must use that exact `tx`.
 */
export function createAuthorityReductionAuditAppender({ adminAuditRepository } = {}) {
  if (!adminAuditRepository || typeof adminAuditRepository.appendAdminAuditEventInTransaction !== "function") {
    throw new TypeError("adminAuditRepository must provide appendAdminAuditEventInTransaction");
  }

  async function appendAuthorityReductionAudit(input = {}) {
    const values = normalizeInput(input);
    let result;
    try {
      result = await adminAuditRepository.appendAdminAuditEventInTransaction({
        tx: values.tx,
        organizationId: values.organizationId,
        actorId: values.actor.member_id,
        eventType: values.eventType,
        targetType: values.resource.type,
        targetId: values.resource.id,
        details: values.details,
        idempotencyKey: `${values.mutationKey}:audit`
      });
    } catch (error) {
      if (error instanceof AuthorityReductionAuditError) throw error;
      throw new AuthorityReductionAuditError("ERR_AUTHORITY_REDUCTION_AUDIT_UNAVAILABLE", "authority reduction audit is unavailable", error);
    }
    assertStoredResult(result, values);
    return result;
  }

  return Object.freeze({ appendAuthorityReductionAudit });
}

export const AUTHORITY_REDUCTION_AUDIT_EVENTS = EVENT_RULES;

function normalizeInput(input) {
  const tx = input?.tx;
  if (!tx || typeof tx.query !== "function") throw inputError("caller-owned transaction is required");
  const organizationId = uuid(input.organizationId ?? input.organization_id, "organization_id");
  const actor = normalizeActor(input.actor);
  const resource = normalizeResource(input.resource);
  const eventType = text(input.eventType ?? input.event_type, "event_type", 64);
  const rule = EVENT_RULES[eventType];
  if (!rule || rule.targetType !== resource.type) throw inputError("authority reduction event is not allow-listed");
  const mutationKey = input.mutationKey ?? input.mutation_key ?? input.idempotencyKey ?? input.idempotency_key;
  if (typeof mutationKey !== "string" || !MUTATION_KEY.test(mutationKey)) throw inputError("mutation key is invalid");
  const occurredAt = timestamp(input.occurredAt ?? input.occurred_at, "occurred_at");
  const metadata = normalizeMetadata(input.metadata, rule.metadata);
  const details = Object.freeze({
    occurred_at: occurredAt,
    reason: boundedText(input.reason, "reason", 256),
    source: enumValue(input.source, SOURCE, "source"),
    ...metadata
  });
  return Object.freeze({ tx, organizationId, actor, resource, eventType, mutationKey, details });
}

function normalizeActor(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw inputError("actor metadata is required");
  const memberId = uuid(value.memberId ?? value.member_id, "actor.member_id");
  if (Object.keys(value).some((key) => !["memberId", "member_id"].includes(key))) throw inputError("actor metadata is invalid");
  return Object.freeze({ member_id: memberId });
}

function normalizeResource(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw inputError("resource metadata is required");
  const type = text(value.type, "resource.type", 32);
  const id = uuid(value.id, "resource.id");
  return Object.freeze({ type, id });
}

function normalizeMetadata(value, allowed) {
  if (value === undefined) return Object.freeze({});
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw inputError("metadata must be a plain object");
  const allowedSet = new Set(allowed);
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    if (!allowedSet.has(key)) throw inputError("metadata field is not allow-listed");
    if (key.endsWith("role")) output[key] = enumValue(item, new Set(["owner", "admin", "auditor", "viewer"]), key);
    else if (["policy_version", "revoked_count", "generation"].includes(key)) output[key] = positiveInteger(item, key);
    else throw inputError("metadata field is invalid");
  }
  for (const key of allowed) if (key === "previous_role" || key === "new_role") {
    if (!(key in output)) throw inputError(`${key} is required`);
  }
  return Object.freeze(output);
}

function assertStoredResult(result, values) {
  if (!result || typeof result !== "object" || Array.isArray(result)
    || result.organization_id !== values.organizationId
    || result.actor_id !== values.actor.member_id
    || result.event_type !== values.eventType
    || result.target_type !== values.resource.type
    || result.target_id !== values.resource.id
    || !UUID.test(result.audit_event_id)
    || !/^[0-9a-f]{64}$/u.test(result.event_hash)
    || typeof result.recorded_at !== "string") {
    throw new AuthorityReductionAuditError("ERR_AUTHORITY_REDUCTION_AUDIT_INVALID", "authority reduction audit response is invalid");
  }
}

function text(value, label, max) {
  if (typeof value !== "string" || value.length < 1 || !SAFE_TEXT.test(value) || Buffer.byteLength(value, "utf8") > max) throw inputError(`${label} is invalid`);
  return value;
}
function boundedText(value, label, max) { return text(value, label, max); }
function uuid(value, label) { if (typeof value !== "string" || !UUID.test(value)) throw inputError(`${label} is invalid`); return value.toLowerCase(); }
function enumValue(value, values, label) { if (typeof value !== "string" || !values.has(value)) throw inputError(`${label} is invalid`); return value; }
function positiveInteger(value, label) { const number = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(number) || number < 1) throw inputError(`${label} is invalid`); return number; }
function timestamp(value, label) { const date = new Date(value); if (value === undefined || Number.isNaN(date.getTime())) throw inputError(`${label} is invalid`); return date.toISOString(); }
function inputError(message) { return new AuthorityReductionAuditError("ERR_AUTHORITY_REDUCTION_AUDIT_INPUT", message); }

// Keep the event identity visible to callers that need to precompute a stable
// mutation record, without accepting caller-controlled UUIDs.
export function authorityReductionAuditIdentity({ organizationId, actorId, eventType, resourceType, resourceId, mutationKey } = {}) {
  return crypto.createHash("sha256").update(canonicalJson({ organizationId, actorId, eventType, resourceType, resourceId, mutationKey })).digest("hex");
}

export default createAuthorityReductionAuditAppender;

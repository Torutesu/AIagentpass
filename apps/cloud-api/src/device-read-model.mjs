const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u;
const REFRESH_STATES = new Set(["pending", "fetching", "applied", "blocked", "stale", "offline", "revoked"]);
const DEVICE_STATUSES = new Set(["active", "revoked", "pending"]);
const BLOCKED_REASONS = new Set([
  "bundle_expired", "bundle_not_yet_valid", "bundle_signature_invalid", "bundle_signer_untrusted",
  "bundle_audience_mismatch", "bundle_sequence_rollback", "bundle_sequence_conflict", "bundle_storage_failed",
  "device_revoked", "emergency_stop", "internal_error"
]);
const READ_MODEL_KEYS = new Set([
  "device_id", "organization_id", "name", "device_public_key", "key_algorithm", "status", "metadata", "created_at", "last_seen_at", "version",
  "desired_generation", "observed_generation", "refresh_state", "current_bundle_sequence", "current_bundle_expires_at",
  "last_ack_observed_at", "last_ack_received_at", "bundle_sequence", "bundle_expires_at", "last_ack_at", "blocked_reason"
]);

export const DEVICE_READ_MODEL_REFRESH_STATES = Object.freeze([...REFRESH_STATES]);
export const DEVICE_READ_MODEL_BLOCKED_REASONS = Object.freeze([...BLOCKED_REASONS]);

export class DeviceReadModelError extends Error {
  constructor(message) {
    super(message);
    this.name = "DeviceReadModelError";
    this.code = "ERR_DEVICE_READ_MODEL";
  }
}

/**
 * Normalize the single public Console device DTO. The input is intentionally
 * closed: a new SQL column cannot become a Console field without an explicit
 * review of its sensitivity and contract.
 */
export function normalizeDeviceReadModel(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new DeviceReadModelError("device read model must be an object");
  const unknown = Object.keys(value).filter((key) => !READ_MODEL_KEYS.has(key));
  if (unknown.length > 0) throw new DeviceReadModelError("device read model contains unknown fields");
  if (value.organization_id !== undefined) uuid(value.organization_id, "organization_id");
  const deviceId = uuid(value.device_id, "device_id");
  const name = text(value.name, "name", 128);
  const status = enumValue(value.status, DEVICE_STATUSES, "status");
  const metadata = value.metadata;
  if (metadata !== undefined && (!metadata || typeof metadata !== "object" || Array.isArray(metadata))) throw new DeviceReadModelError("device metadata is invalid");
  if (value.device_public_key !== undefined) publicKey(value.device_public_key);
  if (value.key_algorithm !== undefined) text(value.key_algorithm, "key_algorithm", 32);
  const bundleSequence = exclusiveAlias(value.current_bundle_sequence, value.bundle_sequence, "bundle_sequence");
  const bundleExpiresAt = exclusiveAlias(value.current_bundle_expires_at, value.bundle_expires_at, "bundle_expires_at");
  const internalAck = value.last_ack_received_at ?? value.last_ack_observed_at;
  const lastAckAt = exclusiveAlias(internalAck, value.last_ack_at, "last_ack_at");
  const result = {
    device_id: deviceId,
    name,
    status,
    created_at: timestamp(value.created_at, "created_at"),
    last_seen_at: nullableTimestamp(value.last_seen_at, "last_seen_at"),
    version: safeInteger(value.version, "version"),
    desired_generation: nullablePositiveInteger(value.desired_generation, "desired_generation"),
    observed_generation: nullablePositiveInteger(value.observed_generation, "observed_generation"),
    refresh_state: enumValue(value.refresh_state, REFRESH_STATES, "refresh_state"),
    bundle_sequence: nullablePositiveInteger(bundleSequence, "bundle_sequence"),
    bundle_expires_at: nullableTimestamp(bundleExpiresAt, "bundle_expires_at"),
    last_ack_at: nullableTimestamp(lastAckAt, "last_ack_at"),
    blocked_reason: value.blocked_reason === undefined || value.blocked_reason === null ? null : enumValue(value.blocked_reason, BLOCKED_REASONS, "blocked_reason")
  };
  if (result.observed_generation !== null && result.desired_generation !== null && result.observed_generation > result.desired_generation) throw new DeviceReadModelError("observed_generation exceeds desired_generation");
  if (result.refresh_state === "blocked" && result.blocked_reason === null) throw new DeviceReadModelError("blocked device is missing a stable blocked reason");
  if (result.refresh_state !== "blocked" && result.blocked_reason !== null) throw new DeviceReadModelError("blocked reason is only valid for blocked devices");
  if (result.bundle_expires_at !== null && result.bundle_sequence === null) throw new DeviceReadModelError("bundle expiry requires a bundle sequence");
  return Object.freeze(result);
}

export function normalizeDeviceReadModels(values) {
  if (!Array.isArray(values)) throw new DeviceReadModelError("device read model list must be an array");
  const seen = new Set();
  const result = values.map((value) => {
    const normalized = normalizeDeviceReadModel(value);
    if (seen.has(normalized.device_id)) throw new DeviceReadModelError("device read model contains duplicate devices");
    seen.add(normalized.device_id);
    return normalized;
  });
  return Object.freeze(result);
}

function uuid(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) throw new DeviceReadModelError(`${field} is invalid`);
  return value.toLowerCase();
}

function text(value, field, maximum) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) throw new DeviceReadModelError(`${field} is invalid`);
  return value;
}

function enumValue(value, allowed, field) {
  if (typeof value !== "string" || !allowed.has(value)) throw new DeviceReadModelError(`${field} is invalid`);
  return value;
}

function safeInteger(value, field) {
  const number = typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) throw new DeviceReadModelError(`${field} is invalid`);
  return number;
}

function nullablePositiveInteger(value, field) {
  if (value === null || value === undefined) return null;
  const number = safeInteger(value, field);
  if (number < 1) throw new DeviceReadModelError(`${field} is invalid`);
  return number;
}

function timestamp(value, field) {
  if (typeof value !== "string" || !RFC3339_UTC.test(value) || !Number.isFinite(Date.parse(value))) throw new DeviceReadModelError(`${field} is invalid`);
  return new Date(value).toISOString();
}

function nullableTimestamp(value, field) { return value === null || value === undefined ? null : timestamp(value, field); }

function exclusiveAlias(internalValue, publicValue, field) {
  if (internalValue !== undefined && publicValue !== undefined && internalValue !== publicValue) throw new DeviceReadModelError(`${field} aliases conflict`);
  return publicValue !== undefined ? publicValue : internalValue;
}

function publicKey(value) {
  if (typeof value !== "string" || value.length > 8192 || /PRIVATE\s+KEY/u.test(value) || !value.startsWith("-----BEGIN PUBLIC KEY-----")) throw new DeviceReadModelError("device public key is invalid");
  return value;
}

// Keep the hash primitive visible to tests/reviewers without allowing hashes,
// signatures, or nonce digests into the DTO itself.
export const DEVICE_READ_MODEL_SENSITIVE_FIELD_NAMES = Object.freeze(["signature", "nonce", "refresh_nonce_digest", "statement_hash", "policy", "private_key"]);

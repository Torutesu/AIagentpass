import crypto from "node:crypto";
import { intersectScopes, validateScope } from "../../../packages/capability/src/index.mjs";

export const BUNDLE_VERSION = 1;
export const DEFAULT_BUNDLE_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_OFFLINE_TTL_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_CLOCK_SKEW_MS = 60 * 1000;
export const MAX_REVOCATION_ITEMS = 256;
export const MAX_REVOCATION_ID_LENGTH = 64;

export const BUNDLE_TYPES = Object.freeze({ POLICY: "policy", REVOCATION: "revocation" });

export const BUNDLE_REASONS = Object.freeze({
  INVALID_BUNDLE: "invalid_bundle",
  UNKNOWN_FIELD: "unknown_field",
  UNSUPPORTED_VERSION: "unsupported_version",
  INVALID_BUNDLE_TYPE: "invalid_bundle_type",
  INVALID_IDENTIFIER: "invalid_identifier",
  INVALID_ORGANIZATION_ID: "invalid_organization_id",
  INVALID_DEVICE_ID: "invalid_device_id",
  INVALID_AGENT_ID: "invalid_agent_id",
  INVALID_CAPABILITY_ID: "invalid_capability_id",
  INVALID_AUDIENCE: "invalid_audience",
  AUDIENCE_MISMATCH: "audience_mismatch",
  INVALID_SCOPE: "invalid_scope",
  INVALID_TIMESTAMP: "invalid_timestamp",
  ISSUED_IN_FUTURE: "bundle_issued_in_future",
  EXPIRED: "bundle_expired",
  TTL_EXCEEDED: "bundle_ttl_exceeded",
  INVALID_OFFLINE_TTL: "invalid_offline_ttl",
  OFFLINE_TTL_EXPIRED: "bundle_offline_ttl_expired",
  INVALID_SEQUENCE: "invalid_sequence",
  SEQUENCE_ROLLBACK: "bundle_sequence_rollback",
  SEQUENCE_CONFLICT: "bundle_sequence_conflict",
  SEQUENCE_REJECTED: "bundle_sequence_rejected",
  INVALID_REVOCATION: "invalid_revocation",
  DUPLICATE_REVOCATION: "duplicate_revocation",
  LIST_TOO_LARGE: "revocation_list_too_large",
  ISSUER_NOT_TRUSTED: "issuer_not_trusted",
  KEY_ID_NOT_TRUSTED: "key_id_not_trusted",
  ISSUER_KEY_MISMATCH: "issuer_key_mismatch",
  INVALID_KEY: "invalid_key",
  INVALID_SIGNATURE_ENCODING: "invalid_signature_encoding",
  INVALID_SIGNATURE: "invalid_signature",
  POLICY_BUNDLE_REQUIRED: "policy_bundle_required"
});

const TOP_LEVEL_KEYS = new Set([
  "version", "bundle_type", "issuer", "organization_id", "device_id", "audience",
  "issued_at", "expires_at", "sequence", "policy_scope", "global_revoked",
  "revoked_devices", "revoked_agents", "revoked_capabilities", "offline_ttl_ms", "key_id", "signature"
]);
const ISSUE_KEYS = new Set([
  ...[...TOP_LEVEL_KEYS].filter((key) => key !== "signature"),
  "private_key", "signing_key", "organizationId", "deviceId", "bundleType", "policyScope",
  "issuedAt", "expiresAt", "ttl_ms", "ttlMs", "offlineTtlMs", "keyId", "now"
]);
const AUDIENCE_KEYS = new Set(["organization_id", "device_id"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export class BundleError extends Error {
  constructor(reason, message = reason) {
    super(message);
    this.name = "BundleError";
    this.reason = reason;
    this.code = reason;
  }
}

export const BundleValidationError = BundleError;

/** Issue the canonical signed envelope used by both bundle kinds. */
export function issueBundle(input, privateKey, options = {}) {
  if (!isObject(input)) fail(BUNDLE_REASONS.INVALID_BUNDLE, "Bundle statement must be an object");
  rejectUnknown(input, ISSUE_KEYS, "bundle");
  rejectAliases(input, [
    ["organization_id", "organizationId"], ["device_id", "deviceId"],
    ["bundle_type", "bundleType"], ["policy_scope", "policyScope"],
    ["issued_at", "issuedAt"], ["expires_at", "expiresAt"],
    ["ttl_ms", "ttlMs"], ["offline_ttl_ms", "offlineTtlMs"], ["key_id", "keyId"],
    ["private_key", "signing_key"]
  ]);

  const key = privateKey?.privateKey ?? privateKey ?? input.private_key ?? input.signing_key;
  if (!key) fail(BUNDLE_REASONS.INVALID_KEY, "An Ed25519 private key is required");
  const now = toNow(options.now ?? input.now ?? Date.now());
  const issuedInput = input.issued_at ?? input.issuedAt ?? new Date(now).toISOString();
  const issuedAt = issueTimestamp(issuedInput);
  const issuedMs = parseIssueTimestamp(issuedAt);
  const ttlMs = input.ttl_ms ?? input.ttlMs ?? options.ttlMs ?? options.maxTtlMs ?? 24 * 60 * 60 * 1000;
  if (input.expires_at === undefined && input.expiresAt === undefined && (!Number.isSafeInteger(ttlMs) || ttlMs <= 0)) {
    fail(BUNDLE_REASONS.TTL_EXCEEDED, "Bundle TTL is invalid");
  }
  const expiresInput = input.expires_at ?? input.expiresAt;
  const expiresAt = expiresInput === undefined ? issueTimestamp(issuedMs + ttlMs) : issueTimestamp(expiresInput);
  const statement = {
    version: input.version ?? BUNDLE_VERSION,
    bundle_type: input.bundle_type ?? input.bundleType ?? BUNDLE_TYPES.POLICY,
    issuer: input.issuer,
    organization_id: input.organization_id ?? input.organizationId,
    device_id: input.device_id ?? input.deviceId,
    audience: input.audience,
    issued_at: issuedAt,
    expires_at: expiresAt,
    sequence: input.sequence,
    policy_scope: input.policy_scope ?? input.policyScope,
    global_revoked: input.global_revoked,
    revoked_devices: input.revoked_devices,
    revoked_agents: input.revoked_agents,
    revoked_capabilities: input.revoked_capabilities,
    offline_ttl_ms: input.offline_ttl_ms ?? input.offlineTtlMs ?? options.offlineTtlMs ?? DEFAULT_OFFLINE_TTL_MS,
    key_id: input.key_id ?? input.keyId
  };
  if (statement.audience === undefined) {
    statement.audience = {
      organization_id: statement.organization_id,
      device_id: statement.device_id
    };
  }
  if (statement.global_revoked === undefined) statement.global_revoked = false;
  if (statement.revoked_devices === undefined) statement.revoked_devices = [];
  if (statement.revoked_agents === undefined) statement.revoked_agents = [];
  if (statement.revoked_capabilities === undefined) statement.revoked_capabilities = [];
  const normalized = validateBundle(statement, {
    now,
    maxTtlMs: options.maxTtlMs ?? DEFAULT_BUNDLE_MAX_TTL_MS,
    maxOfflineTtlMs: options.maxOfflineTtlMs ?? options.maxTtlMs ?? DEFAULT_BUNDLE_MAX_TTL_MS,
    clockSkewMs: options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS
  });
  const signing = toPrivateKey(key);
  if (signing.asymmetricKeyType !== "ed25519") fail(BUNDLE_REASONS.INVALID_KEY, "Bundle signing key must be Ed25519");
  return {
    ...normalized,
    signature: crypto.sign(null, canonicalBytes(normalized), signing).toString("base64")
  };
}

export const signBundle = issueBundle;

export function issuePolicyBundle(input, privateKey, options = {}) {
  if ((input?.bundle_type ?? input?.bundleType) !== undefined && (input?.bundle_type ?? input?.bundleType) !== BUNDLE_TYPES.POLICY) fail(BUNDLE_REASONS.INVALID_BUNDLE_TYPE, "Policy issuer cannot create another bundle type");
  return issueBundle({ ...input, bundle_type: input?.bundle_type ?? BUNDLE_TYPES.POLICY }, privateKey, options);
}

export function issueRevocationBundle(input, privateKey, options = {}) {
  if ((input?.bundle_type ?? input?.bundleType) !== undefined && (input?.bundle_type ?? input?.bundleType) !== BUNDLE_TYPES.REVOCATION) fail(BUNDLE_REASONS.INVALID_BUNDLE_TYPE, "Revocation issuer cannot create another bundle type");
  return issueBundle({ ...input, bundle_type: input?.bundle_type ?? BUNDLE_TYPES.REVOCATION }, privateKey, options);
}

/** Validate and normalize the unsigned statement. Signature is ignored here. */
export function validateBundle(bundle, options = {}) {
  if (!isObject(bundle)) fail(BUNDLE_REASONS.INVALID_BUNDLE, "Bundle must be an object");
  rejectUnknown(bundle, TOP_LEVEL_KEYS, "bundle");
  if (bundle.signature !== undefined && typeof bundle.signature !== "string") {
    fail(BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING, "Bundle signature must be a string");
  }
  const now = toNow(options.now ?? Date.now());
  const maxTtlMs = positiveLimit(options.maxTtlMs ?? DEFAULT_BUNDLE_MAX_TTL_MS, BUNDLE_REASONS.TTL_EXCEEDED, "Bundle maximum TTL is invalid");
  const maxOfflineTtlMs = positiveLimit(options.maxOfflineTtlMs ?? maxTtlMs, BUNDLE_REASONS.INVALID_OFFLINE_TTL, "Bundle maximum offline TTL is invalid");
  const clockSkewMs = nonNegativeLimit(options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS, BUNDLE_REASONS.INVALID_TIMESTAMP, "Bundle clock skew is invalid");

  if (bundle.version !== BUNDLE_VERSION) fail(BUNDLE_REASONS.UNSUPPORTED_VERSION, "Unsupported bundle version");
  if (!Object.values(BUNDLE_TYPES).includes(bundle.bundle_type)) fail(BUNDLE_REASONS.INVALID_BUNDLE_TYPE, "Bundle type is invalid");
  if (!isIdentifier(bundle.issuer)) fail(BUNDLE_REASONS.INVALID_IDENTIFIER, "Bundle issuer is invalid");
  assertUuid(bundle.organization_id, BUNDLE_REASONS.INVALID_ORGANIZATION_ID, "Bundle organization ID is invalid");
  assertUuid(bundle.device_id, BUNDLE_REASONS.INVALID_DEVICE_ID, "Bundle device ID is invalid");
  const audience = validateAudience(bundle.audience);
  if (audience.organization_id !== bundle.organization_id || audience.device_id !== bundle.device_id) {
    fail(BUNDLE_REASONS.AUDIENCE_MISMATCH, "Bundle audience does not match its organization and device");
  }
  const issued = parseCanonicalTimestamp(bundle.issued_at);
  const expires = parseCanonicalTimestamp(bundle.expires_at);
  if (expires <= issued) fail(BUNDLE_REASONS.INVALID_TIMESTAMP, "Bundle expiry must be after issuance");
  if (expires - issued > maxTtlMs) fail(BUNDLE_REASONS.TTL_EXCEEDED, "Bundle lifetime exceeds the maximum TTL");
  if (!options.allowFuture && issued > now + clockSkewMs) fail(BUNDLE_REASONS.ISSUED_IN_FUTURE, "Bundle was issued in the future");
  if (!options.allowExpired && expires <= now) fail(BUNDLE_REASONS.EXPIRED, "Bundle has expired");
  if (!Number.isSafeInteger(bundle.sequence) || bundle.sequence < 1) fail(BUNDLE_REASONS.INVALID_SEQUENCE, "Bundle sequence must be a positive integer");
  if (!isObject(bundle.policy_scope)) fail(BUNDLE_REASONS.INVALID_SCOPE, "Bundle policy scope is required");
  const policyScope = validatePolicyScope(bundle.policy_scope);
  if (typeof bundle.global_revoked !== "boolean") fail(BUNDLE_REASONS.INVALID_REVOCATION, "Bundle global revocation must be boolean");
  const revokedDevices = validateRevocationList(bundle.revoked_devices, BUNDLE_REASONS.INVALID_DEVICE_ID, "device");
  const revokedAgents = validateRevocationList(bundle.revoked_agents, BUNDLE_REASONS.INVALID_AGENT_ID, "agent");
  const revokedCapabilities = validateRevocationList(bundle.revoked_capabilities, BUNDLE_REASONS.INVALID_CAPABILITY_ID, "capability");
  if (!Number.isSafeInteger(bundle.offline_ttl_ms) || bundle.offline_ttl_ms <= 0 || bundle.offline_ttl_ms > maxOfflineTtlMs) {
    fail(BUNDLE_REASONS.INVALID_OFFLINE_TTL, "Bundle offline TTL is invalid or exceeds its limit");
  }
  if (!isIdentifier(bundle.key_id)) fail(BUNDLE_REASONS.INVALID_IDENTIFIER, "Bundle key ID is invalid");
  return {
    version: BUNDLE_VERSION,
    bundle_type: bundle.bundle_type,
    issuer: bundle.issuer,
    organization_id: bundle.organization_id,
    device_id: bundle.device_id,
    audience,
    issued_at: new Date(issued).toISOString(),
    expires_at: new Date(expires).toISOString(),
    sequence: bundle.sequence,
    policy_scope: policyScope,
    global_revoked: bundle.global_revoked,
    revoked_devices: revokedDevices,
    revoked_agents: revokedAgents,
    revoked_capabilities: revokedCapabilities,
    offline_ttl_ms: bundle.offline_ttl_ms,
    key_id: bundle.key_id
  };
}

export function canonicalBundle(bundle) {
  return canonicalJson(validateBundle(bundle, { allowExpired: true, allowFuture: true }));
}

export function bundleHash(bundle) {
  return crypto.createHash("sha256").update(canonicalBytes(validateBundle(bundle, { allowExpired: true, allowFuture: true }))).digest("hex");
}

/** Verify an issuer's bundle with a trusted issuer key or issuer/key map. */
export function verifyIssuerBundle(bundle, trust = {}, options = {}) {
  const normalized = validateBundle(bundle, { ...options, now: toNow(options.now ?? Date.now()) });
  const verified = verifySignedBundle(bundle, resolveIssuerKey(normalized, trust, options), options);
  const expectedIssuer = options.issuer ?? trust?.issuer;
  if (expectedIssuer !== undefined && verified.issuer !== expectedIssuer) fail(BUNDLE_REASONS.ISSUER_KEY_MISMATCH, "Bundle issuer is not trusted for this key");
  if (options.audience !== undefined || options.expectedAudience !== undefined) checkAudience(verified, options.audience ?? options.expectedAudience);
  return verified;
}

/** Verify on a device. A pinned public key and an expected audience are mandatory. */
export function verifyDeviceBundle(bundle, pinnedKey, options = {}) {
  const trust = pinnedKey ?? {};
  const normalized = validateBundle(bundle, {
    ...options,
    now: toNow(options.now ?? Date.now()),
    allowExpired: options.allowOffline === true
  });
  const key = resolvePinnedKey(trust, normalized, options);
  const verified = verifySignedBundle(bundle, key, { ...options, allowExpired: options.allowOffline === true });
  const expectedAudience = options.audience ?? options.expectedAudience ?? trust?.audience;
  if (expectedAudience === undefined) fail(BUNDLE_REASONS.INVALID_AUDIENCE, "Device verification requires an expected audience");
  checkAudience(verified, expectedAudience);
  if (options.allowOffline === true && verified.expires_at <= new Date(toNow(options.now ?? Date.now())).toISOString()) {
    const offlineEnds = Date.parse(verified.expires_at) + verified.offline_ttl_ms;
    if (toNow(options.now ?? Date.now()) > offlineEnds) fail(BUNDLE_REASONS.OFFLINE_TTL_EXPIRED, "Bundle offline TTL has expired");
  }
  enforceSequence(verified, options, trust);
  return verified;
}

export const verifyBundle = verifyDeviceBundle;

export function verifyCachedBundle(bundle, pinnedKey, options = {}) {
  return verifyDeviceBundle(bundle, pinnedKey, { ...options, allowOffline: true });
}

/** Consume cloud policy only by intersecting it with the local policy. */
export function narrowPolicyScope(localPolicy, cloudPolicy) {
  const remoteScope = cloudPolicy?.policy_scope ?? cloudPolicy;
  return intersectPolicyScopes(localPolicy, remoteScope);
}

export function narrowPolicyBundle(localPolicy, verifiedBundle) {
  if (!isObject(verifiedBundle) || verifiedBundle.bundle_type !== BUNDLE_TYPES.POLICY) {
    fail(BUNDLE_REASONS.POLICY_BUNDLE_REQUIRED, "A verified policy bundle is required");
  }
  return narrowPolicyScope(localPolicy, verifiedBundle.policy_scope);
}

export function consumePolicyBundle(bundle, localPolicy, pinnedKey, options = {}) {
  const verified = verifyDeviceBundle(bundle, pinnedKey, options);
  return { bundle: verified, effective_scope: narrowPolicyBundle(localPolicy, verified) };
}

export function evaluateRevocations(bundle, { organization_id, device_id, agent_id, capability_id } = {}) {
  const normalized = validateBundle(bundle, { allowExpired: true, allowFuture: true });
  if (normalized.global_revoked) return { allowed: false, reason: "global_revoked", sequence: normalized.sequence };
  if (device_id !== undefined && normalized.revoked_devices.includes(device_id)) return { allowed: false, reason: "device_revoked", sequence: normalized.sequence };
  if (agent_id !== undefined && normalized.revoked_agents.includes(agent_id)) return { allowed: false, reason: "agent_revoked", sequence: normalized.sequence };
  if (capability_id !== undefined && normalized.revoked_capabilities.includes(capability_id)) return { allowed: false, reason: "capability_revoked", sequence: normalized.sequence };
  if (organization_id !== undefined && organization_id !== normalized.organization_id) return { allowed: false, reason: "organization_mismatch", sequence: normalized.sequence };
  return { allowed: true, reason: "not_revoked", sequence: normalized.sequence };
}

function verifySignedBundle(bundle, publicKey, options) {
  const normalized = validateBundle(bundle, {
    ...options,
    now: toNow(options.now ?? Date.now()),
    allowExpired: options.allowExpired ?? false
  });
  const signatureBytes = decodeSignature(bundle.signature);
  let valid = false;
  try { valid = crypto.verify(null, canonicalBytes(normalized), publicKey, signatureBytes); } catch { valid = false; }
  if (!valid) fail(BUNDLE_REASONS.INVALID_SIGNATURE, "Bundle signature is invalid");
  return { ...normalized, signature: bundle.signature };
}

function resolvePinnedKey(trust, bundle, options) {
  const direct = isKeyLike(trust) ? trust : trust?.pinned_key ?? trust?.pinnedKey ?? trust?.public_key ?? trust?.publicKey ?? options.pinned_key ?? options.pinnedKey ?? options.public_key ?? options.publicKey;
  if (direct === undefined) fail(BUNDLE_REASONS.INVALID_KEY, "A pinned Ed25519 public key is required");
  const keyId = (isObject(trust) && !isKeyLike(trust) ? trust.key_id ?? trust.keyId : undefined) ?? options.key_id ?? options.keyId;
  if (keyId !== undefined && keyId !== bundle.key_id) fail(BUNDLE_REASONS.KEY_ID_NOT_TRUSTED, "Bundle key ID is not trusted");
  const issuer = (isObject(trust) && !isKeyLike(trust) ? trust.issuer : undefined) ?? options.issuer;
  if (issuer !== undefined && issuer !== bundle.issuer) fail(BUNDLE_REASONS.ISSUER_KEY_MISMATCH, "Bundle issuer is not trusted for this key");
  return publicKeyFor(direct);
}

function resolveIssuerKey(bundle, trust, options) {
  if (isKeyLike(trust)) return publicKeyFor(trust);
  if (trust instanceof Map || Array.isArray(trust)) {
    const entry = getValue(trust, bundle.key_id);
    if (entry === undefined) fail(BUNDLE_REASONS.KEY_ID_NOT_TRUSTED, "Bundle key ID is not trusted");
    return publicKeyFor(entry?.public_key ?? entry?.publicKey ?? entry);
  }
  trust = trust ?? {};
  const direct = trust.public_key ?? trust.publicKey ?? trust.pinned_key ?? trust.pinnedKey ?? options.public_key ?? options.publicKey;
  if (direct !== undefined) {
    if ((trust.key_id ?? trust.keyId ?? options.key_id ?? options.keyId) !== undefined && (trust.key_id ?? trust.keyId ?? options.key_id ?? options.keyId) !== bundle.key_id) fail(BUNDLE_REASONS.KEY_ID_NOT_TRUSTED, "Bundle key ID is not trusted");
    if ((trust.issuer ?? options.issuer) !== undefined && (trust.issuer ?? options.issuer) !== bundle.issuer) fail(BUNDLE_REASONS.ISSUER_KEY_MISMATCH, "Bundle issuer is not trusted for this key");
    return publicKeyFor(direct);
  }
  const issuers = trust.issuers ?? trust.trustedIssuers ?? options.issuers ?? options.trustedIssuers;
  if (issuers !== undefined) {
    const entry = getValue(issuers, bundle.issuer);
    if (entry === undefined) fail(BUNDLE_REASONS.ISSUER_NOT_TRUSTED, "Bundle issuer is not trusted");
    if (entry?.public_key !== undefined || entry?.publicKey !== undefined) {
      const trustedId = entry.key_id ?? entry.keyId;
      if (trustedId !== undefined && trustedId !== bundle.key_id) fail(BUNDLE_REASONS.KEY_ID_NOT_TRUSTED, "Bundle key ID is not trusted");
      return publicKeyFor(entry.public_key ?? entry.publicKey);
    }
    const key = getValue(entry?.keys ?? entry, bundle.key_id);
    if (key === undefined) fail(BUNDLE_REASONS.KEY_ID_NOT_TRUSTED, "Bundle key ID is not trusted");
    return publicKeyFor(key?.public_key ?? key?.publicKey ?? key);
  }
  const keys = trust.keys ?? trust.trustedKeys ?? trust.trusted_keys ?? options.keys ?? options.trustedKeys ?? options.trusted_keys;
  if (keys === undefined) fail(BUNDLE_REASONS.ISSUER_NOT_TRUSTED, "Bundle issuer trust is not configured");
  const entry = isKeyLike(keys) ? keys : getValue(keys, bundle.key_id);
  if (entry === undefined) fail(BUNDLE_REASONS.KEY_ID_NOT_TRUSTED, "Bundle key ID is not trusted");
  if (entry && !isKeyLike(entry) && entry.issuer !== undefined && entry.issuer !== bundle.issuer) fail(BUNDLE_REASONS.ISSUER_KEY_MISMATCH, "Bundle issuer is not trusted for this key");
  return publicKeyFor(entry?.public_key ?? entry?.publicKey ?? entry);
}

function enforceSequence(bundle, options, trust) {
  const highest = options.highestSequence ?? trust?.highestSequence;
  if (highest !== undefined && (!Number.isSafeInteger(highest) || bundle.sequence < highest)) fail(BUNDLE_REASONS.SEQUENCE_ROLLBACK, "Bundle sequence rolled back");
  const state = options.sequenceState ?? trust?.sequenceState;
  const hash = bundleHash(bundle);
  if (state) {
    if (!Number.isSafeInteger(state.highestSequence ?? 0) || bundle.sequence < (state.highestSequence ?? 0)) fail(BUNDLE_REASONS.SEQUENCE_ROLLBACK, "Bundle sequence rolled back");
    const oldHash = state.highestBundleHash ?? state.highest_bundle_hash;
    if (bundle.sequence === state.highestSequence && oldHash !== undefined && oldHash !== hash) fail(BUNDLE_REASONS.SEQUENCE_CONFLICT, "Bundle sequence conflicts with previously verified content");
  }
  const hook = options.sequenceHook ?? options.checkSequence ?? trust?.sequenceHook;
  if (hook !== undefined) {
    if (typeof hook !== "function") fail(BUNDLE_REASONS.SEQUENCE_REJECTED, "Bundle sequence hook is invalid");
    let result;
    try { result = hook(bundle.sequence, bundle); } catch { fail(BUNDLE_REASONS.SEQUENCE_REJECTED, "Bundle sequence was rejected"); }
    if (result === false || (result && typeof result === "object" && result.allowed === false) || (Number.isSafeInteger(result) && bundle.sequence < result)) fail(BUNDLE_REASONS.SEQUENCE_ROLLBACK, "Bundle sequence rolled back");
  }
  const onSequence = options.onSequence ?? trust?.onSequence;
  if (onSequence !== undefined) {
    if (typeof onSequence !== "function") fail(BUNDLE_REASONS.SEQUENCE_REJECTED, "Bundle sequence hook is invalid");
    try { onSequence(bundle.sequence, bundle); } catch { fail(BUNDLE_REASONS.SEQUENCE_REJECTED, "Bundle sequence was rejected"); }
  }
  if (state && bundle.sequence >= (state.highestSequence ?? 0)) {
    state.highestSequence = bundle.sequence;
    state.highestBundleHash = hash;
    delete state.highest_bundle_hash;
  }
}

function validateAudience(audience) {
  if (!isObject(audience)) fail(BUNDLE_REASONS.INVALID_AUDIENCE, "Bundle audience must contain an organization and device");
  rejectUnknown(audience, AUDIENCE_KEYS, "bundle audience");
  assertUuid(audience.organization_id, BUNDLE_REASONS.INVALID_ORGANIZATION_ID, "Bundle audience organization ID is invalid");
  assertUuid(audience.device_id, BUNDLE_REASONS.INVALID_DEVICE_ID, "Bundle audience device ID is invalid");
  return { organization_id: audience.organization_id, device_id: audience.device_id };
}

function checkAudience(bundle, expected) {
  const audience = validateAudience(expected);
  if (audience.organization_id !== bundle.organization_id || audience.device_id !== bundle.device_id) fail(BUNDLE_REASONS.AUDIENCE_MISMATCH, "Bundle audience does not match the device");
}

function validateRevocationList(value, idReason, kind) {
  if (!Array.isArray(value)) fail(BUNDLE_REASONS.INVALID_REVOCATION, `Bundle revoked ${kind} list is invalid`);
  if (value.length > MAX_REVOCATION_ITEMS) fail(BUNDLE_REASONS.LIST_TOO_LARGE, `Bundle revoked ${kind} list is too large`);
  const seen = new Set();
  for (const id of value) {
    if (typeof id !== "string" || id.length > MAX_REVOCATION_ID_LENGTH || !UUID.test(id)) fail(idReason, `Bundle contains an invalid ${kind} ID`);
    if (seen.has(id)) fail(BUNDLE_REASONS.DUPLICATE_REVOCATION, `Bundle contains a duplicate revoked ${kind} ID`);
    seen.add(id);
  }
  const sorted = [...value].sort();
  if (sorted.some((id, index) => id !== value[index])) fail(BUNDLE_REASONS.INVALID_REVOCATION, `Bundle revoked ${kind} list is not canonical`);
  return [...value];
}

function validatePolicyScope(scope) {
  try { return validateScope(scope); }
  catch (error) {
    if (error?.reason === "unknown_field") fail(BUNDLE_REASONS.UNKNOWN_FIELD, error.message);
    fail(BUNDLE_REASONS.INVALID_SCOPE, "Bundle policy scope is invalid");
  }
}

function intersectPolicyScopes(local, remote) {
  try { return intersectScopes(validatePolicyScope(local), validatePolicyScope(remote)); }
  catch (error) {
    if (error instanceof BundleError) throw error;
    fail(error?.reason === "unknown_field" ? BUNDLE_REASONS.UNKNOWN_FIELD : BUNDLE_REASONS.INVALID_SCOPE, "Policy scope intersection is invalid");
  }
}

function parseCanonicalTimestamp(value) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(Date.parse(value)).toISOString() !== value) fail(BUNDLE_REASONS.INVALID_TIMESTAMP, "Bundle timestamps must be canonical UTC strings");
  return Date.parse(value);
}

function parseIssueTimestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.getTime();
  return parseCanonicalTimestamp(value);
}

function issueTimestamp(value) {
  let milliseconds;
  try { milliseconds = parseIssueTimestamp(value); } catch (error) { throw error; }
  const date = new Date(milliseconds);
  if (!Number.isFinite(date.getTime())) fail(BUNDLE_REASONS.INVALID_TIMESTAMP, "Bundle timestamp is out of range");
  return date.toISOString();
}

function decodeSignature(signature) {
  if (typeof signature !== "string" || !BASE64.test(signature)) fail(BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING, "Bundle signature encoding is invalid");
  const bytes = Buffer.from(signature, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== signature) fail(BUNDLE_REASONS.INVALID_SIGNATURE_ENCODING, "Bundle signature encoding is invalid");
  return bytes;
}

function toPrivateKey(key) {
  try { return key?.type === "private" ? key : crypto.createPrivateKey(key); }
  catch { fail(BUNDLE_REASONS.INVALID_KEY, "Bundle private key is invalid"); }
}

function publicKeyFor(key) {
  try {
    const publicKey = key?.type === "public" ? key : crypto.createPublicKey(key);
    if (publicKey.asymmetricKeyType !== "ed25519") fail(BUNDLE_REASONS.INVALID_KEY, "Bundle pinned key must be Ed25519");
    return publicKey;
  } catch (error) {
    if (error instanceof BundleError) throw error;
    fail(BUNDLE_REASONS.INVALID_KEY, "Bundle pinned key is invalid");
  }
}

function canonicalBytes(statement) { return Buffer.from(canonicalJson(statement)); }

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function rejectUnknown(value, allowed, label) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(BUNDLE_REASONS.UNKNOWN_FIELD, `${label} contains an unknown field: ${key}`);
}

function rejectAliases(value, pairs) {
  for (const [left, right] of pairs) if (Object.hasOwn(value, left) && Object.hasOwn(value, right)) fail(BUNDLE_REASONS.UNKNOWN_FIELD, `Bundle cannot contain both ${left} and ${right}`);
}

function assertUuid(value, reason, message) { if (typeof value !== "string" || !UUID.test(value)) fail(reason, message); }
function isIdentifier(value) { return typeof value === "string" && IDENTIFIER.test(value); }
function isObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function isKeyLike(value) { return typeof value === "string" || Buffer.isBuffer(value) || value?.type === "public" || value?.type === "private"; }
function getValue(container, key) { return container instanceof Map ? container.get(key) : container?.[key]; }
function positiveLimit(value, reason, message) { if (!Number.isSafeInteger(value) || value <= 0) fail(reason, message); return value; }
function nonNegativeLimit(value, reason, message) { if (!Number.isSafeInteger(value) || value < 0) fail(reason, message); return value; }
function toNow(value) { if (value instanceof Date) value = value.getTime(); if (!Number.isFinite(value)) fail(BUNDLE_REASONS.INVALID_TIMESTAMP, "Bundle clock time is invalid"); return value; }
function fail(reason, message) { throw new BundleError(reason, message); }

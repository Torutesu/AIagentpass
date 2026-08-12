import crypto from "node:crypto";
import path from "node:path";

export const CAPABILITY_VERSION = 1;
export const PROTOCOL_V1 = CAPABILITY_VERSION;
export const DEFAULT_MAX_TTL_MS = 15 * 60 * 1000;
export const DEFAULT_CLOCK_SKEW_MS = 60 * 1000;
export const MAX_NONCE_BYTES = 64;
export const MIN_NONCE_BYTES = 32;

export const CAPABILITY_REASONS = Object.freeze({
  ALLOWED: "allowed",
  INVALID_CAPABILITY: "invalid_capability",
  UNKNOWN_FIELD: "unknown_field",
  UNSUPPORTED_VERSION: "unsupported_version",
  INVALID_IDENTIFIER: "invalid_identifier",
  INVALID_CAPABILITY_ID: "invalid_capability_id",
  INVALID_NONCE: "invalid_nonce",
  INVALID_AUDIENCE: "invalid_audience",
  AUDIENCE_MISMATCH: "audience_mismatch",
  INVALID_SCOPE: "invalid_scope",
  INVALID_TIMESTAMP: "invalid_timestamp",
  NOT_BEFORE_IN_FUTURE: "capability_not_yet_valid",
  EXPIRED: "capability_expired",
  TTL_EXCEEDED: "capability_ttl_exceeded",
  INVALID_SEQUENCE: "invalid_sequence",
  SEQUENCE_ROLLBACK: "capability_sequence_rollback",
  SEQUENCE_CONFLICT: "capability_sequence_conflict",
  ISSUER_NOT_TRUSTED: "issuer_not_trusted",
  KEY_ID_NOT_TRUSTED: "key_id_not_trusted",
  ISSUER_KEY_MISMATCH: "issuer_key_mismatch",
  INVALID_SIGNATURE: "invalid_signature",
  INVALID_SIGNATURE_ENCODING: "invalid_signature_encoding",
  SEQUENCE_HOOK_REJECTED: "capability_sequence_rejected"
});

const TOP_LEVEL_KEYS = new Set([
  "version", "capability_id", "nonce", "issuer", "key_id", "audience",
  "scope", "not_before", "expires_at", "sequence", "signature"
]);
const ISSUE_INPUT_KEYS = new Set([
  ...TOP_LEVEL_KEYS, "private_key", "signing_key", "ttl_ms", "ttlMs", "notBefore", "expiresAt", "keyId", "now"
]);
const AUDIENCE_KEYS = new Set(["agent_id", "device_id"]);
const SCOPE_KEYS = new Set(["operations", "repositories", "branches", "remotes", "tags"]);
const FILTER_KEYS = new Set(["allow", "deny"]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_SCOPE_ITEMS = 256;
const MAX_SCOPE_ITEM_LENGTH = 2048;

export class CapabilityError extends Error {
  constructor(reason, message = reason) {
    super(message);
    this.name = "CapabilityError";
    this.reason = reason;
    this.code = reason;
  }
}

export const CapabilityValidationError = CapabilityError;

/**
 * Create and sign a v1 capability. The returned object is the exact signed
 * transport envelope; its signature covers every field except signature.
 */
export function issueCapability(input, privateKey, options = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(CAPABILITY_REASONS.INVALID_CAPABILITY, "Capability statement must be an object");
  rejectUnknown(input, ISSUE_INPUT_KEYS, CAPABILITY_REASONS.UNKNOWN_FIELD, "capability");
  rejectAliases(input, [["key_id", "keyId"], ["not_before", "notBefore"], ["expires_at", "expiresAt"], ["ttl_ms", "ttlMs"], ["private_key", "signing_key"]]);
  const key = privateKey?.privateKey ?? privateKey ?? input.private_key ?? input.signing_key;
  if (!key) fail(CAPABILITY_REASONS.INVALID_SIGNATURE, "An Ed25519 private key is required");
  const statement = {
    version: input.version ?? CAPABILITY_VERSION,
    capability_id: input.capability_id ?? crypto.randomUUID(),
    nonce: input.nonce ?? randomNonce(),
    issuer: input.issuer,
    key_id: input.key_id ?? input.keyId,
    audience: input.audience,
    scope: input.scope,
    not_before: input.not_before ?? input.notBefore,
    expires_at: input.expires_at ?? input.expiresAt,
    sequence: input.sequence
  };
  const now = toNow(options.now ?? input.now);
  if (statement.not_before === undefined) statement.not_before = new Date(now).toISOString();
  else statement.not_before = issueTimestamp(statement.not_before);
  if (statement.expires_at === undefined) {
    const ttlMs = input.ttl_ms ?? input.ttlMs ?? options.ttlMs ?? 60 * 1000;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) fail(CAPABILITY_REASONS.TTL_EXCEEDED, "Capability TTL is invalid");
    statement.expires_at = new Date(parseTimestamp(statement.not_before) + ttlMs).toISOString();
  } else statement.expires_at = issueTimestamp(statement.expires_at);
  const normalized = validateStatement(statement, {
    now,
    maxTtlMs: options.maxTtlMs ?? DEFAULT_MAX_TTL_MS,
    clockSkewMs: options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS,
    allowExpired: false,
    allowFuture: false
  });
  const signing = toPrivateKey(key);
  const publicKey = crypto.createPublicKey(signing);
  if (publicKey.asymmetricKeyType !== "ed25519") fail(CAPABILITY_REASONS.INVALID_SIGNATURE, "Capability signing key must be Ed25519");
  return {
    ...normalized,
    signature: crypto.sign(null, canonicalBytes(normalized), signing).toString("base64")
  };
}

export const signCapability = issueCapability;

/** Validate the unsigned statement and return a canonical normalized copy. */
export function validateCapability(capability, options = {}) {
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) fail(CAPABILITY_REASONS.INVALID_CAPABILITY, "Capability must be an object");
  const { signature, ...statement } = capability;
  if (signature !== undefined && typeof signature !== "string") fail(CAPABILITY_REASONS.INVALID_SIGNATURE_ENCODING, "Capability signature must be a string");
  return validateStatement(statement, {
    now: toNow(options.now ?? Date.now()),
    maxTtlMs: options.maxTtlMs ?? DEFAULT_MAX_TTL_MS,
    clockSkewMs: options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS,
    allowExpired: options.allowExpired ?? false,
    allowFuture: options.allowFuture ?? false
  });
}

/**
 * Verify a capability against an issuer/key trust map and an optional target
 * audience. No state is changed until the signature and validity checks pass.
 */
export function verifyCapability(capability, trust = {}, options = {}) {
  options = options ?? {};
  trust = trust ?? {};
  if (typeof trust === "string" || isKeyObject(trust)) trust = { public_key: trust };
  else if (trust instanceof Map || Array.isArray(trust)) trust = { keys: trust };
  const now = toNow(options.now ?? trust.now ?? Date.now());
  const normalized = validateCapability(capability, { ...options, now });
  const signature = capability.signature;
  if (typeof signature !== "string" || !BASE64.test(signature)) fail(CAPABILITY_REASONS.INVALID_SIGNATURE_ENCODING, "Capability signature encoding is invalid");
  const signatureBytes = Buffer.from(signature, "base64");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64") !== signature) fail(CAPABILITY_REASONS.INVALID_SIGNATURE_ENCODING, "Capability signature encoding is invalid");
  const publicKey = resolveTrustedKey(normalized.issuer, normalized.key_id, trust, options);
  let valid = false;
  try { valid = crypto.verify(null, canonicalBytes(normalized), publicKey, signatureBytes); }
  catch { valid = false; }
  if (!valid) fail(CAPABILITY_REASONS.INVALID_SIGNATURE, "Capability signature is invalid");

  const expectedAudience = options.audience ?? options.expectedAudience ?? trust.audience ??
    (options.agent_id || options.device_id ? { agent_id: options.agent_id, device_id: options.device_id } : undefined);
  if (expectedAudience !== undefined) {
    const expected = validateAudience(expectedAudience);
    if (expected.agent_id !== normalized.audience.agent_id || expected.device_id !== normalized.audience.device_id) {
      fail(CAPABILITY_REASONS.AUDIENCE_MISMATCH, "Capability audience does not match the local agent and device");
    }
  }
  enforceSequence({ ...normalized, signature }, options, trust);
  return { ...normalized, signature };
}

export function canonicalCapability(capability) {
  return canonicalJson(validateCapability(capability, { allowExpired: true, allowFuture: true }));
}

/** Intersect scopes conservatively. An empty allow list means deny all. */
export function intersectScopes(...scopes) {
  if (scopes.length === 0) fail(CAPABILITY_REASONS.INVALID_SCOPE, "At least one scope is required");
  const normalized = scopes.map((scope) => validateScope(scope, { allowEmpty: true }));
  let result = cloneScope(normalized[0]);
  for (const next of normalized.slice(1)) result = intersectTwoScopes(result, next);
  return result;
}

export const intersectScope = intersectScopes;
export const narrowScope = intersectScopes;

/** Effective access is always local policy intersected with every remote scope. */
export function effectiveScope(localPolicy, ...narrowingScopes) {
  return intersectScopes(localPolicy, ...narrowingScopes);
}

export function effectiveIntersection({ localPolicy, agentScope, capabilityScope, scopes = [] } = {}) {
  return effectiveScope(localPolicy, ...[agentScope, capabilityScope, ...scopes].filter((scope) => scope !== undefined));
}

/** Check a request against all constraints in a scope. */
export function scopeAllows(scope, { operation, repository, branch, remote, tag } = {}) {
  const normalized = validateScope(scope, { allowEmpty: true });
  if (typeof operation !== "string" || !matchesAny(operation, normalized.operations)) return false;
  if (typeof repository !== "string" || !canonicalRepositoryPath(repository) || !matchesAny(repository, normalized.repositories)) return false;
  if (!matchesFilter(branch, normalized.branches)) return false;
  if (!matchesFilter(remote, normalized.remotes)) return false;
  if (normalized.tags && (tag === undefined || !matchesFilter(tag, normalized.tags))) return false;
  return true;
}

export function validateScope(scope, { allowEmpty = false } = {}) {
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) fail(CAPABILITY_REASONS.INVALID_SCOPE, "Capability scope must be an object");
  rejectUnknown(scope, SCOPE_KEYS, CAPABILITY_REASONS.UNKNOWN_FIELD, "scope");
  const operations = validateStringList(scope.operations, "scope.operations", { allowEmpty });
  const repositories = validateStringList(scope.repositories, "scope.repositories", { allowEmpty });
  if (repositories.some((repository) => !canonicalRepositoryPattern(repository))) fail(CAPABILITY_REASONS.INVALID_SCOPE, "scope.repositories must contain canonical absolute paths");
  const branches = validateFilter(scope.branches, "scope.branches", allowEmpty);
  const remotes = validateFilter(scope.remotes, "scope.remotes", allowEmpty);
  const tags = scope.tags === undefined ? undefined : validateFilter(scope.tags, "scope.tags", allowEmpty);
  return { operations, repositories, branches, remotes, ...(tags ? { tags } : {}) };
}

function validateStatement(statement, { now, maxTtlMs, clockSkewMs, allowExpired, allowFuture }) {
  rejectUnknown(statement, TOP_LEVEL_KEYS, CAPABILITY_REASONS.UNKNOWN_FIELD, "capability");
  if (statement.version !== CAPABILITY_VERSION) fail(CAPABILITY_REASONS.UNSUPPORTED_VERSION, "Unsupported capability version");
  if (!UUID.test(statement.capability_id ?? "")) fail(CAPABILITY_REASONS.INVALID_CAPABILITY_ID, "Capability ID must be a UUID");
  validateNonce(statement.nonce);
  if (!isIdentifier(statement.issuer)) fail(CAPABILITY_REASONS.INVALID_IDENTIFIER, "Capability issuer is invalid");
  if (!isIdentifier(statement.key_id)) fail(CAPABILITY_REASONS.INVALID_IDENTIFIER, "Capability key ID is invalid");
  const audience = validateAudience(statement.audience);
  const scope = validateScope(statement.scope);
  const notBefore = parseCanonicalTimestamp(statement.not_before);
  const expiresAt = parseCanonicalTimestamp(statement.expires_at);
  if (expiresAt <= notBefore) fail(CAPABILITY_REASONS.INVALID_TIMESTAMP, "Capability expiry must be after not-before");
  if (expiresAt - notBefore > maxTtlMs) fail(CAPABILITY_REASONS.TTL_EXCEEDED, "Capability lifetime exceeds the maximum TTL");
  if (!Number.isSafeInteger(statement.sequence) || statement.sequence < 1) fail(CAPABILITY_REASONS.INVALID_SEQUENCE, "Capability sequence must be a positive integer");
  if (!allowFuture && notBefore > now + clockSkewMs) fail(CAPABILITY_REASONS.NOT_BEFORE_IN_FUTURE, "Capability is not yet valid");
  if (!allowExpired && expiresAt <= now) fail(CAPABILITY_REASONS.EXPIRED, "Capability has expired");
  return {
    version: CAPABILITY_VERSION,
    capability_id: statement.capability_id,
    nonce: statement.nonce,
    issuer: statement.issuer,
    key_id: statement.key_id,
    audience,
    scope,
    not_before: new Date(notBefore).toISOString(),
    expires_at: new Date(expiresAt).toISOString(),
    sequence: statement.sequence
  };
}

function validateAudience(audience) {
  if (!audience || typeof audience !== "object" || Array.isArray(audience)) fail(CAPABILITY_REASONS.INVALID_AUDIENCE, "Capability audience must contain an agent and device");
  rejectUnknown(audience, AUDIENCE_KEYS, CAPABILITY_REASONS.UNKNOWN_FIELD, "audience");
  if (!UUID.test(audience.agent_id ?? "") || !UUID.test(audience.device_id ?? "")) fail(CAPABILITY_REASONS.INVALID_AUDIENCE, "Capability audience IDs must be UUID values");
  return { agent_id: audience.agent_id, device_id: audience.device_id };
}

function validateNonce(nonce) {
  if (typeof nonce !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{31,127}$/.test(nonce)) fail(CAPABILITY_REASONS.INVALID_NONCE, "Capability nonce is invalid");
}

function randomNonce() {
  const nonce = crypto.randomBytes(MIN_NONCE_BYTES).toString("base64url");
  return /^[A-Za-z0-9]/.test(nonce) ? nonce : `A${nonce.slice(1)}`;
}

function validateFilter(filter, label, allowEmpty) {
  if (!filter || typeof filter !== "object" || Array.isArray(filter)) fail(CAPABILITY_REASONS.INVALID_SCOPE, `${label} must be an object`);
  rejectUnknown(filter, FILTER_KEYS, CAPABILITY_REASONS.UNKNOWN_FIELD, label);
  return {
    allow: validateStringList(filter.allow, `${label}.allow`, { allowEmpty }),
    ...(filter.deny === undefined ? {} : { deny: validateStringList(filter.deny, `${label}.deny`, { allowEmpty: true }) })
  };
}

function validateStringList(value, label, { allowEmpty = false } = {}) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > MAX_SCOPE_ITEMS || value.some((item) => typeof item !== "string" || item.length === 0 || item.length > MAX_SCOPE_ITEM_LENGTH)) fail(CAPABILITY_REASONS.INVALID_SCOPE, `${label} is invalid`);
  if (new Set(value).size !== value.length) fail(CAPABILITY_REASONS.INVALID_SCOPE, `${label} contains duplicates`);
  return [...value];
}

function resolveTrustedKey(issuer, keyId, trust, options) {
  const directKey = trust.public_key ?? trust.publicKey ?? options.public_key ?? options.publicKey;
  if (directKey !== undefined) {
    if (trust.issuer !== undefined && trust.issuer !== issuer) fail(CAPABILITY_REASONS.ISSUER_KEY_MISMATCH, "Capability key is not trusted for this issuer");
    const trustedKeyId = trust.key_id ?? trust.keyId;
    if (trustedKeyId !== undefined && trustedKeyId !== keyId) fail(CAPABILITY_REASONS.KEY_ID_NOT_TRUSTED, "Capability key ID is not trusted");
    return publicKeyFor(directKey);
  }
  const issuers = trust.issuers ?? trust.trustedIssuers ?? options.issuers ?? options.trustedIssuers;
  if (issuers !== undefined) {
    const issuerEntry = getValue(issuers, issuer);
    if (issuerEntry === undefined) fail(CAPABILITY_REASONS.ISSUER_NOT_TRUSTED, "Capability issuer is not trusted");
    if (issuerEntry?.public_key !== undefined || issuerEntry?.publicKey !== undefined) {
      const trustedKeyId = issuerEntry.key_id ?? issuerEntry.keyId;
      if (trustedKeyId !== undefined && trustedKeyId !== keyId) fail(CAPABILITY_REASONS.KEY_ID_NOT_TRUSTED, "Capability key ID is not trusted");
      return publicKeyFor(issuerEntry.public_key ?? issuerEntry.publicKey);
    }
    const keys = issuerEntry?.keys ?? issuerEntry;
    const key = getValue(keys, keyId);
    if (key === undefined) fail(CAPABILITY_REASONS.KEY_ID_NOT_TRUSTED, "Capability key ID is not trusted");
    return publicKeyFor(key);
  }
  const keys = trust.keys ?? options.keys ?? trust.trustedKeys ?? options.trustedKeys ?? trust.trusted_keys ?? options.trusted_keys;
  if (keys === undefined) fail(CAPABILITY_REASONS.ISSUER_NOT_TRUSTED, "Capability issuer trust is not configured");
  if (isKeyObject(keys)) return publicKeyFor(keys);
  const entry = getValue(keys, keyId);
  if (entry === undefined) fail(CAPABILITY_REASONS.KEY_ID_NOT_TRUSTED, "Capability key ID is not trusted");
  if (entry && typeof entry === "object" && !isKeyObject(entry) && entry.issuer !== undefined && entry.issuer !== issuer) fail(CAPABILITY_REASONS.ISSUER_KEY_MISMATCH, "Capability key is not trusted for this issuer");
  return publicKeyFor(entry?.public_key ?? entry?.publicKey ?? entry);
}

function enforceSequence(capability, options, trust) {
  const highest = options.highestSequence ?? trust.highestSequence;
  if (highest !== undefined && (!Number.isSafeInteger(highest) || capability.sequence < highest)) fail(CAPABILITY_REASONS.SEQUENCE_ROLLBACK, "Capability sequence rolled back");
  const state = options.sequenceState ?? trust.sequenceState;
  const capabilityHash = crypto.createHash("sha256").update(canonicalBytes(capability)).digest("hex");
  const highestHash = options.highestCapabilityHash ?? trust.highestCapabilityHash;
  if (highest !== undefined && capability.sequence === highest && (typeof highestHash !== "string" || highestHash !== capabilityHash)) fail(CAPABILITY_REASONS.SEQUENCE_CONFLICT, "Capability sequence requires matching durable content evidence");
  if (state) {
    if (!Number.isSafeInteger(state.highestSequence ?? 0) || capability.sequence < (state.highestSequence ?? 0)) fail(CAPABILITY_REASONS.SEQUENCE_ROLLBACK, "Capability sequence rolled back");
    if (capability.sequence === state.highestSequence && state.highestCapabilityHash !== undefined && state.highestCapabilityHash !== capabilityHash) {
      fail(CAPABILITY_REASONS.SEQUENCE_CONFLICT, "Capability sequence conflicts with previously verified content");
    }
  }
  const hook = options.sequenceHook ?? options.checkSequence ?? trust.sequenceHook;
  if (hook !== undefined) {
    if (typeof hook !== "function") fail(CAPABILITY_REASONS.SEQUENCE_HOOK_REJECTED, "Capability sequence hook is invalid");
    let result;
    try { result = hook(capability.sequence, capability); } catch { fail(CAPABILITY_REASONS.SEQUENCE_HOOK_REJECTED, "Capability sequence was rejected"); }
    if (result === false || (result && typeof result === "object" && result.allowed === false) || (Number.isSafeInteger(result) && capability.sequence < result)) fail(CAPABILITY_REASONS.SEQUENCE_ROLLBACK, "Capability sequence rolled back");
  }
  const onSequence = options.onSequence ?? trust.onSequence;
  if (onSequence !== undefined) {
    if (typeof onSequence !== "function") fail(CAPABILITY_REASONS.SEQUENCE_HOOK_REJECTED, "Capability sequence hook is invalid");
    try { onSequence(capability.sequence, capability); } catch { fail(CAPABILITY_REASONS.SEQUENCE_HOOK_REJECTED, "Capability sequence was rejected"); }
  }
  if (state && capability.sequence >= (state.highestSequence ?? 0)) {
    state.highestSequence = capability.sequence;
    state.highestCapabilityHash = capabilityHash;
  }
}

function intersectTwoScopes(left, right) {
  const result = {
    operations: intersectExact(left.operations, right.operations),
    repositories: intersectPatterns(left.repositories, right.repositories),
    branches: intersectFilter(left.branches, right.branches),
    remotes: intersectFilter(left.remotes, right.remotes)
  };
  if (left.tags || right.tags) result.tags = left.tags && right.tags ? intersectFilter(left.tags, right.tags) : cloneFilter(left.tags ?? right.tags);
  return result;
}

function intersectFilter(left, right) {
  return {
    allow: intersectPatterns(left.allow, right.allow),
    deny: [...new Set([...(left.deny ?? []), ...(right.deny ?? [])])]
  };
}

function intersectExact(left, right) {
  const values = new Set(right);
  return left.filter((value) => values.has(value));
}

function intersectPatterns(left, right) {
  const output = [];
  for (const a of left) for (const b of right) {
    const narrower = narrowerPattern(a, b);
    if (narrower !== undefined && !output.includes(narrower)) output.push(narrower);
  }
  return output;
}

function narrowerPattern(a, b) {
  if (a === b) return a;
  if (globSubset(a, b)) return a;
  if (globSubset(b, a)) return b;
  return undefined;
}

// This deliberately returns false for patterns whose intersection cannot be
// represented without introducing a new constraint. Under-granting is safe;
// accidentally returning a wider glob would violate the local policy.
function globSubset(inner, outer) {
  if (inner === outer || outer === "*") return true;
  if (!inner.includes("*")) return globMatch(inner, outer);
  if (outer.includes("*") && inner.indexOf("*") === inner.lastIndexOf("*") && outer.indexOf("*") === outer.lastIndexOf("*")) {
    const [ip, is] = splitGlob(inner);
    const [op, os] = splitGlob(outer);
    return ip.startsWith(op) && is.endsWith(os);
  }
  return false;
}

function splitGlob(pattern) {
  const index = pattern.indexOf("*");
  return [pattern.slice(0, index), pattern.slice(index + 1)];
}

function canonicalRepositoryPattern(value) {
  return typeof value === "string" && path.isAbsolute(value) && path.posix.normalize(value) === value && !value.split("/").some((segment) => segment === "." || segment === "..");
}

function canonicalRepositoryPath(value) { return canonicalRepositoryPattern(value) && !value.includes("*"); }

function globMatch(value, pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${escaped}$`).test(value);
}

function matchesFilter(value, filter) {
  return typeof value === "string" && !(filter.deny && matchesAny(value, filter.deny)) && matchesAny(value, filter.allow);
}

function matchesAny(value, patterns) { return patterns.some((pattern) => globMatch(value, pattern)); }

function cloneScope(scope) {
  return {
    operations: [...scope.operations],
    repositories: [...scope.repositories],
    branches: cloneFilter(scope.branches),
    remotes: cloneFilter(scope.remotes),
    ...(scope.tags ? { tags: cloneFilter(scope.tags) } : {})
  };
}

function cloneFilter(filter) { return { allow: [...filter.allow], ...(filter.deny ? { deny: [...filter.deny] } : {}) }; }

function rejectUnknown(value, allowed, reason, label) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(reason, `${label} contains an unknown field: ${key}`);
}

function rejectAliases(value, pairs) {
  for (const [left, right] of pairs) {
    if (Object.hasOwn(value, left) && Object.hasOwn(value, right)) fail(CAPABILITY_REASONS.UNKNOWN_FIELD, `Capability cannot contain both ${left} and ${right}`);
  }
}

function parseCanonicalTimestamp(value) {
  if (typeof value !== "string") fail(CAPABILITY_REASONS.INVALID_TIMESTAMP, "Capability timestamps must be RFC 3339 UTC strings");
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) fail(CAPABILITY_REASONS.INVALID_TIMESTAMP, "Capability timestamps must be canonical UTC strings");
  return parsed;
}

function parseTimestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.getTime();
  return parseCanonicalTimestamp(value);
}

function issueTimestamp(value) {
  const timestamp = parseTimestamp(value);
  if (!Number.isSafeInteger(timestamp)) fail(CAPABILITY_REASONS.INVALID_TIMESTAMP, "Capability timestamp is invalid");
  return new Date(timestamp).toISOString();
}

function toNow(value) {
  const now = value === undefined ? Date.now() : Number(value);
  if (!Number.isFinite(now)) fail(CAPABILITY_REASONS.INVALID_TIMESTAMP, "Verification clock is invalid");
  return now;
}

function isIdentifier(value) { return typeof value === "string" && IDENTIFIER.test(value); }
function isKeyObject(value) { return value && typeof value === "object" && value.type && typeof value.export === "function"; }
function getValue(container, key) {
  if (container instanceof Map) return container.get(key);
  if (Array.isArray(container)) return container.find((item) => item?.key_id === key || item?.keyId === key || item?.id === key);
  if (container && typeof container === "object") return container[key];
  return undefined;
}
function publicKeyFor(value) {
  try {
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.asymmetricKeyType !== "ed25519") throw new Error();
    return key;
  } catch { fail(CAPABILITY_REASONS.KEY_ID_NOT_TRUSTED, "Trusted capability key is not a valid Ed25519 public key"); }
}
function toPrivateKey(value) {
  try { return value?.type === "private" ? value : crypto.createPrivateKey(value); }
  catch { fail(CAPABILITY_REASONS.INVALID_SIGNATURE, "Capability signing key is invalid"); }
}
function fail(reason, message) { throw new CapabilityError(reason, message); }

export function canonicalJson(value) {
  return canonicalValue(value, new Set());
}

function canonicalValue(value, seen) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail(CAPABILITY_REASONS.INVALID_CAPABILITY, "Capability contains a non-finite number");
    return JSON.stringify(value);
  }
  if (!value || typeof value !== "object" || seen.has(value)) fail(CAPABILITY_REASONS.INVALID_CAPABILITY, "Capability is not canonical JSON");
  seen.add(value);
  let encoded;
  if (Array.isArray(value)) {
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string" || (key !== "length" && !/^\d+$/.test(key)))) fail(CAPABILITY_REASONS.INVALID_CAPABILITY, "Capability array has extra properties");
    encoded = `[${value.map((item) => canonicalValue(item, seen)).join(",")}]`;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail(CAPABILITY_REASONS.INVALID_CAPABILITY, "Capability must use plain JSON objects");
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) fail(CAPABILITY_REASONS.INVALID_CAPABILITY, "Capability contains symbol fields");
    encoded = `{${keys.sort().map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key], seen)}`).join(",")}}`;
  }
  seen.delete(value);
  return encoded;
}

function canonicalBytes(value) { return Buffer.from(canonicalJson(value), "utf8"); }

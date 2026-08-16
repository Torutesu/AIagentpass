import path from "node:path";

const PROTOCOL_VERSION = 1;

const ALLOWED_AGENT_KINDS = Object.freeze([
  "claude-code",
  "cursor",
  "mcp",
  "cli",
  "custom"
]);

// v1 intentionally exposes only the operation described by the platform contract.
const ALLOWED_OPERATIONS = Object.freeze(["git.commit.sign"]);

const DECISION_REASONS = Object.freeze([
  "allowed",
  "branch_denied",
  "branch_not_allowed",
  "capability_expired",
  "capability_missing",
  "operation_not_allowed",
  "policy_changed",
  "remote_control_stale",
  "remote_denied",
  "remote_not_allowed",
  "repository_not_allowed",
  "revoked",
  "session_required",
  "signer_failed",
  "tag_denied",
  "tag_not_allowed"
]);

const AUDIT_DECISIONS = Object.freeze(["allow", "deny", "error"]);

const LIMITS = Object.freeze({
  maxDocumentBytes: 16 * 1024,
  maxJsonDepth: 32,
  maxStringBytes: 4096,
  maxNameBytes: 128,
  maxPublicKeyBytes: 8192,
  maxReasonBytes: 128,
  maxArrayItems: 64,
  maxPatternBytes: 2048,
  maxRepositoryBytes: 4096,
  maxNonceBytes: 128
});

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const NONCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const RFC3339_UTC_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const CANONICAL_MILLISECOND_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BASE64URL_16_BYTES = /^[A-Za-z0-9_-]{22}$/;
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;
const BASE64URL_64_BYTES = /^[A-Za-z0-9_-]{86}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const SAFE_CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TEAM_ID = /^[A-Z0-9]{10}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const PEM_PUBLIC_KEY = /^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----\n?$/;
const P256_HALF_ORDER = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");

export const REFRESH_HINT_TYPE = "agentpass.refresh-hint";
export const BUNDLE_ACK_TYPE = "agentpass.bundle-ack";
export const REFRESH_HINT_SIGNATURE_ALGORITHM = "ed25519";
export const BUNDLE_ACK_SIGNATURE_ALGORITHM = "p256-sha256";
export const REFRESH_HINT_SIGNATURE_DOMAIN = "AgentPass-Refresh-Hint-v1\0";
export const BUNDLE_ACK_SIGNATURE_DOMAIN = "AgentPass-Bundle-Ack-v1\0";
export const ONBOARDING_INVITATION_DELIVERY_TYPE = "agentpass.browser-onboarding.invitation";
export const ONBOARDING_TRUST_INSTALLATION_ACK_TYPE = "agentpass.browser-onboarding.trust-installation-ack";
export const ONBOARDING_CONTRACT_VERSION = 1;
export const ONBOARDING_INVITATION_VERSION = 2;
export const BUNDLE_ACK_RESULTS = Object.freeze(["applied", "blocked"]);
export const DEVICE_REFRESH_STATES = Object.freeze([
  "pending",
  "fetching",
  "applied",
  "blocked",
  "stale",
  "offline",
  "revoked"
]);
export const BUNDLE_ACK_REASON_CODES = Object.freeze([
  "bundle_expired",
  "bundle_not_yet_valid",
  "bundle_signature_invalid",
  "bundle_signer_untrusted",
  "bundle_audience_mismatch",
  "bundle_sequence_rollback",
  "bundle_sequence_conflict",
  "bundle_storage_failed",
  "device_revoked",
  "emergency_stop",
  "internal_error"
]);

export { ALLOWED_AGENT_KINDS, ALLOWED_OPERATIONS, AUDIT_DECISIONS, DECISION_REASONS, LIMITS, PROTOCOL_VERSION };

// Short aliases make the protocol constants convenient for adapters while retaining
// the explicit names used by the architecture document.
export const AGENT_KINDS = ALLOWED_AGENT_KINDS;
export const OPERATIONS = ALLOWED_OPERATIONS;
export const PROTOCOL_V1 = PROTOCOL_VERSION;

export class ProtocolValidationError extends TypeError {
  constructor(issues) {
    const normalizedIssues = issues.map((issue) => Object.freeze({
      path: issue.path,
      code: issue.code,
      message: issue.message
    }));
    super(normalizedIssues.map((issue) => `${issue.code} at ${issue.path}: ${issue.message}`).join("; "));
    this.name = "ProtocolValidationError";
    this.code = "ERR_PROTOCOL_VALIDATION";
    this.issues = Object.freeze(normalizedIssues);
  }
}

export function canonicalJson(value) {
  const seen = new Set();
  return canonicalizeValue(value, seen, "$", false);
}

export const canonicalize = canonicalJson;

export function normalizeAgentDescriptor(input) {
  const object = asObject(input, "agent");
  const issues = [];
  exactKeys(object, ["version", "agent_id", "name", "kind", "public_key", "created_at"], "agent", issues);
  const publicKey = stringValue(object.public_key, "agent.public_key", { maxBytes: LIMITS.maxPublicKeyBytes, nonEmpty: true, allowNewlines: true }, issues);
  if (publicKey !== undefined && /PRIVATE KEY/.test(publicKey)) {
    issues.push(issue("agent.public_key", "invalid_public_key", "private key material is not allowed"));
  }
  const value = {
    version: protocolVersion(object.version, "agent.version", issues),
    agent_id: uuid(object.agent_id, "agent.agent_id", issues),
    name: stringValue(object.name, "agent.name", { maxBytes: LIMITS.maxNameBytes, nonEmpty: true }, issues),
    kind: enumValue(object.kind, "agent.kind", ALLOWED_AGENT_KINDS, issues),
    public_key: publicKey,
    created_at: timestamp(object.created_at, "agent.created_at", issues)
  };
  return finish(value, issues, "agent");
}

export function normalizeScope(input) {
  const object = asObject(input, "scope");
  const issues = [];
  exactKeys(object, ["operations", "repositories", "branches", "remotes", "tags"], "scope", issues);
  const value = {
    operations: stringArray(object.operations, "scope.operations", {
      maxBytes: LIMITS.maxPatternBytes,
      nonEmpty: true,
      values: ALLOWED_OPERATIONS
    }, issues),
    repositories: stringArray(object.repositories, "scope.repositories", {
      maxBytes: LIMITS.maxRepositoryBytes,
      nonEmpty: true,
      absolutePath: true
    }, issues),
    branches: normalizePatternSet(object.branches, "scope.branches", issues, true),
    remotes: normalizePatternSet(object.remotes, "scope.remotes", issues, true),
    tags: object.tags === undefined ? undefined : normalizePatternSet(object.tags, "scope.tags", issues, false)
  };
  if (value.tags === undefined) delete value.tags;
  return finish(value, issues, "scope");
}

export function normalizeOperationRequest(input) {
  const object = asObject(input, "request");
  const issues = [];
  exactKeys(object, [
    "version",
    "request_id",
    "agent_id",
    "operation",
    "nonce",
    "requested_at",
    "repository",
    "branch",
    "remote",
    "payload_digest"
  ], "request", issues);
  const value = {
    version: protocolVersion(object.version, "request.version", issues),
    request_id: uuid(object.request_id, "request.request_id", issues),
    agent_id: uuid(object.agent_id, "request.agent_id", issues),
    operation: enumValue(object.operation, "request.operation", ALLOWED_OPERATIONS, issues),
    nonce: nonce(object.nonce, "request.nonce", issues),
    requested_at: timestamp(object.requested_at, "request.requested_at", issues),
    repository: stringValue(object.repository, "request.repository", {
      maxBytes: LIMITS.maxRepositoryBytes,
      nonEmpty: true,
      absolutePath: true
    }, issues),
    branch: stringValue(object.branch, "request.branch", { maxBytes: LIMITS.maxPatternBytes, nonEmpty: true }, issues),
    remote: stringValue(object.remote, "request.remote", { maxBytes: LIMITS.maxPatternBytes, nonEmpty: true }, issues),
    payload_digest: sha256(object.payload_digest, "request.payload_digest", issues)
  };
  return finish(value, issues, "request");
}

export function normalizeDecision(input) {
  const object = asObject(input, "decision");
  const issues = [];
  exactKeys(object, ["version", "allowed", "reason", "operation", "request_id", "evaluated_at"], "decision", issues);
  const value = {
    version: protocolVersion(object.version, "decision.version", issues),
    allowed: booleanValue(object.allowed, "decision.allowed", issues),
    reason: enumValue(object.reason, "decision.reason", DECISION_REASONS, issues),
    operation: enumValue(object.operation, "decision.operation", ALLOWED_OPERATIONS, issues),
    request_id: uuid(object.request_id, "decision.request_id", issues),
    evaluated_at: timestamp(object.evaluated_at, "decision.evaluated_at", issues)
  };
  if (value.allowed === true && value.reason !== undefined && value.reason !== "allowed") {
    issues.push(issue("decision.reason", "inconsistent_value", "allowed decisions must use reason allowed"));
  }
  if (value.allowed === false && value.reason === "allowed") {
    issues.push(issue("decision.reason", "inconsistent_value", "denied decisions cannot use reason allowed"));
  }
  return finish(value, issues, "decision");
}

export function normalizeAuditEvent(input) {
  const object = asObject(input, "audit");
  const issues = [];
  exactKeys(object, [
    "version",
    "event_id",
    "request_id",
    "agent_id",
    "operation",
    "decision",
    "reason",
    "policy_sequence",
    "capability_sequence",
    "repository",
    "branch",
    "remote",
    "payload_digest",
    "device_timestamp",
    "previous_hash",
    "event_hash"
  ], "audit", issues);
  const value = {
    version: protocolVersion(object.version, "audit.version", issues),
    event_id: uuid(object.event_id, "audit.event_id", issues),
    request_id: uuid(object.request_id, "audit.request_id", issues),
    agent_id: uuid(object.agent_id, "audit.agent_id", issues),
    operation: enumValue(object.operation, "audit.operation", ALLOWED_OPERATIONS, issues),
    decision: enumValue(object.decision, "audit.decision", AUDIT_DECISIONS, issues),
    reason: enumValue(object.reason, "audit.reason", DECISION_REASONS, issues),
    policy_sequence: sequence(object.policy_sequence, "audit.policy_sequence", issues),
    capability_sequence: sequence(object.capability_sequence, "audit.capability_sequence", issues),
    repository: stringValue(object.repository, "audit.repository", {
      maxBytes: LIMITS.maxRepositoryBytes,
      nonEmpty: true,
      absolutePath: true
    }, issues),
    branch: stringValue(object.branch, "audit.branch", { maxBytes: LIMITS.maxPatternBytes, nonEmpty: true }, issues),
    remote: stringValue(object.remote, "audit.remote", { maxBytes: LIMITS.maxPatternBytes, nonEmpty: true }, issues),
    payload_digest: sha256(object.payload_digest, "audit.payload_digest", issues),
    device_timestamp: timestamp(object.device_timestamp, "audit.device_timestamp", issues),
    previous_hash: sha256(object.previous_hash, "audit.previous_hash", issues),
    event_hash: sha256(object.event_hash, "audit.event_hash", issues)
  };
  if (value.decision === "allow" && value.reason !== undefined && value.reason !== "allowed") {
    issues.push(issue("audit.reason", "inconsistent_value", "allow audit events must use reason allowed"));
  }
  if (value.decision !== undefined && value.decision !== "allow" && value.reason === "allowed") {
    issues.push(issue("audit.reason", "inconsistent_value", "non-allow audit events cannot use reason allowed"));
  }
  return finish(value, issues, "audit");
}

export function normalizeRefreshHint(input) {
  const object = asObject(input, "refresh_hint");
  const issues = [];
  exactKeys(object, ["version", "type", "organization_id", "device_id", "authority_generation", "published_at", "expires_at", "nonce", "key_id", "signature_algorithm", "signature"], "refresh_hint", issues);
  const publishedAt = canonicalMillisecondTimestamp(object.published_at, "refresh_hint.published_at", issues);
  const expiresAt = canonicalMillisecondTimestamp(object.expires_at, "refresh_hint.expires_at", issues);
  if (publishedAt !== undefined && expiresAt !== undefined) {
    const duration = Date.parse(expiresAt) - Date.parse(publishedAt);
    if (duration <= 0 || duration > 5 * 60_000) issues.push(issue("refresh_hint.expires_at", "invalid_window", "refresh hint lifetime must be greater than zero and at most five minutes"));
  }
  return finish({
    version: protocolVersion(object.version, "refresh_hint.version", issues),
    type: constantString(object.type, REFRESH_HINT_TYPE, "refresh_hint.type", issues),
    organization_id: uuid(object.organization_id, "refresh_hint.organization_id", issues),
    device_id: uuid(object.device_id, "refresh_hint.device_id", issues),
    authority_generation: positiveSequence(object.authority_generation, "refresh_hint.authority_generation", issues),
    published_at: publishedAt,
    expires_at: expiresAt,
    nonce: exactBase64Url(object.nonce, 16, BASE64URL_16_BYTES, "refresh_hint.nonce", issues),
    key_id: safeKeyId(object.key_id, "refresh_hint.key_id", issues),
    signature_algorithm: constantString(object.signature_algorithm, REFRESH_HINT_SIGNATURE_ALGORITHM, "refresh_hint.signature_algorithm", issues),
    signature: exactBase64Url(object.signature, 64, BASE64URL_64_BYTES, "refresh_hint.signature", issues)
  }, issues, "refresh_hint");
}

export function normalizeBundleAcknowledgement(input) {
  const object = asObject(input, "bundle_ack");
  const issues = [];
  exactKeys(object, ["version", "type", "organization_id", "device_id", "device_key_epoch", "format_epoch", "sequence", "statement_hash", "result", "reason_code", "observed_at", "nonce", "signature_algorithm", "signature"], "bundle_ack", issues);
  const result = enumValue(object.result, "bundle_ack.result", BUNDLE_ACK_RESULTS, issues);
  const reasonCode = object.reason_code === undefined ? undefined : enumValue(object.reason_code, "bundle_ack.reason_code", BUNDLE_ACK_REASON_CODES, issues);
  if (result === "blocked" && reasonCode === undefined) issues.push(issue("bundle_ack.reason_code", "missing_field", "blocked acknowledgements require a stable reason code"));
  if (result === "applied" && object.reason_code !== undefined) issues.push(issue("bundle_ack.reason_code", "inconsistent_value", "applied acknowledgements cannot include a reason code"));
  return finish({
    version: protocolVersion(object.version, "bundle_ack.version", issues),
    type: constantString(object.type, BUNDLE_ACK_TYPE, "bundle_ack.type", issues),
    organization_id: uuid(object.organization_id, "bundle_ack.organization_id", issues),
    device_id: uuid(object.device_id, "bundle_ack.device_id", issues),
    device_key_epoch: positiveSequence(object.device_key_epoch, "bundle_ack.device_key_epoch", issues),
    format_epoch: exactInteger(object.format_epoch, 2, "bundle_ack.format_epoch", issues),
    sequence: positiveSequence(object.sequence, "bundle_ack.sequence", issues),
    statement_hash: sha256(object.statement_hash, "bundle_ack.statement_hash", issues),
    result,
    reason_code: reasonCode,
    observed_at: canonicalMillisecondTimestamp(object.observed_at, "bundle_ack.observed_at", issues),
    nonce: exactBase64Url(object.nonce, 16, BASE64URL_16_BYTES, "bundle_ack.nonce", issues),
    signature_algorithm: constantString(object.signature_algorithm, BUNDLE_ACK_SIGNATURE_ALGORITHM, "bundle_ack.signature_algorithm", issues),
    signature: canonicalP256Signature(object.signature, "bundle_ack.signature", issues)
  }, issues, "bundle_ack");
}

/** Public, non-secret local setup data imported by the browser-led flow. */
export function normalizeOnboardingPreflight(input) {
  const object = asObject(input, "onboarding_preflight");
  const issues = [];
  exactKeys(object, ["version", "platform", "candidate_id", "device_key_fingerprint"], "onboarding_preflight", issues);
  return finish({
    version: protocolVersion(object.version, "onboarding_preflight.version", issues),
    platform: constantString(object.platform, "macos", "onboarding_preflight.platform", issues),
    candidate_id: boundedPattern(object.candidate_id, SAFE_CANDIDATE_ID, "onboarding_preflight.candidate_id", issues),
    device_key_fingerprint: boundedPattern(object.device_key_fingerprint, FINGERPRINT, "onboarding_preflight.device_key_fingerprint", issues)
  }, issues, "onboarding_preflight");
}

/**
 * Normalize the only credential-bearing browser delivery envelope. It is a
 * one-shot in-memory body: the correlation id and nonce may identify a
 * loopback path, but the invitation itself is never a URL, argv, environment
 * value, durable document, or authority selector.
 */
export function normalizeOnboardingInvitationDelivery(input) {
  const object = asObject(input, "onboarding_invitation_delivery");
  const issues = [];
  exactKeys(object, ["version", "type", "correlation_id", "nonce", "invitation"], "onboarding_invitation_delivery", issues);
  let invitation;
  try {
    invitation = normalizeOnboardingInvitation(object.invitation);
  } catch (error) {
    if (error instanceof ProtocolValidationError) issues.push(...error.issues.map((item) => ({ ...item, path: `onboarding_invitation_delivery.${item.path}` })));
    else issues.push(issue("onboarding_invitation_delivery.invitation", "invalid_value", "invitation is invalid"));
  }
  return finish({
    version: protocolVersion(object.version, "onboarding_invitation_delivery.version", issues),
    type: constantString(object.type, ONBOARDING_INVITATION_DELIVERY_TYPE, "onboarding_invitation_delivery.type", issues),
    correlation_id: exactBase64Url(object.correlation_id, 32, BASE64URL_32_BYTES, "onboarding_invitation_delivery.correlation_id", issues),
    nonce: exactBase64Url(object.nonce, 32, BASE64URL_32_BYTES, "onboarding_invitation_delivery.nonce", issues),
    invitation
  }, issues, "onboarding_invitation_delivery");
}

/** Normalize the secret-free local acknowledgement emitted after trust install. */
export function normalizeOnboardingTrustInstallationAcknowledgement(input) {
  const object = asObject(input, "trust_installation_ack");
  const issues = [];
  exactKeys(object, [
    "version", "type", "organization_id", "device_id", "enrollment_id", "device_key_epoch",
    "control_format_epoch", "control_sequence", "control_statement_hash", "trust_fingerprint", "installed_at", "result"
  ], "trust_installation_ack", issues);
  return finish({
    version: protocolVersion(object.version, "trust_installation_ack.version", issues),
    type: constantString(object.type, ONBOARDING_TRUST_INSTALLATION_ACK_TYPE, "trust_installation_ack.type", issues),
    organization_id: uuid(object.organization_id, "trust_installation_ack.organization_id", issues),
    device_id: uuid(object.device_id, "trust_installation_ack.device_id", issues),
    enrollment_id: uuid(object.enrollment_id, "trust_installation_ack.enrollment_id", issues),
    device_key_epoch: positiveSequence(object.device_key_epoch, "trust_installation_ack.device_key_epoch", issues),
    control_format_epoch: exactInteger(object.control_format_epoch, 2, "trust_installation_ack.control_format_epoch", issues),
    control_sequence: positiveSequence(object.control_sequence, "trust_installation_ack.control_sequence", issues),
    control_statement_hash: sha256(object.control_statement_hash, "trust_installation_ack.control_statement_hash", issues),
    trust_fingerprint: boundedPattern(object.trust_fingerprint, FINGERPRINT, "trust_installation_ack.trust_fingerprint", issues),
    installed_at: canonicalMillisecondTimestamp(object.installed_at, "trust_installation_ack.installed_at", issues),
    result: enumValue(object.result, "trust_installation_ack.result", ["installed", "already_installed"], issues)
  }, issues, "trust_installation_ack");
}

/** Control ACK is the existing signed bundle ACK under its onboarding name. */
export function normalizeOnboardingControlAcknowledgement(input) {
  return normalizeBundleAcknowledgement(input);
}

export function normalizeOnboardingInvitation(input) {
  const issues = [];
  const invitation = normalizeOnboardingInvitationValue(input, issues);
  if (issues.length) throw new ProtocolValidationError(issues);
  return finish(invitation, [], "onboarding_invitation");
}

function normalizeOnboardingInvitationValue(input, issues) {
  const object = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  exactKeys(object, [
    "version", "proof_version", "enrollment_id", "organization_id", "device_id", "label", "platform",
    "candidate_binding", "challenge_id", "nonce", "expires_at", "challenge", "credential", "endpoint",
    "possession_receipt_verification"
  ], "onboarding_invitation", issues);
  const candidate = object.candidate_binding && typeof object.candidate_binding === "object" && !Array.isArray(object.candidate_binding)
    ? object.candidate_binding : {};
  exactKeys(candidate, ["version", "enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256", "source_commit", "team_id", "device_key_fingerprint", "expires_at"], "onboarding_invitation.candidate_binding", issues);
  const challenge = object.challenge && typeof object.challenge === "object" && !Array.isArray(object.challenge) ? object.challenge : {};
  exactKeys(challenge, ["challenge_id", "nonce", "expires_at", "candidate_id", "device_key_fingerprint"], "onboarding_invitation.challenge", issues);
  const verification = object.possession_receipt_verification && typeof object.possession_receipt_verification === "object" && !Array.isArray(object.possession_receipt_verification)
    ? object.possession_receipt_verification : {};
  exactKeys(verification, ["key_id", "algorithm", "public_key"], "onboarding_invitation.possession_receipt_verification", issues);
  const invitation = {
    version: exactInteger(object.version, ONBOARDING_INVITATION_VERSION, "onboarding_invitation.version", issues),
    proof_version: exactInteger(object.proof_version, ONBOARDING_INVITATION_VERSION, "onboarding_invitation.proof_version", issues),
    enrollment_id: uuid(object.enrollment_id, "onboarding_invitation.enrollment_id", issues),
    organization_id: uuid(object.organization_id, "onboarding_invitation.organization_id", issues),
    device_id: uuid(object.device_id, "onboarding_invitation.device_id", issues),
    label: stringValue(object.label, "onboarding_invitation.label", { maxBytes: LIMITS.maxNameBytes, nonEmpty: true }, issues),
    platform: constantString(object.platform, "macos", "onboarding_invitation.platform", issues),
    candidate_binding: {
      version: exactInteger(candidate.version, 1, "onboarding_invitation.candidate_binding.version", issues),
      enrollment_id: uuid(candidate.enrollment_id, "onboarding_invitation.candidate_binding.enrollment_id", issues),
      organization_id: uuid(candidate.organization_id, "onboarding_invitation.candidate_binding.organization_id", issues),
      device_id: uuid(candidate.device_id, "onboarding_invitation.candidate_binding.device_id", issues),
      candidate_id: boundedPattern(candidate.candidate_id, SAFE_CANDIDATE_ID, "onboarding_invitation.candidate_binding.candidate_id", issues),
      artifact_sha256: sha256(candidate.artifact_sha256, "onboarding_invitation.candidate_binding.artifact_sha256", issues),
      source_commit: boundedPattern(candidate.source_commit, /^[0-9a-f]{40}$/, "onboarding_invitation.candidate_binding.source_commit", issues),
      team_id: boundedPattern(candidate.team_id, TEAM_ID, "onboarding_invitation.candidate_binding.team_id", issues),
      device_key_fingerprint: boundedPattern(candidate.device_key_fingerprint, FINGERPRINT, "onboarding_invitation.candidate_binding.device_key_fingerprint", issues),
      expires_at: canonicalMillisecondTimestamp(candidate.expires_at, "onboarding_invitation.candidate_binding.expires_at", issues)
    },
    challenge_id: uuid(object.challenge_id, "onboarding_invitation.challenge_id", issues),
    nonce: exactBase64Url(object.nonce, 32, BASE64URL_32_BYTES, "onboarding_invitation.nonce", issues),
    expires_at: canonicalMillisecondTimestamp(object.expires_at, "onboarding_invitation.expires_at", issues),
    challenge: {
      challenge_id: uuid(challenge.challenge_id, "onboarding_invitation.challenge.challenge_id", issues),
      nonce: exactBase64Url(challenge.nonce, 32, BASE64URL_32_BYTES, "onboarding_invitation.challenge.nonce", issues),
      expires_at: canonicalMillisecondTimestamp(challenge.expires_at, "onboarding_invitation.challenge.expires_at", issues),
      candidate_id: boundedPattern(challenge.candidate_id, SAFE_CANDIDATE_ID, "onboarding_invitation.challenge.candidate_id", issues),
      device_key_fingerprint: boundedPattern(challenge.device_key_fingerprint, FINGERPRINT, "onboarding_invitation.challenge.device_key_fingerprint", issues)
    },
    credential: exactBase64Url(object.credential, 32, BASE64URL_32_BYTES, "onboarding_invitation.credential", issues),
    endpoint: boundedPattern(object.endpoint, /^\/v1\/enrollments\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, "onboarding_invitation.endpoint", issues),
    possession_receipt_verification: {
      key_id: safeKeyId(verification.key_id, "onboarding_invitation.possession_receipt_verification.key_id", issues),
      algorithm: enumValue(verification.algorithm, "onboarding_invitation.possession_receipt_verification.algorithm", ["ed25519", "p256-sha256"], issues),
      public_key: stringValue(verification.public_key, "onboarding_invitation.possession_receipt_verification.public_key", { maxBytes: LIMITS.maxPublicKeyBytes, nonEmpty: true, allowNewlines: true }, issues)
    }
  };
  if (invitation.possession_receipt_verification.public_key !== undefined && !PEM_PUBLIC_KEY.test(invitation.possession_receipt_verification.public_key)) issues.push(issue("onboarding_invitation.possession_receipt_verification.public_key", "invalid_public_key", "expected a PEM public key"));
  if (typeof invitation.possession_receipt_verification.public_key === "string" && /PRIVATE KEY/i.test(invitation.possession_receipt_verification.public_key)) issues.push(issue("onboarding_invitation.possession_receipt_verification.public_key", "invalid_public_key", "private key material is not allowed"));
  if (invitation.challenge_id !== undefined && invitation.enrollment_id !== undefined && invitation.challenge_id !== invitation.enrollment_id) issues.push(issue("onboarding_invitation.challenge_id", "inconsistent_value", "challenge_id must equal enrollment_id"));
  for (const [label, actual, expected] of [["candidate_binding.enrollment_id", invitation.candidate_binding.enrollment_id, invitation.enrollment_id], ["candidate_binding.organization_id", invitation.candidate_binding.organization_id, invitation.organization_id], ["candidate_binding.device_id", invitation.candidate_binding.device_id, invitation.device_id], ["candidate_binding.expires_at", invitation.candidate_binding.expires_at, invitation.expires_at], ["challenge.challenge_id", invitation.challenge.challenge_id, invitation.challenge_id], ["challenge.nonce", invitation.challenge.nonce, invitation.nonce], ["challenge.expires_at", invitation.challenge.expires_at, invitation.expires_at], ["challenge.candidate_id", invitation.challenge.candidate_id, invitation.candidate_binding.candidate_id], ["challenge.device_key_fingerprint", invitation.challenge.device_key_fingerprint, invitation.candidate_binding.device_key_fingerprint]]) {
    if (leftValueMismatch(label, actual, expected)) issues.push(issue(`onboarding_invitation.${label}`, "inconsistent_value", "invitation binding does not match"));
  }
  return invitation;
}

function leftValueMismatch(_label, actual, expected) {
  return actual !== undefined && expected !== undefined && actual !== expected;
}

function boundedPattern(value, pattern, path, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected a bounded string"));
    return undefined;
  }
  if (Buffer.byteLength(value, "utf8") > LIMITS.maxStringBytes || !pattern.test(value)) issues.push(issue(path, "invalid_value", "value is outside the bounded contract"));
  return value;
}

// This is the closed public inventory of the wire contracts exposed by this
// package.  Keep this data deliberately boring: it is metadata for discovery
// and compatibility checks, not an authority document.  In particular, it
// must never grow parser functions, signing keys, signatures, or credentials.
const CONTRACT_DEFINITIONS = [
  { kind: "agent_descriptor_v1", version: PROTOCOL_VERSION, purpose: "agent-descriptor", parser_version: PROTOCOL_VERSION },
  { kind: "operation_request_v1", version: PROTOCOL_VERSION, purpose: "operation-request", parser_version: PROTOCOL_VERSION },
  { kind: "operation_decision_v1", version: PROTOCOL_VERSION, purpose: "operation-decision", parser_version: PROTOCOL_VERSION },
  { kind: "audit_event_v1", version: PROTOCOL_VERSION, purpose: "audit-event", parser_version: PROTOCOL_VERSION },
  { kind: "refresh_hint_v1", version: PROTOCOL_VERSION, purpose: "refresh-hint", parser_version: PROTOCOL_VERSION },
  { kind: "bundle_ack_v1", version: PROTOCOL_VERSION, purpose: "bundle-ack", parser_version: PROTOCOL_VERSION },
  { kind: "onboarding_preflight_v1", version: ONBOARDING_CONTRACT_VERSION, purpose: "onboarding-preflight", parser_version: ONBOARDING_CONTRACT_VERSION },
  { kind: "onboarding_invitation_delivery_v1", version: ONBOARDING_CONTRACT_VERSION, purpose: "onboarding-invitation-delivery", parser_version: ONBOARDING_CONTRACT_VERSION },
  { kind: "onboarding_trust_installation_ack_v1", version: ONBOARDING_CONTRACT_VERSION, purpose: "onboarding-trust-installation-ack", parser_version: ONBOARDING_CONTRACT_VERSION },
  { kind: "onboarding_control_ack_v1", version: ONBOARDING_CONTRACT_VERSION, purpose: "onboarding-control-ack", parser_version: ONBOARDING_CONTRACT_VERSION }
];

const CONTRACT_PARSERS = Object.freeze({
  agent_descriptor_v1: normalizeAgentDescriptor,
  operation_request_v1: normalizeOperationRequest,
  operation_decision_v1: normalizeDecision,
  audit_event_v1: normalizeAuditEvent,
  refresh_hint_v1: normalizeRefreshHint,
  bundle_ack_v1: normalizeBundleAcknowledgement,
  onboarding_preflight_v1: normalizeOnboardingPreflight,
  onboarding_invitation_delivery_v1: normalizeOnboardingInvitationDelivery,
  onboarding_trust_installation_ack_v1: normalizeOnboardingTrustInstallationAcknowledgement,
  onboarding_control_ack_v1: normalizeOnboardingControlAcknowledgement
});
const PUBLIC_CONTRACT_METADATA_KEYS = Object.freeze(["kind", "version", "purpose", "parser_version"]);

function createPublicContractManifest(definitions) {
  const kinds = new Set();
  const purposes = new Set();
  const contracts = definitions.map((definition) => {
    const keys = Object.keys(definition).sort();
    if (keys.length !== PUBLIC_CONTRACT_METADATA_KEYS.length || keys.some((key, index) => key !== PUBLIC_CONTRACT_METADATA_KEYS.toSorted()[index])) {
      throw new Error(`public contract metadata has an unsupported shape: ${definition.kind}`);
    }
    if (kinds.has(definition.kind)) throw new Error(`duplicate public contract kind: ${definition.kind}`);
    if (purposes.has(definition.purpose)) throw new Error(`duplicate public contract purpose: ${definition.purpose}`);
    if (typeof CONTRACT_PARSERS[definition.kind] !== "function") throw new Error(`missing parser for public contract kind: ${definition.kind}`);
    kinds.add(definition.kind);
    purposes.add(definition.purpose);
    return Object.freeze({ ...definition });
  });
  return deepFreeze({
    version: PROTOCOL_VERSION,
    contracts
  });
}

export const CONTRACT_MANIFEST_VERSION = PROTOCOL_VERSION;
export const CONTRACT_KINDS = Object.freeze(CONTRACT_DEFINITIONS.map(({ kind }) => kind));
export const PUBLIC_CONTRACT_MANIFEST = createPublicContractManifest(CONTRACT_DEFINITIONS);
const CONTRACT_METADATA_BY_KIND = Object.freeze(Object.fromEntries(
  PUBLIC_CONTRACT_MANIFEST.contracts.map((contract) => [contract.kind, contract])
));

// Alias retained for consumers that refer to the public inventory simply as
// the contract manifest. Both names point to the same immutable object.
export const CONTRACT_MANIFEST = PUBLIC_CONTRACT_MANIFEST;

/** Return the immutable public contract inventory. */
export function getPublicContractManifest() {
  return PUBLIC_CONTRACT_MANIFEST;
}

/** Return immutable metadata for one known contract kind. */
export function getContractMetadata(kind) {
  if (typeof kind !== "string") {
    throw new ProtocolValidationError([issue("kind", "invalid_type", "expected a known contract kind")]);
  }
  if (!Object.hasOwn(CONTRACT_METADATA_BY_KIND, kind)) {
    throw new ProtocolValidationError([issue("kind", "unknown_kind", `expected one of ${CONTRACT_KINDS.join(", ")}`)]);
  }
  return CONTRACT_METADATA_BY_KIND[kind];
}

export function refreshHintSigningData(input) {
  const { signature: _signature, ...statement } = normalizeRefreshHint(input);
  return Buffer.concat([Buffer.from(REFRESH_HINT_SIGNATURE_DOMAIN, "utf8"), Buffer.from(canonicalJson(statement), "utf8")]);
}

export function bundleAcknowledgementSigningData(input) {
  const { signature: _signature, ...statement } = normalizeBundleAcknowledgement(input);
  return Buffer.concat([Buffer.from(BUNDLE_ACK_SIGNATURE_DOMAIN, "utf8"), Buffer.from(canonicalJson(statement), "utf8")]);
}

/**
 * Decode a refresh hint received across an untrusted JSON boundary.
 *
 * This intentionally does not use JSON.parse directly: JSON.parse silently
 * accepts duplicate object members and cannot distinguish malformed UTF-8
 * after a lossy string conversion. The strict decoder below preserves the
 * boundary properties before handing the resulting object to the normalizer.
 */
export function parseRefreshHintJson(input) {
  return parseContractJson("refresh_hint_v1", input);
}

/** Decode a bundle acknowledgement received across an untrusted JSON boundary. */
export function parseBundleAcknowledgementJson(input) {
  return parseContractJson("bundle_ack_v1", input);
}

export function parseOnboardingPreflightJson(input) {
  return parseContractJson("onboarding_preflight_v1", input);
}

export function parseOnboardingInvitationDeliveryJson(input) {
  return parseContractJson("onboarding_invitation_delivery_v1", input);
}

export function parseOnboardingTrustInstallationAcknowledgementJson(input) {
  return parseContractJson("onboarding_trust_installation_ack_v1", input);
}

export function parseOnboardingControlAcknowledgementJson(input) {
  return parseContractJson("onboarding_control_ack_v1", input);
}

/**
 * Decode any public contract through the parser selected by the closed
 * manifest. Unknown kinds fail before the input crosses the JSON boundary.
 */
export function parseContractJson(kind, input) {
  const metadata = getContractMetadata(kind);
  const parser = CONTRACT_PARSERS[metadata.kind];
  return parseProtocolJson(input, metadata.kind, parser);
}

export function parseAgentJson(input) { return parseContractJson("agent_descriptor_v1", input); }
export function parseOperationRequestJson(input) { return parseContractJson("operation_request_v1", input); }
export function parseDecisionJson(input) { return parseContractJson("operation_decision_v1", input); }
export function parseAuditEventJson(input) { return parseContractJson("audit_event_v1", input); }

export function validateAgentDescriptor(input) { return normalizeAgentDescriptor(input); }
export function validateScope(input) { return normalizeScope(input); }
export function validateOperationRequest(input) { return normalizeOperationRequest(input); }
export function validateDecision(input) { return normalizeDecision(input); }
export function validateAuditEvent(input) { return normalizeAuditEvent(input); }
export function validateRefreshHint(input) { return normalizeRefreshHint(input); }
export function validateBundleAcknowledgement(input) { return normalizeBundleAcknowledgement(input); }
export function validateOnboardingPreflight(input) { return normalizeOnboardingPreflight(input); }
export function validateOnboardingInvitationDelivery(input) { return normalizeOnboardingInvitationDelivery(input); }
export function validateOnboardingTrustInstallationAcknowledgement(input) { return normalizeOnboardingTrustInstallationAcknowledgement(input); }
export function validateOnboardingControlAcknowledgement(input) { return normalizeOnboardingControlAcknowledgement(input); }

export function isValidAgentDescriptor(input) { return valid(normalizeAgentDescriptor, input); }
export function isValidScope(input) { return valid(normalizeScope, input); }
export function isValidOperationRequest(input) { return valid(normalizeOperationRequest, input); }
export function isValidDecision(input) { return valid(normalizeDecision, input); }
export function isValidAuditEvent(input) { return valid(normalizeAuditEvent, input); }
export function isValidRefreshHint(input) { return valid(normalizeRefreshHint, input); }
export function isValidBundleAcknowledgement(input) { return valid(normalizeBundleAcknowledgement, input); }
export function isValidOnboardingPreflight(input) { return valid(normalizeOnboardingPreflight, input); }
export function isValidOnboardingInvitationDelivery(input) { return valid(normalizeOnboardingInvitationDelivery, input); }
export function isValidOnboardingTrustInstallationAcknowledgement(input) { return valid(normalizeOnboardingTrustInstallationAcknowledgement, input); }
export function isValidOnboardingControlAcknowledgement(input) { return valid(normalizeOnboardingControlAcknowledgement, input); }

function normalizePatternSet(input, path, issues, required) {
  const object = input === undefined && !required ? {} : asObject(input, path);
  exactKeys(object, ["allow", "deny"], path, issues);
  const value = {
    allow: stringArray(object.allow, `${path}.allow`, {
      maxBytes: LIMITS.maxPatternBytes,
      nonEmpty: required,
      allowEmpty: !required
    }, issues),
    deny: stringArray(object.deny, `${path}.deny`, {
      maxBytes: LIMITS.maxPatternBytes,
      allowEmpty: true
    }, issues)
  };
  return value;
}

function finish(value, issues, label) {
  if (issues.length) throw new ProtocolValidationError(issues);
  const normalized = stripUndefined(value);
  const encoded = canonicalJson(normalized);
  if (Buffer.byteLength(encoded, "utf8") > LIMITS.maxDocumentBytes) {
    throw new ProtocolValidationError([issue(label, "limit_exceeded", `canonical document exceeds ${LIMITS.maxDocumentBytes} bytes`)]);
  }
  return deepFreeze(normalized);
}

function asObject(value, path) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolValidationError([issue(path, "invalid_type", "expected a JSON object")]);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new ProtocolValidationError([issue(path, "invalid_type", "expected a plain JSON object")]);
  }
  return value;
}

function exactKeys(object, allowed, path, issues) {
  const allowedSet = new Set(allowed);
  for (const key of Reflect.ownKeys(object)) {
    if (typeof key !== "string" || !allowedSet.has(key)) {
      issues.push(issue(`${path}.${typeof key === "string" ? key : "<symbol>"}`, "unknown_field", "field is not allowed"));
    }
  }
}

function protocolVersion(value, path, issues) {
  if (value !== PROTOCOL_VERSION) {
    issues.push(issue(path, "invalid_version", `expected protocol version ${PROTOCOL_VERSION}`));
    return undefined;
  }
  return PROTOCOL_VERSION;
}

function uuid(value, path, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected a UUID string"));
    return undefined;
  }
  if (!UUID_PATTERN.test(value)) {
    issues.push(issue(path, "invalid_uuid", "expected a canonical RFC 4122 UUID"));
    return undefined;
  }
  return value.toLowerCase();
}

function nonce(value, path, issues) {
  const result = stringValue(value, path, { maxBytes: LIMITS.maxNonceBytes, nonEmpty: true }, issues);
  if (result !== undefined && !NONCE_PATTERN.test(result)) {
    issues.push(issue(path, "invalid_nonce", "expected a bounded token using letters, digits, or . _ : -"));
  }
  return result;
}

function timestamp(value, path, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected an RFC 3339 UTC string"));
    return undefined;
  }
  if (!RFC3339_UTC_PATTERN.test(value)) {
    issues.push(issue(path, "invalid_timestamp", "expected an RFC 3339 UTC timestamp ending in Z"));
    return undefined;
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    issues.push(issue(path, "invalid_timestamp", "timestamp is not a real date"));
    return undefined;
  }
  return date.toISOString();
}

function sha256(value, path, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected a lowercase SHA-256 hex digest"));
    return undefined;
  }
  if (!SHA256_PATTERN.test(value)) {
    issues.push(issue(path, "invalid_digest", "expected exactly 64 lowercase hexadecimal characters"));
    return undefined;
  }
  return value;
}

function sequence(value, path, issues) {
  if (!Number.isSafeInteger(value) || value < 0) {
    issues.push(issue(path, "invalid_sequence", "expected a non-negative safe integer"));
    return undefined;
  }
  return value;
}

function positiveSequence(value, path, issues) {
  if (!Number.isSafeInteger(value) || value < 1) {
    issues.push(issue(path, "invalid_sequence", "expected a positive safe integer"));
    return undefined;
  }
  return value;
}

function exactInteger(value, expected, path, issues) {
  if (value !== expected) {
    issues.push(issue(path, "invalid_value", `expected integer ${expected}`));
    return undefined;
  }
  return expected;
}

function constantString(value, expected, path, issues) {
  if (value !== expected) {
    issues.push(issue(path, "invalid_value", `expected ${expected}`));
    return undefined;
  }
  return expected;
}

function canonicalMillisecondTimestamp(value, path, issues) {
  if (typeof value !== "string" || !CANONICAL_MILLISECOND_TIMESTAMP.test(value)) {
    issues.push(issue(path, "invalid_timestamp", "expected canonical UTC timestamp with exactly millisecond precision"));
    return undefined;
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) {
    issues.push(issue(path, "invalid_timestamp", "timestamp is not a real canonical UTC instant"));
    return undefined;
  }
  return value;
}

function exactBase64Url(value, bytes, pattern, path, issues) {
  if (typeof value !== "string" || !pattern.test(value)) {
    issues.push(issue(path, "invalid_encoding", `expected canonical unpadded base64url for exactly ${bytes} bytes`));
    return undefined;
  }
  let decoded;
  try { decoded = Buffer.from(value, "base64url"); }
  catch { decoded = null; }
  if (!decoded || decoded.length !== bytes || decoded.toString("base64url") !== value) {
    issues.push(issue(path, "invalid_encoding", `expected canonical unpadded base64url for exactly ${bytes} bytes`));
    return undefined;
  }
  return value;
}

function safeKeyId(value, path, issues) {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) {
    issues.push(issue(path, "invalid_identifier", "expected a bounded key identifier"));
    return undefined;
  }
  return value;
}

function canonicalP256Signature(value, path, issues) {
  const normalized = exactBase64Url(value, 64, BASE64URL_64_BYTES, path, issues);
  if (normalized === undefined) return undefined;
  const bytes = Buffer.from(normalized, "base64url");
  const r = bytes.subarray(0, 32);
  const s = bytes.subarray(32);
  const zero = Buffer.alloc(32);
  if (r.equals(zero) || s.equals(zero) || Buffer.compare(s, P256_HALF_ORDER) > 0) {
    issues.push(issue(path, "noncanonical_signature", "expected non-zero IEEE-P1363 P-256 signature with canonical low-S encoding"));
    return undefined;
  }
  return normalized;
}

function booleanValue(value, path, issues) {
  if (typeof value !== "boolean") {
    issues.push(issue(path, "invalid_type", "expected a boolean"));
    return undefined;
  }
  return value;
}

function enumValue(value, path, allowed, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", `expected one of ${allowed.join(", ")}`));
    return undefined;
  }
  if (!allowed.includes(value)) {
    issues.push(issue(path, "invalid_value", `expected one of ${allowed.join(", ")}`));
    return undefined;
  }
  return value;
}

function stringArray(value, path, options, issues) {
  if (!Array.isArray(value)) {
    if (options.allowEmpty && value === undefined) return [];
    issues.push(issue(path, "invalid_type", "expected an array of strings"));
    return [];
  }
  if (value.length > LIMITS.maxArrayItems) {
    issues.push(issue(path, "limit_exceeded", `array cannot contain more than ${LIMITS.maxArrayItems} items`));
  }
  if (options.nonEmpty && value.length === 0) {
    issues.push(issue(path, "empty_value", "array must contain at least one item"));
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const item = stringValue(value[index], `${path}[${index}]`, {
      maxBytes: options.maxBytes,
      nonEmpty: true,
      absolutePath: options.absolutePath
    }, issues);
    if (item !== undefined && options.values && !options.values.includes(item)) {
      issues.push(issue(`${path}[${index}]`, "invalid_value", `expected one of ${options.values.join(", ")}`));
    }
    if (item !== undefined) result.push(item);
  }
  return result;
}

function stringValue(value, path, options, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected a string"));
    return undefined;
  }
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes > options.maxBytes) {
    issues.push(issue(path, "limit_exceeded", `string cannot exceed ${options.maxBytes} UTF-8 bytes`));
  }
  if (options.nonEmpty && value.length === 0) {
    issues.push(issue(path, "empty_value", "string must not be empty"));
  }
  const controls = options.allowNewlines ? value.replace(/[\r\n]/g, "") : value;
  if (CONTROL_CHARACTER_PATTERN.test(controls)) {
    issues.push(issue(path, "unsafe_string", "control characters are not allowed"));
  }
  if (options.absolutePath && (!value.startsWith("/") || value.split("/").some((segment) => segment === "." || segment === "..") || pathModuleNormalize(value) !== value)) {
    issues.push(issue(path, "invalid_path", "repository paths must be absolute and canonical"));
  }
  return value;
}

function pathModuleNormalize(value) { return path.posix.normalize(value); }

function issue(path, code, message) {
  return { path, code, message };
}

function stripUndefined(value) {
  if (Array.isArray(value)) return value.map(stripUndefined);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .map(([key, item]) => [key, stripUndefined(item)]));
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function valid(normalizer, value) {
  try {
    normalizer(value);
    return true;
  } catch (error) {
    if (error instanceof ProtocolValidationError) return false;
    throw error;
  }
}

function parseProtocolJson(input, label, normalizer) {
  const text = decodeJsonUtf8(input, label);
  const value = new StrictJsonParser(text, label).parse();
  return normalizer(value);
}

function decodeJsonUtf8(input, label) {
  let bytes;
  let text;
  if (typeof input === "string") {
    if (hasLoneSurrogate(input)) {
      throw jsonBoundaryError(label, "invalid_utf8", "input string contains an unpaired UTF-16 surrogate");
    }
    bytes = Buffer.from(input, "utf8");
    text = input;
  } else if (Buffer.isBuffer(input)) {
    bytes = input;
  } else if (input instanceof Uint8Array) {
    bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  } else if (input instanceof ArrayBuffer) {
    bytes = Buffer.from(input);
  } else if (ArrayBuffer.isView(input)) {
    bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  } else {
    throw jsonBoundaryError(label, "invalid_type", "expected a UTF-8 JSON string or byte buffer");
  }

  if (bytes.byteLength > LIMITS.maxDocumentBytes) {
    throw jsonBoundaryError(label, "limit_exceeded", `JSON document cannot exceed ${LIMITS.maxDocumentBytes} UTF-8 bytes`);
  }

  if (text === undefined) {
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      throw jsonBoundaryError(label, "invalid_utf8", "input is not valid UTF-8");
    }
  }
  if (text.startsWith("\uFEFF")) {
    throw jsonBoundaryError(label, "malformed_json", "a UTF-8 BOM is not permitted");
  }
  return text;
}

function hasLoneSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

class StrictJsonParser {
  constructor(text, label) {
    this.text = text;
    this.label = label;
    this.index = 0;
  }

  parse() {
    this.skipWhitespace();
    const value = this.readValue(0, this.label);
    this.skipWhitespace();
    if (this.index !== this.text.length) this.fail("malformed_json", "trailing data is not permitted");
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      this.fail("invalid_type", "top-level JSON value must be an object");
    }
    return value;
  }

  readValue(depth, path) {
    this.skipWhitespace();
    const code = this.text.charCodeAt(this.index);
    if (code === 0x7b) return this.readObject(depth, path);
    if (code === 0x5b) return this.readArray(depth, path);
    if (code === 0x22) return this.readString();
    if (code === 0x74 && this.consumeLiteral("true")) return true;
    if (code === 0x66 && this.consumeLiteral("false")) return false;
    if (code === 0x6e && this.consumeLiteral("null")) return null;
    if (code === 0x2d || (code >= 0x30 && code <= 0x39)) return this.readNumber();
    this.fail("malformed_json", "expected a JSON value");
  }

  readObject(depth, path) {
    this.enterComposite(depth);
    this.index += 1;
    const object = Object.create(null);
    const keys = new Set();
    this.skipWhitespace();
    if (this.consume("}")) return object;
    while (true) {
      this.skipWhitespace();
      if (this.text.charCodeAt(this.index) !== 0x22) this.fail("malformed_json", "object keys must be strings");
      const key = this.readString();
      if (keys.has(key)) this.fail("duplicate_field", `duplicate JSON field ${JSON.stringify(key)}`, `${path}.${key}`);
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) this.fail("malformed_json", "object member is missing a colon");
      object[key] = this.readValue(depth + 1, `${path}.${key}`);
      this.skipWhitespace();
      if (this.consume("}")) return object;
      if (!this.consume(",")) this.fail("malformed_json", "object members must be comma separated");
    }
  }

  readArray(depth, path) {
    this.enterComposite(depth);
    this.index += 1;
    const array = [];
    this.skipWhitespace();
    if (this.consume("]")) return array;
    while (true) {
      array.push(this.readValue(depth + 1, `${path}[${array.length}]`));
      this.skipWhitespace();
      if (this.consume("]")) return array;
      if (!this.consume(",")) this.fail("malformed_json", "array values must be comma separated");
    }
  }

  readString() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        const raw = this.text.slice(start, this.index);
        try {
          const value = JSON.parse(raw);
          if (typeof value !== "string") this.fail("malformed_json", "invalid JSON string");
          return value;
        } catch (error) {
          if (error instanceof ProtocolValidationError) throw error;
          this.fail("malformed_json", "invalid JSON string");
        }
      }
      if (code === 0x5c) {
        this.index += 2;
        continue;
      }
      if (code < 0x20) this.fail("malformed_json", "JSON strings cannot contain control characters");
      this.index += 1;
    }
    this.fail("malformed_json", "unterminated JSON string");
  }

  readNumber() {
    const match = this.text.slice(this.index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (!match) this.fail("malformed_json", "invalid JSON number");
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.fail("malformed_json", "JSON number is outside the supported range");
    return value;
  }

  consume(value) {
    if (this.text.startsWith(value, this.index)) {
      this.index += value.length;
      return true;
    }
    return false;
  }

  consumeLiteral(value) {
    return this.consume(value);
  }

  skipWhitespace() {
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) return;
      this.index += 1;
    }
  }

  enterComposite(depth) {
    if (depth + 1 > LIMITS.maxJsonDepth) {
      this.fail("json_too_deep", `JSON nesting cannot exceed ${LIMITS.maxJsonDepth} levels`);
    }
  }

  fail(code, message, path = this.label) {
    throw jsonBoundaryError(path, code, message);
  }
}

function jsonBoundaryError(path, code, message) {
  return new ProtocolValidationError([issue(path, code, message)]);
}

function canonicalizeValue(value, seen, path, inArray) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw canonicalError(path, "non-finite numbers are not valid JSON");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw canonicalError(path, "value is not JSON-serializable");
  if (seen.has(value)) throw canonicalError(path, "cyclic values are not valid JSON");
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) throw canonicalError(`${path}[${index}]`, "sparse arrays are not valid JSON");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^\d+$/.test(key)))) {
      throw canonicalError(path, "arrays may not have symbol or extra properties");
    }
    result = `[${value.map((item, index) => canonicalizeValue(item, seen, `${path}[${index}]`, true)).join(",")}]`;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw canonicalError(path, "only plain objects are valid JSON");
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) throw canonicalError(path, "symbol keys are not valid JSON");
    result = `{${keys.sort().map((key) => `${JSON.stringify(key)}:${canonicalizeValue(value[key], seen, `${path}.${key}`, false)}`).join(",")}}`;
  }
  seen.delete(value);
  return result;
}

function canonicalError(path, message) {
  return new ProtocolValidationError([issue(path, "invalid_json", message)]);
}

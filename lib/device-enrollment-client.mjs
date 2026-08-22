import crypto from "node:crypto";

import { canonicalDeviceRequest } from "../apps/cloud-api/src/auth.mjs";
import { parseControlBundleJson } from "./control-bundle-v2.mjs";
import { canonicalJson } from "./identity.mjs";

const VERSION = 1;
const PLATFORM = "macos";
const METHOD = "POST";
const PROOF_HEADER = "AgentPass-Enrollment-Signature";
const CREDENTIAL_HEADER = "AgentPass-Enrollment-Credential";
const NONCE_HEADER = "AgentPass-Enrollment-Nonce";
const CANDIDATE_BINDING_HEADER = "AgentPass-Enrollment-Candidate-Binding";
const PROOF_PROTOCOL = "AgentPass-Enrollment-Proof-v1";
const PROOF_PROTOCOL_V2 = "AgentPass-Enrollment-Proof-v2";
const RECEIPT_PROTOCOL_V1 = "AgentPass-Cloud-Possession-Receipt-v1";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_DEPTH = 16;
const MAX_LABEL_CODE_POINTS = 128;
const MAX_PEM_BYTES = 8 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_CREDENTIAL = /^[A-Za-z0-9_-]{43}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RECEIPT_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/;
const TEAM_ID = /^[A-Z0-9]{10}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1"]);
const RESPONSE_KEYS = new Set(["request_id", "enrollment"]);
const RECEIPT_RESPONSE_KEYS = new Set(["request_id", "receipt"]);
const ENROLLMENT_KEYS = new Set(["version", "enrollment_id", "organization_id", "device_id", "status", "key_algorithm", "device_key_epoch", "control"]);
const CONTROL_KEYS = new Set(["format_epoch", "issuer", "key_id", "public_key", "bundle_path", "refresh_hint"]);
const REFRESH_HINT_KEYS = new Set(["key_id", "algorithm", "public_key"]);
const REQUEST_INPUT_KEYS = new Set(["enrollmentId", "enrollment_id", "organizationId", "organization_id", "deviceId", "device_id", "label", "deviceKey", "device_key"]);
const RECOVERY_INPUT_KEYS = new Set([
  "baseUrl", "url", "api_base_url", "loopbackTestMode", "allowLoopbackHttp",
  "enrollmentId", "enrollment_id", "organizationId", "organization_id", "deviceId", "device_id",
  "label", "deviceKey", "device_key", "keyFingerprint", "key_fingerprint",
  "requestDigest", "request_digest",
  "candidateBinding", "candidate_binding", "challengeNonceDigest", "challenge_nonce_digest", "challengeDigest", "challenge_digest",
  "possessionReceiptPublicKey", "possession_receipt_public_key", "receiptPublicKey", "receipt_public_key", "verification_public_key",
  "possessionReceiptKeyId", "possession_receipt_key_id", "receiptKeyId", "receipt_key_id", "verification_key_id",
  "verificationAlgorithm", "verification_algorithm",
  "control", "expectedControl", "expected_control", "controlTrust", "control_trust",
  "signer", "sign", "fetchImpl", "fetch", "timeoutMs", "maxResponseBytes"
]);
const CANDIDATE_BINDING_KEYS = new Set(["version", "enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256", "source_commit", "team_id", "device_key_fingerprint", "expires_at"]);
const POSSESSION_RECEIPT_KEYS = new Set(["version", "purpose", "key_id", "algorithm", "statement", "statement_hash", "signature"]);
const RECEIPT_STATEMENT_KEYS = new Set(["version", "enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256", "source_commit", "team_id", "device_key_fingerprint", "device_key_epoch", "challenge_nonce_digest", "control", "issued_at"]);
const RECEIPT_CONTROL_KEYS = new Set(["format_epoch", "issuer", "key_id", "public_key", "bundle_path", "refresh_hint"]);
const SECRET_KEY = /(?:private(?:[_-]?key)?|bearer(?:[_-]?token)?|access(?:[_-]?token)?|refresh[_-]?token|session[_-]?token|secret|password|credential(?:[_-]?digest)?|completion[_-]?hash)/i;

export const DEVICE_ENROLLMENT_ERRORS = Object.freeze({
  INVALID_CONFIG: "ERR_DEVICE_ENROLLMENT_CONFIG",
  INVALID_REQUEST: "ERR_DEVICE_ENROLLMENT_REQUEST",
  INVALID_KEY: "ERR_DEVICE_ENROLLMENT_KEY",
  SIGNER: "ERR_DEVICE_ENROLLMENT_SIGNER",
  INVALID_URL: "ERR_DEVICE_ENROLLMENT_URL",
  TIMEOUT: "ERR_DEVICE_ENROLLMENT_TIMEOUT",
  NETWORK: "ERR_DEVICE_ENROLLMENT_NETWORK",
  REDIRECT: "ERR_DEVICE_ENROLLMENT_REDIRECT",
  HTTP: "ERR_DEVICE_ENROLLMENT_HTTP",
  RESPONSE: "ERR_DEVICE_ENROLLMENT_RESPONSE",
  RESPONSE_TOO_LARGE: "ERR_DEVICE_ENROLLMENT_RESPONSE_TOO_LARGE",
  BINDING: "ERR_DEVICE_ENROLLMENT_BINDING",
  RECOVERY_UNPROVEN: "ERR_DEVICE_ENROLLMENT_RECOVERY_UNPROVEN",
  RECOVERY_PROVEN: "ERR_DEVICE_ENROLLMENT_RECOVERY_PROVEN"
});

export class DeviceEnrollmentError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "DeviceEnrollmentError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * Build the exact v1 enrollment body. The returned bytes have no whitespace,
 * aliases, secret, or private-key material and are safe to hand to a signer.
 */
export function buildDeviceEnrollmentRequest(input = {}) {
  try {
    if (!plainObject(input)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request must be an object");
    if (Object.keys(input).some((key) => !REQUEST_INPUT_KEYS.has(key))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request contains unknown fields");
    const enrollmentId = uuid(input.enrollmentId ?? input.enrollment_id, "enrollment_id");
    const organizationId = uuid(input.organizationId ?? input.organization_id, "organization_id");
    const deviceId = uuid(input.deviceId ?? input.device_id, "device_id");
    const label = boundedLabel(input.label);
    const deviceKey = normalizeDeviceKey(input.deviceKey ?? input.device_key);
    const bodyObject = {
      version: VERSION,
      enrollment_id: enrollmentId,
      organization_id: organizationId,
      device_id: deviceId,
      label,
      platform: PLATFORM,
      device_key: { algorithm: deviceKey.algorithm, spki_pem: deviceKey.spki_pem }
    };
    const body = Buffer.from(canonicalJson(bodyObject), "utf8");
    if (body.length > MAX_REQUEST_BYTES) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request is too large");
    return Object.freeze({
      body: Buffer.from(body),
      body_digest: sha256(body),
      enrollment_id: enrollmentId,
      organization_id: organizationId,
      device_id: deviceId,
      label,
      platform: PLATFORM,
      device_key: Object.freeze({ algorithm: deviceKey.algorithm, spki_pem: deviceKey.spki_pem })
    });
  } catch (error) {
    if (error instanceof DeviceEnrollmentError) throw error;
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request is invalid");
  }
}

/**
 * The enrollment proof binds the method, exact endpoint path, exact body
 * digest, and the SHA-256 digest of the one-time credential. The raw
 * credential is sent only in its dedicated HTTP header. It is signed by the
 * newly generated device key through a callback; this module never accepts or
 * stores a device private key.
 */
export function canonicalEnrollmentProof({ method = METHOD, path, bodyDigest, credentialDigest }) {
  const canonicalMethod = typeof method === "string" ? method.toUpperCase() : "";
  if (canonicalMethod !== METHOD || !validPath(path) || !HASH.test(bodyDigest ?? "") || !HASH.test(credentialDigest ?? "")) {
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment proof input is invalid");
  }
  return [PROOF_PROTOCOL, canonicalMethod, path, bodyDigest, credentialDigest].join("\n");
}

/**
 * Validate and canonicalize the release identity bound to an enrollment.
 * v2 deliberately accepts only the wire (snake_case) names.  The returned
 * JSON is the exact object hashed into the v2 proof; aliases are not allowed.
 */
export function buildEnrollmentCandidateBinding(input = {}) {
  try {
    if (!plainObject(input) || Object.keys(input).some((key) => !CANDIDATE_BINDING_KEYS.has(key)) || Object.keys(input).length !== CANDIDATE_BINDING_KEYS.size) {
      fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "candidate binding must contain the exact v2 fields");
    }
    const binding = {
      version: input.version,
      enrollment_id: strictUuid(input.enrollment_id, "candidate binding enrollment_id"),
      organization_id: strictUuid(input.organization_id, "candidate binding organization_id"),
      device_id: strictUuid(input.device_id, "candidate binding device_id"),
      candidate_id: boundedSafeId(input.candidate_id, "candidate binding candidate_id"),
      artifact_sha256: lowerHash(input.artifact_sha256, "candidate binding artifact_sha256"),
      source_commit: lowerSourceCommit(input.source_commit),
      team_id: strictTeamId(input.team_id),
      device_key_fingerprint: strictFingerprint(input.device_key_fingerprint, "candidate binding device_key_fingerprint"),
      expires_at: canonicalTimestamp(input.expires_at, "candidate binding expires_at")
    };
    if (binding.version !== 1) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "candidate binding version is unsupported");
    const json = canonicalJson(binding);
    if (Buffer.byteLength(json, "utf8") > 4096) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "candidate binding is too large");
    return Object.freeze(binding);
  } catch (error) {
    if (error instanceof DeviceEnrollmentError) throw error;
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "candidate binding is invalid");
  }
}

/** Return the exact SHA-256 digest used for the v2 candidate binding field. */
export function candidateBindingDigest(binding) {
  const canonical = canonicalJson(buildEnrollmentCandidateBinding(binding));
  return sha256(Buffer.from(canonical, "utf8"));
}

/**
 * Build the v2 proof preimage. The NUL after the protocol label is deliberate
 * domain separation from every other enrollment and receipt signature.
 * v1's canonicalEnrollmentProof is intentionally not routed through this.
 */
export function canonicalEnrollmentProofV2({ method = METHOD, path, bodyDigest, credentialDigest, challengeNonce, candidateBinding }) {
  const canonicalMethod = typeof method === "string" ? method.toUpperCase() : "";
  const binding = buildEnrollmentCandidateBinding(candidateBinding);
  const nonce = strictNonce(challengeNonce);
  const canonicalPath = strictEnrollmentPath(path, binding.enrollment_id);
  if (canonicalMethod !== METHOD || !HASH.test(bodyDigest ?? "") || !HASH.test(credentialDigest ?? "")) {
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment v2 proof input is invalid");
  }
  return `${PROOF_PROTOCOL_V2}\0${[canonicalMethod, canonicalPath, bodyDigest, credentialDigest, nonce, candidateBindingDigest(binding)].join("\n")}`;
}

/** Validate a challenge nonce and return its canonical wire representation. */
export function validateEnrollmentChallengeNonce(value) {
  return strictNonce(value);
}

/** Explicit qualification profile for hardware-backed P-256 enrollment. */
export function validateEnrollmentQualification(value, deviceKeyAlgorithm = undefined) {
  if (value !== undefined && value !== "p256-sha256") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "unsupported enrollment qualification profile");
  if (value === "p256-sha256" && deviceKeyAlgorithm !== undefined && deviceKeyAlgorithm !== "p256-sha256") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "p256-sha256 qualification requires a P-256 device key");
  return value;
}

/** Verify a Cloud possession receipt without depending on Cloud code or HTTP. */
export function verifyDeviceEnrollmentReceipt(receipt, signerPublicKey, expected = {}) {
  try {
    if (!plainObject(receipt)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment receipt must be an object");
    return verifyPossessionReceiptEnvelope(receipt, signerPublicKey, expected);
  } catch (error) {
    if (error instanceof DeviceEnrollmentError && error.code === DEVICE_ENROLLMENT_ERRORS.BINDING) throw error;
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment receipt is invalid");
  }
}

function verifyPossessionReceiptEnvelope(receipt, signerPublicKey, expected) {
  exactKeys(receipt, POSSESSION_RECEIPT_KEYS, "enrollment possession receipt");
  if (receipt.version !== 1 || receipt.purpose !== "device-enrollment-possession-receipt" || !["ed25519", "p256-sha256"].includes(receipt.algorithm)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment possession receipt metadata is invalid");
  if (typeof receipt.key_id !== "string" || !SAFE_ID.test(receipt.key_id) || typeof receipt.statement_hash !== "string" || !HASH.test(receipt.statement_hash)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment possession receipt metadata is invalid");
  const statement = validateReceiptStatement(receipt.statement);
  const statementBytes = Buffer.from(canonicalJson(statement), "utf8");
  if (receipt.statement_hash !== sha256(statementBytes)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment possession receipt statement hash does not match");
  if (typeof receipt.signature !== "string" || !/^[A-Za-z0-9_-]+$/.test(receipt.signature)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment possession receipt signature is invalid");
  const signature = Buffer.from(receipt.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== receipt.signature) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment possession receipt signature is invalid");
  const key = canonicalReceiptPublicKey(signerPublicKey, receipt.algorithm);
  const signed = Buffer.from(`${RECEIPT_PROTOCOL_V1}\0${canonicalJson(statement)}`, "utf8");
  if (!verifyReceiptSignature(signed, signature, key, receipt.algorithm)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment possession receipt signature does not verify");
  verifyReceiptExpected(statement, expected);
  return Object.freeze({
    version: 1,
    purpose: receipt.purpose,
    key_id: receipt.key_id,
    algorithm: receipt.algorithm,
    statement: Object.freeze({ ...statement }),
    statement_hash: receipt.statement_hash,
    signature: receipt.signature
  });
}

/**
 * Create a one-shot enrollment client. Concurrent calls share one request;
 * successful enrollment is cached locally so setup cannot accidentally submit
 * the one-time enrollment twice. Failed calls are not retried automatically.
 */
export function createDeviceEnrollmentClient(options = {}) {
  const config = normalizeOptions(options);
  let inFlight = null;
  let completed = null;
  let terminalFailure = null;

  async function enroll() {
    if (completed) return clone(completed);
    if (terminalFailure) throw cloneFailure(terminalFailure);
    if (inFlight) return inFlight;
    inFlight = performEnrollment(config).then((result) => {
      completed = result;
      return clone(result);
    }).catch((error) => {
      if (config.proof_version === 2) {
        const safeFailure = sanitizeFailure(error);
        // Receipt lookup before the one-time POST is read-only and safe to
        // retry. Once the POST has been dispatched, the same uncertainty is
        // terminal so a caller can never blindly resubmit the credential.
        if (!(safeFailure.code === DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN && safeFailure.details?.phase === "preflight")) {
          terminalFailure = safeFailure;
        }
        throw cloneFailure(safeFailure);
      }
      throw error;
    }).finally(() => { inFlight = null; });
    return inFlight;
  }

  return Object.freeze({
    config: Object.freeze({
      endpoint: config.endpoint.toString(),
      enrollment_id: config.request.enrollment_id,
      organization_id: config.request.organization_id,
      device_id: config.request.device_id,
      label: config.request.label,
      platform: config.request.platform,
      key_fingerprint: config.key_fingerprint,
      proof_version: config.proof_version,
      ...(config.proof_version === 2 ? { candidate_binding: Object.freeze({ ...config.candidate_binding }) } : {}),
      device_key: Object.freeze({ ...config.request.device_key })
    }),
    request: () => cloneRequest(config.request),
    enroll,
    status: () => completed ? "enrolled" : (terminalFailure ? "failed" : (inFlight ? "in_flight" : "ready"))
  });
}

/** Create a production enrollment client with the v2 proof contract locked. */
export function createV2DeviceEnrollmentClient(options = {}) {
  return createDeviceEnrollmentClient({ ...options, proofVersion: 2, requireV2: true });
}

export async function enrollDevice(options = {}) {
  return createDeviceEnrollmentClient(options).enroll();
}

/**
 * Recover an already-submitted v2 enrollment after process or machine loss.
 *
 * This is intentionally a separate public entry point from the one-shot
 * enrollment client.  Its configuration has no credential, challenge nonce,
 * or POST request fields, and its implementation calls only the signed
 * enrollment-receipt GET path.  The native signer is used solely to
 * authenticate that read against the existing device public key.
 */
export async function recoverDeviceEnrollment(options = {}) {
  const config = normalizeRecoveryOptions(options);
  const observed = await readPossessionReceipt(config, config.request);
  if (!observed.receipt) throw recoveryUnproven(observed.status);
  return enrollmentResultFromReceipt(config, config.request, observed);
}

/** Return the non-secret evidence envelope consumed by setup state adapters. */
export function deviceEnrollmentEvidence(result) {
  if (!plainObject(result)) throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment result is invalid");
  const enrollmentId = uuid(result.enrollment_id ?? result.enrollmentId, "enrollment_id");
  const organizationId = uuid(result.organization_id ?? result.organizationId, "organization_id");
  const deviceId = uuid(result.device_id ?? result.deviceId, "device_id");
  const deviceKeyEpoch = positiveInteger(result.device_key_epoch, "device_key_epoch");
  if (typeof result.key_fingerprint !== "string" || !FINGERPRINT.test(result.key_fingerprint)) throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment key fingerprint is invalid");
  return Object.freeze({ organization_id: organizationId, device_id: deviceId, enrollment_id: enrollmentId, device_key_epoch: deviceKeyEpoch, key_fingerprint: result.key_fingerprint });
}

async function performEnrollment(config) {
  const request = config.request;
  if (config.proof_version === 2) {
    const preflight = await assertNoCompletedEnrollment(config, request);
    if (preflight.receipt) return enrollmentResultFromReceipt(config, request, preflight);
  }
  const path = strictEnrollmentPath(config.endpoint.pathname, request.enrollment_id);
  const proof = config.proof_version === 2
    ? canonicalEnrollmentProofV2({ path, bodyDigest: request.body_digest, credentialDigest: config.credential_digest, challengeNonce: config.challenge_nonce, candidateBinding: config.candidate_binding })
    : canonicalEnrollmentProof({ path, bodyDigest: request.body_digest, credentialDigest: config.credential_digest });
  const signature = await signProof(config.signer, {
    version: config.proof_version,
    method: METHOD,
    path,
    body_digest: request.body_digest,
    credential_digest: config.credential_digest,
    ...(config.proof_version === 2 ? { challenge_nonce: config.challenge_nonce, candidate_binding: Object.freeze({ ...config.candidate_binding }) } : {}),
    body: Buffer.from(request.body),
    bytes: Buffer.from(proof, "utf8")
  }, request.device_key);
  const headers = {
    accept: "application/json",
    "content-type": "application/json",
    [PROOF_HEADER]: signature,
    [CREDENTIAL_HEADER]: config.credential
  };
  if (config.proof_version === 2) {
    headers[NONCE_HEADER] = config.challenge_nonce;
    headers[CANDIDATE_BINDING_HEADER] = canonicalJson(config.candidate_binding);
  }
  let response;
  try {
    response = await requestHttp(config, {
      method: METHOD,
      url: config.endpoint.toString(),
      headers,
      body: request.body
    });
  } catch (error) {
    if (config.proof_version === 2) return recoverAfterAmbiguousCompletion(config, request);
    throw error;
  }
  let parsed;
  try {
    parsed = await parseResponse(response, config.maxResponseBytes);
  } catch (error) {
    // A malformed/oversized 201 may mean Cloud committed the mutation but the
    // response body was lost. Reconcile only that ambiguous success boundary;
    // an explicitly rejected HTTP status is definitive and needs no replay or
    // receipt lookup.
    if (config.proof_version === 2 && response.status === 201) return recoverAfterAmbiguousCompletion(config, request);
    throw error;
  }
  const safeResponse = validateResponseBinding(parsed, request, config.key_fingerprint);
  const possessionReceipt = config.require_receipt
    ? await requirePossessionReceipt(config, request, safeResponse.device_key_epoch, safeResponse.control)
    : undefined;
  return enrollmentResult(config, request, safeResponse, possessionReceipt);
}

/**
 * A v2 client always checks the authoritative receipt before consuming the
 * one-time credential.  A pre-enrollment device is not yet known to the
 * Device API, so 401/404 are the only responses that permit the first POST.
 * Every other result is an inability to establish the recovery boundary and
 * therefore stops setup before any mutation.
 */
async function assertNoCompletedEnrollment(config, request) {
  const observed = await readPossessionReceipt(config, request, undefined, "preflight");
  if (observed.receipt) return observed;
  if (observed.status === 401 || observed.status === 404) return observed;
  throw recoveryUnproven(observed.status);
}

/**
 * Once the v2 POST has been dispatched, this client never submits it again.
 * The receipt endpoint is the only existing authoritative recovery signal.
 * Its signed statement carries the exact control trust metadata needed to
 * reconstruct the same public enrollment result without trusting GET fields.
 */
async function recoverAfterAmbiguousCompletion(config, request) {
  const observed = await readPossessionReceipt(config, request);
  if (observed.receipt) return enrollmentResultFromReceipt(config, request, observed);
  throw recoveryUnproven(observed.status);
}

async function requirePossessionReceipt(config, request, deviceKeyEpoch, expectedControl) {
  const observed = await readPossessionReceipt(config, request, deviceKeyEpoch);
  if (observed.receipt) {
    if (expectedControl && canonicalJson(observed.receipt.statement.control) !== canonicalJson(expectedControl)) throw recoveryUnproven("receipt_control_mismatch");
    return observed.receipt;
  }
  throw recoveryUnproven(observed.status);
}

async function readPossessionReceipt(config, request, deviceKeyEpoch = undefined, phase = "post") {
  let response;
  try {
    response = await requestPossessionReceipt(config, request);
  } catch (error) {
    throw recoveryUnproven(error instanceof DeviceEnrollmentError ? error.code : undefined, phase);
  }
  if (response.status !== 200) {
    if (response.status === 401 || response.status === 404) return { status: response.status, receipt: null };
    return { status: response.status, receipt: null };
  }
  let value;
  try {
    const bytes = await readBoundedResponse(response, config.maxResponseBytes);
    value = parseControlBundleJson(bytes, { maxBytes: config.maxResponseBytes, maxDepth: MAX_RESPONSE_DEPTH });
  } catch {
    throw recoveryUnproven("invalid_receipt_response", phase);
  }
  try {
    if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment receipt response is invalid");
    exactKeys(value, RECEIPT_RESPONSE_KEYS, "enrollment receipt response");
    if (typeof value.request_id !== "string" || !SAFE_ID.test(value.request_id)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment receipt request_id is invalid");
    const receipt = verifyDeviceEnrollmentReceipt(value.receipt, config.receipt_public_key, {
      candidateBinding: config.candidate_binding,
      enrollmentId: request.enrollment_id,
      organizationId: request.organization_id,
      deviceId: request.device_id,
      deviceKeyFingerprint: config.key_fingerprint,
      ...(config.challenge_nonce_digest
        ? { challengeNonceDigest: config.challenge_nonce_digest }
        : { challengeNonce: config.challenge_nonce }),
      ...(deviceKeyEpoch === undefined ? {} : { deviceKeyEpoch })
    });
    if (config.receipt_key_id !== undefined && receipt.key_id !== config.receipt_key_id) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment receipt signer key does not match the pinned key");
    if (config.receipt_algorithm !== undefined && receipt.algorithm !== config.receipt_algorithm) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment receipt signer algorithm does not match the pinned algorithm");
    if (config.expected_control && canonicalJson(receipt.statement.control) !== canonicalJson(config.expected_control)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment receipt control trust does not match the pinned control");
    return { status: 200, request_id: value.request_id, receipt };
  } catch (error) {
    if (error instanceof DeviceEnrollmentError && error.code === DEVICE_ENROLLMENT_ERRORS.BINDING) throw recoveryUnproven("receipt_binding_failed", phase);
    throw recoveryUnproven("invalid_receipt", phase);
  }
}

async function requestPossessionReceipt(config, request) {
  const body = Buffer.alloc(0);
  const path = `/v1/organizations/${request.organization_id}/devices/${request.device_id}/enrollment-receipt`;
  const timestamp = Date.now();
  const nonce = randomDeviceNonce();
  const bodyDigest = sha256(body);
  const bytes = Buffer.from(canonicalDeviceRequest({ method: "GET", path, body_digest: bodyDigest, timestamp, nonce }), "utf8");
  const signature = await signProof(config.signer, {
    version: 1,
    method: "GET",
    path,
    body_digest: bodyDigest,
    timestamp,
    nonce,
    body,
    bytes
  }, request.device_key);
  return requestHttp(config, {
    method: "GET",
    url: new URL(path, `${config.endpoint.origin}/`).toString(),
    headers: {
      accept: "application/json",
      "AgentPass-Device": request.device_id,
      "AgentPass-Timestamp": String(timestamp),
      "AgentPass-Nonce": nonce,
      "AgentPass-Content-SHA256": bodyDigest,
      "AgentPass-Signature": signature
    },
    body
  });
}

function enrollmentResultFromReceipt(config, request, observed) {
  const receipt = observed.receipt;
  const statement = receipt.statement;
  const control = statement.control;
  const deviceKeyEpoch = statement.device_key_epoch;
  const server = {
    version: VERSION,
    enrollment_id: request.enrollment_id,
    organization_id: request.organization_id,
    device_id: request.device_id,
    status: "active",
    key_algorithm: request.device_key.algorithm,
    device_key_epoch: deviceKeyEpoch,
    control: Object.freeze({ ...control }),
    key_fingerprint: config.key_fingerprint
  };
  return enrollmentResult(config, request, {
    request_id: observed.request_id ?? null,
    device_key_epoch: deviceKeyEpoch,
    control,
    server
  }, receipt);
}

function enrollmentResult(config, request, safeResponse, possessionReceipt = undefined) {
  const evidence = deviceEnrollmentEvidence({ enrollment_id: request.enrollment_id, organization_id: request.organization_id, device_id: request.device_id, device_key_epoch: safeResponse.device_key_epoch, key_fingerprint: config.key_fingerprint });
  const receiptEvidence = possessionReceipt ? {
    proof_version: 2,
    candidate_id: possessionReceipt.statement.candidate_id,
    challenge_nonce_digest: possessionReceipt.statement.challenge_nonce_digest,
    receipt_key_id: possessionReceipt.key_id,
    receipt_statement_hash: possessionReceipt.statement_hash
  } : {};
  return Object.freeze({
    status: "enrolled",
    enrollment_id: request.enrollment_id,
    organization_id: request.organization_id,
    device_id: request.device_id,
    label: request.label,
    platform: request.platform,
    device_key: Object.freeze({ ...request.device_key }),
    key_fingerprint: config.key_fingerprint,
    request_hash: config.request_digest ?? request.body_digest,
    request_id: safeResponse.request_id ?? null,
    device_key_epoch: safeResponse.device_key_epoch,
    control: Object.freeze({ ...safeResponse.control }),
    server: Object.freeze(safeResponse.server),
    ...(possessionReceipt ? { possession_receipt: possessionReceipt } : {}),
    evidence: Object.freeze({ ...evidence, ...receiptEvidence })
  });
}

function recoveryUnproven(observed = undefined, phase = "post") {
  return new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.RECOVERY_UNPROVEN, "Cloud could not prove whether this one-time device enrollment completed; the credential will not be retried", {
    recovery: "receipt_unavailable",
    phase,
    ...(Number.isInteger(observed) ? { observed_status: observed } : (typeof observed === "string" && /^[A-Z0-9_:-]{1,96}$/u.test(observed) ? { observed_code: observed } : {}))
  });
}

function randomDeviceNonce() {
  let nonce;
  do { nonce = crypto.randomBytes(32).toString("base64url"); } while (!/^[A-Za-z0-9]/.test(nonce));
  return nonce;
}

async function signProof(signer, input, deviceKey) {
  const callback = typeof signer === "function" ? signer : signer?.sign;
  if (typeof callback !== "function") fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "a native device signing callback is required");
  let value;
  try {
    value = await callback({ ...input, body: Buffer.from(input.body), bytes: Buffer.from(input.bytes) });
  } catch {
    fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof signing failed");
  }
  if (value && typeof value === "object" && !Buffer.isBuffer(value)) value = value.signature;
  const signature = decodeSignature(value);
  const publicKey = crypto.createPublicKey(deviceKey.spki_pem);
  let valid = false;
  try {
    valid = deviceKey.algorithm === "ed25519"
      ? crypto.verify(null, Buffer.from(input.bytes), publicKey, signature)
      : crypto.verify("sha256", Buffer.from(input.bytes), { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
  } catch { valid = false; }
  if (!valid) fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof does not match the enrolled public key");
  return signature.toString("base64");
}

async function requestHttp(config, { method, url, headers, body }) {
  const controller = new AbortController();
  let timer;
  let raceTimer;
  let timedOut = false;
  try {
    timer = setTimeout(() => { timedOut = true; controller.abort(); }, config.timeoutMs);
    return await Promise.race([
      Promise.resolve(config.fetchImpl(url, {
        method,
        headers,
        ...(body?.length > 0 ? { body: Buffer.from(body) } : {}),
        redirect: "error",
        signal: controller.signal
      })),
      new Promise((_, reject) => {
        raceTimer = setTimeout(() => {
          timedOut = true;
          controller.abort();
          reject(new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.TIMEOUT, "device enrollment request timed out"));
        }, config.timeoutMs);
      })
    ]);
  } catch (error) {
    if (error instanceof DeviceEnrollmentError) throw error;
    if (timedOut || error?.name === "AbortError") throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.TIMEOUT, "device enrollment request timed out");
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.NETWORK, "device enrollment request could not be completed");
  } finally {
    clearTimeout(timer);
    if (raceTimer) clearTimeout(raceTimer);
  }
}

async function parseResponse(response, maxBytes) {
  if (!response || !Number.isInteger(response.status)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response is invalid");
  if (response.status >= 300 && response.status < 400) fail(DEVICE_ENROLLMENT_ERRORS.REDIRECT, "device enrollment redirects are not permitted");
  if (response.status !== 201) fail(DEVICE_ENROLLMENT_ERRORS.HTTP, `device enrollment request failed with HTTP ${response.status}`);
  const bytes = await readBoundedResponse(response, maxBytes);
  try {
    return parseControlBundleJson(bytes, { maxBytes, maxDepth: MAX_RESPONSE_DEPTH });
  } catch {
    fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response is not valid canonical JSON");
  }
}

async function readBoundedResponse(response, maxBytes) {
  const declared = response.headers?.get?.("content-length") ?? response.headers?.["content-length"] ?? response.headers?.["Content-Length"];
  if (declared !== undefined && declared !== null && declared !== "") {
    if (!/^\d+$/.test(String(declared)) || Number(declared) > maxBytes) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE_TOO_LARGE, "device enrollment response is too large");
  }
  const chunks = [];
  let total = 0;
  const add = (value) => {
    const chunk = Buffer.from(value);
    total += chunk.length;
    if (total > maxBytes) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE_TOO_LARGE, "device enrollment response is too large");
    chunks.push(chunk);
  };
  try {
    if (response.body?.getReader) {
      const reader = response.body.getReader();
      try { while (true) { const next = await reader.read(); if (next.done) break; add(next.value); } }
      finally { reader.releaseLock?.(); }
    } else if (response.body && typeof response.body[Symbol.asyncIterator] === "function") {
      for await (const chunk of response.body) add(chunk);
    } else if (typeof response.arrayBuffer === "function") {
      add(await response.arrayBuffer());
    } else if (typeof response.text === "function") {
      add(Buffer.from(await response.text(), "utf8"));
    } else {
      fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response body is unreadable");
    }
  } catch (error) {
    if (error instanceof DeviceEnrollmentError) throw error;
    fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response body could not be read");
  }
  if (total === 0) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response body is empty");
  try { return Buffer.from(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total)), "utf8"); }
  catch { fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response is not valid UTF-8"); }
}

function validateResponseBinding(value, request, expectedFingerprint) {
  if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response must be an object");
  exactKeys(value, RESPONSE_KEYS, "device enrollment response");
  rejectSecrets(value, 0);
  if (typeof value.request_id !== "string" || !SAFE_ID.test(value.request_id)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response request_id is invalid");
  const enrollment = responseObject(value.enrollment, ENROLLMENT_KEYS, "enrollment");
  if (enrollment.version !== VERSION || enrollment.enrollment_id !== request.enrollment_id || enrollment.organization_id !== request.organization_id || enrollment.device_id !== request.device_id) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment response binding does not match");
  if (enrollment.status !== "active") fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment response does not activate the device");
  if (enrollment.key_algorithm !== request.device_key.algorithm) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment response key algorithm does not match");
  const deviceKeyEpoch = positiveInteger(enrollment.device_key_epoch, "device_key_epoch");
  const control = responseObject(enrollment.control, CONTROL_KEYS, "control");
  if (!Number.isSafeInteger(control.format_epoch) || control.format_epoch !== 2) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment control format is unsupported");
  if (typeof control.issuer !== "string" || !SAFE_ID.test(control.issuer) || typeof control.key_id !== "string" || !SAFE_ID.test(control.key_id)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control identifiers are invalid");
  const controlKey = normalizeEd25519PublicKey(control.public_key);
  const refreshHint = responseObject(control.refresh_hint, REFRESH_HINT_KEYS, "refresh hint");
  if (typeof refreshHint.key_id !== "string" || !SAFE_ID.test(refreshHint.key_id) || refreshHint.algorithm !== "ed25519") fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment refresh hint trust metadata is invalid");
  const refreshHintKey = normalizeEd25519PublicKey(refreshHint.public_key);
  if (refreshHintKey === controlKey) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment refresh hint key must be purpose-separated from the control key");
  if (typeof control.bundle_path !== "string" || control.bundle_path.length < 1 || control.bundle_path.length > 1024 || CONTROL.test(control.bundle_path)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment bundle path is invalid");
  if (control.bundle_path !== `/v1/organizations/${request.organization_id}/bundles/${request.device_id}`) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment control path does not match the device");
  return {
    request_id: value.request_id,
    device_key_epoch: deviceKeyEpoch,
    control: { ...control, public_key: controlKey, refresh_hint: { key_id: refreshHint.key_id, algorithm: "ed25519", public_key: refreshHintKey } },
    server: {
      version: VERSION,
      enrollment_id: request.enrollment_id,
      organization_id: request.organization_id,
      device_id: request.device_id,
      status: enrollment.status,
      key_algorithm: enrollment.key_algorithm,
      device_key_epoch: deviceKeyEpoch,
      control: { format_epoch: 2, issuer: control.issuer, key_id: control.key_id, public_key: controlKey, bundle_path: control.bundle_path, refresh_hint: { key_id: refreshHint.key_id, algorithm: "ed25519", public_key: refreshHintKey } },
      key_fingerprint: expectedFingerprint
    }
  };
}

function normalizeEd25519PublicKey(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_PEM_BYTES || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value) || /PRIVATE KEY/.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control public key is invalid");
  let key;
  try { key = crypto.createPublicKey(value); }
  catch { fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control public key is invalid"); }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control public key is invalid");
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== value) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control public key is not canonical");
  return canonical;
}

function canonicalReceiptPublicKey(value, algorithm) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_PEM_BYTES || /PRIVATE KEY/.test(value) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt signer public key is invalid");
  let key;
  try { key = crypto.createPublicKey(value); } catch { fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt signer public key is invalid"); }
  const valid = algorithm === "ed25519"
    ? key.type === "public" && key.asymmetricKeyType === "ed25519"
    : key.type === "public" && key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
  if (!valid) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt signer public key algorithm is invalid");
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== value) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt signer public key is not canonical");
  return key;
}

function normalizeReceiptPublicKey(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_PEM_BYTES || /PRIVATE KEY/.test(value) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "a public possession receipt key is required");
  let key;
  try { key = crypto.createPublicKey(value); } catch { fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "possession receipt public key is invalid"); }
  if (key.type !== "public" || !["ed25519", "ec"].includes(key.asymmetricKeyType) || (key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve !== "prime256v1")) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "possession receipt public key algorithm is invalid");
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== value) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "possession receipt public key is not canonical");
  return canonical;
}

function publicKeyAlgorithm(value) {
  let key;
  try { key = crypto.createPublicKey(value); } catch { fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "pinned verification public key is invalid"); }
  return key.asymmetricKeyType === "ed25519" ? "ed25519" : "p256-sha256";
}

function verifyReceiptSignature(bytes, signature, key, algorithm) {
  try {
    return algorithm === "ed25519"
      ? crypto.verify(null, bytes, key, signature)
      : crypto.verify("sha256", bytes, { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch { return false; }
}

function validateReceiptStatement(value) {
  if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment receipt statement must be an object");
  exactKeys(value, RECEIPT_STATEMENT_KEYS, "enrollment receipt statement");
  const statement = {
    version: value.version,
    enrollment_id: strictUuid(value.enrollment_id, "receipt enrollment_id"),
    organization_id: strictUuid(value.organization_id, "receipt organization_id"),
    device_id: strictUuid(value.device_id, "receipt device_id"),
    candidate_id: boundedSafeId(value.candidate_id, "receipt candidate_id"),
    artifact_sha256: lowerHash(value.artifact_sha256, "receipt artifact_sha256"),
    source_commit: lowerSourceCommit(value.source_commit),
    team_id: strictTeamId(value.team_id),
    device_key_fingerprint: strictFingerprint(value.device_key_fingerprint, "receipt device_key_fingerprint"),
    device_key_epoch: positiveInteger(value.device_key_epoch, "receipt device_key_epoch"),
    challenge_nonce_digest: lowerHash(value.challenge_nonce_digest, "receipt challenge_nonce_digest"),
    control: validateReceiptControl(value.control),
    issued_at: canonicalTimestamp(value.issued_at, "receipt issued_at")
  };
  if (statement.version !== 1) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt statement version is unsupported");
  return statement;
}

function validateReceiptControl(value) {
  if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt control metadata is invalid");
  exactKeys(value, RECEIPT_CONTROL_KEYS, "receipt control metadata");
  if (value.format_epoch !== 2 || typeof value.issuer !== "string" || !SAFE_ID.test(value.issuer) || typeof value.key_id !== "string" || !SAFE_ID.test(value.key_id)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt control metadata is invalid");
  const publicKey = normalizeEd25519PublicKey(value.public_key);
  if (typeof value.bundle_path !== "string" || !/^\/v1\/organizations\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\/bundles\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value.bundle_path)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt control bundle path is invalid");
  const refreshHint = responseObject(value.refresh_hint, REFRESH_HINT_KEYS, "receipt refresh hint");
  if (typeof refreshHint.key_id !== "string" || !SAFE_ID.test(refreshHint.key_id) || refreshHint.algorithm !== "ed25519") fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt refresh hint trust metadata is invalid");
  const refreshPublicKey = normalizeEd25519PublicKey(refreshHint.public_key);
  if (refreshPublicKey === publicKey) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt refresh hint key must be purpose-separated from the control key");
  return Object.freeze({ format_epoch: 2, issuer: value.issuer, key_id: value.key_id, public_key: publicKey, bundle_path: value.bundle_path, refresh_hint: Object.freeze({ key_id: refreshHint.key_id, algorithm: "ed25519", public_key: refreshPublicKey }) });
}

function verifyReceiptExpected(statement, expected) {
  if (!plainObject(expected)) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt expectations must be an object");
  const candidate = expected.candidateBinding ?? expected.candidate_binding;
  if (candidate !== undefined) {
    const binding = buildEnrollmentCandidateBinding(candidate);
    for (const key of ["enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256", "source_commit", "team_id", "device_key_fingerprint"]) {
      if (statement[key] !== binding[key]) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt candidate binding does not match");
    }
  }
  for (const [key, label] of [["enrollmentId", "enrollment_id"], ["organizationId", "organization_id"], ["deviceId", "device_id"], ["candidateId", "candidate_id"], ["artifactSha256", "artifact_sha256"], ["sourceCommit", "source_commit"], ["teamId", "team_id"], ["deviceKeyFingerprint", "device_key_fingerprint"]]) {
    if (expected[key] !== undefined && statement[label] !== expected[key]) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt expectation does not match");
  }
  if (expected.deviceKeyEpoch !== undefined && statement.device_key_epoch !== expected.deviceKeyEpoch) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt device key epoch does not match");
  if (expected.challengeNonce !== undefined && sha256(Buffer.from(strictNonce(expected.challengeNonce), "utf8")) !== statement.challenge_nonce_digest) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt challenge nonce does not match");
  if (expected.challengeNonceDigest !== undefined && lowerHash(expected.challengeNonceDigest, "expected challenge nonce digest") !== statement.challenge_nonce_digest) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt challenge nonce digest does not match");
  if (statement.control.bundle_path !== `/v1/organizations/${statement.organization_id}/bundles/${statement.device_id}`) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "receipt control bundle path does not match the device");
}

function responseObject(value, allowed, label) {
  if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, `${label} response must be an object`);
  exactKeys(value, allowed, `${label} response`);
  return value;
}

function normalizeRecoveryOptions(input) {
  if (!plainObject(input)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device enrollment recovery options must be an object");
  for (const forbidden of [
    "credential", "enrollmentCredential", "enrollment_credential", "privateKey", "private_key",
    "devicePrivateKey", "device_private_key", "bearerToken", "bearer_token", "accessToken",
    "access_token", "refreshToken", "refresh_token", "authorization", "challengeNonce",
    "challenge_nonce", "challengeId", "challenge_id", "proofVersion", "proof_version"
  ]) {
    if (Object.hasOwn(input, forbidden)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device enrollment recovery accepts no credential or challenge secret");
  }
  if (Object.keys(input).some((key) => !RECOVERY_INPUT_KEYS.has(key))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device enrollment recovery options contain unknown fields");
  const request = buildDeviceEnrollmentRequest({
    enrollmentId: input.enrollmentId ?? input.enrollment_id,
    organizationId: input.organizationId ?? input.organization_id,
    deviceId: input.deviceId ?? input.device_id,
    label: input.label,
    deviceKey: input.deviceKey ?? input.device_key
  });
  const baseUrl = input.baseUrl ?? input.url ?? input.api_base_url;
  if (typeof baseUrl !== "string") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment recovery baseUrl is required");
  const endpoint = validateBaseUrl(baseUrl, input.loopbackTestMode === true || input.allowLoopbackHttp === true);
  const signer = input.signer ?? input.sign;
  if (typeof signer !== "function" && !(signer && typeof signer.sign === "function")) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "an existing native device signer is required for enrollment recovery");
  if (signer && typeof signer === "object" && Object.hasOwn(signer, "privateKey")) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device signer must not contain private key material");
  const keyFingerprint = input.keyFingerprint ?? input.key_fingerprint;
  if (typeof keyFingerprint !== "string" || !FINGERPRINT.test(keyFingerprint)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "a native device key fingerprint is required");
  if (keyFingerprint !== publicKeyFingerprint(request.device_key.spki_pem)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "native device key fingerprint does not match the public key");
  const candidateBinding = buildEnrollmentCandidateBinding(input.candidateBinding ?? input.candidate_binding);
  if (candidateBinding.enrollment_id !== request.enrollment_id || candidateBinding.organization_id !== request.organization_id || candidateBinding.device_id !== request.device_id) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "candidate binding identities do not match the recovery descriptor");
  if (candidateBinding.device_key_fingerprint !== keyFingerprint) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "candidate binding fingerprint does not match the recovery key");
  const requestDigest = strictRecoveryHash(input.requestDigest ?? input.request_digest, "request_digest");
  const challengeNonceDigest = lowerHash(input.challengeNonceDigest ?? input.challenge_nonce_digest ?? input.challengeDigest ?? input.challenge_digest, "challenge_nonce_digest");
  const receiptPublicKeyInput = input.possessionReceiptPublicKey ?? input.possession_receipt_public_key ?? input.receiptPublicKey ?? input.receipt_public_key ?? input.verification_public_key;
  const receiptKeyIdInput = input.possessionReceiptKeyId ?? input.possession_receipt_key_id ?? input.receiptKeyId ?? input.receipt_key_id ?? input.verification_key_id;
  const receiptPublicKey = normalizeReceiptPublicKey(receiptPublicKeyInput);
  const receiptKeyId = strictReceiptKeyId(receiptKeyIdInput);
  const verificationAlgorithm = input.verificationAlgorithm ?? input.verification_algorithm;
  if (verificationAlgorithm !== undefined && !["ed25519", "p256-sha256"].includes(verificationAlgorithm)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "verification algorithm is invalid");
  if (verificationAlgorithm !== undefined && verificationAlgorithm !== publicKeyAlgorithm(receiptPublicKey)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "verification algorithm does not match the pinned public key");
  const controlInput = input.control ?? input.expectedControl ?? input.expected_control ?? input.controlTrust ?? input.control_trust;
  const expectedControl = controlInput === undefined ? undefined : normalizeRecoveryControl(controlInput);
  const fetchImpl = input.fetchImpl ?? input.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "fetchImpl must be a function");
  const timeoutMs = boundedInteger(input.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1, 120_000, "timeoutMs");
  const maxResponseBytes = boundedInteger(input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES, 1, 4 * 1024 * 1024, "maxResponseBytes");
  return Object.freeze({
    endpoint,
    request,
    signer,
    fetchImpl,
    timeoutMs,
    maxResponseBytes,
    key_fingerprint: keyFingerprint,
    request_digest: requestDigest,
    candidate_binding: candidateBinding,
    challenge_nonce_digest: challengeNonceDigest,
    receipt_public_key: receiptPublicKey,
    receipt_key_id: receiptKeyId,
    receipt_algorithm: verificationAlgorithm ?? publicKeyAlgorithm(receiptPublicKey),
    expected_control: expectedControl
  });
}

function normalizeRecoveryControl(value) {
  try {
    return validateReceiptControl(value);
  } catch {
    fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "pinned control trust is invalid");
  }
}

function strictRecoveryHash(value, label) {
  if (typeof value !== "string" || !HASH.test(value) || value !== value.toLowerCase()) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, `${label} is invalid`);
  return value;
}

function normalizeOptions(input) {
  if (!plainObject(input)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device enrollment options must be an object");
  for (const forbidden of ["privateKey", "private_key", "devicePrivateKey", "device_private_key", "bearerToken", "bearer_token", "authorization"]) {
    if (Object.hasOwn(input, forbidden)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device enrollment options must not contain secret material");
  }
  let request = buildDeviceEnrollmentRequest({
    enrollmentId: input.enrollmentId ?? input.enrollment_id,
    organizationId: input.organizationId ?? input.organization_id,
    deviceId: input.deviceId ?? input.device_id,
    label: input.label,
    deviceKey: input.deviceKey ?? input.device_key
  });
  const requireV2 = input.requireV2 === true || input.require_v2 === true;
  const proofVersion = input.proofVersion ?? input.proof_version ?? 1;
  if (proofVersion !== 1 && proofVersion !== 2) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "enrollment proof version is unsupported");
  if (requireV2 && proofVersion !== 2) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "production enrollment requires proofVersion 2; implicit v1 fallback is disabled");
  const qualification = input.qualification ?? input.qualificationProfile ?? input.qualification_profile;
  validateEnrollmentQualification(qualification, request.device_key.algorithm);
  if (input.requireP256 === true || input.require_p256 === true) validateEnrollmentQualification("p256-sha256", request.device_key.algorithm);
  if (proofVersion === 2) {
    if (request.device_key.algorithm !== "p256-sha256") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "v2 enrollment requires a P-256 device key");
    validateEnrollmentQualification("p256-sha256", request.device_key.algorithm);
  }
  const baseUrl = input.baseUrl ?? input.url;
  if (typeof baseUrl !== "string") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment baseUrl is required");
  const parsed = validateBaseUrl(baseUrl, input.loopbackTestMode === true || input.allowLoopbackHttp === true);
  const endpoint = new URL(`enrollments/${encodeURIComponent(request.enrollment_id)}`, parsed);
  if (endpoint.pathname !== `/v1/enrollments/${request.enrollment_id}`) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment endpoint must be the exact v1 enrollment path");
  const signer = input.signer ?? input.sign;
  if (signer && typeof signer === "object" && Object.hasOwn(signer, "privateKey")) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device signer must not contain private key material");
  const credential = input.credential ?? input.enrollmentCredential ?? input.enrollment_credential;
  if (typeof credential !== "string" || !BASE64URL_CREDENTIAL.test(credential) || Buffer.from(credential, "base64url").length !== 32 || Buffer.from(credential, "base64url").toString("base64url") !== credential) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "a 32-byte enrollment credential is required");
  const keyFingerprint = input.keyFingerprint ?? input.key_fingerprint;
  if (typeof keyFingerprint !== "string" || !FINGERPRINT.test(keyFingerprint)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "a native device key fingerprint is required");
  if (keyFingerprint !== publicKeyFingerprint(request.device_key.spki_pem)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "native device key fingerprint does not match the public key");
  const receiptPublicKeyInput = input.possessionReceiptPublicKey ?? input.possession_receipt_public_key ?? input.receiptPublicKey ?? input.receipt_public_key;
  const receiptKeyIdInput = input.possessionReceiptKeyId ?? input.possession_receipt_key_id ?? input.receiptKeyId ?? input.receipt_key_id;
  const receiptPublicKey = proofVersion === 2 ? normalizeReceiptPublicKey(receiptPublicKeyInput) : undefined;
  const receiptKeyId = proofVersion === 2
    ? boundedSafeId(receiptKeyIdInput, "possession receipt key_id")
    : undefined;
  let candidateBinding;
  let challengeNonce;
  let challengeId;
  if (proofVersion === 2) {
    candidateBinding = buildEnrollmentCandidateBinding(input.candidateBinding ?? input.candidate_binding);
    if (candidateBinding.enrollment_id !== request.enrollment_id || candidateBinding.organization_id !== request.organization_id || candidateBinding.device_id !== request.device_id) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "candidate binding identities do not match the enrollment request");
    if (candidateBinding.device_key_fingerprint !== keyFingerprint) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "candidate binding fingerprint does not match the enrollment key");
    if (Date.parse(candidateBinding.expires_at) <= Date.now()) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "candidate binding has expired");
    challengeNonce = strictNonce(input.challengeNonce ?? input.challenge_nonce);
    challengeId = strictUuid(input.challengeId ?? input.challenge_id, "challenge_id");
    if (challengeId !== request.enrollment_id) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "v2 challenge_id must equal the enrollment_id");
    const bodyObject = {
      version: 2,
      proof_version: 2,
      enrollment_id: request.enrollment_id,
      organization_id: request.organization_id,
      device_id: request.device_id,
      label: request.label,
      platform: request.platform,
      device_key: { ...request.device_key },
      candidate_id: candidateBinding.candidate_id,
      device_key_fingerprint: candidateBinding.device_key_fingerprint,
      challenge: {
        challenge_id: challengeId,
        nonce: challengeNonce,
        expires_at: candidateBinding.expires_at,
        candidate_id: candidateBinding.candidate_id,
        device_key_fingerprint: candidateBinding.device_key_fingerprint
      }
    };
    const body = Buffer.from(canonicalJson(bodyObject), "utf8");
    if (body.length > MAX_REQUEST_BYTES) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request is too large");
    request = Object.freeze({ ...request, ...bodyObject, body, body_digest: sha256(body) });
  }
  if (Object.hasOwn(input, "headers") || Object.hasOwn(input, "requestHeaders")) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "custom enrollment headers are not permitted");
  const fetchImpl = input.fetchImpl ?? input.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "fetchImpl must be a function");
  const timeoutMs = boundedInteger(input.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1, 120_000, "timeoutMs");
  const maxResponseBytes = boundedInteger(input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES, 1, 4 * 1024 * 1024, "maxResponseBytes");
  return Object.freeze({ endpoint, request, signer, fetchImpl, timeoutMs, maxResponseBytes, credential, credential_digest: sha256(Buffer.from(credential, "utf8")), key_fingerprint: keyFingerprint, proof_version: proofVersion, qualification, candidate_binding: candidateBinding, challenge_nonce: challengeNonce, challenge_id: challengeId, receipt_public_key: receiptPublicKey, receipt_key_id: receiptKeyId, require_receipt: proofVersion === 2, require_v2: requireV2 });
}

function validateBaseUrl(value, allowLoopbackHttp) {
  let parsed;
  try { parsed = new URL(value.endsWith("/") ? value : `${value}/`); }
  catch { fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment baseUrl is invalid"); }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (parsed.protocol !== "https:" && !(allowLoopbackHttp && parsed.protocol === "http:" && LOOPBACK.has(hostname))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment requires HTTPS");
  if (parsed.username || parsed.password || parsed.search || parsed.hash) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment URL cannot contain credentials, query, or fragment");
  if (!/^\/v1\/?$/.test(parsed.pathname)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment baseUrl must end at /v1");
  parsed.pathname = "/v1/";
  return parsed;
}

function normalizeDeviceKey(value) {
  if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device_key must be an object");
  if (Object.keys(value).some((key) => !["algorithm", "spki_pem", "spkiPem"].includes(key))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device_key contains unknown fields");
  const algorithm = value.algorithm;
  if (!["p256-sha256", "ed25519"].includes(algorithm)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device key algorithm is invalid");
  const pem = value.spki_pem ?? value.spkiPem;
  if (typeof pem !== "string" || Buffer.byteLength(pem, "utf8") > MAX_PEM_BYTES || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(pem) || /PRIVATE KEY/.test(pem)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device public key encoding is invalid");
  let key;
  try { key = crypto.createPublicKey(pem); }
  catch { fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device public key encoding is invalid"); }
  if (key.type !== "public" || (algorithm === "ed25519" && key.asymmetricKeyType !== "ed25519") || (algorithm === "p256-sha256" && (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1"))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device public key algorithm does not match");
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (Buffer.byteLength(canonical, "utf8") < 80 || Buffer.byteLength(canonical, "utf8") > MAX_PEM_BYTES) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device public key encoding is invalid");
  return { algorithm, spki_pem: canonical };
}

function boundedLabel(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_LABEL_CODE_POINTS || [...value].length > MAX_LABEL_CODE_POINTS || CONTROL.test(value) || value.trim().length === 0) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "device label is invalid");
  return value;
}

function boundedText(value, label, maxBytes, required) {
  if (value === undefined && !required) return value;
  if (typeof value !== "string" || value.length < (required ? 1 : 0) || value.length > maxBytes || CONTROL.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, `${label} is invalid`);
  return value;
}

function uuid(value, label) {
  if (typeof value !== "string" || !UUID.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, `${label} is invalid`);
  return value.toLowerCase();
}

function decodeSignature(value) {
  if (Buffer.isBuffer(value)) {
    if (value.length !== 64) fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof signature is invalid");
    return Buffer.from(value);
  }
  if (typeof value !== "string" || !BASE64.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof signature is invalid");
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== value) fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof signature is invalid");
  return bytes;
}

function rejectSecrets(value, depth) {
  if (depth > MAX_RESPONSE_DEPTH) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response is too deeply nested");
  if (Array.isArray(value)) { for (const child of value) rejectSecrets(child, depth + 1); return; }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response contains prohibited data");
    rejectSecrets(child, depth + 1);
  }
}

function exactKeys(value, allowed, label) {
  if (Object.keys(value).some((key) => !allowed.has(key))) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, `${label} contains unknown fields`);
}

function validPath(value) { return typeof value === "string" && /^\/v1\/enrollments\/[0-9a-f-]+$/i.test(value) && !CONTROL.test(value); }
function strictEnrollmentPath(value, enrollmentId) {
  const expected = `/v1/enrollments/${strictUuid(enrollmentId, "enrollment_id")}`;
  if (value !== expected) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment path must be the exact v1 enrollment path");
  return expected;
}
function strictUuid(value, label) {
  if (typeof value !== "string" || !UUID.test(value) || value !== value.toLowerCase()) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, `${label} is not canonical`);
  return value;
}
function boundedSafeId(value, label) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, `${label} is invalid`);
  return value;
}
function lowerHash(value, label) {
  if (typeof value !== "string" || !HASH.test(value) || value !== value.toLowerCase()) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, `${label} is invalid`);
  return value;
}
function lowerSourceCommit(value) {
  if (typeof value !== "string" || !SOURCE_COMMIT.test(value) || value !== value.toLowerCase()) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "source commit is invalid");
  return value;
}
function strictTeamId(value) {
  if (typeof value !== "string" || !TEAM_ID.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "Team ID is invalid");
  return value;
}
function strictFingerprint(value, label) {
  if (typeof value !== "string" || !FINGERPRINT.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, `${label} is invalid`);
  return value;
}
function strictReceiptKeyId(value) {
  if (typeof value !== "string" || !RECEIPT_KEY_ID.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "possession receipt key_id is invalid");
  return value;
}
function strictNonce(value) {
  if (typeof value !== "string" || !NONCE.test(value) || Buffer.from(value, "base64url").length !== 32 || Buffer.from(value, "base64url").toString("base64url") !== value) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "challenge nonce is invalid");
  return value;
}
function canonicalTimestamp(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, `${label} is invalid`);
  return value;
}
function boundedInteger(value, min, max, label) { if (!Number.isSafeInteger(value) || value < min || value > max) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, `${label} is out of bounds`); return value; }
function positiveInteger(value, label) { if (!Number.isSafeInteger(value) || value < 1) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, `${label} is invalid`); return value; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function publicKeyFingerprint(pem) { return `SHA256:${crypto.createHash("sha256").update(crypto.createPublicKey(pem).export({ type: "spki", format: "der" })).digest("base64url")}`; }
function plainObject(value) { const prototype = value && typeof value === "object" && !Array.isArray(value) ? Object.getPrototypeOf(value) : undefined; return prototype === Object.prototype || prototype === null; }
function cloneRequest(request) { return { ...request, body: Buffer.from(request.body), device_key: { ...request.device_key }, ...(request.challenge ? { challenge: { ...request.challenge } } : {}) }; }
function clone(value) { return structuredClone(value); }
function sanitizeFailure(error) {
  if (error instanceof DeviceEnrollmentError) {
    const details = plainObject(error.details) ? Object.fromEntries(Object.entries(error.details).filter(([key, value]) => SAFE_ID.test(key) && (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null))) : undefined;
    return new DeviceEnrollmentError(error.code, error.message, details);
  }
  return new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.NETWORK, "device enrollment request could not be completed");
}
function cloneFailure(error) { return new DeviceEnrollmentError(error.code, error.message, error.details === undefined ? undefined : { ...error.details }); }
function fail(code, message, details) { throw new DeviceEnrollmentError(code, message, details); }

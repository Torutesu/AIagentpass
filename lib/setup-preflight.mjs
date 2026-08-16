import crypto from "node:crypto";

import { normalizeOnboardingPreflight } from "./onboarding-contract.mjs";

const CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/;
const TEAM_ID = /^[A-Z0-9]{10}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const P256_PEM_MAX_BYTES = 8192;

export const SETUP_PREFLIGHT_VERSION = 1;
export const SETUP_PREFLIGHT_PLATFORM = "macos";
export const SETUP_PREFLIGHT_HANDOFF_KEYS = Object.freeze([
  "version",
  "platform",
  "candidate_id",
  "device_key_fingerprint"
]);

// This is deliberately a boundary, not a replacement release verifier. The
// install authority must supply both values after running the existing signed
// release validation primitive. The current package does not retain such a
// candidate-bound receipt, so the CLI supplies neither dependency by default
// and fails closed until the installer contract is implemented.
export const SETUP_PREFLIGHT_INSTALL_RECEIPT_CONTRACT = Object.freeze({
  version: 1,
  kind: "agentpass.installed-release-receipt",
  fields: Object.freeze([
    "version",
    "kind",
    "candidate_id",
    "manifest_sha256",
    "artifact_sha256",
    "source_commit",
    "team_id",
    "release_signer_fingerprint"
  ]),
  binding: "candidate_id and all release digests must match the exact result returned by the existing signed-release verifier"
});

export const SETUP_PREFLIGHT_ERROR_CODES = Object.freeze({
  INSTALL_PROOF_UNAVAILABLE: "INSTALLED_RELEASE_PROOF_UNAVAILABLE",
  INSTALL_RECEIPT_INVALID: "INSTALLED_RELEASE_RECEIPT_INVALID",
  CANDIDATE_MISSING: "INSTALLED_CANDIDATE_ID_MISSING",
  CANDIDATE_BINDING_MISMATCH: "INSTALLED_CANDIDATE_BINDING_MISMATCH",
  HANDOFF_INVALID: "SETUP_PREFLIGHT_HANDOFF_INVALID",
  NATIVE_KEY_INVALID: "NATIVE_ENROLLMENT_KEY_INVALID",
  NATIVE_KEY_UNAVAILABLE: "NATIVE_ENROLLMENT_KEY_UNAVAILABLE"
});

export class SetupPreflightError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SetupPreflightError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new SetupPreflightError(code, message);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected, label, code = SETUP_PREFLIGHT_ERROR_CODES.INSTALL_RECEIPT_INVALID) {
  if (!plainObject(value) || Object.keys(value).sort().join("\0") !== [...expected].sort().join("\0")) {
    fail(code, `${label} has an invalid schema`);
  }
}

function boundedString(value, expression, label, code = SETUP_PREFLIGHT_ERROR_CODES.INSTALL_RECEIPT_INVALID) {
  if (typeof value !== "string" || !expression.test(value)) fail(code, `${label} is invalid`);
  return value;
}

function releaseBinding(value, label, code = SETUP_PREFLIGHT_ERROR_CODES.INSTALL_RECEIPT_INVALID) {
  if (!plainObject(value)) fail(code, `${label} is unavailable`);
  if (!Object.hasOwn(value, "candidate_id") || value.candidate_id === undefined) fail(SETUP_PREFLIGHT_ERROR_CODES.CANDIDATE_MISSING, `${label} candidate_id is missing`);
  const fields = SETUP_PREFLIGHT_INSTALL_RECEIPT_CONTRACT.fields;
  exactKeys(value, fields, label, code);
  if (value.version !== SETUP_PREFLIGHT_INSTALL_RECEIPT_CONTRACT.version || value.kind !== SETUP_PREFLIGHT_INSTALL_RECEIPT_CONTRACT.kind) {
    fail(code, `${label} identity is invalid`);
  }
  boundedString(value.candidate_id, CANDIDATE_ID, `${label} candidate_id`, code);
  boundedString(value.manifest_sha256, SHA256, `${label} manifest_sha256`, code);
  boundedString(value.artifact_sha256, SHA256, `${label} artifact_sha256`, code);
  boundedString(value.source_commit, SOURCE_COMMIT, `${label} source_commit`, code);
  boundedString(value.team_id, TEAM_ID, `${label} team_id`, code);
  boundedString(value.release_signer_fingerprint, FINGERPRINT, `${label} release signer fingerprint`, code);
  return Object.freeze({
    version: value.version,
    kind: value.kind,
    candidate_id: value.candidate_id,
    manifest_sha256: value.manifest_sha256,
    artifact_sha256: value.artifact_sha256,
    source_commit: value.source_commit,
    team_id: value.team_id,
    release_signer_fingerprint: value.release_signer_fingerprint
  });
}

/** Parse the public receipt emitted by a validated installer. */
export function parseValidatedInstallReceipt(value) {
  if (value === null || value === undefined) fail(SETUP_PREFLIGHT_ERROR_CODES.INSTALL_PROOF_UNAVAILABLE, "Installed release identity cannot be proven");
  return releaseBinding(value, "Installed release receipt");
}

/** Parse the result adapter backed by scripts/release/verify-release.mjs. */
export function parseVerifiedReleaseBinding(value) {
  if (value === null || value === undefined) fail(SETUP_PREFLIGHT_ERROR_CODES.INSTALL_PROOF_UNAVAILABLE, "Installed release verification is unavailable");
  return releaseBinding(value, "Verified release binding");
}

function compareReleaseBindings(receipt, verified) {
  for (const field of SETUP_PREFLIGHT_INSTALL_RECEIPT_CONTRACT.fields) {
    if (receipt[field] !== verified[field]) fail(SETUP_PREFLIGHT_ERROR_CODES.CANDIDATE_BINDING_MISMATCH, "Installed release identity does not match its verified receipt");
  }
}

function nativeEnrollmentKey(value) {
  if (!plainObject(value)) fail(SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID, "Native enrollment key response is invalid");
  exactKeys(value, ["algorithm", "spki_pem", "fingerprint"], "Native enrollment key", SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID);
  if (value.algorithm !== "p256-sha256" || typeof value.spki_pem !== "string" || Buffer.byteLength(value.spki_pem) > P256_PEM_MAX_BYTES || /PRIVATE\s+KEY/i.test(value.spki_pem)) {
    fail(SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID, "Native enrollment key response is invalid");
  }
  boundedString(value.fingerprint, FINGERPRINT, "Native enrollment key fingerprint", SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID);
  let key;
  try { key = crypto.createPublicKey(value.spki_pem); } catch { fail(SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID, "Native enrollment public key is invalid"); }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") fail(SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID, "Native enrollment key is not P-256");
  const canonicalPem = key.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
  if (canonicalPem !== value.spki_pem || fingerprint !== value.fingerprint) fail(SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID, "Native enrollment key fingerprint does not match its public key");
  return Object.freeze({ algorithm: value.algorithm, fingerprint: value.fingerprint });
}

export function parseSetupPreflightHandoff(value) {
  try {
    return normalizeOnboardingPreflight(value);
  } catch {
    fail(SETUP_PREFLIGHT_ERROR_CODES.HANDOFF_INVALID, "Setup preflight handoff is invalid");
  }
}

function publicHandoff(candidateId, fingerprint) {
  return parseSetupPreflightHandoff({
    version: SETUP_PREFLIGHT_VERSION,
    platform: SETUP_PREFLIGHT_PLATFORM,
    candidate_id: candidateId,
    device_key_fingerprint: fingerprint
  });
}

/**
 * Produce the public handoff without persisting config, journal, or receipt
 * data. `readInstalledReleaseReceipt` and `verifyInstalledRelease` are
 * intentionally injectable so the installer can wire the existing release
 * verifier without introducing a second validation implementation here.
 */
export async function prepareSetupPreflight({
  readInstalledReleaseReceipt,
  verifyInstalledRelease,
  nativeRunner
} = {}) {
  if (typeof readInstalledReleaseReceipt !== "function" || typeof verifyInstalledRelease !== "function") {
    fail(SETUP_PREFLIGHT_ERROR_CODES.INSTALL_PROOF_UNAVAILABLE, "Installed release identity cannot be proven");
  }
  let receiptValue;
  let verifiedValue;
  try {
    receiptValue = await readInstalledReleaseReceipt();
    verifiedValue = await verifyInstalledRelease();
  } catch (error) {
    if (error instanceof SetupPreflightError) throw error;
    fail(SETUP_PREFLIGHT_ERROR_CODES.INSTALL_PROOF_UNAVAILABLE, "Installed release identity cannot be proven");
  }
  const receipt = parseValidatedInstallReceipt(receiptValue);
  const verified = parseVerifiedReleaseBinding(verifiedValue);
  compareReleaseBindings(receipt, verified);
  if (!nativeRunner || typeof nativeRunner.publicKey !== "function") fail(SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_UNAVAILABLE, "Native enrollment key is unavailable");
  let nativeValue;
  try { nativeValue = await nativeRunner.publicKey(); }
  catch (error) {
    if (error instanceof SetupPreflightError) throw error;
    fail(SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_UNAVAILABLE, "Native enrollment key is unavailable");
  }
  const key = nativeEnrollmentKey(nativeValue);
  return publicHandoff(verified.candidate_id, key.fingerprint);
}

export function publicSetupPreflightFailure(error) {
  const code = Object.values(SETUP_PREFLIGHT_ERROR_CODES).includes(error?.code)
    ? error.code
    : SETUP_PREFLIGHT_ERROR_CODES.INSTALL_PROOF_UNAVAILABLE;
  const messages = {
    [SETUP_PREFLIGHT_ERROR_CODES.INSTALL_PROOF_UNAVAILABLE]: "Installed release identity cannot be proven",
    [SETUP_PREFLIGHT_ERROR_CODES.INSTALL_RECEIPT_INVALID]: "Installed release receipt is invalid",
    [SETUP_PREFLIGHT_ERROR_CODES.CANDIDATE_MISSING]: "Installed release candidate identity is missing",
    [SETUP_PREFLIGHT_ERROR_CODES.CANDIDATE_BINDING_MISMATCH]: "Installed release identity does not match its verified receipt",
    [SETUP_PREFLIGHT_ERROR_CODES.HANDOFF_INVALID]: "Setup preflight handoff is invalid",
    [SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID]: "Native enrollment key response is invalid",
    [SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_UNAVAILABLE]: "Native enrollment key is unavailable"
  };
  return Object.freeze({ version: SETUP_PREFLIGHT_VERSION, ok: false, error: Object.freeze({ code, message: messages[code] }) });
}

export function serializeSetupPreflightHandoff(value) {
  const dto = parseSetupPreflightHandoff(value);
  return `${JSON.stringify(dto)}\n`;
}

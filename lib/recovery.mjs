import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJson } from "./identity.mjs";
import { anchorRecoveryAuthorization, createAnchorRecoveryPolicy } from "./anchor.mjs";
import { nativeAuditPublicKeyFingerprint, parseNativeAuditPublicKey } from "./native-audit.mjs";

const HASH = /^[0-9a-f]{64}$/;
const SLUG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const REQUEST_KEYS = ["audit_entries", "audit_head_hash", "control_sequence", "expires_at", "from_fingerprint", "from_generation", "installation_id", "issued_at", "latest_checkpoint_hash", "latest_receipt_hash", "lifecycle_head_hash", "nonce", "proposed_generation", "proposed_public_key", "recovery_policy_hash", "recovery_policy_id", "recovery_policy_version", "role", "version"];
const AUTHORIZATION_KEYS = ["public_key_fingerprint", "request_hash", "signature", "signed_at", "signer_id", "version"];
const POLICY_KEYS = ["authorities", "policy_id", "threshold", "version"];
const AUTHORITY_KEYS = ["id", "public_key"];
const ANCHOR_AUTHORIZATION_KEYS = ["created_at", "expires_at", "from_generation", "installation_id", "last_checkpoint_hash", "last_checkpoint_index", "last_checkpoint_receipt_hash", "lifecycle_head_hash", "new_key_fingerprint", "new_public_key", "old_key_fingerprint", "operation_id", "previous_anchor_event_hash", "previous_anchor_event_index", "previous_transition_hash", "previous_transition_receipt_hash", "recovery_policy_hash", "recovery_policy_id", "recovery_request_id", "retiring_generation_pending_checkpoint_count", "role", "tenant", "to_generation", "version"];
const ANCHOR_APPROVAL_KEYS = ["key_id", "signature"];
const MAX_ANCHOR_AUTHORIZATION_MS = 15 * 60_000;
const MAX_CLOCK_SKEW_MS = 5_000;

export function generateRecoveryIdentity(directory, signerID) {
  if (!SLUG.test(signerID ?? "")) throw new Error("Recovery signer ID is invalid");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  assertPrivateDirectory(directory);
  const privateFile = path.join(directory, `${signerID}.private.pem`);
  const publicFile = path.join(directory, `${signerID}.public.pem`);
  if (fs.existsSync(privateFile) || fs.existsSync(publicFile)) throw new Error("Recovery identity files already exist");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  let privateCreated = false;
  let publicCreated = false;
  try {
    fs.writeFileSync(privateFile, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
    privateCreated = true;
    fs.writeFileSync(publicFile, publicKey.export({ type: "spki", format: "pem" }), { flag: "wx", mode: 0o600 });
    publicCreated = true;
    assertPrivateKeyFile(privateFile);
  } catch (error) {
    for (const [file, created] of [[publicFile, publicCreated], [privateFile, privateCreated]]) {
      if (!created) continue;
      try {
        const stat = fs.lstatSync(file);
        if (stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1) fs.unlinkSync(file);
      } catch {}
    }
    throw error;
  }
  return { signer_id: signerID, private_file: privateFile, public_file: publicFile, public_key: fs.readFileSync(publicFile, "utf8"), fingerprint: keyFingerprint(publicKey) };
}

export function validateRecoveryRequest(request, now = Date.now()) {
  assertExactKeys(request, REQUEST_KEYS, "Recovery request");
  if (request.version !== 1 || !SLUG.test(request.installation_id ?? "") || !["git_signing", "audit_checkpoint", "session_approval"].includes(request.role)) throw new Error("Recovery request identity is invalid");
  if (!Number.isSafeInteger(request.from_generation) || request.from_generation < 1 || !Number.isSafeInteger(request.proposed_generation) || request.proposed_generation !== request.from_generation + 1) throw new Error("Recovery request generation is invalid");
  if (!FINGERPRINT.test(request.from_fingerprint ?? "")) throw new Error("Recovery request current fingerprint is invalid");
  if (typeof request.proposed_public_key !== "string" || request.proposed_public_key.length > 4096) throw new Error("Recovery request proposed public key is invalid");
  try { parseNativeAuditPublicKey(request.proposed_public_key); } catch { throw new Error("Recovery request proposed public key must be P-256"); }
  if (!HASH.test(request.lifecycle_head_hash ?? "") || !HASH.test(request.audit_head_hash ?? "") || !HASH.test(request.latest_checkpoint_hash ?? "") || !HASH.test(request.latest_receipt_hash ?? "")) throw new Error("Recovery request history binding is invalid");
  if (request.recovery_policy_version !== 1 || !SLUG.test(request.recovery_policy_id ?? "") || !HASH.test(request.recovery_policy_hash ?? "")) throw new Error("Recovery request policy binding is invalid");
  if (!Number.isSafeInteger(request.audit_entries) || request.audit_entries < 0 || !Number.isSafeInteger(request.control_sequence) || request.control_sequence < 0 || !/^[A-Za-z0-9_-]{43}$/.test(request.nonce ?? "")) throw new Error("Recovery request state is invalid");
  const issued = Date.parse(request.issued_at);
  const expires = Date.parse(request.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > 15 * 60_000 || issued > now + 5_000 || expires < now) throw new Error("Recovery request is expired or outside the allowed window");
  return structuredClone(request);
}

export function signRecoveryRequest(request, privateKeyFile, signerID, now = Date.now()) {
  const verified = validateRecoveryRequest(request, now);
  if (!SLUG.test(signerID ?? "")) throw new Error("Recovery signer ID is invalid");
  const privateBytes = readPrivateKeyFile(privateKeyFile);
  let privateKey;
  try { privateKey = crypto.createPrivateKey(privateBytes); }
  finally { privateBytes.fill(0); }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Recovery private key must be Ed25519");
  const publicKey = crypto.createPublicKey(privateKey);
  const statement = { version: 1, signer_id: signerID, request_hash: requestHash(verified), signed_at: new Date(now).toISOString(), public_key_fingerprint: keyFingerprint(publicKey) };
  return { ...statement, signature: crypto.sign(null, Buffer.from(canonicalJson(statement)), privateKey).toString("base64") };
}

export function verifyRecoveryAuthorization(request, authorization, authority, now = Date.now()) {
  const verified = validateRecoveryRequest(request, now);
  assertExactKeys(authorization, AUTHORIZATION_KEYS, "Recovery authorization");
  if (!authority || !SLUG.test(authority.id ?? "") || authority.id !== authorization.signer_id) throw new Error("Recovery authorization signer is not trusted");
  const key = parseEd25519PublicKey(authority.public_key);
  const statement = { version: authorization.version, signer_id: authorization.signer_id, request_hash: authorization.request_hash, signed_at: authorization.signed_at, public_key_fingerprint: authorization.public_key_fingerprint };
  const signedAt = Date.parse(statement.signed_at);
  if (statement.version !== 1 || statement.request_hash !== requestHash(verified) || statement.public_key_fingerprint !== keyFingerprint(key) || !Number.isFinite(signedAt) || signedAt < Date.parse(verified.issued_at) || signedAt > Math.min(now + 5_000, Date.parse(verified.expires_at))) throw new Error("Recovery authorization statement is invalid");
  if (!canonicalBase64(authorization.signature)) throw new Error("Recovery authorization signature is invalid");
  const signature = Buffer.from(authorization.signature, "base64");
  if (signature.length !== 64 || !crypto.verify(null, Buffer.from(canonicalJson(statement)), key, signature)) throw new Error("Recovery authorization signature is invalid");
  return structuredClone(authorization);
}

export function verifyRecoveryThreshold(request, authorizations, policy, now = Date.now()) {
  assertExactKeys(policy, POLICY_KEYS, "Recovery policy");
  if (!policy || policy.version !== 1 || !SLUG.test(policy.policy_id ?? "") || !Number.isSafeInteger(policy.threshold) || policy.threshold < 1 || !Array.isArray(policy.authorities) || policy.threshold > policy.authorities.length) throw new Error("Recovery policy is invalid");
  for (const authority of policy.authorities) assertExactKeys(authority, AUTHORITY_KEYS, "Recovery authority");
  const ids = policy.authorities.map((item) => item?.id);
  if (new Set(ids).size !== ids.length || ids.some((id) => !SLUG.test(id ?? ""))) throw new Error("Recovery policy authority IDs are invalid");
  const fingerprints = policy.authorities.map((item) => keyFingerprint(parseEd25519PublicKey(item.public_key)));
  if (new Set(fingerprints).size !== fingerprints.length) throw new Error("Recovery policy contains duplicate authority keys");
  if (request.recovery_policy_version !== policy.version || request.recovery_policy_id !== policy.policy_id || request.recovery_policy_hash !== recoveryPolicyHash(policy)) throw new Error("Recovery request is not bound to the supplied policy");
  if (!Array.isArray(authorizations) || authorizations.length < policy.threshold) throw new Error("Recovery authorization threshold is not satisfied");
  const accepted = new Map();
  for (const authorization of authorizations) {
    if (accepted.has(authorization?.signer_id)) throw new Error("Duplicate recovery authorization signer");
    const authority = policy.authorities.find((item) => item.id === authorization?.signer_id);
    const verified = verifyRecoveryAuthorization(request, authorization, authority, now);
    accepted.set(verified.signer_id, verified);
  }
  if (accepted.size < policy.threshold) throw new Error("Recovery authorization threshold is not satisfied");
  return { valid: true, threshold: policy.threshold, accepted: [...accepted.keys()].sort(), request_hash: requestHash(request) };
}

// Converts the host recovery policy used by the existing offline ceremony into
// the exact policy pinned by the schema-v3 anchor. The anchor implementation is
// the canonical normalizer so both call sites share PEM, fingerprint, ordering,
// and policy-hash behavior.
export function recoveryPolicyToAnchorPolicy(policy) {
  assertExactKeys(policy, POLICY_KEYS, "Recovery policy");
  if (policy.version !== 1 || !SLUG.test(policy.policy_id ?? "") || !Number.isSafeInteger(policy.threshold) || policy.threshold < 1 || !Array.isArray(policy.authorities) || policy.authorities.length < 1 || policy.authorities.length > 16 || policy.threshold > policy.authorities.length) throw new Error("Recovery policy is invalid");
  for (const authority of policy.authorities) assertExactKeys(authority, AUTHORITY_KEYS, "Recovery authority");
  return createAnchorRecoveryPolicy({
    policy_id: policy.policy_id,
    threshold: policy.threshold,
    keys: policy.authorities.map((authority) => ({ id: authority.id, public_key: authority.public_key }))
  });
}

export function validateAnchorRecoveryAuthorization(value, now = Date.now()) {
  assertExactKeys(value, ANCHOR_AUTHORIZATION_KEYS, "Anchor recovery authorization");
  const statement = anchorRecoveryAuthorization(value);
  if (statement.version !== 3 || !SLUG.test(statement.tenant ?? "") || !SLUG.test(statement.installation_id ?? "") || statement.role !== "audit_checkpoint" || !SLUG.test(statement.operation_id ?? "") || !SLUG.test(statement.recovery_request_id ?? "") || !SLUG.test(statement.recovery_policy_id ?? "") || !HASH.test(statement.recovery_policy_hash ?? "")) throw new Error("Anchor recovery authorization identity is invalid");
  if (!Number.isSafeInteger(statement.from_generation) || statement.from_generation < 1 || !Number.isSafeInteger(statement.to_generation) || statement.to_generation !== statement.from_generation + 1 || !FINGERPRINT.test(statement.old_key_fingerprint ?? "") || !FINGERPRINT.test(statement.new_key_fingerprint ?? "") || statement.new_key_fingerprint === statement.old_key_fingerprint) throw new Error("Anchor recovery authorization key generation is invalid");
  let replacement;
  try { replacement = parseNativeAuditPublicKey(statement.new_public_key); }
  catch { throw new Error("Anchor recovery replacement public key must be P-256"); }
  if (nativeAuditPublicKeyFingerprint(replacement) !== statement.new_key_fingerprint) throw new Error("Anchor recovery replacement key fingerprint is invalid");
  const hashes = [statement.lifecycle_head_hash, statement.previous_transition_hash, statement.previous_transition_receipt_hash, statement.last_checkpoint_hash, statement.last_checkpoint_receipt_hash, statement.previous_anchor_event_hash];
  if (hashes.some((hash) => !HASH.test(hash ?? "")) || !Number.isSafeInteger(statement.last_checkpoint_index) || statement.last_checkpoint_index < 1 || !Number.isSafeInteger(statement.previous_anchor_event_index) || statement.previous_anchor_event_index < 1 || statement.retiring_generation_pending_checkpoint_count !== 0) throw new Error("Anchor recovery authorization history boundary is invalid");
  const createdAt = Date.parse(statement.created_at);
  const expiresAt = Date.parse(statement.expires_at);
  if (!Number.isFinite(createdAt) || !Number.isFinite(expiresAt) || new Date(createdAt).toISOString() !== statement.created_at || new Date(expiresAt).toISOString() !== statement.expires_at || expiresAt <= createdAt || expiresAt - createdAt > MAX_ANCHOR_AUTHORIZATION_MS || !Number.isFinite(now) || createdAt > now + MAX_CLOCK_SKEW_MS || expiresAt < now) throw new Error("Anchor recovery authorization is expired or outside the allowed window");
  return structuredClone(statement);
}

export function signAnchorRecoveryAuthorization(authorization, privateKeyFile, signerID, now = Date.now()) {
  const statement = validateAnchorRecoveryAuthorization(authorization, now);
  if (!SLUG.test(signerID ?? "")) throw new Error("Recovery signer ID is invalid");
  const privateBytes = readPrivateKeyFile(privateKeyFile);
  let privateKey;
  try { privateKey = crypto.createPrivateKey(privateBytes); }
  finally { privateBytes.fill(0); }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Recovery private key must be Ed25519");
  return { key_id: signerID, signature: crypto.sign(null, Buffer.from(canonicalJson(statement), "utf8"), privateKey).toString("base64") };
}

export function verifyAnchorRecoveryApprovals(authorization, policy, approvals, now = Date.now()) {
  const statement = validateAnchorRecoveryAuthorization(authorization, now);
  const anchorPolicy = recoveryPolicyToAnchorPolicy(policy);
  if (statement.recovery_policy_id !== anchorPolicy.policy_id || statement.recovery_policy_hash !== anchorPolicy.policy_hash) throw new Error("Anchor recovery authorization is not bound to the supplied policy");
  if (!Array.isArray(approvals) || approvals.length < anchorPolicy.threshold) throw new Error("Anchor recovery approval threshold is not satisfied");
  const trustedKeys = new Map(anchorPolicy.keys.map((item) => [item.id, item]));
  const accepted = new Map();
  for (const approval of approvals) {
    assertExactKeys(approval, ANCHOR_APPROVAL_KEYS, "Anchor recovery approval");
    if (!SLUG.test(approval.key_id ?? "") || accepted.has(approval.key_id)) throw new Error("Anchor recovery approval signer IDs must be unique");
    const trusted = trustedKeys.get(approval.key_id);
    if (!trusted) throw new Error("Anchor recovery approval signer is not trusted");
    if (!canonicalBase64(approval.signature)) throw new Error("Anchor recovery approval signature is invalid");
    const signature = Buffer.from(approval.signature, "base64");
    const key = parseEd25519PublicKey(trusted.public_key);
    if (signature.length !== 64 || !crypto.verify(null, Buffer.from(canonicalJson(statement), "utf8"), key, signature)) throw new Error("Anchor recovery approval signature is invalid");
    accepted.set(approval.key_id, structuredClone(approval));
  }
  if (approvals.length > anchorPolicy.keys.length) throw new Error("Anchor recovery approval set exceeds the enrolled policy");
  if (accepted.size < anchorPolicy.threshold) throw new Error("Anchor recovery approval threshold is not satisfied");
  const sortedApprovals = [...accepted.values()].sort((left, right) => left.key_id < right.key_id ? -1 : left.key_id > right.key_id ? 1 : 0);
  return { version: 1, policy: anchorPolicy, authorization: statement, approvals: sortedApprovals };
}

export function recoveryPolicyHash(policy) {
  assertExactKeys(policy, POLICY_KEYS, "Recovery policy");
  return crypto.createHash("sha256").update(canonicalJson(policy)).digest("hex");
}

export function requestHash(request) {
  return crypto.createHash("sha256").update(canonicalJson(request)).digest("hex");
}

function parseEd25519PublicKey(value) {
  try {
    const key = crypto.createPublicKey(value);
    if (key.asymmetricKeyType !== "ed25519") throw new Error();
    return key;
  } catch { throw new Error("Recovery authority public key must be Ed25519"); }
}

function keyFingerprint(key) {
  return `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function assertPrivateKeyFile(file) {
  const descriptor = openPrivateKeyFile(file);
  try { assertPrivateKeyStat(fs.fstatSync(descriptor)); }
  finally { fs.closeSync(descriptor); }
}

function readPrivateKeyFile(file) {
  const descriptor = openPrivateKeyFile(file);
  try {
    const stat = fs.fstatSync(descriptor);
    assertPrivateKeyStat(stat);
    if (stat.size <= 0 || stat.size > 16 * 1024) throw new Error("Recovery private key size is invalid");
    return readBounded(descriptor, 16 * 1024, "Recovery private key size is invalid");
  } finally { fs.closeSync(descriptor); }
}

function readBounded(descriptor, maxBytes, errorMessage) {
  const buffer = Buffer.allocUnsafe(maxBytes + 1);
  let total = 0;
  while (total < buffer.length) {
    const count = fs.readSync(descriptor, buffer, total, buffer.length - total, null);
    if (count === 0) break;
    total += count;
  }
  if (total === 0 || total > maxBytes) throw new Error(errorMessage);
  return buffer.subarray(0, total);
}

function openPrivateKeyFile(file) {
  try {
    assertProtectedAncestry(path.resolve(file));
    const before = fs.lstatSync(file);
    if (before.isSymbolicLink()) throw new Error("Recovery private key permissions are unsafe");
    return fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    if (error.message === "Recovery private key permissions are unsafe") throw error;
    throw new Error("Recovery private key permissions are unsafe");
  }
}

function assertPrivateKeyStat(stat) {
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error("Recovery private key permissions are unsafe");
}

function assertPrivateDirectory(directory) {
  assertProtectedAncestry(path.resolve(directory));
  const stat = fs.lstatSync(directory);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error("Recovery identity directory permissions are unsafe");
}

function assertProtectedAncestry(target) {
  const uid = process.getuid?.();
  let current = target;
  while (true) {
    const stat = fs.lstatSync(current);
    const stickyRoot = stat.isDirectory() && stat.uid === 0 && (stat.mode & 0o1000) !== 0;
    if ((stat.isSymbolicLink() && stat.uid !== 0) || (uid !== undefined && stat.uid !== uid && stat.uid !== 0) || ((stat.mode & 0o022) !== 0 && !stickyRoot)) throw new Error("Recovery private key permissions are unsafe");
    if (process.platform === "darwin") {
      const listed = spawnSync("/bin/ls", ["-lde", current], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
      if (listed.status !== 0 || /^\S+\+/.test(listed.stdout)) throw new Error("Recovery private key permissions are unsafe");
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function assertExactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson(keys)) throw new Error(`${label} encoding is invalid`);
}

function canonicalBase64(value) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  try { return Buffer.from(value, "base64").toString("base64") === value; } catch { return false; }
}

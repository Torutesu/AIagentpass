import crypto from "node:crypto";

import { parseBoundedJson } from "../../../lib/control-bundle-v2.mjs";
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM,
  QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
  createQualificationGrantBatchManifestSigner,
  verifyQualificationGrantBatchManifest
} from "./qualification-grant-batch-manifest.mjs";

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const MAX_RETIRING_KEYS = 3;
const MAX_RETIRING_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;

export const QUALIFICATION_MANIFEST_SIGNER_ENV = Object.freeze([
  "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID",
  "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY",
  "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_TIMEOUT_MS",
  "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_VERIFICATION_KEYS_JSON"
]);

export function createHostedQualificationManifestSigner({ provider, env = process.env, references = {}, now = () => Date.now() } = {}) {
  const config = parseQualificationManifestSignerConfig(env, references, { now });
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function") throw invalidConfig();
  const signer = createQualificationGrantBatchManifestSigner({ provider, keyId: config.keyId, timeoutMs: config.timeoutMs, now });

  async function assertProvider() {
    let metadata;
    try {
      metadata = await withDeadline((signal) => provider.publicKeyMetadata({
        key_id: config.keyId,
        algorithm: QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM,
        purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
        version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
        signal
      }), config.timeoutMs);
    } catch { throw invalidConfig(); }
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)
      || Object.keys(metadata).sort().join(",") !== "algorithm,key_id,public_key"
      || metadata.key_id !== config.keyId || metadata.algorithm !== QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM
      || fingerprintOf(metadata.public_key) !== config.publicKeyFingerprint) throw invalidConfig();
    return metadata;
  }

  async function verificationKeyMetadata(keyId, { at = undefined } = {}) {
    await assertProvider();
    const clock = exactNow(at === undefined ? now() : at);
    const activeKeys = config.keys.filter((key) => key.status === "active" || Date.parse(key.not_after) > clock);
    if (keyId !== undefined) {
      const key = activeKeys.find((candidate) => candidate.key_id === keyId);
      if (!key) throw invalidConfig();
      return key;
    }
    return Object.freeze({ version: 1, purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE, active_key_id: config.keyId, keys: Object.freeze(activeKeys) });
  }

  async function verifyManifest(manifest, { at = undefined } = {}) {
    const key = await verificationKeyMetadata(manifest?.statement?.key_id, { at });
    return verifyQualificationGrantBatchManifest(manifest, {
      publicKey: key.public_key,
      keyId: key.key_id,
      now: exactNow(at === undefined ? now() : at)
    });
  }

  async function health() {
    await assertProvider();
    return Object.freeze({
      ready: true,
      purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
      algorithm: QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM,
      key_id: config.keyId,
      public_key_fingerprint: config.publicKeyFingerprint
    });
  }

  async function signManifest(statement) {
    await assertProvider();
    return signer.signQualificationGrantBatchManifest(statement);
  }

  return Object.freeze({
    key_id: config.keyId,
    signQualificationGrantBatchManifest: signManifest,
    verifyQualificationGrantBatchManifest: verifyManifest,
    verificationKeyMetadata,
    health
  });
}

export function parseQualificationManifestSignerConfig(env = process.env, references = {}, { now = () => Date.now() } = {}) {
  try {
    if (env?.AGENTPASS_CLOUD_PROFILE !== "hosted") throw invalidConfig();
    const keyId = requiredKeyId(env.AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID);
    const publicKey = parsePublicKey(env.AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY);
    const timeoutMs = integer(env.AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_TIMEOUT_MS ?? "5000", 1, 30_000);
    const clock = exactNow(now());
    const active = publicMetadata({ keyId, publicKey, status: "active" });
    const retiring = parseRetiringKeys(env.AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_VERIFICATION_KEYS_JSON, clock);
    const keys = [active, ...retiring];
    if (new Set(keys.map((key) => key.key_id)).size !== keys.length
      || new Set(keys.map((key) => key.public_key_fingerprint)).size !== keys.length) throw invalidConfig();
    const forbidden = referenceFingerprints(references);
    if (keys.some((key) => forbidden.has(key.public_key_fingerprint))) throw invalidConfig();
    return Object.freeze({ keyId, timeoutMs, publicKeyFingerprint: active.public_key_fingerprint, keys: Object.freeze(keys) });
  } catch (error) {
    if (error?.code === "ERR_QUALIFICATION_MANIFEST_SIGNER_CONFIG") throw error;
    throw invalidConfig();
  }
}

function parseRetiringKeys(text, now) {
  if (text === undefined) return [];
  const value = parseBoundedJson(Buffer.from(text, "utf8"), { maxBytes: 32 * 1024, maxDepth: 8 });
  if (!Array.isArray(value) || value.length > MAX_RETIRING_KEYS) throw invalidConfig();
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)
      || Object.keys(entry).sort().join(",") !== "key_id,not_after,public_key") throw invalidConfig();
    const notAfter = Date.parse(entry.not_after);
    if (!Number.isFinite(notAfter) || notAfter <= now || notAfter - now > MAX_RETIRING_LIFETIME_MS) throw invalidConfig();
    return publicMetadata({ keyId: requiredKeyId(entry.key_id), publicKey: parsePublicKey(entry.public_key), status: "retiring", notAfter: new Date(notAfter).toISOString() });
  });
}

function publicMetadata({ keyId, publicKey, status, notAfter }) {
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return Object.freeze({
    key_id: keyId,
    algorithm: QUALIFICATION_GRANT_BATCH_MANIFEST_ALGORITHM,
    public_key: pem,
    public_key_fingerprint: fingerprintOf(publicKey),
    status,
    ...(notAfter ? { not_after: notAfter } : {})
  });
}

function referenceFingerprints(references) {
  const values = [];
  const visit = (value) => {
    if (!value) return;
    if (Array.isArray(value)) return value.forEach(visit);
    if (value.publicKey !== undefined) values.push(value.publicKey);
    else if (value.public_key !== undefined) values.push(value.public_key);
  };
  Object.values(references ?? {}).forEach(visit);
  return new Set(values.map((value) => fingerprintOf(parsePublicKey(value))));
}

function parsePublicKey(value) {
  let key;
  try { key = value?.type === "public" ? value : value?.type === "private" ? crypto.createPublicKey(value) : crypto.createPublicKey(value); }
  catch { throw invalidConfig(); }
  if (key.asymmetricKeyType !== "ed25519") throw invalidConfig();
  return key;
}

function fingerprintOf(value) {
  const key = value?.asymmetricKeyType ? (value.type === "private" ? crypto.createPublicKey(value) : value) : parsePublicKey(value);
  return crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
}

function requiredKeyId(value) { if (!KEY_ID.test(value ?? "")) throw invalidConfig(); return value; }
function integer(value, min, max) { if (!/^\d+$/u.test(value ?? "")) throw invalidConfig(); const number = Number(value); if (!Number.isSafeInteger(number) || number < min || number > max) throw invalidConfig(); return number; }
function exactNow(value) { const number = value instanceof Date ? value.getTime() : value; if (!Number.isFinite(number) || number < 0) throw invalidConfig(); return number; }
async function withDeadline(operation, timeoutMs) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(invalidConfig()); }, timeoutMs); })
    ]);
  } finally { clearTimeout(timer); }
}
function invalidConfig() { return Object.assign(new Error("qualification manifest signer configuration is invalid"), { code: "ERR_QUALIFICATION_MANIFEST_SIGNER_CONFIG" }); }

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const CLOUD_EVIDENCE_KIND = "agentpass.cloud-deployment-evidence";
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const REVISION = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}_shape`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new Error(`${label}_fields`);
}

function timestamp(value, label) {
  if (typeof value !== "string" || !ISO_UTC.test(value) || new Date(value).toISOString() !== value) throw new Error(`${label}_timestamp`);
}

function validateUnsigned(evidence) {
  exactKeys(evidence, ["schema_version", "evidence_kind", "status", "environment", "service", "revision", "commit_sha", "artifact_digest", "health", "observed_at"], "evidence");
  if (evidence.schema_version !== 1 || evidence.evidence_kind !== CLOUD_EVIDENCE_KIND || evidence.status !== "verified" || evidence.environment !== "production" || evidence.service !== "agentpass-cloud-api") throw new Error("evidence_binding");
  if (typeof evidence.revision !== "string" || !REVISION.test(evidence.revision)) throw new Error("revision_invalid");
  if (!COMMIT_SHA.test(evidence.commit_sha) || !SHA256_DIGEST.test(evidence.artifact_digest)) throw new Error("deployment_identity_invalid");
  exactKeys(evidence.health, ["status", "url", "checked_at"], "health");
  if (evidence.health.status !== "ready" || typeof evidence.health.url !== "string" || !/^https:\/\//u.test(evidence.health.url)) throw new Error("health_not_ready");
  timestamp(evidence.health.checked_at, "health");
  timestamp(evidence.observed_at, "observed");
}

export function verifyCloudDeploymentEvidence(evidence, { publicKey, expectedFingerprint } = {}) {
  exactKeys(evidence, ["schema_version", "evidence_kind", "status", "environment", "service", "revision", "commit_sha", "artifact_digest", "health", "observed_at", "signature"], "evidence");
  const { signature, ...unsigned } = evidence;
  validateUnsigned(unsigned);
  exactKeys(signature, ["algorithm", "public_key_fingerprint", "value"], "signature");
  if (signature.algorithm !== "ed25519" || !FINGERPRINT.test(signature.public_key_fingerprint) || signature.public_key_fingerprint !== expectedFingerprint || typeof signature.value !== "string") throw new Error("signature_binding");
  const key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
  const der = key.export({ type: "spki", format: "der" });
  if (crypto.createHash("sha256").update(der).digest("hex") !== expectedFingerprint) throw new Error("public_key_fingerprint_mismatch");
  if (!crypto.verify(null, Buffer.from(`${canonicalJson(unsigned)}\n`), key, Buffer.from(signature.value, "base64url"))) throw new Error("invalid_signature");
  return Object.freeze({ ...unsigned, signature: { ...signature } });
}

export async function readCloudDeploymentEvidence(evidencePath, publicKeyPath) {
  if (!path.isAbsolute(evidencePath) || !path.isAbsolute(publicKeyPath)) throw new Error("absolute_paths_required");
  return { evidence: JSON.parse(await fs.readFile(evidencePath, "utf8")), publicKey: await fs.readFile(publicKeyPath) };
}

async function main() {
  const [evidencePath, publicKeyPath, fingerprint] = process.argv.slice(2);
  if (!evidencePath || !publicKeyPath || !fingerprint || process.argv.length !== 5 || !FINGERPRINT.test(fingerprint)) throw new Error("invalid_arguments");
  const { evidence, publicKey } = await readCloudDeploymentEvidence(path.resolve(evidencePath), path.resolve(publicKeyPath));
  const result = verifyCloudDeploymentEvidence(evidence, { publicKey, expectedFingerprint: fingerprint });
  process.stdout.write(`${JSON.stringify({ status: "verified", source_commit: result.commit_sha, image_digest: result.artifact_digest, revision: result.revision, health_url: result.health.url })}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`cloud-deployment-verify: ${error.message}\n`); process.exitCode = error.message === "invalid_arguments" ? 2 : 1; });

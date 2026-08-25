#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, CLOUD_EVIDENCE_KIND, verifyCloudDeploymentEvidence } from "./verify-cloud-deployment.mjs";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;

export async function produceCloudDeploymentEvidence({ healthUrl, expectedCommit, expectedDigest, privateKeyPem, outputPath, authorization, fetchImpl = fetch, now = () => new Date() }) {
  if (!/^https:\/\//u.test(healthUrl) || !COMMIT.test(expectedCommit) || !DIGEST.test(expectedDigest) || typeof authorization !== "string" || !/^Bearer\s+\S+$/u.test(authorization)) throw new Error("deployment_inputs_invalid");
  const response = await fetchImpl(healthUrl, { redirect: "error", headers: { accept: "application/json", authorization } });
  if (!response.ok) throw new Error("health_request_failed");
  const body = await response.json();
  if (body === null || typeof body !== "object" || Array.isArray(body) || Object.keys(body).sort().join(",") !== "artifact_digest,commit_sha,revision,status" || body.status !== "ready" || body.commit_sha !== expectedCommit || body.artifact_digest !== expectedDigest || typeof body.revision !== "string") throw new Error("health_identity_mismatch");
  const observedAt = now().toISOString();
  const unsigned = { schema_version: 1, evidence_kind: CLOUD_EVIDENCE_KIND, status: "verified", environment: "production", service: "agentpass-cloud-api", revision: body.revision, commit_sha: body.commit_sha, artifact_digest: body.artifact_digest, health: { status: "ready", url: healthUrl, checked_at: observedAt }, observed_at: observedAt };
  const key = privateKeyPem?.type === "private" ? privateKeyPem : crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(key);
  const der = publicKey.export({ type: "spki", format: "der" });
  const evidence = { ...unsigned, signature: { algorithm: "ed25519", public_key_fingerprint: crypto.createHash("sha256").update(der).digest("hex"), value: crypto.sign(null, Buffer.from(`${canonicalJson(unsigned)}\n`), key).toString("base64url") } };
  verifyCloudDeploymentEvidence(evidence, { publicKey, expectedFingerprint: evidence.signature.public_key_fingerprint });
  await fs.writeFile(outputPath, `${canonicalJson(evidence)}\n`, { mode: 0o600, flag: "wx" });
  return evidence;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [healthUrl, expectedCommit, expectedDigest, privateKeyPath, outputPath] = process.argv.slice(2);
  if (!healthUrl || !expectedCommit || !expectedDigest || !privateKeyPath || !outputPath || process.argv.length !== 7) { process.stderr.write("cloud-deployment-produce: invalid_arguments\n"); process.exitCode = 2; }
  else produceCloudDeploymentEvidence({ healthUrl, expectedCommit, expectedDigest, privateKeyPem: await fs.readFile(privateKeyPath), outputPath, authorization: process.env.AGENTPASS_CLOUD_HEALTH_AUTHORIZATION }).then(() => process.stdout.write(`${outputPath}\n`)).catch((error) => { process.stderr.write(`cloud-deployment-produce: ${error.message}\n`); process.exitCode = 1; });
}

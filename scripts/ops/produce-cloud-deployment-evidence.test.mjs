import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { produceCloudDeploymentEvidence } from "./produce-cloud-deployment-evidence.mjs";
import { verifyCloudDeploymentEvidence } from "./verify-cloud-deployment.mjs";

test("producer requires live identity-bound ready health and writes signed evidence", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const dir = await mkdtemp(join(tmpdir(), "agentpass-cloud-producer-"));
  const outputPath = join(dir, "evidence.json");
  const commit = "a".repeat(40);
  const digest = `sha256:${"b".repeat(64)}`;
  const evidence = await produceCloudDeploymentEvidence({
    healthUrl: "https://api.example.com/health/ready",
    expectedCommit: commit,
    expectedDigest: digest,
    privateKeyPem: privateKey,
    outputPath,
    authorization: "Bearer test-token",
    now: () => new Date("2026-08-20T00:00:00.000Z"),
    fetchImpl: async () => new Response(JSON.stringify({ status: "ready", revision: "rev-1", commit_sha: commit, artifact_digest: digest }), { status: 200 })
  });
  const parsed = JSON.parse(await readFile(outputPath, "utf8"));
  assert.equal(parsed.signature.value, evidence.signature.value);
  assert.equal(verifyCloudDeploymentEvidence(parsed, { publicKey, expectedFingerprint: parsed.signature.public_key_fingerprint }).artifact_digest, digest);
});

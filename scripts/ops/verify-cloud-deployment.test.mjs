import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const script = new URL("./verify-cloud-deployment.mjs", import.meta.url).pathname;
const valid = () => ({ status: "verified", environment: "production", service: "agentpass-cloud-api", revision: "rev-2026-08-20", commit_sha: "a".repeat(40), artifact_digest: `sha256:${"b".repeat(64)}`, health: { status: "ready", url: "https://api.example.com/health/ready", checked_at: "2026-08-20T00:00:00Z" } });
const signedEvidence = (privateKey) => {
  const evidence = valid();
  evidence.signature = sign(null, Buffer.from(`${JSON.stringify(evidence)}\n`), privateKey).toString("base64");
  return evidence;
};

test("accepts exact production deployment evidence", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-cloud-evidence-"));
  const file = join(dir, "evidence.json");
  const keyFile = join(dir, "deployment-public.pem");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ type: "spki", format: "pem" });
  await writeFile(keyFile, publicKeyBytes);
  await writeFile(file, `${JSON.stringify(signedEvidence(privateKey))}\n`);
  const fingerprint = createHash("sha256").update(publicKeyBytes).digest("hex");
  const { stdout } = await run(process.execPath, [script, file, keyFile, fingerprint]);
  assert.match(stdout, /"status":"verified"/u);
});

test("rejects a healthy non-production or floating artifact", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-cloud-evidence-"));
  const file = join(dir, "evidence.json");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const evidence = signedEvidence(privateKey);
  evidence.environment = "staging";
  evidence.artifact_digest = "latest";
  const keyFile = join(dir, "deployment-public.pem");
  const publicKeyBytes = publicKey.export({ type: "spki", format: "pem" });
  await writeFile(keyFile, publicKeyBytes);
  await writeFile(file, `${JSON.stringify(evidence)}\n`);
  const fingerprint = createHash("sha256").update(publicKeyBytes).digest("hex");
  await assert.rejects(run(process.execPath, [script, file, keyFile, fingerprint]), /evidence rejected/u);
});

test("rejects a substituted public key even when its signature is valid", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-cloud-evidence-"));
  const file = join(dir, "evidence.json");
  const keyFile = join(dir, "deployment-public.pem");
  const trusted = generateKeyPairSync("ed25519");
  const substituted = generateKeyPairSync("ed25519");
  const substitutedBytes = substituted.publicKey.export({ type: "spki", format: "pem" });
  await writeFile(keyFile, substitutedBytes);
  await writeFile(file, `${JSON.stringify(signedEvidence(trusted.privateKey))}\n`);
  const trustedBytes = trusted.publicKey.export({ type: "spki", format: "pem" });
  const trustedFingerprint = createHash("sha256").update(trustedBytes).digest("hex");
  await assert.rejects(run(process.execPath, [script, file, keyFile, trustedFingerprint]), /evidence rejected/u);
});

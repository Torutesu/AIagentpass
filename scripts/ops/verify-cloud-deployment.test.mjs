import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { canonicalJson } from "./verify-cloud-deployment.mjs";

const run = promisify(execFile);
const script = new URL("./verify-cloud-deployment.mjs", import.meta.url).pathname;
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const publicDer = publicKey.export({ type: "spki", format: "der" });
const fingerprint = crypto.createHash("sha256").update(publicDer).digest("hex");
const valid = () => ({ schema_version: 1, evidence_kind: "agentpass.cloud-deployment-evidence", status: "verified", environment: "production", service: "agentpass-cloud-api", revision: "rev-2026-08-20", commit_sha: "a".repeat(40), artifact_digest: `sha256:${"b".repeat(64)}`, health: { status: "ready", url: "https://api.example.com/health/ready", checked_at: "2026-08-20T00:00:00.000Z" }, observed_at: "2026-08-20T00:00:00.000Z" });
const signed = () => { const unsigned = valid(); return { ...unsigned, signature: { algorithm: "ed25519", public_key_fingerprint: fingerprint, value: crypto.sign(null, Buffer.from(`${canonicalJson(unsigned)}\n`), privateKey).toString("base64url") } }; };

test("accepts exact production deployment evidence", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-cloud-evidence-"));
  const file = join(dir, "evidence.json");
  await writeFile(file, `${JSON.stringify(signed())}\n`);
  const keyFile = join(dir, "public.pem");
  await writeFile(keyFile, publicKey.export({ type: "spki", format: "pem" }));
  const { stdout } = await run(process.execPath, [script, file, keyFile, fingerprint]);
  assert.match(stdout, /"status":"verified"/u);
});

test("rejects a healthy non-production or floating artifact", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-cloud-evidence-"));
  const file = join(dir, "evidence.json");
  const evidence = signed();
  evidence.environment = "staging";
  evidence.artifact_digest = "latest";
  await writeFile(file, `${JSON.stringify(evidence)}\n`);
  const keyFile = join(dir, "public.pem");
  await writeFile(keyFile, publicKey.export({ type: "spki", format: "pem" }));
  await assert.rejects(run(process.execPath, [script, file, keyFile, fingerprint]), /cloud-deployment-verify/u);
});

test("reports unknown when production deployment evidence is absent", async () => {
  await assert.rejects(
    run(process.execPath, [script, "/tmp/agentpass-cloud-evidence-does-not-exist.json", "/tmp/no-key.pem", fingerprint]),
    (error) => error.code === 1 && /ENOENT/u.test(error.stderr),
  );
});

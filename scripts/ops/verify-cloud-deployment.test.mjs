import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const script = new URL("./verify-cloud-deployment.mjs", import.meta.url).pathname;
const valid = () => ({ status: "verified", environment: "production", service: "agentpass-cloud-api", revision: "rev-2026-08-20", commit_sha: "a".repeat(40), artifact_digest: `sha256:${"b".repeat(64)}`, health: { status: "ready", url: "https://api.example.com/health/ready", checked_at: "2026-08-20T00:00:00Z" } });

test("accepts exact production deployment evidence", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-cloud-evidence-"));
  const file = join(dir, "evidence.json");
  await writeFile(file, `${JSON.stringify(valid())}\n`);
  const { stdout } = await run(process.execPath, [script, file]);
  assert.match(stdout, /"status":"verified"/u);
});

test("rejects a healthy non-production or floating artifact", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-cloud-evidence-"));
  const file = join(dir, "evidence.json");
  const evidence = valid();
  evidence.environment = "staging";
  evidence.artifact_digest = "latest";
  await writeFile(file, `${JSON.stringify(evidence)}\n`);
  await assert.rejects(run(process.execPath, [script, file]), /evidence rejected/u);
});

import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";

const run = promisify(execFile);
const script = new URL("./verify-macos-release-evidence.mjs", import.meta.url).pathname;
const commit = "a".repeat(40);
const digest = `sha256:${"b".repeat(64)}`;
function valid() {
  return { schema_version: 1, candidate: { commit_sha: commit, artifact_digest: digest }, package: { name: "AgentPass-1.0.0.pkg", artifact_digest: digest }, signing: { status: "verified", identity: "Developer ID Application: Example (ABCDE12345)", team_id: "ABCDE12345", bundle_id: "dev.agentpass.native" }, notarization: { status: "accepted", ticket_id: "ticket-12345678" }, stapling: { status: "verified" }, gatekeeper: { status: "accepted" } };
}
async function evidence(value) { const dir = await mkdtemp(join(tmpdir(), "agentpass-macos-evidence-")); const path = join(dir, "evidence.json"); await writeFile(path, `${JSON.stringify(value)}\n`); return path; }

test("passes only for a candidate-bound Developer ID and notarized package", async () => {
  const path = await evidence(valid());
  const { stdout } = await run(process.execPath, [script, path, "--candidate-commit-sha", commit, "--candidate-artifact-digest", digest]);
  assert.equal(JSON.parse(stdout).status, "passed");
});

test("fails closed on digest or signing evidence substitution", async () => {
  const value = valid(); value.package.artifact_digest = `sha256:${"c".repeat(64)}`; value.signing.identity = "Apple Development: Example";
  const path = await evidence(value);
  await assert.rejects(run(process.execPath, [script, path]), (error) => error.code === 1 && /evidence failed/u.test(error.stderr));
});

test("reports unknown when real Apple evidence is absent", async () => {
  await assert.rejects(run(process.execPath, [script, "/tmp/agentpass-macos-evidence-missing.json"]), (error) => error.code === 2 && /evidence is unknown/u.test(error.stderr));
});

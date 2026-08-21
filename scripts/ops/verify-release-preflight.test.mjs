import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const script = new URL("./verify-release-preflight.mjs", import.meta.url).pathname;
const commitSha = "a".repeat(40);
const artifactDigest = `sha256:${"b".repeat(64)}`;
const checkNames = [
  "native_audit_delivery",
  "cloud_production_deploy",
  "real_postgresql",
  "developer_id_notarization",
  "hardware_qualification",
];

function validEvidence() {
  return {
    schema_version: 1,
    candidate: { commit_sha: commitSha, artifact_digest: artifactDigest },
    checks: Object.fromEntries(checkNames.map((name) => [name, {
      status: "passed",
      evidence_ref: `${name}.json`,
      evidence_sha256: createHash("sha256").update(`evidence:${name}`).digest("hex"),
      commit_sha: commitSha,
      artifact_digest: artifactDigest,
    }])),
  };
}

async function writeEvidence(value) {
  const dir = await mkdtemp(join(tmpdir(), "agentpass-release-preflight-"));
  for (const [name, check] of Object.entries(value.checks ?? {})) {
    if (check.status !== "passed") continue;
    const target = join(dir, check.evidence_ref);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, `evidence:${name}`);
  }
  const file = join(dir, "evidence.json");
  await writeFile(file, `${JSON.stringify(value)}\n`);
  return file;
}

test("passes only when all five gates are passed and candidate-bound", async () => {
  const file = await writeEvidence(validEvidence());
  const { stdout } = await run(process.execPath, [script, file, "--candidate-commit-sha", commitSha]);
  const report = JSON.parse(stdout);
  assert.equal(report.status, "passed");
  assert.deepEqual(Object.values(report.checks).map((check) => check.status), ["passed", "passed", "passed", "passed", "passed"]);
});

test("returns unknown when evidence is absent", async () => {
  await assert.rejects(
    run(process.execPath, [script, "/tmp/agentpass-release-evidence-does-not-exist.json"]),
    (error) => error.code === 2 && /release preflight unknown/u.test(error.stderr),
  );
});

test("returns unknown when a live production gate is not verified", async () => {
  const evidence = validEvidence();
  evidence.checks.real_postgresql = { status: "unknown", evidence_ref: "qualification/live-postgresql.json", evidence_sha256: "0".repeat(64) };
  const file = await writeEvidence(evidence);
  await assert.rejects(
    run(process.execPath, [script, file]),
    (error) => error.code === 2 && /release preflight unknown/u.test(error.stderr),
  );
});

test("fails closed when a passed gate references a missing or tampered file", async () => {
  const missing = validEvidence();
  missing.checks.hardware_qualification.evidence_ref = "missing.json";
  const missingFile = await writeEvidence(missing);
  await rm(join(dirname(missingFile), "missing.json"));
  await assert.rejects(run(process.execPath, [script, missingFile]), (error) => error.code === 1 && /release preflight failed/u.test(error.stderr));
  const tampered = validEvidence();
  const tamperedFile = await writeEvidence(tampered);
  await writeFile(join(dirname(tamperedFile), "native_audit_delivery.json"), "tampered");
  await assert.rejects(run(process.execPath, [script, tamperedFile]), (error) => error.code === 1);
});

test("fails a failed gate or a candidate binding mismatch", async () => {
  const failed = validEvidence();
  failed.checks.developer_id_notarization.status = "failed";
  const failedFile = await writeEvidence(failed);
  await assert.rejects(
    run(process.execPath, [script, failedFile]),
    (error) => error.code === 1 && /release preflight failed/u.test(error.stderr),
  );

  const mismatch = validEvidence();
  mismatch.checks.hardware_qualification.commit_sha = "c".repeat(40);
  const mismatchFile = await writeEvidence(mismatch);
  await assert.rejects(run(process.execPath, [script, mismatchFile]), (error) => error.code === 1);
});

import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  HOSTED_ACCOUNT_TEST_FILES,
  HOSTED_ACCOUNT_QUALIFICATION_SCENARIOS,
  HostedAccountQualificationEvidenceError,
  createHostedAccountQualificationEvidence,
  verifyHostedAccountQualificationEvidence,
  writeHostedAccountQualificationEvidence
} from "../scripts/postgres/hosted-account-qualification-evidence.mjs";

const SOURCE = "a".repeat(40);
const validTap = ({ skipped = 0, failed = 0, todo = 0 } = {}) => {
  const tests = HOSTED_ACCOUNT_TEST_FILES.length + 5;
  const passed = tests - skipped - failed - todo;
  return `TAP version 13\n1..${tests}\n# tests ${tests}\n# pass ${passed}\n# fail ${failed}\n# skipped ${skipped}\n# todo ${todo}\n# duration_ms 42\n`;
};

async function fixture(t, tap = validTap()) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-hosted-evidence-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tapFile = path.join(directory, "hosted.tap");
  const evidenceFile = path.join(directory, "hosted.json");
  await writeFile(tapFile, tap, { mode: 0o600 });
  return { directory, tapFile, evidenceFile };
}

test("creates source- and TAP-bound Hosted account qualification evidence", async (t) => {
  const f = await fixture(t);
  const evidence = await createHostedAccountQualificationEvidence({
    sourceCommit: SOURCE,
    postgresVersion: "17.6 (Ubuntu 17.6-1)",
    runId: "123",
    runAttempt: "2",
    tapFile: f.tapFile
  });
  assert.equal(evidence.migration_version, 64);
  assert.equal(evidence.catalog_entries, 175);
  assert.deepEqual(evidence.test_files, HOSTED_ACCOUNT_TEST_FILES);
  assert.deepEqual(evidence.scenarios, HOSTED_ACCOUNT_QUALIFICATION_SCENARIOS);
  assert.deepEqual(evidence.summary, { tests: 12, passed: 12, failed: 0, skipped: 0, todo: 0 });
  assert.match(evidence.tap_sha256, /^[0-9a-f]{64}$/u);
  assert.match(evidence.source_tree_sha256, /^[0-9a-f]{64}$/u);
});

test("writes canonical private evidence and independently verifies it", async (t) => {
  const f = await fixture(t);
  const written = await writeHostedAccountQualificationEvidence(f.evidenceFile, {
    sourceCommit: SOURCE,
    postgresVersion: "17.6",
    runId: 9,
    runAttempt: 1,
    tapFile: f.tapFile
  });
  const verified = await verifyHostedAccountQualificationEvidence(f.evidenceFile, { expectedSourceCommit: SOURCE });
  assert.equal(verified.evidence_sha256, written.evidence_sha256);
  assert.equal(verified.tests, 12);
  assert.equal((await readFile(f.evidenceFile, "utf8")).endsWith("\n"), true);
});

test("rejects skipped, TODO, failed, bailed-out, and incomplete TAP", async (t) => {
  const cases = [
    validTap({ skipped: 1 }),
    validTap({ todo: 1 }),
    validTap({ failed: 1 }),
    `${validTap()}Bail out! database disappeared\n`,
    "TAP version 13\n1..1\n# tests 1\n# pass 1\n"
  ];
  for (const [index, tap] of cases.entries()) {
    const f = await fixture(t, tap);
    await assert.rejects(
      createHostedAccountQualificationEvidence({ sourceCommit: SOURCE, postgresVersion: "17.6", runId: String(index + 1), runAttempt: 1, tapFile: f.tapFile }),
      (error) => error instanceof HostedAccountQualificationEvidenceError
    );
  }
});

test("rejects tampering, source substitution, and broad evidence permissions", async (t) => {
  const f = await fixture(t);
  await writeHostedAccountQualificationEvidence(f.evidenceFile, {
    sourceCommit: SOURCE,
    postgresVersion: "17.6",
    runId: 1,
    runAttempt: 1,
    tapFile: f.tapFile
  });
  await assert.rejects(
    verifyHostedAccountQualificationEvidence(f.evidenceFile, { expectedSourceCommit: "b".repeat(40) }),
    { code: "invalid_evidence" }
  );
  await chmod(f.evidenceFile, 0o644);
  await assert.rejects(
    verifyHostedAccountQualificationEvidence(f.evidenceFile, { expectedSourceCommit: SOURCE }),
    { code: "invalid_file" }
  );
});

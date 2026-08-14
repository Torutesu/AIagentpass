import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PROVIDER_OPERATION_QUALIFICATION_COMMAND,
  PROVIDER_OPERATION_QUALIFICATION_SCENARIOS,
  ProviderOperationQualificationEvidenceError,
  createProviderOperationQualificationEvidence,
  normalizeProviderOperationQualificationEvidence,
  verifyProviderOperationQualificationEvidence,
  writeProviderOperationQualificationEvidence
} from "../scripts/postgres/provider-operation-qualification-evidence.mjs";

const SOURCE_COMMIT = "a".repeat(40);

test("creates the exact source-bound PostgreSQL 17 C1.4 qualification contract", async () => {
  const evidence = await createProviderOperationQualificationEvidence({
    sourceCommit: SOURCE_COMMIT,
    postgresVersion: "17.6",
    runId: "31841799223",
    runAttempt: "1"
  });
  assert.equal(evidence.source_commit, SOURCE_COMMIT);
  assert.equal(evidence.postgres_version, "17.6");
  assert.equal(evidence.catalog_entries >= 129, true);
  assert.equal(evidence.migration_version >= 42, true);
  assert.equal(evidence.command, PROVIDER_OPERATION_QUALIFICATION_COMMAND);
  assert.deepEqual(evidence.scenarios, PROVIDER_OPERATION_QUALIFICATION_SCENARIOS);
  assert.deepEqual(evidence.summary, { passed: 6, failed: 0, skipped: 0 });
  assert.equal(Object.isFrozen(evidence), true);
  assert.equal(Object.isFrozen(evidence.summary), true);
});

test("writes one private canonical artifact and verifies its source and catalog bindings", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-c1-evidence-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.chmod(directory, 0o700);
  const output = path.join(directory, "provider-operation.json");
  const written = await writeProviderOperationQualificationEvidence(output, {
    sourceCommit: SOURCE_COMMIT,
    postgresVersion: "17.6 (Debian 17.6-1.pgdg120+1)",
    runId: "31841799223",
    runAttempt: 2
  });
  assert.match(written.evidence_sha256, /^[0-9a-f]{64}$/u);
  assert.equal((await fs.stat(output)).mode & 0o777, 0o600);
  assert.deepEqual(await verifyProviderOperationQualificationEvidence(output, { expectedSourceCommit: SOURCE_COMMIT }), {
    evidence_sha256: written.evidence_sha256,
    source_commit: SOURCE_COMMIT,
    scenarios: 6
  });
  await assert.rejects(
    () => writeProviderOperationQualificationEvidence(output, {
      sourceCommit: SOURCE_COMMIT,
      postgresVersion: "17.6",
      runId: "31841799223",
      runAttempt: 2
    }),
    { code: "invalid_output" }
  );
});

test("rejects source, outcome, command, scenario and skip substitution", async () => {
  const evidence = await createProviderOperationQualificationEvidence({
    sourceCommit: SOURCE_COMMIT,
    postgresVersion: "17.6",
    runId: "31841799223",
    runAttempt: 1
  });
  for (const mutation of [
    { source_commit: "b".repeat(40) },
    { outcome: "failed" },
    { command: `${evidence.command} --test-only` },
    { scenarios: [...evidence.scenarios].reverse() },
    { summary: { passed: 5, failed: 0, skipped: 1 } },
    { postgres_version: "16.10" },
    { unexpected: true }
  ]) {
    assert.throws(
      () => normalizeProviderOperationQualificationEvidence({ ...evidence, ...mutation }, { expectedSourceCommit: SOURCE_COMMIT }),
      ProviderOperationQualificationEvidenceError
    );
  }
});

test("rejects non-private, linked, noncanonical and catalog-substituted evidence", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-c1-evidence-negative-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const output = path.join(directory, "evidence.json");
  await writeProviderOperationQualificationEvidence(output, {
    sourceCommit: SOURCE_COMMIT,
    postgresVersion: "17.6",
    runId: "31841799223",
    runAttempt: 1
  });
  await fs.chmod(output, 0o644);
  await assert.rejects(() => verifyProviderOperationQualificationEvidence(output, { expectedSourceCommit: SOURCE_COMMIT }), { code: "invalid_file" });

  const linked = path.join(directory, "linked.json");
  await fs.link(output, linked);
  await fs.chmod(output, 0o600);
  await assert.rejects(() => verifyProviderOperationQualificationEvidence(output, { expectedSourceCommit: SOURCE_COMMIT }), { code: "invalid_file" });
});

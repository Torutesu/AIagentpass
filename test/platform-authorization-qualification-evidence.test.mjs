import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PLATFORM_AUTHORIZATION_QUALIFICATION_COMMAND,
  PLATFORM_AUTHORIZATION_QUALIFICATION_SCENARIOS,
  PlatformAuthorizationQualificationEvidenceError,
  createPlatformAuthorizationQualificationEvidence,
  normalizePlatformAuthorizationQualificationEvidence,
  verifyPlatformAuthorizationQualificationEvidence,
  writePlatformAuthorizationQualificationEvidence
} from "../scripts/postgres/platform-authorization-qualification-evidence.mjs";

const SOURCE_COMMIT = "a".repeat(40);

test("creates the exact source, migration-55, PostgreSQL-17 authorization qualification contract", async () => {
  const evidence = await createPlatformAuthorizationQualificationEvidence({
    sourceCommit: SOURCE_COMMIT,
    postgresVersion: "17.6",
    runId: "31841799223",
    runAttempt: "1"
  });
  assert.equal(evidence.source_commit, SOURCE_COMMIT);
  assert.equal(evidence.migration_version, 55);
  assert.equal(evidence.command, PLATFORM_AUTHORIZATION_QUALIFICATION_COMMAND);
  assert.deepEqual(evidence.scenarios, PLATFORM_AUTHORIZATION_QUALIFICATION_SCENARIOS);
  assert.deepEqual(evidence.summary, { passed: 10, failed: 0, skipped: 0 });
  assert.equal(Object.isFrozen(evidence), true);
});

test("writes one private canonical artifact and verifies source/catalog binding", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-platform-auth-evidence-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.chmod(directory, 0o700);
  const output = path.join(directory, "platform-authorization.json");
  const written = await writePlatformAuthorizationQualificationEvidence(output, {
    sourceCommit: SOURCE_COMMIT,
    postgresVersion: "17.6 (Debian 17.6-1.pgdg120+1)",
    runId: "31841799223",
    runAttempt: 2
  });
  assert.equal((await fs.stat(output)).mode & 0o777, 0o600);
  assert.deepEqual(await verifyPlatformAuthorizationQualificationEvidence(output, { expectedSourceCommit: SOURCE_COMMIT }), {
    evidence_sha256: written.evidence_sha256,
    source_commit: SOURCE_COMMIT,
    migration_version: 55,
    scenarios: 10
  });
});

test("rejects source, PostgreSQL, migration, command, scenario, skip, and extra-field substitution", async () => {
  const evidence = await createPlatformAuthorizationQualificationEvidence({
    sourceCommit: SOURCE_COMMIT,
    postgresVersion: "17.6",
    runId: "31841799223",
    runAttempt: 1
  });
  for (const mutation of [
    { source_commit: "b".repeat(40) },
    { postgres_version: "16.10" },
    { migration_version: 54 },
    { command: `${evidence.command} --test-only` },
    { scenarios: [...evidence.scenarios].reverse() },
    { summary: { passed: 9, failed: 0, skipped: 1 } },
    { outcome: "failed" },
    { unexpected: true }
  ]) {
    assert.throws(
      () => normalizePlatformAuthorizationQualificationEvidence({ ...evidence, ...mutation }, { expectedSourceCommit: SOURCE_COMMIT }),
      PlatformAuthorizationQualificationEvidenceError
    );
  }
});

test("rejects public or linked evidence files", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-platform-auth-evidence-negative-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const output = path.join(directory, "evidence.json");
  await writePlatformAuthorizationQualificationEvidence(output, {
    sourceCommit: SOURCE_COMMIT,
    postgresVersion: "17.6",
    runId: "31841799223",
    runAttempt: 1
  });
  await fs.chmod(output, 0o644);
  await assert.rejects(
    () => verifyPlatformAuthorizationQualificationEvidence(output, { expectedSourceCommit: SOURCE_COMMIT }),
    { code: "invalid_file" }
  );
  const linked = path.join(directory, "linked.json");
  await fs.link(output, linked);
  await fs.chmod(output, 0o600);
  await assert.rejects(
    () => verifyPlatformAuthorizationQualificationEvidence(output, { expectedSourceCommit: SOURCE_COMMIT }),
    { code: "invalid_file" }
  );
});

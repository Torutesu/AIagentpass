import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import test from "node:test";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  assertRedactedQualificationEvidence,
  computeQualificationInputArtifactSha256,
  CURRENT_SCHEMA_HEAD_VERSION,
  DEFAULT_QUALIFICATION_INPUT_ARTIFACT_PATH,
  downgradeSuccessfulQualificationOnCleanupFailure,
  QUALIFICATION_DIAGNOSTICS,
  TARGET_NAME,
  TARGET_VERSION,
  normalizeQualificationEvidence,
  runC3Migration0047Qualification,
  verifyQualificationEvidence,
  writeQualificationEvidence
} from "../../../../scripts/qualification/postgres-c3-migration-0047.mjs";

const DEFAULT_ARTIFACT_SHA256 = await computeQualificationInputArtifactSha256(DEFAULT_QUALIFICATION_INPUT_ARTIFACT_PATH);

function digest(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

class FailingQualificationPool {
  async connect() {
    const error = new Error("connection refused");
    error.code = "ECONNREFUSED";
    throw error;
  }
  async end() {}
}

test("C3 migration 0047 qualification emits fail-closed not_run evidence without a real database", async () => {
  const evidence = await runC3Migration0047Qualification({ env: {} });

  assert.deepEqual(evidence, {
    schema_version: 1,
    qualification: "postgres-c3-migration-0047",
    status: "not_run",
    qualified: false,
    reason: QUALIFICATION_DIAGNOSTICS.DATABASE_URL_MISSING,
    migration_version: TARGET_VERSION,
    migration_name: TARGET_NAME,
    migration_checksum: null,
    migration_applied_this_run: false,
    current_version: null,
    server_version: null,
    database_name: null,
    server_port: null,
    tls_version: null,
    artifact_sha256: null,
    source_commit: null,
    source_tree: null,
    ci_run_id: null,
    ci_run_attempt: null,
    ci_job_id: null,
    redacted: true,
    checks: [],
    started_at: evidence.started_at,
    completed_at: evidence.completed_at
  });
});

test("C3 artifact_sha256 is computed from stable qualification-input bytes", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "agentpass-c3-artifact-"));
  const artifactPath = path.join(directory, "0047_platform_promotion_issuance.sql");
  const bytes = Buffer.from("-- qualification input bytes\n", "utf8");
  await writeFile(artifactPath, bytes, { mode: 0o600 });
  t.after(() => rm(directory, { recursive: true, force: true }));

  assert.equal(await computeQualificationInputArtifactSha256(artifactPath), digest(bytes));
  assert.equal(DEFAULT_QUALIFICATION_INPUT_ARTIFACT_PATH.endsWith("contracts/postgres/0047_platform_promotion_issuance.sql"), true);

  const evidence = await runC3Migration0047Qualification({
    env: { AGENTPASS_C3_ALLOW_TEST_POOL: "true" },
    databaseUrl: "postgresql://user:password@example.invalid/db?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactPath,
    expectedPostgresMajor: "16",
    PoolClass: FailingQualificationPool
  });
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.DATABASE_UNAVAILABLE);
  assert.equal(evidence.artifact_sha256, digest(bytes));
  assert.equal(evidence.source_commit, "a".repeat(40));
  assert.equal(evidence.source_tree, "b".repeat(40));
  assert.equal(evidence.ci_run_id, "123");
  assert.equal(evidence.ci_run_attempt, "1");
  assert.equal(evidence.ci_job_id, "postgres-authority-16");
});

test("C3 rejects substituted, empty, zero, and unknown artifact bindings", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "agentpass-c3-artifact-negative-"));
  const artifactPath = path.join(directory, "0047_platform_promotion_issuance.sql");
  await writeFile(artifactPath, "actual qualification input\n", { mode: 0o600 });
  t.after(() => rm(directory, { recursive: true, force: true }));

  for (const artifactSha256 of [digest(Buffer.from("substituted\n")), "", "0".repeat(64), "unknown"]) {
    const evidence = await runC3Migration0047Qualification({
      env: { AGENTPASS_C3_ALLOW_TEST_POOL: "true" },
      databaseUrl: "postgresql://user:password@example.invalid/db?sslmode=verify-full",
      sourceCommit: "a".repeat(40),
      sourceTree: "b".repeat(40),
      ciRunId: "123",
      ciRunAttempt: "1",
      ciJobId: "postgres-authority-16",
      artifactPath,
      artifactSha256,
      expectedPostgresMajor: "16",
      PoolClass: FailingQualificationPool
    });
    assert.equal(evidence.status, "failed");
    assert.equal(evidence.qualified, false);
    assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
    assert.equal(evidence.artifact_sha256, null);
  }
});

test("C3 migration 0047 qualification rejects an invalid database URL without connecting", async () => {
  const evidence = await runC3Migration0047Qualification({
    databaseUrl: "postgres://invalid",
    sourceCommit: "a".repeat(40), sourceTree: "b".repeat(40), ciRunId: "123", ciRunAttempt: "1", ciJobId: "postgres-authority-16", artifactSha256: DEFAULT_ARTIFACT_SHA256
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.qualified, false);
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.DATABASE_URL_INVALID);
  assert.equal(evidence.migration_version, TARGET_VERSION);
});

test("C3 migration 0047 qualification rejects a configured database without source binding", async () => {
  const evidence = await runC3Migration0047Qualification({
    databaseUrl: "postgresql://user:password@example.invalid/db?sslmode=verify-full",
    sourceCommit: "not-a-sha"
  });
  assert.equal(evidence.status, "failed");
  assert.equal(evidence.qualified, false);
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.INVALID_SOURCE_BINDING);
  assert.equal(evidence.source_commit, null);
});

test("C3 migration 0047 qualification requires the complete source/tree/run binding", async () => {
  const evidence = await runC3Migration0047Qualification({
    databaseUrl: "postgresql://user:password@example.invalid/db?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "invalid"
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.qualified, false);
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING);
  assert.equal(evidence.source_commit, "a".repeat(40));
  assert.equal(evidence.source_tree, "b".repeat(40));
  assertRedactedQualificationEvidence(evidence);
});

test("C3 migration 0047 qualification requires the canonical CI job binding", async () => {
  const evidence = await runC3Migration0047Qualification({
    databaseUrl: "postgresql://user:password@example.invalid/db?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "not a github job",
    artifactSha256: DEFAULT_ARTIFACT_SHA256
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.qualified, false);
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING);
  assert.equal(evidence.ci_job_id, null);
  assertRedactedQualificationEvidence(evidence);
});

test("C3 qualification rejects source/run substitutions against the GitHub context", async () => {
  const evidence = await runC3Migration0047Qualification({
    env: {
      GITHUB_SHA: "b".repeat(40),
      GITHUB_RUN_ID: "456",
      GITHUB_RUN_ATTEMPT: "2"
    },
    databaseUrl: "postgresql://user:password@example.invalid/db",
    sourceCommit: "a".repeat(40),
    sourceTree: "c".repeat(40),
    ciRunId: "456",
    ciRunAttempt: "2"
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING);
  assertRedactedQualificationEvidence(evidence);
});

test("C3 evidence verification rejects not_run and non-canonical evidence", async () => {
  const evidence = await runC3Migration0047Qualification({ env: {} });

  assert.throws(() => verifyQualificationEvidence(`${JSON.stringify(evidence)}\n`), /invalid_evidence/u);
  assert.throws(() => verifyQualificationEvidence(evidence), /invalid_evidence/u);
});

test("C3 failed evidence preserves a valid artifact digest and verifies every supplied binding", async () => {
  class FailingPool {
    async connect() {
      const error = new Error("connection refused");
      error.code = "ECONNREFUSED";
      throw error;
    }
    async end() {}
  }
  const binding = {
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactSha256: DEFAULT_ARTIFACT_SHA256,
    expectedPostgresMajor: "16"
  };
  const evidence = await runC3Migration0047Qualification({
    ...binding,
    env: { AGENTPASS_C3_ALLOW_TEST_POOL: "true" },
    PoolClass: FailingPool,
    databaseUrl: "postgresql://user:password@127.0.0.1:1/db?sslmode=verify-full"
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.DATABASE_UNAVAILABLE);
  assert.equal(evidence.artifact_sha256, binding.artifactSha256);
  assert.deepEqual(verifyQualificationEvidence(evidence, {
    ...Object.fromEntries(Object.entries(binding).map(([key, value]) => [
      { sourceCommit: "expectedSourceCommit", sourceTree: "expectedSourceTree", ciRunId: "expectedCiRunId", ciRunAttempt: "expectedCiRunAttempt", ciJobId: "expectedCiJobId", artifactSha256: "expectedArtifactSha256" }[key], value
    ])),
    requirePassed: false
  }).artifact_sha256, binding.artifactSha256);

  for (const [option, value, pattern] of [
    ["expectedSourceCommit", "c".repeat(40), /invalid_source_binding/u],
    ["expectedSourceTree", "c".repeat(40), /invalid_source_binding/u],
    ["expectedCiRunId", "124", /invalid_run_binding/u],
    ["expectedCiRunAttempt", "2", /invalid_run_binding/u],
    ["expectedCiJobId", "postgres-authority-17", /invalid_run_binding/u],
    ["expectedArtifactSha256", "e".repeat(64), /invalid_artifact_binding/u]
  ]) {
    assert.throws(() => verifyQualificationEvidence(evidence, { [option]: value, requirePassed: false }), pattern);
  }
});

test("C3 not_run evidence retains valid binding and rejects malformed artifact evidence", async () => {
  const binding = {
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactSha256: DEFAULT_ARTIFACT_SHA256
  };
  const evidence = await runC3Migration0047Qualification({ env: {}, ...binding });

  assert.equal(evidence.status, "not_run");
  assert.equal(evidence.artifact_sha256, binding.artifactSha256);
  assert.equal(verifyQualificationEvidence(evidence, {
    expectedSourceCommit: binding.sourceCommit,
    expectedSourceTree: binding.sourceTree,
    expectedCiRunId: binding.ciRunId,
    expectedCiRunAttempt: binding.ciRunAttempt,
    expectedCiJobId: binding.ciJobId,
    expectedArtifactSha256: binding.artifactSha256,
    requirePassed: false
  }).artifact_sha256, binding.artifactSha256);
  assert.throws(() => verifyQualificationEvidence({ ...evidence, artifact_sha256: "not-a-digest" }, { requirePassed: false }), /invalid_artifact_binding/u);
  assert.throws(() => verifyQualificationEvidence({ ...evidence, source_tree: "c".repeat(40) }, {
    expectedSourceTree: binding.sourceTree,
    requirePassed: false
  }), /invalid_source_binding/u);
});

test("C3 evidence verification binds source, tree, run, job, and PostgreSQL major and rejects nested secrets", () => {
  const checks = [
    "tls_connection",
    "postgres_major", "migration_checksum", "schema_objects", "catalog_constraints_validated", "role_privileges_and_ownership",
    "rls_policy_catalog", "positive_insert_and_transition", "rls_cross_role_read_write",
    "negative_authority_mutation_rejected", "audit_event_append_only", "generation_contention_single_winner",
    "transaction_rollback", "cross_role_privilege_boundary", "backup_restore", "pitr_recovery"
  ].map((id) => ({ id, status: "passed" }));
  const evidence = {
    schema_version: 1,
    qualification: "postgres-c3-migration-0047",
    status: "passed",
    qualified: true,
    reason: null,
    started_at: "2026-08-20T00:00:00.000Z",
    completed_at: "2026-08-20T00:00:01.000Z",
    migration_version: TARGET_VERSION,
    migration_name: TARGET_NAME,
    migration_checksum: "e".repeat(64),
    migration_applied_this_run: true,
    current_version: CURRENT_SCHEMA_HEAD_VERSION,
    server_version: "16.4",
    database_name: "agentpass_c3_16",
    server_port: 5432,
    tls_version: "TLSv1.3",
    artifact_sha256: DEFAULT_ARTIFACT_SHA256,
    source_commit: "a".repeat(40),
    source_tree: "b".repeat(40),
    ci_run_id: "123",
    ci_run_attempt: "1",
    ci_job_id: "postgres-authority-16",
    redacted: true,
    checks
  };
  assert.equal(verifyQualificationEvidence(evidence, {
    expectedSourceCommit: "a".repeat(40), expectedSourceTree: "b".repeat(40),
    expectedCiRunId: "123", expectedCiRunAttempt: "1", expectedCiJobId: "postgres-authority-16",
    expectedPostgresMajor: "16"
  }).ci_job_id, "postgres-authority-16");
  assert.throws(() => verifyQualificationEvidence(evidence, { expectedCiJobId: "postgres-authority-17" }), /invalid_run_binding/u);
  assert.throws(() => verifyQualificationEvidence(evidence, { expectedPostgresMajor: "17" }), /server_version_unexpected/u);
  assert.throws(() => normalizeQualificationEvidence({ ...evidence, checks: [{ ...checks[0], details: "access_token" }, ...checks.slice(1)] }), /invalid_evidence/u);
});

test("real PostgreSQL qualification requires a CA before it can connect", async () => {
  const evidence = await runC3Migration0047Qualification({
    env: {},
    databaseUrl: "postgresql://user:password@example.invalid/agentpass_c3_16?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactSha256: DEFAULT_ARTIFACT_SHA256,
    expectedPostgresMajor: "16",
    expectedDatabaseName: "agentpass_c3_16",
    expectedServerPort: "5432",
    caCertPath: "/private/tmp/agentpass-c3-missing-ca.pem"
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.CA_CERT_INVALID);
  assert.equal(evidence.qualified, false);
  assertRedactedQualificationEvidence(evidence);
});

test("real PostgreSQL qualification requires the expected major and database target bindings", async () => {
  const missingMajor = await runC3Migration0047Qualification({
    env: {},
    databaseUrl: "postgresql://user:password@example.invalid/agentpass_c3_16?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactSha256: DEFAULT_ARTIFACT_SHA256,
    expectedDatabaseName: "agentpass_c3_16",
    expectedServerPort: "5432"
  });
  assert.equal(missingMajor.reason, QUALIFICATION_DIAGNOSTICS.SERVER_VERSION_UNEXPECTED);

  const missingTarget = await runC3Migration0047Qualification({
    env: {},
    databaseUrl: "postgresql://user:password@example.invalid/agentpass_c3_16?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactSha256: DEFAULT_ARTIFACT_SHA256,
    expectedPostgresMajor: "16"
  });
  assert.equal(missingTarget.reason, QUALIFICATION_DIAGNOSTICS.DATABASE_TARGET_MISSING);
});

test("real PostgreSQL qualification requires backup and PITR evidence instead of synthesizing not_run checks", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "agentpass-c3-"));
  const caCertPath = path.join(directory, "ca.pem");
  await writeFile(caCertPath, "-----BEGIN CERTIFICATE-----\nredacted-test-certificate\n-----END CERTIFICATE-----\n", { mode: 0o600 });
  t.after(() => rm(directory, { recursive: true, force: true }));

  const evidence = await runC3Migration0047Qualification({
    env: {},
    databaseUrl: "postgresql://user:password@example.invalid/agentpass_c3_16?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactSha256: DEFAULT_ARTIFACT_SHA256,
    expectedPostgresMajor: "16",
    expectedDatabaseName: "agentpass_c3_16",
    expectedServerPort: "5432",
    caCertPath
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_NOT_RUN);
  assert.equal(evidence.qualified, false);
  assertRedactedQualificationEvidence(evidence);
});

test("C3 qualification binds the canonical authority job to the expected PostgreSQL major", async () => {
  const evidence = await runC3Migration0047Qualification({
    env: { AGENTPASS_C3_ALLOW_TEST_POOL: "true" },
    databaseUrl: "postgresql://user:password@example.invalid/agentpass_c3_16?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-17",
    artifactSha256: DEFAULT_ARTIFACT_SHA256,
    expectedPostgresMajor: "16",
    PoolClass: class {
      async end() {}
    }
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING);
  assert.equal(evidence.qualified, false);
});

test("the real-database gate rejects an injected pool even when the test-pool switch is set", async () => {
  const evidence = await runC3Migration0047Qualification({
    env: {
      AGENTPASS_C3_ALLOW_TEST_POOL: "true",
      AGENTPASS_C3_REQUIRE_REAL_DATABASE: "1"
    },
    databaseUrl: "postgresql://user:password@example.invalid/agentpass_c3_16?sslmode=verify-full",
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactSha256: DEFAULT_ARTIFACT_SHA256,
    expectedPostgresMajor: "16",
    PoolClass: class {
      async end() {}
    }
  });

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.REAL_DATABASE_REQUIRED);
  assert.equal(evidence.qualified, false);
});

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("C3 migration 0047 applies and validates against the configured real PostgreSQL", {
  timeout: 120_000
}, async () => {
  const evidence = await runC3Migration0047Qualification({ databaseUrl });

  if (!databaseUrl) {
    if (process.env.AGENTPASS_C3_REQUIRE_REAL_DATABASE === "1") {
      assert.fail("CI C3 qualification must not pass without a configured PostgreSQL database");
    }
    assert.equal(evidence.status, "not_run");
    assert.equal(evidence.qualified, false);
    assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.DATABASE_URL_MISSING);
    assertRedactedQualificationEvidence(evidence);
    return;
  }

  assert.equal(evidence.status, "passed", JSON.stringify(evidence));
  assert.equal(evidence.qualified, true);
  assert.equal(evidence.migration_version, TARGET_VERSION);
  assert.equal(evidence.current_version, TARGET_VERSION);
  assert.equal(evidence.migration_name, TARGET_NAME);
  assert.equal(evidence.checks.length, 16);
  assert.equal(evidence.redacted, true);
  assert.match(evidence.source_commit, /^[0-9a-f]{40}$/u);
  assert.match(evidence.source_tree, /^[0-9a-f]{40}$/u);
  assert.match(evidence.ci_run_id, /^[1-9][0-9]{0,19}$/u);
  assert.match(evidence.ci_run_attempt, /^[1-9][0-9]{0,9}$/u);
  assertRedactedQualificationEvidence(evidence);
  assert.ok(process.env.AGENTPASS_C3_EVIDENCE_OUTPUT, "real qualification requires a redacted evidence output path");
  await writeQualificationEvidence(process.env.AGENTPASS_C3_EVIDENCE_OUTPUT, evidence);
});

test("C3 qualification redacts connection failures from evidence", async () => {
  class FailingPool {
    constructor() {}
    async connect() {
      const error = new Error("postgresql://user:super-secret@example.invalid/db");
      error.code = "ECONNREFUSED";
      throw error;
    }
    async end() {}
  }

  const evidence = await runC3Migration0047Qualification({
    env: { AGENTPASS_C3_ALLOW_TEST_POOL: "true" },
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    ciRunId: "123",
    ciRunAttempt: "1",
    ciJobId: "postgres-authority-16",
    artifactSha256: DEFAULT_ARTIFACT_SHA256,
    databaseUrl: "postgresql://user:password@example.invalid/db?sslmode=verify-full",
    expectedPostgresMajor: "16",
    PoolClass: FailingPool
  });
  assert.equal(evidence.status, "failed");
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.DATABASE_UNAVAILABLE);
  assert.equal(evidence.source_commit, "a".repeat(40));
  assert.equal(evidence.ci_job_id, "postgres-authority-16");
  assert.doesNotMatch(JSON.stringify(evidence), /super-secret|postgresql:\/\//u);
});

test("C3 qualification never promotes a successful result when pool cleanup fails", () => {
  const evidence = downgradeSuccessfulQualificationOnCleanupFailure(
    { status: "passed", qualified: true },
    {
      cleanupError: new Error("pool cleanup failed"),
      startedAt: "2026-08-21T00:00:00.000Z",
      binding: {
        sourceCommit: "a".repeat(40),
        sourceTree: "b".repeat(40),
        ciRunId: "123",
        ciRunAttempt: "1",
        ciJobId: "postgres-authority-16",
        artifactSha256: DEFAULT_ARTIFACT_SHA256
      }
    }
  );

  assert.equal(evidence.status, "failed");
  assert.equal(evidence.qualified, false);
  assert.equal(evidence.reason, QUALIFICATION_DIAGNOSTICS.DATABASE_CLEANUP_FAILED);
  assert.equal(evidence.artifact_sha256, DEFAULT_ARTIFACT_SHA256);
});

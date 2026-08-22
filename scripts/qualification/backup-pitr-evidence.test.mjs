import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, symlink, writeFile, link, chmod, lstat } from "node:fs/promises";
import { writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";
import {
  BACKUP_PITR_EVIDENCE_ERROR_CODES,
  BACKUP_PITR_EXECUTION_RESULT_KIND,
  backupPitrEvidenceSHA256,
  canonicalBackupPitrEvidence,
  createBackupPitrEvidence,
  runBackupPitrQualification,
  runBackupPitrEvidenceCli,
  writeBackupPitrEvidence
} from "./backup-pitr-evidence.mjs";

const binding = Object.freeze({
  sourceCommit: "a".repeat(40),
  sourceTree: "b".repeat(40),
  ciRunId: "42",
  ciRunAttempt: "2",
  ciJobId: "1001",
  artifactSha256: "c".repeat(64)
});

const schemaHead = Object.freeze({ version: POSTGRES_SCHEMA_HEAD.version, name: POSTGRES_SCHEMA_HEAD.name, checksum: POSTGRES_SCHEMA_HEAD.checksum });
const roleEvidence = (purpose) => ({
  dml_denied: true,
  identity_sha256: `${purpose === "source" ? "1" : purpose === "restore" ? "2" : "3"}`.repeat(64),
  purpose,
  read_only: true,
  role: "agentpass_backup",
  schema_head: schemaHead,
  tls: true
});
const roleEvidenceDigest = (purpose) => crypto.createHash("sha256").update(canonicalJson({
  dml_denied: true, purpose, read_only: true, role: "agentpass_backup", schema_head: schemaHead, tls: true
}), "utf8").digest("hex");

const executionResult = () => ({
  schema_version: 1,
  kind: BACKUP_PITR_EXECUTION_RESULT_KIND,
  source_commit: binding.sourceCommit,
  source_tree: binding.sourceTree,
  ci_run_id: binding.ciRunId,
  ci_run_attempt: binding.ciRunAttempt,
  ci_job_id: binding.ciJobId,
  artifact_sha256: binding.artifactSha256,
  started_at: "2026-08-20T01:00:00.000Z",
  completed_at: "2026-08-20T01:15:00.000Z",
  execution: { environment: "postgresql", real_execution: true, runner_id: "github-actions/backup-pitr" },
  verification: {
    instances: ["source", "restore", "pitr"].map((purpose) => ({
      ...roleEvidence(purpose),
      role_evidence_sha256: roleEvidenceDigest(purpose)
    })),
    wal_replay: { recovery_state: "promoted", replay_lsn_sha256: "4".repeat(64), status: "passed" }
  },
  backup_restore: { expected: "passed", observed: "passed", status: "passed" },
  pitr_recovery: { expected: "passed", observed: "passed", status: "passed" }
});

async function fixtureFiles() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-backup-pitr-"));
  return {
    directory,
    input: path.join(directory, "execution.json"),
    output: path.join(directory, "backup-pitr.json")
  };
}

function cliFlags() {
  return [
    "--source-commit", binding.sourceCommit,
    "--source-tree", binding.sourceTree,
    "--run-id", binding.ciRunId,
    "--run-attempt", binding.ciRunAttempt,
    "--job-id", binding.ciJobId,
    "--artifact-sha256", binding.artifactSha256
  ];
}

function bindingEnv() {
  return {
    AGENTPASS_BACKUP_PITR_SOURCE_COMMIT: binding.sourceCommit,
    AGENTPASS_BACKUP_PITR_SOURCE_TREE: binding.sourceTree,
    AGENTPASS_BACKUP_PITR_CI_RUN_ID: binding.ciRunId,
    AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT: binding.ciRunAttempt,
    AGENTPASS_BACKUP_PITR_CI_JOB_ID: binding.ciJobId,
    AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256: binding.artifactSha256
  };
}

function runnerEnv(directory, overrides = {}) {
  return {
    ...bindingEnv(),
    PATH: "/protected/bin",
    AGENTPASS_DATABASE_URL: "postgresql://agentpass_backup:source-secret@source.example.test/source?sslmode=verify-full",
    AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL: "postgresql://agentpass_backup:restore-secret@restore.example.test/restore?sslmode=verify-full",
    AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL: "postgresql://agentpass_backup:pitr-secret@pitr.example.test/pitr?sslmode=verify-full",
    AGENTPASS_BACKUP_PITR_CA_CERT_FILE: path.join(directory, "ca.pem"),
    AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION: "isolated-disposable",
    AGENTPASS_BACKUP_PITR_PITR_CONFIRMATION: "isolated-disposable",
    AGENTPASS_BACKUP_PITR_RUNNER_ID: "protected-postgresql/backup-pitr",
    ...overrides
  };
}

function fakeSpawn(calls, { failCommand = null, pitrResult = "replayed:ready" } = {}) {
  return (command, args, options) => {
    calls.push({ command, args: [...args], env: { ...options.env } });
    const child = new EventEmitter();
    const outputIndex = args.indexOf("--output");
    if (command === "pg_dump") writeFileSync(args[args.indexOf("--file") + 1], "dump", { mode: 0o600 });
    if (command === "psql" && outputIndex >= 0) {
      if (args.some((arg) => arg.includes("pg_last_wal_replay_lsn"))) {
        writeFileSync(args[outputIndex + 1], pitrResult === "replayed:ready"
          ? JSON.stringify({ replay_lsn: "0/16B6C50", recovery_state: "promoted" }) + "\n"
          : JSON.stringify({ replay_lsn: null, recovery_state: "promoted" }) + "\n");
      } else {
        writeFileSync(args[outputIndex + 1], JSON.stringify({
          current_user: "agentpass_backup", session_user: "agentpass_backup", ssl: true,
          schema_version: POSTGRES_SCHEMA_HEAD.version, schema_checksum: POSTGRES_SCHEMA_HEAD.checksum,
          schema_count: POSTGRES_SCHEMA_HEAD.migration_count, read_only: true, dml_denied: true
        }) + "\n");
      }
    }
    queueMicrotask(() => child.emit("exit", command === failCommand ? 1 : 0, null));
    return child;
  };
}

test("projects only typed real-run results into redacted canonical evidence", () => {
  const evidence = createBackupPitrEvidence(executionResult(), binding);
  assert.deepEqual(Object.keys(evidence).sort(), [
    "artifact_sha256", "backup_restore", "ci_job_id", "ci_run_attempt", "ci_run_id",
    "pitr_recovery", "redacted", "schema_version", "source_commit", "source_tree"
  ].sort());
  assert.equal(evidence.redacted, true);
  assert.equal(canonicalBackupPitrEvidence(evidence, binding), canonicalJson(evidence));
  assert.equal(JSON.stringify(evidence).includes("github-actions"), false);
  assert.equal(JSON.stringify(evidence).includes("postgresql://"), false);
  assert.match(evidence.backup_restore.evidence_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(backupPitrEvidenceSHA256(evidence, binding).length, 64);
});

test("fails closed for source/tree/run/job/artifact substitution and non-real execution", () => {
  for (const [key, value] of Object.entries({
    sourceCommit: "d".repeat(40),
    sourceTree: "d".repeat(40),
    ciRunId: "43",
    ciRunAttempt: "3",
    ciJobId: "1002",
    artifactSha256: "d".repeat(64)
  })) {
    assert.throws(() => createBackupPitrEvidence(executionResult(), { ...binding, [key]: value }), (error) => {
      assert.equal(error.code, key.startsWith("source") ? BACKUP_PITR_EVIDENCE_ERROR_CODES.SOURCE_BINDING
        : key.startsWith("ci") ? BACKUP_PITR_EVIDENCE_ERROR_CODES.RUN_BINDING
          : BACKUP_PITR_EVIDENCE_ERROR_CODES.ARTIFACT_BINDING);
      return true;
    }, key);
  }
  for (const execution of [
    { environment: "postgresql", real_execution: false, runner_id: "github-actions/backup-pitr" },
    { environment: "postgresql", real_execution: true, runner_id: "local/backup-pitr" }
  ]) {
    assert.throws(() => createBackupPitrEvidence({ ...executionResult(), execution }, binding), (error) => {
      assert.equal(error.code, BACKUP_PITR_EVIDENCE_ERROR_CODES.NOT_EXTERNAL);
      return true;
    });
  }
});

test("rejects raw URL/credential fields and unsuccessful checks instead of carrying them forward", () => {
  assert.throws(() => createBackupPitrEvidence({ ...executionResult(), database_url: "postgresql://user:secret@example.invalid/db" }, binding), (error) => {
    assert.equal(error.code, BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
    return true;
  });
  assert.throws(() => createBackupPitrEvidence({
    ...executionResult(),
    backup_restore: { expected: "passed", observed: "failed", status: "failed" }
  }, binding), (error) => {
    assert.equal(error.code, BACKUP_PITR_EVIDENCE_ERROR_CODES.CHECK_FAILED);
    return true;
  });
});

test("CLI reads protected input and writes a new 0600 regular, single-link canonical file", async () => {
  const files = await fixtureFiles();
  await writeFile(files.input, `${canonicalJson(executionResult())}\n`, { mode: 0o600 });
  await runBackupPitrEvidenceCli(["build", files.input, files.output, ...cliFlags()], {});
  const output = await readFile(files.output, "utf8");
  assert.equal(output, `${canonicalJson(JSON.parse(output))}\n`);
  const metadata = await lstat(files.output);
  assert.equal(metadata.isFile(), true);
  assert.equal(metadata.isSymbolicLink(), false);
  assert.equal(metadata.nlink, 1);
  assert.equal(metadata.mode & 0o077, 0);
  assert.deepEqual(JSON.parse(output), createBackupPitrEvidence(executionResult(), binding));

  const verified = await runBackupPitrEvidenceCli(["verify", files.output, ...cliFlags()], {});
  assert.deepEqual(verified, {
    status: "passed",
    qualified: true,
    evidence_sha256: crypto.createHash("sha256").update(output.slice(0, -1), "utf8").digest("hex")
  });
});

test("rejects non-canonical, symlinked, and multiply-linked input files", async () => {
  const files = await fixtureFiles();
  await writeFile(files.input, `${JSON.stringify(executionResult(), null, 2)}\n`, { mode: 0o600 });
  await assert.rejects(() => runBackupPitrEvidenceCli(["build", files.input, files.output], bindingEnv()), (error) => {
    assert.equal(error.code, BACKUP_PITR_EVIDENCE_ERROR_CODES.NON_CANONICAL);
    return true;
  });

  const canonicalInput = path.join(files.directory, "canonical.json");
  await writeFile(canonicalInput, `${canonicalJson(executionResult())}\n`, { mode: 0o600 });
  const linkedInput = path.join(files.directory, "linked.json");
  await symlink(canonicalInput, linkedInput);
  await assert.rejects(() => runBackupPitrEvidenceCli(["build", linkedInput, files.output], bindingEnv()), (error) => {
    assert.equal(error.code, BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT_FILE);
    return true;
  });

  const hardlink = path.join(files.directory, "hardlink.json");
  await link(canonicalInput, hardlink);
  await assert.rejects(() => runBackupPitrEvidenceCli(["build", hardlink, files.output], bindingEnv()), (error) => {
    assert.equal(error.code, BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT_FILE);
    return true;
  });

  await chmod(canonicalInput, 0o644);
  await assert.rejects(() => runBackupPitrEvidenceCli(["build", canonicalInput, files.output], bindingEnv()), (error) => {
    assert.equal(error.code, BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT_FILE);
    return true;
  });
});

test("does not overwrite an existing evidence path", async () => {
  const files = await fixtureFiles();
  const evidence = createBackupPitrEvidence(executionResult(), binding);
  await writeBackupPitrEvidence(files.output, evidence);
  await assert.rejects(() => writeBackupPitrEvidence(files.output, evidence), (error) => {
    assert.equal(error.code, BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE);
    return true;
  });
});

test("run performs fixed real PostgreSQL command sequence and writes only redacted evidence", async () => {
  const files = await fixtureFiles();
  const ca = path.join(files.directory, "ca.pem");
  await writeFile(ca, "PUBLIC CA\n", { mode: 0o600 });
  const calls = [];
  const evidence = await runBackupPitrQualification({
    outputPath: files.output,
    expectedBinding: binding,
    env: runnerEnv(files.directory),
    spawnProcess: fakeSpawn(calls),
    clock: (() => {
      const values = [new Date("2026-08-20T02:00:00.000Z"), new Date("2026-08-20T02:15:00.000Z")];
      return () => values.shift();
    })()
  });
  assert.deepEqual(calls.map(({ command }) => command), ["pg_dump", "psql", "pg_restore", "psql", "psql", "psql"]);
  assert.match(calls[2].args.at(-1), /\/base\.dump$/u);
  assert.deepEqual(Object.keys(evidence).sort(), [
    "artifact_sha256", "backup_restore", "ci_job_id", "ci_run_attempt", "ci_run_id",
    "pitr_recovery", "redacted", "schema_version", "source_commit", "source_tree"
  ].sort());
  assert.doesNotMatch(await readFile(files.output, "utf8"), /postgresql:\/\/|source-secret|restore-secret|pitr-secret/u);
  assert.equal(calls.every(({ args }) => args.every((arg) => !arg.includes("postgresql://") && !arg.includes("secret"))), true);
  assert.equal(calls[0].env.PGSSLMODE, "verify-full");
  assert.equal(calls[0].env.PGPASSWORD, "source-secret");
});

test("run fails closed and leaves no evidence when a fixed command fails", async () => {
  const files = await fixtureFiles();
  await writeFile(path.join(files.directory, "ca.pem"), "PUBLIC CA\n", { mode: 0o600 });
  const calls = [];
  await assert.rejects(() => runBackupPitrQualification({
    outputPath: files.output,
    expectedBinding: binding,
    env: runnerEnv(files.directory),
    spawnProcess: fakeSpawn(calls, { failCommand: "pg_restore" })
  }), (error) => error.code === BACKUP_PITR_EVIDENCE_ERROR_CODES.COMMAND_FAILED);
  await assert.rejects(() => lstat(files.output), /ENOENT/u);
});

test("run rejects a non-TLS or non-isolated target before spawning commands", async () => {
  const files = await fixtureFiles();
  await writeFile(path.join(files.directory, "ca.pem"), "PUBLIC CA\n", { mode: 0o600 });
  let spawned = false;
  await assert.rejects(() => runBackupPitrQualification({
    outputPath: files.output,
    expectedBinding: binding,
    env: runnerEnv(files.directory, {
      AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL: "postgresql://restore:secret@restore.example.test/restore?sslmode=require"
    }),
    spawnProcess: (...args) => {
      spawned = true;
      return fakeSpawn([], ...args);
    }
  }), (error) => error.code === BACKUP_PITR_EVIDENCE_ERROR_CODES.DATABASE_CONFIG);
  assert.equal(spawned, false);
});

test("run rejects a PITR endpoint that has not replayed WAL", async () => {
  const files = await fixtureFiles();
  await writeFile(path.join(files.directory, "ca.pem"), "PUBLIC CA\n", { mode: 0o600 });
  await assert.rejects(() => runBackupPitrQualification({
    outputPath: files.output,
    expectedBinding: binding,
    env: runnerEnv(files.directory),
    spawnProcess: fakeSpawn([], { pitrResult: "not-replayed:ready" })
  }), (error) => error.code === BACKUP_PITR_EVIDENCE_ERROR_CODES.COMMAND_FAILED);
});

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../apps/cloud-api/src/postgres/schema-head.mjs";
import { NOT_PROVEN, verifyBackupRestoreQualification } from "./backup-restore-qualification.mjs";

const SCRIPT = path.resolve("scripts/postgres/backup-restore-qualification.mjs");
const CANDIDATE = `release-pkg-sha256-v1-${"a".repeat(64)}`;
const SOURCE = "b".repeat(40);
const OTHER_CANDIDATE = `release-pkg-sha256-v1-${"c".repeat(64)}`;
const OTHER_SOURCE = "d".repeat(40);
const HASH_1 = "1".repeat(64);
const HASH_2 = "2".repeat(64);
const HASH_3 = "3".repeat(64);
const HASH_4 = "4".repeat(64);
const EXPECTED_SCHEMA_HEAD = {
  version: POSTGRES_SCHEMA_HEAD.version,
  name: POSTGRES_SCHEMA_HEAD.name,
  checksum: POSTGRES_SCHEMA_HEAD.checksum
};

function qualificationEvidence() {
  return {
    after_manifest_sha256: HASH_2,
    artifact_sha256: HASH_1,
    before_manifest_sha256: HASH_2,
    candidate_id: CANDIDATE,
    compare_same: true,
    instances: [
      {
        candidate_id: CANDIDATE,
        instance_id: "postgres-primary",
        role_evidence_sha256: HASH_3,
        schema_head: { ...EXPECTED_SCHEMA_HEAD }
      },
      {
        candidate_id: CANDIDATE,
        instance_id: "postgres-restore",
        role_evidence_sha256: HASH_4,
        schema_head: { ...EXPECTED_SCHEMA_HEAD }
      }
    ],
    kind: "agentpass-postgres-backup-restore-qualification",
    pitr: {
      candidate_id: CANDIDATE,
      recovery_target: "2026-08-19T00:00:00Z",
      restored_manifest_sha256: HASH_2,
      status: "verified"
    },
    role_evidence_sha256: HASH_3,
    schema_head: { ...EXPECTED_SCHEMA_HEAD },
    source_commit: SOURCE,
    version: 1
  };
}

function assertRejected(value, reason = "invalid_or_unclosed_evidence") {
  assert.throws(
    () => verifyBackupRestoreQualification(value, {
      expectedCandidateId: CANDIDATE,
      expectedSourceCommit: SOURCE
    }),
    (error) => error?.code === reason
  );
}

function runCli(...args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });
}

function stdoutJson(result) {
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

test("a canonical, candidate-bound qualification envelope closes", () => {
  const result = verifyBackupRestoreQualification(qualificationEvidence(), {
    expectedCandidateId: CANDIDATE,
    expectedSourceCommit: SOURCE
  });

  assert.equal(result.status, "closed");
  assert.equal(result.candidate_id, CANDIDATE);
  assert.equal(result.source_commit, SOURCE);
  assert.equal(result.instance_count, 2);
  assert.deepEqual(result.schema_head, {
    version: EXPECTED_SCHEMA_HEAD.version,
    checksum: EXPECTED_SCHEMA_HEAD.checksum
  });
  assert.equal(result.pitr_restore, "verified");
  assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
});

test("unknown top-level and nested fields are rejected", () => {
  const topLevel = qualificationEvidence();
  topLevel.unexpected = "attacker-controlled";
  assertRejected(topLevel);

  const nested = qualificationEvidence();
  nested.instances[0].unexpected = true;
  assertRejected(nested);

  const pitr = qualificationEvidence();
  pitr.pitr.unexpected = true;
  assertRejected(pitr);
});

test("duplicate instance identity or role evidence is rejected", () => {
  const duplicateId = qualificationEvidence();
  duplicateId.instances[1].instance_id = duplicateId.instances[0].instance_id;
  assertRejected(duplicateId, "duplicate_instance_evidence");

  const duplicateRoleEvidence = qualificationEvidence();
  duplicateRoleEvidence.instances[1].role_evidence_sha256 = duplicateRoleEvidence.instances[0].role_evidence_sha256;
  assertRejected(duplicateRoleEvidence, "duplicate_instance_evidence");
});

test("candidate, source, schema, and PITR substitutions fail closed", () => {
  const candidate = qualificationEvidence();
  candidate.candidate_id = OTHER_CANDIDATE;
  assertRejected(candidate);

  const source = qualificationEvidence();
  source.source_commit = OTHER_SOURCE;
  assertRejected(source);

  const schema = qualificationEvidence();
  schema.schema_head = { ...schema.schema_head, checksum: HASH_1 };
  assertRejected(schema);

  const pitrCandidate = qualificationEvidence();
  pitrCandidate.pitr.candidate_id = OTHER_CANDIDATE;
  assertRejected(pitrCandidate);

  const pitrManifest = qualificationEvidence();
  pitrManifest.pitr.restored_manifest_sha256 = HASH_1;
  assertRejected(pitrManifest);
});

test("CLI rejects noncanonical evidence bytes as not_proven", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-postgres-qualification-"));
  const file = path.join(directory, "evidence.json");
  fs.writeFileSync(file, `${JSON.stringify(qualificationEvidence())}\n`, { mode: 0o600 });

  const result = runCli("verify", file, CANDIDATE, SOURCE);

  assert.equal(result.status, 2);
  assert.deepEqual(stdoutJson(result), { status: "not_proven", reason: "noncanonical_evidence" });
});

test("CLI returns the stable not_proven result and nonzero status when evidence is unavailable", () => {
  const result = runCli();

  assert.equal(result.status, 2);
  assert.deepEqual(stdoutJson(result), NOT_PROVEN);
});

test("the canonical fixture is newline-terminated canonical JSON", () => {
  const bytes = `${canonicalJson(qualificationEvidence())}\n`;
  assert.equal(JSON.parse(bytes).candidate_id, CANDIDATE);
  assert.equal(bytes.endsWith("\n"), true);
});

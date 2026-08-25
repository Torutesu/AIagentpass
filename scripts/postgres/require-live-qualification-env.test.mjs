import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  LivePostgresQualificationEnvironmentError,
  validateLivePostgresQualificationEnvironment,
} from "./require-live-qualification-env.mjs";

const SCRIPT = fileURLToPath(new URL("./require-live-qualification-env.mjs", import.meta.url));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-pg-preflight-"));
const caPath = path.join(directory, "postgres-ca.pem");
fs.writeFileSync(caPath, "-----BEGIN CERTIFICATE-----\nqualification-ca\n-----END CERTIFICATE-----\n", { mode: 0o600 });
fs.chmodSync(caPath, 0o600);

test.after(() => fs.rmSync(directory, { recursive: true, force: true }));

const base = Object.freeze({
  AGENTPASS_TEST_DATABASE_URL: "postgresql://test:test@role-db.example.test:5432/agentpass?sslmode=verify-full",
  AGENTPASS_TEST_POSTGRES_ADMIN_URL: "postgresql://admin:admin@role-db.example.test:5432/agentpass?sslmode=verify-full",
  AGENTPASS_TEST_APP_DATABASE_URL: "postgresql://app:app@role-db.example.test:5432/agentpass?sslmode=verify-full",
  AGENTPASS_TEST_SIGNER_DATABASE_URL: "postgresql://signer:signer@role-db.example.test:5432/agentpass?sslmode=verify-full",
  AGENTPASS_TEST_MIGRATION_DATABASE_URL: "postgresql://migrator:migrator@role-db.example.test:5432/agentpass?sslmode=verify-full",
  AGENTPASS_TEST_BACKUP_DATABASE_URL: "postgresql://backup:backup@role-db.example.test:5432/agentpass?sslmode=verify-full",
  AGENTPASS_TEST_MAINTENANCE_DATABASE_URL: "postgresql://maintenance:maintenance@role-db.example.test:5432/agentpass?sslmode=verify-full",
  AGENTPASS_DATABASE_URL: "postgresql://agentpass_backup:source-secret@source-db.example.test/source?sslmode=verify-full",
  AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL: "postgresql://agentpass_backup:restore-secret@restore-db.example.test/restore?sslmode=verify-full",
  AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL: "postgresql://agentpass_backup:pitr-secret@pitr-db.example.test/pitr?sslmode=verify-full",
  AGENTPASS_BACKUP_PITR_CA_CERT_FILE: caPath,
  AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION: "isolated-disposable",
  AGENTPASS_BACKUP_PITR_PITR_CONFIRMATION: "isolated-disposable",
  AGENTPASS_BACKUP_PITR_RUNNER_ID: "protected-postgresql/backup-pitr",
  AGENTPASS_BACKUP_PITR_SOURCE_COMMIT: "a".repeat(40),
  AGENTPASS_BACKUP_PITR_SOURCE_TREE: "b".repeat(40),
  AGENTPASS_BACKUP_PITR_CI_RUN_ID: "123456",
  AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT: "1",
  AGENTPASS_BACKUP_PITR_CI_JOB_ID: "987654",
  AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256: "c".repeat(64),
});

test("validates protected preflight without opening a database connection", () => {
  const result = validateLivePostgresQualificationEnvironment(base);
  assert.equal(result.status, "preflight_validated");
  assert.equal(result.connection_attempted, false);
  assert.equal(result.tls_mode, "verify-full");
  assert.equal(result.endpoint_separation, "source_restore_pitr_distinct");
  assert.equal(result.ca_path_validated, true);
  assert.equal(result.isolation_acknowledged, true);
  assert.equal(result.runner_identity_validated, true);
  assert.deepEqual(result.binding_validated, {
    source_commit: true,
    source_tree: true,
    ci_run_id: true,
    ci_run_attempt: true,
    ci_job_id: true,
    artifact_sha256: true,
  });
  assert.ok(!JSON.stringify(result).includes("source-secret"));
  assert.ok(!JSON.stringify(result).includes(caPath));
});

test("does not require legacy test DSNs for the protected backup/PITR profile", () => {
  const protectedOnly = Object.fromEntries([
    "AGENTPASS_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_CA_CERT_FILE",
    "AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION",
    "AGENTPASS_BACKUP_PITR_PITR_CONFIRMATION",
    "AGENTPASS_BACKUP_PITR_RUNNER_ID",
    "AGENTPASS_BACKUP_PITR_SOURCE_COMMIT",
    "AGENTPASS_BACKUP_PITR_SOURCE_TREE",
    "AGENTPASS_BACKUP_PITR_CI_RUN_ID",
    "AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT",
    "AGENTPASS_BACKUP_PITR_CI_JOB_ID",
    "AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256",
  ].map((key) => [key, base[key]]));
  const result = validateLivePostgresQualificationEnvironment(protectedOnly);
  assert.deepEqual(result.validated_keys, [
    "AGENTPASS_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_SOURCE_COMMIT",
    "AGENTPASS_BACKUP_PITR_SOURCE_TREE",
    "AGENTPASS_BACKUP_PITR_CI_RUN_ID",
    "AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT",
    "AGENTPASS_BACKUP_PITR_CI_JOB_ID",
    "AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256",
  ]);
});

test("requires every protected endpoint, CA, isolation acknowledgement, and binding", () => {
  const required = [
    "AGENTPASS_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL",
    "AGENTPASS_BACKUP_PITR_CA_CERT_FILE",
    "AGENTPASS_BACKUP_PITR_RUNNER_ID",
    "AGENTPASS_BACKUP_PITR_SOURCE_COMMIT",
    "AGENTPASS_BACKUP_PITR_SOURCE_TREE",
    "AGENTPASS_BACKUP_PITR_CI_RUN_ID",
    "AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT",
    "AGENTPASS_BACKUP_PITR_CI_JOB_ID",
    "AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256",
  ];
  for (const key of required) {
    assert.throws(
      () => validateLivePostgresQualificationEnvironment({ ...base, [key]: undefined }),
      LivePostgresQualificationEnvironmentError,
      key,
    );
  }
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION: "yes" }),
    /isolated_disposable_confirmation_required/u,
  );
});

test("requires verify-full as the only PostgreSQL URL parameter", () => {
  for (const value of [
    "postgresql://user:secret@source-db.example.test/source",
    "postgresql://user:secret@source-db.example.test/source?sslmode=require",
    "postgresql://user:secret@source-db.example.test/source?sslmode=verify-full&application_name=qualification",
    "postgresql://user:secret@source-db.example.test/source?sslmode=verify-full#fragment",
  ]) {
    assert.throws(
      () => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_DATABASE_URL: value }),
      /invalid_source_url/u,
    );
  }
});

test("rejects loopback and restore/PITR endpoint identity reuse even with different credentials", () => {
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({
      ...base,
      AGENTPASS_DATABASE_URL: "postgresql://user:secret@127.0.0.1/source?sslmode=verify-full",
    }),
    /invalid_source_url/u,
  );
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({
      ...base,
      AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL: "postgresql://other:secret@restore-db.example.test/restore?sslmode=verify-full",
    }),
    /postgres_endpoint_not_separate/u,
  );
});

test("requires a readable regular non-world-writable CA file and rejects symlinks", () => {
  const worldWritable = path.join(directory, "world-readable-ca.pem");
  fs.writeFileSync(worldWritable, "ca\n", { mode: 0o644 });
  fs.chmodSync(worldWritable, 0o644);
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_BACKUP_PITR_CA_CERT_FILE: worldWritable }),
    /invalid_ca_path/u,
  );

  const symlink = path.join(directory, "ca-link.pem");
  fs.symlinkSync(caPath, symlink);
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_BACKUP_PITR_CA_CERT_FILE: symlink }),
    /invalid_ca_path/u,
  );
});

test("rejects untrusted runner identities and substituted bindings", () => {
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_BACKUP_PITR_RUNNER_ID: "local/postgres" }),
    /invalid_runner_identity/u,
  );
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_BACKUP_PITR_SOURCE_COMMIT: "local" }),
    /invalid_source_commit/u,
  );
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_BACKUP_PITR_CI_RUN_ID: "0" }),
    /invalid_run_id/u,
  );
  assert.throws(
    () => validateLivePostgresQualificationEnvironment({ ...base, AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256: "not-an-artifact" }),
    /invalid_artifact_sha256/u,
  );
});

test("CLI returns stable not_proven JSON, nonzero, and no secret or path", () => {
  const secretUrl = "postgresql://user:super-secret@source-db.example.test/source";
  const result = spawnSync(process.execPath, [SCRIPT], {
    env: { ...process.env, ...base, AGENTPASS_DATABASE_URL: secretUrl, AGENTPASS_BACKUP_PITR_CA_CERT_FILE: "/missing/private/ca.pem" },
    encoding: "utf8",
  });
  assert.equal(result.status, 2);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), { status: "not_proven", reason: "invalid_source_url" });
  assert.ok(!result.stdout.includes("super-secret"));
  assert.ok(!result.stdout.includes("/missing/private/ca.pem"));
});

test("CLI emits a validated preflight projection without contacting PostgreSQL", () => {
  const result = execFileSync(process.execPath, [SCRIPT], {
    env: { ...process.env, ...base },
    encoding: "utf8",
  });
  const projection = JSON.parse(result);
  assert.equal(projection.status, "preflight_validated");
  assert.equal(projection.connection_attempted, false);
  assert.ok(!result.includes("source-secret"));
  assert.ok(!result.includes(caPath));
});

import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import pg from "pg";

import { bundleAcknowledgementSigningData, normalizeBundleAcknowledgement } from "../../../../packages/protocol/src/index.mjs";
import { createRefreshHintService } from "../../src/refresh-hint-service.mjs";
import { createEd25519RefreshHintSigner } from "../../src/refresh-hint-signer.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import {
  createG41PropagationLatencyRecorder,
  validateG41PropagationReport
} from "../../src/postgres/g4-1-propagation-qualification.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";

const { Pool } = pg;
const databaseUrl = process.env.AGENTPASS_TEST_POSTGRES_URL;
const ATTEMPTS = 100;
const HALF_ORDER = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");

test("G4.1 PostgreSQL qualification measures 100 commit-to-hint and signed-ACK attempts", { skip: !databaseUrl, timeout: 30_000 }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8, options: "-c statement_timeout=5000 -c lock_timeout=2000" });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "g4-1-propagation-qualification" }).run(); }
  finally { migrationClient.release(); }

  const fixture = await seedFixture(pool);
  const codec = createRefreshNonceCodec({ keys: { "refresh-nonce-v5": Buffer.alloc(32, 0x75) }, activeKeyId: "refresh-nonce-v5" });
  const repository = createControlPlaneAuthorityRepository({ client: pool, cursorSecret: Buffer.alloc(32, 0x45), refreshNonceCodec: codec });
  const hintKeys = crypto.generateKeyPairSync("ed25519");
  const service = createRefreshHintService({
    source: repository,
    nonceDeriver: codec,
    signer: createEd25519RefreshHintSigner({ privateKey: hintKeys.privateKey, keyId: "refresh-qualification-v1" })
  });
  const recorder = createG41PropagationLatencyRecorder();

  for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
    const issuedAt = new Date(Date.now() + attempt).toISOString();
    const reduction = await repository.advanceAuthorityGenerationAndEnqueueRefresh({
      organization_id: fixture.organizationId,
      issued_at: issuedAt,
      expires_at: new Date(Date.parse(issuedAt) + 5 * 60_000).toISOString()
    });
    const committedAt = performance.now();
    const expectedGeneration = attempt + 2;
    assert.equal(reduction.generation, expectedGeneration);

    const hint = await service.poll({
      organization_id: fixture.organizationId,
      device_id: fixture.deviceId,
      after_generation: expectedGeneration - 1,
      wait_ms: 0
    });
    recorder.recordCommitToObservation({
      latency_ms: performance.now() - committedAt,
      resource_snapshot: resources(pool)
    });
    assert.equal(hint.authority_generation, expectedGeneration);

    const bundle = await repository.snapshotAndAssignBundleHead({
      organization_id: fixture.organizationId,
      device_id: fixture.deviceId,
      minimum_sequence: attempt + 1,
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 60_000).toISOString()
    });
    const acknowledgement = signAcknowledgement({
      privateKey: fixture.devicePrivateKey,
      organizationId: fixture.organizationId,
      deviceId: fixture.deviceId,
      generation: expectedGeneration,
      sequence: bundle.head.sequence,
      statementHash: bundle.head.state_fingerprint,
      nonce: hint.nonce
    });
    const accepted = await repository.acknowledgeBundle(acknowledgement);
    assert.equal(accepted.refresh_state, "applied");
    recorder.recordCommitToAppliedAck({
      latency_ms: performance.now() - committedAt,
      resource_snapshot: resources(pool)
    });
  }

  const report = recorder.report();
  assert.equal(validateG41PropagationReport(report), report);
  assert.equal(report.accepted_samples, ATTEMPTS * 2);
  assert.equal(report.phases.commit_to_observation.count, ATTEMPTS);
  assert.equal(report.phases.commit_to_applied_ack.count, ATTEMPTS);
  assert.equal(report.qualified, true, JSON.stringify(report.failures));
  assert.equal(JSON.stringify(report).includes(fixture.organizationId), false);
  assert.equal(JSON.stringify(report).includes(fixture.deviceId), false);
  t.diagnostic(`G4.1 p50/p95/p99 observation=${report.phases.commit_to_observation.p50_ms}/${report.phases.commit_to_observation.p95_ms}/${report.phases.commit_to_observation.p99_ms}ms ACK=${report.phases.commit_to_applied_ack.p50_ms}/${report.phases.commit_to_applied_ack.p95_ms}/${report.phases.commit_to_applied_ack.p99_ms}ms`);
});

function resources(pool) {
  return {
    pool_connections: pool.totalCount,
    pool_waiters: pool.waitingCount,
    in_flight_operations: 1,
    notification_reconnects: 0
  };
}

async function seedFixture(pool) {
  const organizationId = crypto.randomUUID();
  const memberId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const agentId = crypto.randomUUID();
  const policyId = crypto.randomUUID();
  const deviceKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const devicePublicKey = deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'G4.1 propagation qualification')", [organizationId]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'G4.1 qualification owner')", [memberId, `g41-${memberId}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, membershipId, memberId]);
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,'Qualification Mac','p256-sha256',$3,'active','{}'::jsonb)`, [organizationId, deviceId, devicePublicKey]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'claude-code','Qualification agent',$4,'active')`, [organizationId, agentId, deviceId, devicePublicKey]);
  await pool.query(`INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
    VALUES ($1,$2,1,'qualification',$3::jsonb,'active',$4)`, [organizationId, policyId, JSON.stringify({ operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } }), memberId]);
  return { organizationId, deviceId, devicePrivateKey: deviceKeys.privateKey };
}

function signAcknowledgement({ privateKey, organizationId, deviceId, generation, sequence, statementHash, nonce }) {
  const unsigned = {
    version: 1,
    type: "agentpass.bundle-ack",
    organization_id: organizationId,
    device_id: deviceId,
    device_key_epoch: 1,
    format_epoch: 2,
    sequence,
    statement_hash: statementHash,
    result: "applied",
    observed_at: new Date().toISOString(),
    nonce,
    signature_algorithm: "p256-sha256"
  };
  const placeholder = { ...unsigned, signature: Buffer.alloc(64, 1).toString("base64url") };
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const signature = crypto.sign("sha256", bundleAcknowledgementSigningData(placeholder), { key: privateKey, dsaEncoding: "ieee-p1363" });
    if (signature.subarray(32).compare(HALF_ORDER) <= 0) return normalizeBundleAcknowledgement({ ...unsigned, signature: signature.toString("base64url") });
  }
  throw new Error("could not produce a canonical low-S qualification signature");
}

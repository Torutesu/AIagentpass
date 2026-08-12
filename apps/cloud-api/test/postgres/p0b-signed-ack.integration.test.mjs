/*
 * P0-B PostgreSQL integration lane.
 *
 * CI command (PostgreSQL 17+):
 *   AGENTPASS_TEST_DATABASE_URL="$DATABASE_URL" \
 *     node --test apps/cloud-api/test/postgres/p0b-signed-ack.integration.test.mjs
 *
 * The test also accepts AGENTPASS_TEST_POSTGRES_URL and DATABASE_URL as
 * explicit compatibility aliases. AGENTPASS_TEST_DATABASE_URL wins.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import pg from "pg";

import { signDeviceRequest, createApiTokenRecord } from "../../src/auth.mjs";
import { createCloudApi } from "../../src/server.mjs";
import { createRefreshHintService } from "../../src/refresh-hint-service.mjs";
import { createEd25519RefreshHintSigner } from "../../src/refresh-hint-signer.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createPostgresControlPlaneStore } from "../../src/postgres/control-plane-store.mjs";
import {
  bundleAcknowledgementSigningData,
  normalizeBundleAcknowledgement,
  normalizeRefreshHint,
  refreshHintSigningData
} from "../../../../packages/protocol/src/index.mjs";
import { verifyControlBundle } from "../../../../lib/control-bundle-v2.mjs";

const { Pool } = pg;
const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL
  ?? process.env.AGENTPASS_TEST_POSTGRES_URL
  ?? process.env.DATABASE_URL;
const HALF_ORDER = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");
const ACK_NONCE = "p0b-ack-abcdefghijklmnopqrstuvwxyz-0001";

test("P0-B: manual wake to signed P-256 ACK produces a synced Console read model", {
  skip: !DATABASE_URL,
  timeout: 30_000
}, async (t) => {
  const fixture = await createFixture(t);
  const { ids, keys, authority, store, pool, base, nowMs, nowIso } = fixture;

  const authorityAdvance = await authority.advanceAuthorityGenerationAndEnqueueRefresh({
    organization_id: ids.organization,
    issued_at: nowIso,
    expires_at: new Date(nowMs + 60_000).toISOString()
  });
  assert.equal(authorityAdvance.generation, 2);

  const generationBeforeWake = await scalar(pool, "SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]);
  const stateBeforeWake = await pool.query(`SELECT desired_generation,observed_generation,refresh_state
    FROM device_control_plane_state WHERE organization_id=$1 AND device_id=$2`, [ids.organization, ids.deviceA]);
  const outboxBeforeWake = await scalar(pool, `SELECT count(*) FROM device_refresh_outbox
    WHERE organization_id=$1 AND device_id=$2 AND desired_generation=$3 AND status IN ('pending','delivered')`, [ids.organization, ids.deviceA, 2]);

  const wakePath = `/v1/organizations/${ids.organization}/devices/${ids.deviceA}/refresh-requests`;
  const wake = await fetch(`${base}${wakePath}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${fixture.token}`,
      "content-type": "application/json",
      "idempotency-key": "p0b-manual-wake-0001",
      "agentpass-recent-auth": "webauthn-proof-abcdefghijklmnopqrstuvwxyz"
    },
    body: "{}"
  });
  const wakeBody = await json(wake);
  assert.equal(wake.status, 202, JSON.stringify(publicError(wakeBody)));
  assert.equal(wakeBody.refresh_request.status, "accepted");
  assert.equal(wakeBody.refresh_request.device_id, ids.deviceA);
  assert.equal(wakeBody.refresh_request.desired_generation, 2);

  // Manual wake is a delivery hint. It must not alter authority, state, or
  // the authority outbox; only its independent wake ledger/audit may change.
  assert.equal(await scalar(pool, "SELECT generation FROM control_plane_authority_generations WHERE organization_id=$1 AND superseded_at IS NULL", [ids.organization]), generationBeforeWake);
  const stateAfterWake = await pool.query(`SELECT desired_generation,observed_generation,refresh_state
    FROM device_control_plane_state WHERE organization_id=$1 AND device_id=$2`, [ids.organization, ids.deviceA]);
  assert.deepEqual(stateAfterWake.rows, stateBeforeWake.rows);
  assert.equal(await scalar(pool, `SELECT count(*) FROM device_refresh_outbox
    WHERE organization_id=$1 AND device_id=$2 AND desired_generation=$3 AND status IN ('pending','delivered')`, [ids.organization, ids.deviceA, 2]), outboxBeforeWake);
  assert.equal(await scalar(pool, `SELECT count(*) FROM device_manual_wake_events
    WHERE organization_id=$1 AND device_id=$2 AND desired_generation=$3`, [ids.organization, ids.deviceA, 2]), 1);

  const pollPath = `/v1/organizations/${ids.organization}/devices/${ids.deviceA}/refresh?after_generation=1&wait_ms=0`;
  const poll = await deviceFetch({ base, path: pollPath, method: "GET", body: Buffer.alloc(0), privateKey: keys.deviceA.privateKey, deviceId: ids.deviceA, timestamp: nowMs, nonce: "p0b-poll-abcdefghijklmnopqrstuvwxyz-0001" });
  const pollBody = await json(poll.response);
  assert.equal(poll.response.status, 200, JSON.stringify(publicError(pollBody)));
  const hint = normalizeRefreshHint(pollBody.hint);
  assert.equal(hint.organization_id, ids.organization);
  assert.equal(hint.device_id, ids.deviceA);
  assert.equal(hint.authority_generation, 2);
  assert.equal(crypto.verify(null, refreshHintSigningData(hint), fixture.refreshHintKeys.publicKey, Buffer.from(hint.signature, "base64url")), true);

  const bundlePath = `/v1/organizations/${ids.organization}/bundles/${ids.deviceA}`;
  const bundleResponse = await deviceFetch({ base, path: bundlePath, method: "GET", body: Buffer.alloc(0), privateKey: keys.deviceA.privateKey, deviceId: ids.deviceA, timestamp: nowMs, nonce: "p0b-fetch-abcdefghijklmnopqrstuvwxyz-0001" });
  const bundleBody = await json(bundleResponse.response);
  assert.equal(bundleResponse.response.status, 200, JSON.stringify(publicError(bundleBody)));
  const bundle = bundleBody.bundle;
  const verifiedBundle = verifyControlBundle(bundle, {
    public_key: fixture.bundleKeys.publicKey,
    issuer: "agentpass-cloud",
    key_id: "p0b-control-v1"
  }, { now: nowMs, audience: { organization_id: ids.organization, device_id: ids.deviceA } });
  assert.equal(verifiedBundle.sequence, 1);
  const statement = await pool.query(`SELECT format_epoch,sequence,statement_hash,authority_generation
    FROM control_bundle_statements WHERE organization_id=$1 AND device_id=$2 ORDER BY sequence DESC LIMIT 1`, [ids.organization, ids.deviceA]);
  assert.equal(statement.rows.length, 1);
  const bundleStatement = statement.rows[0];
  assert.equal(Number(bundleStatement.authority_generation), 2);

  const ack = signAcknowledgement({
    privateKey: keys.deviceA.privateKey,
    organizationId: ids.organization,
    deviceId: ids.deviceA,
    sequence: Number(bundleStatement.sequence),
    statementHash: bundleStatement.statement_hash,
    nonce: hint.nonce,
    observedAt: new Date().toISOString()
  });
  const ackBody = Buffer.from(JSON.stringify(ack));
  const ackPath = `/v1/organizations/${ids.organization}/bundles/${ids.deviceA}/acknowledgements`;
  const acceptedAck = await deviceFetch({ base, path: ackPath, method: "POST", body: ackBody, privateKey: keys.deviceA.privateKey, deviceId: ids.deviceA, timestamp: nowMs, nonce: ACK_NONCE });
  const acceptedBody = await json(acceptedAck.response);
  assert.equal(acceptedAck.response.status, 202, JSON.stringify(publicError(acceptedBody)));
  assert.deepEqual({ accepted: acceptedBody.accepted, duplicate: acceptedBody.duplicate, refresh_state: acceptedBody.refresh_state }, { accepted: true, duplicate: false, refresh_state: "applied" });
  assert.equal(acceptedBody.observed_generation, 2);

  // An exact ACK retry is successful and explicitly marked duplicate.
  const duplicateAck = await deviceFetch({ base, path: ackPath, method: "POST", body: ackBody, privateKey: keys.deviceA.privateKey, deviceId: ids.deviceA, timestamp: nowMs, nonce: "p0b-ack-retry-abcdefghijklmnopqrstuvwxyz-0001" });
  const duplicateBody = await json(duplicateAck.response);
  assert.equal(duplicateAck.response.status, 202, JSON.stringify(publicError(duplicateBody)));
  assert.equal(duplicateBody.duplicate, true);
  assert.equal(await scalar(pool, "SELECT count(*) FROM device_bundle_acknowledgements WHERE organization_id=$1 AND device_id=$2", [ids.organization, ids.deviceA]), 1);

  const conflictingAck = signAcknowledgement({
    privateKey: keys.deviceA.privateKey,
    organizationId: ids.organization,
    deviceId: ids.deviceA,
    sequence: Number(bundleStatement.sequence),
    statementHash: bundleStatement.statement_hash,
    nonce: hint.nonce,
    result: "blocked",
    reasonCode: "bundle_expired",
    observedAt: ack.observed_at
  });
  const conflict = await deviceFetch({ base, path: ackPath, method: "POST", body: Buffer.from(JSON.stringify(conflictingAck)), privateKey: keys.deviceA.privateKey, deviceId: ids.deviceA, timestamp: nowMs, nonce: "p0b-ack-conflict-abcdefghijklmnopqrstuvwxyz-0001" });
  const conflictBody = await json(conflict.response);
  assert.equal(conflict.response.status, 409);
  assert.equal(conflictBody.error.code, "ack_conflict");

  // The HTTP boundary rejects key epoch, device, path, and body substitution
  // before any ACK evidence is mutated.
  const wrongEpoch = { ...ack, device_key_epoch: 2 };
  const wrongEpochResponse = await deviceFetch({ base, path: ackPath, method: "POST", body: Buffer.from(JSON.stringify(signExisting({ acknowledgement: wrongEpoch, privateKey: keys.deviceA.privateKey }))), privateKey: keys.deviceA.privateKey, deviceId: ids.deviceA, timestamp: nowMs, nonce: "p0b-ack-epoch-abcdefghijklmnopqrstuvwxyz-0001" });
  const wrongEpochBody = await json(wrongEpochResponse.response);
  assert.equal(wrongEpochResponse.response.status, 409);
  assert.equal(wrongEpochBody.error.code, "acknowledgement_key_epoch_mismatch");

  const wrongDeviceResponse = await deviceFetch({ base, path: ackPath, method: "POST", body: ackBody, privateKey: keys.deviceB.privateKey, deviceId: ids.deviceB, timestamp: nowMs, nonce: "p0b-wrong-device-abcdefghijklmnopqrstuvwxyz-0001" });
  const wrongDeviceBody = await json(wrongDeviceResponse.response);
  assert.equal(wrongDeviceResponse.response.status, 403);
  assert.equal(wrongDeviceBody.error.code, "audience_mismatch");

  const substitutedPath = `/v1/organizations/${ids.organization}/bundles/${ids.deviceB}/acknowledgements`;
  const pathSubstitution = await deviceFetch({ base, path: substitutedPath, method: "POST", body: ackBody, privateKey: keys.deviceA.privateKey, deviceId: ids.deviceA, timestamp: nowMs, nonce: "p0b-path-substitution-abcdefghijklmnopqrstuvwxyz-0001" });
  const pathBody = await json(pathSubstitution.response);
  assert.equal(pathSubstitution.response.status, 403);
  assert.equal(pathBody.error.code, "audience_mismatch");

  const substitutedAck = { ...ack, device_id: ids.deviceB };
  const bodySubstitution = await deviceFetch({ base, path: ackPath, method: "POST", body: Buffer.from(JSON.stringify(substitutedAck)), privateKey: keys.deviceA.privateKey, deviceId: ids.deviceA, timestamp: nowMs, nonce: "p0b-body-substitution-abcdefghijklmnopqrstuvwxyz-0001", signedBody: ackBody });
  const bodySubstitutionBody = await json(bodySubstitution.response);
  assert.equal(bodySubstitution.response.status, 401);
  assert.equal(bodySubstitutionBody.error.code, "auth_body_digest_mismatch");
  assert.equal(await scalar(pool, "SELECT count(*) FROM device_bundle_acknowledgements WHERE organization_id=$1 AND device_id=$2", [ids.organization, ids.deviceA]), 1);

  // A second bundle head makes an otherwise valid older ACK a sequence
  // rollback. The delivery expiry path is checked independently on that same
  // unacknowledged outbox without changing device A's synced state.
  const pendingB = await authority.pollDeviceRefresh({ organization_id: ids.organization, device_id: ids.deviceB, after_generation: 1, wait_ms: 0 });
  assert.ok(pendingB);
  const headB1 = await authority.snapshotAndAssignBundleHead({ organization_id: ids.organization, device_id: ids.deviceB, minimum_sequence: 1, issued_at: nowIso, expires_at: new Date(nowMs + 60_000).toISOString() });
  const headB2 = await authority.snapshotAndAssignBundleHead({ organization_id: ids.organization, device_id: ids.deviceB, minimum_sequence: 1, issued_at: nowIso, expires_at: new Date(nowMs + 60_000).toISOString() });
  assert.equal(headB2.head.sequence, headB1.head.sequence + 1);
  const rollbackAck = signAcknowledgement({
    privateKey: keys.deviceB.privateKey,
    organizationId: ids.organization,
    deviceId: ids.deviceB,
    sequence: headB1.head.sequence,
    statementHash: headB1.head.state_fingerprint,
    nonce: deriveNonce(fixture.nonceCodec, pendingB),
    observedAt: nowIso
  });
  await assert.rejects(authority.acknowledgeBundle(rollbackAck), (error) => error?.code === "ERR_ACK_SEQUENCE_ROLLBACK");

  await pool.query(`UPDATE device_refresh_outbox SET expires_at=clock_timestamp()+interval '1 millisecond'
    WHERE organization_id=$1 AND device_id=$2 AND desired_generation=$3`, [ids.organization, ids.deviceB, pendingB.desired_generation]);
  await delay(10);
  await assert.rejects(authority.markDeviceRefreshDelivered({ organization_id: ids.organization, device_id: ids.deviceB, outbox_id: pendingB.outbox_id, desired_generation: pendingB.desired_generation, delivered_at: new Date().toISOString() }), (error) => error?.code === "ERR_REFRESH_EXPIRED");

  const readModels = await store.listDeviceReadModels({ organizationId: ids.organization });
  const synced = readModels.find((device) => device.device_id === ids.deviceA);
  assert.ok(synced);
  assert.equal(synced.desired_generation, 2);
  assert.equal(synced.observed_generation, 2);
  assert.equal(synced.refresh_state, "applied");
  assert.equal(synced.bundle_sequence, 1);
  assert.equal(typeof synced.last_ack_at, "string");
  assert.deepEqual(Object.keys(synced).sort(), ["blocked_reason", "bundle_expires_at", "bundle_sequence", "created_at", "desired_generation", "device_id", "last_ack_at", "last_seen_at", "name", "observed_generation", "refresh_state", "status", "version"]);
});

async function createFixture(t) {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const ids = {
    organization: crypto.randomUUID(),
    owner: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    deviceA: crypto.randomUUID(),
    deviceB: crypto.randomUUID(),
    agent: crypto.randomUUID(),
    policy: crypto.randomUUID()
  };
  const keys = {
    deviceA: crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
    deviceB: crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  };
  const publicA = keys.deviceA.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const publicB = keys.deviceB.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const nonceCodec = createRefreshNonceCodec({ keys: { "refresh-nonce-v1": Buffer.alloc(32, 0x51) }, activeKeyId: "refresh-nonce-v1" });
  const bundleKeys = crypto.generateKeyPairSync("ed25519");
  const refreshHintKeys = crypto.generateKeyPairSync("ed25519");
  const refreshSigner = createEd25519RefreshHintSigner({ privateKey: refreshHintKeys.privateKey, keyId: "p0b-refresh-v1" });
  const token = "ap_p0b_owner_token_abcdefghijklmnopqrstuvwxyz";
  const tokenRecords = [createApiTokenRecord({ token, tokenId: "p0b-owner", organizationId: ids.organization, memberId: ids.owner, role: "owner" })];

  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "p0b-signed-ack" }).run();
  } finally {
    migrationClient.release();
  }
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'P0-B integration')", [ids.organization]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'P0-B owner')", [ids.owner, `p0b-${ids.owner}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [ids.organization, ids.membership, ids.owner]);
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,'P0-B A','p256-sha256',$3,'active','{}'::jsonb),($1,$4,'P0-B B','p256-sha256',$5,'active','{}'::jsonb)`, [ids.organization, ids.deviceA, publicA, ids.deviceB, publicB]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'cli','P0-B agent',$4,'active')`, [ids.organization, ids.agent, ids.deviceA, publicA]);
  await pool.query(`INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
    VALUES ($1,$2,1,'default',$3::jsonb,'active',$4)`, [ids.organization, ids.policy, JSON.stringify({ operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } }), ids.owner]);

  // Capture the test clock only after the organization insert initialized the
  // first authority generation. Backdating the next generation by even a few
  // milliseconds correctly violates the database's monotonic-time invariant.
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const authority = createControlPlaneAuthorityRepository({ client: pool, cursorSecret: Buffer.alloc(32, 0x52), refreshNonceCodec: nonceCodec, now: () => new Date().toISOString() });
  const refreshHintService = createRefreshHintService({ source: authority, nonceDeriver: nonceCodec, signer: refreshSigner, now: () => Date.now() });
  const store = createPostgresControlPlaneStore({ client: pool, cursorSecret: Buffer.alloc(32, 0x53), refreshNonceCodec: nonceCodec, now: () => new Date().toISOString() });
  const server = createCloudApi({
    store,
    tokenRecords,
    bundleSigner: { privateKey: bundleKeys.privateKey, issuer: "agentpass-cloud", keyId: "p0b-control-v1", ttlMs: 60_000, offlineTtlMs: 120_000 },
    refreshHintService,
    now: () => nowMs,
    verifyRecentWebAuthn: async ({ proof, operation, principal, organization_id }) => ({
      verified: proof === "webauthn-proof-abcdefghijklmnopqrstuvwxyz",
      consumed: proof === "webauthn-proof-abcdefghijklmnopqrstuvwxyz",
      challenge_id: "99999999-9999-4999-8999-999999999999",
      member_id: principal.member_id,
      organization_id,
      operation,
      authenticated_at: nowIso
    })
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await pool.end();
  });
  return { ids, keys, authority, store, pool, base, token, bundleKeys, refreshHintKeys, nonceCodec, nowMs, nowIso };
}

async function deviceFetch({ base, path, method, body, privateKey, deviceId, timestamp, nonce, signedBody = body }) {
  const headers = signDeviceRequest({ method, path, body: signedBody, device_id: deviceId, timestamp, nonce }, privateKey);
  if (method === "POST") headers["content-type"] = "application/json";
  return { response: await fetch(`${base}${path}`, { method, headers, body: body.length === 0 ? undefined : body }) };
}

function signAcknowledgement({ privateKey, organizationId, deviceId, sequence, statementHash, nonce, result = "applied", reasonCode, observedAt }) {
  const unsigned = {
    version: 1,
    type: "agentpass.bundle-ack",
    organization_id: organizationId,
    device_id: deviceId,
    device_key_epoch: 1,
    format_epoch: 2,
    sequence,
    statement_hash: statementHash,
    result,
    ...(reasonCode === undefined ? {} : { reason_code: reasonCode }),
    observed_at: observedAt,
    nonce,
    signature_algorithm: "p256-sha256"
  };
  const placeholder = { ...unsigned, signature: Buffer.alloc(64, 1).toString("base64url") };
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const signature = crypto.sign("sha256", bundleAcknowledgementSigningData(placeholder), { key: privateKey, dsaEncoding: "ieee-p1363" });
    if (signature.subarray(32).compare(HALF_ORDER) <= 0) return normalizeBundleAcknowledgement({ ...unsigned, signature: signature.toString("base64url") });
  }
  throw new Error("P0-B could not create a canonical low-S signature");
}

function signExisting({ acknowledgement, privateKey }) {
  const { signature: _signature, ...unsigned } = normalizeBundleAcknowledgement({ ...acknowledgement, signature: Buffer.alloc(64, 1).toString("base64url") });
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const signature = crypto.sign("sha256", bundleAcknowledgementSigningData({ ...unsigned, signature: Buffer.alloc(64, 1).toString("base64url") }), { key: privateKey, dsaEncoding: "ieee-p1363" });
    if (signature.subarray(32).compare(HALF_ORDER) <= 0) return { ...unsigned, signature: signature.toString("base64url") };
  }
  throw new Error("P0-B could not create a canonical low-S signature");
}

function deriveNonce(codec, poll) {
  const derived = codec.derive({ organization_id: poll.organization_id, device_id: poll.device_id, authority_generation: poll.desired_generation, outbox_id: poll.outbox_id, key_id: poll.refresh_nonce_key_id });
  return derived.nonce_base64url;
}

async function json(response) {
  const text = await response.text();
  return text.length === 0 ? null : JSON.parse(text);
}

function publicError(body) {
  return body?.error ?? body;
}

async function scalar(pool, sql, params) {
  const result = await pool.query(sql, params);
  return Number(result.rows[0]?.count ?? result.rows[0]?.generation ?? 0);
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

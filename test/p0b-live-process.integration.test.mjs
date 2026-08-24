import { POSTGRES_SCHEMA_HEAD } from "../apps/cloud-api/src/postgres/schema-head.mjs";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import https from "node:https";
import test from "node:test";

import { signDeviceRequest } from "../apps/cloud-api/src/auth.mjs";
import { createMigrationRunner } from "../apps/cloud-api/src/postgres/migration-runner.mjs";
import { createControlPlaneAuthorityRepository } from "../apps/cloud-api/src/postgres/control-plane-authority-repository.mjs";
import { createRefreshNonceCodec } from "../apps/cloud-api/src/postgres/refresh-nonce-codec.mjs";
import {
  bundleAcknowledgementSigningData,
  normalizeBundleAcknowledgement,
  normalizeRefreshHint
} from "../packages/protocol/src/index.mjs";
import { controlBundleStatementHash } from "../lib/control-bundle-v2.mjs";
import { P0BSkip, startP0BHarness } from "./support/p0b/harness.mjs";

const P256_HALF_ORDER = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");

test("P0-B live processes: Console BFF read and signed Device API ACK share PostgreSQL state", {
  timeout: 120_000
}, async (t) => {
  let fixture;
  let harness;
  processDiagnostic("harness_start");
  try {
    harness = await startP0BHarness({
      waitTimeoutMs: 30_000,
      prepareDatabase: async ({ pool, organizationId, refreshNonceKeyId, refreshNonceKey }) => {
        fixture = await seedDatabase(pool, organizationId, { refreshNonceKeyId, refreshNonceKey });
      }
    });
  } catch (error) {
    if (error instanceof P0BSkip) {
      t.skip(`${error.code}: ${error.diagnostic}`);
      return;
    }
    throw error;
  }
  t.after(() => harness.close());
  assert.ok(fixture, "the PostgreSQL bootstrap fixture must be available");
  processDiagnostic("session_start");

  const origin = new URL(harness.consoleUrl).origin;
  const session = await requestJson(new URL("/api/auth/session", origin), {
    method: "POST",
    caFile: harness.caCert,
    headers: {
      origin,
      "content-type": "application/json",
      "oai-authenticated-user-id": fixture.subject,
      "oai-authenticated-user-email": "p0b-live@example.test"
    },
    body: "{}"
  });
  assert.equal(session.status, 201, JSON.stringify(session.body));
  assert.equal(session.body.session.organization_id, fixture.organizationId);
  assert.equal(session.body.session.member_id, fixture.memberId);
  assert.equal(session.body.session.role, "owner");
  assert.match(session.body.csrf_token, /^[A-Za-z0-9_-]{43}$/u);
  const cookie = sessionCookie(session.headers);

  processDiagnostic("cloud_read_start");
  const directBefore = await requestJson(new URL(`/v1/organizations/${fixture.organizationId}/devices`, harness.cloudUrl), {
    method: "GET",
    caFile: harness.caCert,
    headers: { cookie, origin }
  });
  assert.equal(directBefore.status, 200, JSON.stringify(directBefore.body));

  const before = await consoleRead(harness, cookie, "devices");
  assert.equal(before.status, 200, JSON.stringify({ console: before.body, cloud: directBefore.body }));
  const beforeDevice = findDevice(before.body, fixture.deviceId);
  assert.equal(beforeDevice.desired_generation, fixture.generation);
  assert.equal(beforeDevice.observed_generation, null);
  assert.notEqual(beforeDevice.refresh_state, "applied");

  processDiagnostic("device_poll_start");
  const pollPath = `/v1/organizations/${fixture.organizationId}/devices/${fixture.deviceId}/refresh?after_generation=1&wait_ms=0`;
  const poll = await deviceRequest(harness.cloudUrl, {
    method: "GET",
    path: pollPath,
    body: Buffer.alloc(0),
    deviceId: fixture.deviceId,
    privateKey: fixture.deviceKeys.privateKey,
    nonce: "p0b-live-poll-abcdefghijklmnopqrstuvwxyz-0001"
  }, harness.caCert);
  assert.equal(poll.status, 200, JSON.stringify(poll.body));
  const hint = normalizeRefreshHint(poll.body.hint);
  assert.equal(hint.organization_id, fixture.organizationId);
  assert.equal(hint.device_id, fixture.deviceId);
  assert.equal(hint.authority_generation, fixture.generation);

  processDiagnostic("bundle_start");
  const bundlePath = `/v1/organizations/${fixture.organizationId}/bundles/${fixture.deviceId}`;
  const bundleResponse = await deviceRequest(harness.cloudUrl, {
    method: "GET",
    path: bundlePath,
    body: Buffer.alloc(0),
    deviceId: fixture.deviceId,
    privateKey: fixture.deviceKeys.privateKey,
    nonce: "p0b-live-bundle-abcdefghijklmnopqrstuvwxyz-0001"
  }, harness.caCert);
  assert.equal(bundleResponse.status, 200, JSON.stringify(bundleResponse.body));
  assert.equal(bundleResponse.body.desired_generation, fixture.generation);

  const bundle = bundleResponse.body.bundle;
  const ack = signAcknowledgement({
    privateKey: fixture.deviceKeys.privateKey,
    organizationId: fixture.organizationId,
    deviceId: fixture.deviceId,
    sequence: bundle.sequence,
    statementHash: controlBundleStatementHash(bundle),
    nonce: hint.nonce,
    observedAt: new Date().toISOString()
  });
  const ackBody = Buffer.from(JSON.stringify(ack));
  const ackPath = `/v1/organizations/${fixture.organizationId}/bundles/${fixture.deviceId}/acknowledgements`;
  processDiagnostic("ack_start");
  const accepted = await deviceRequest(harness.cloudUrl, {
    method: "POST",
    path: ackPath,
    body: ackBody,
    deviceId: fixture.deviceId,
    privateKey: fixture.deviceKeys.privateKey,
    nonce: "p0b-live-ack-abcdefghijklmnopqrstuvwxyz-0001"
  }, harness.caCert);
  assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
  assert.deepEqual(
    { accepted: accepted.body.accepted, duplicate: accepted.body.duplicate, refresh_state: accepted.body.refresh_state },
    { accepted: true, duplicate: false, refresh_state: "applied" }
  );
  assert.equal(accepted.body.observed_generation, fixture.generation);

  processDiagnostic("duplicate_start");
  const duplicate = await deviceRequest(harness.cloudUrl, {
    method: "POST",
    path: ackPath,
    body: ackBody,
    deviceId: fixture.deviceId,
    privateKey: fixture.deviceKeys.privateKey,
    nonce: "p0b-live-ack-retry-abcdefghijklmnopqrstuvwxyz-0001"
  }, harness.caCert);
  assert.equal(duplicate.status, 202, JSON.stringify(duplicate.body));
  assert.equal(duplicate.body.duplicate, true);

  processDiagnostic("conflict_start");
  const conflictAck = signAcknowledgement({
    privateKey: fixture.deviceKeys.privateKey,
    organizationId: fixture.organizationId,
    deviceId: fixture.deviceId,
    sequence: bundle.sequence,
    statementHash: controlBundleStatementHash(bundle),
    nonce: hint.nonce,
    observedAt: ack.observed_at,
    result: "blocked",
    reasonCode: "bundle_expired"
  });
  const conflict = await deviceRequest(harness.cloudUrl, {
    method: "POST",
    path: ackPath,
    body: Buffer.from(JSON.stringify(conflictAck)),
    deviceId: fixture.deviceId,
    privateKey: fixture.deviceKeys.privateKey,
    nonce: "p0b-live-ack-conflict-abcdefghijklmnopqrstuvwxyz-0001"
  }, harness.caCert);
  assert.equal(conflict.status, 409, JSON.stringify(conflict.body));
  assert.equal(conflict.body.error.code, "ack_conflict");

  processDiagnostic("final_read_start");
  const after = await consoleRead(harness, cookie, "devices");
  assert.equal(after.status, 200, JSON.stringify(after.body));
  const afterDevice = findDevice(after.body, fixture.deviceId);
  assert.equal(afterDevice.desired_generation, fixture.generation);
  assert.equal(afterDevice.observed_generation, fixture.generation);
  assert.equal(afterDevice.refresh_state, "applied");
  assert.equal(typeof afterDevice.last_ack_at, "string");
  processDiagnostic("complete");
});

function processDiagnostic(stage) {
  if (/^[a-z][a-z0-9_]{1,31}$/u.test(stage)) {
    process.stdout.write(`P0B_DIAGNOSTIC_PROCESS_STAGE stage=${stage}\n`);
  }
}

async function seedDatabase(pool, organizationId, { refreshNonceKeyId, refreshNonceKey }) {
  const ids = {
    memberId: crypto.randomUUID(),
    membershipId: crypto.randomUUID(),
    deviceId: crypto.randomUUID(),
    agentId: crypto.randomUUID(),
    policyId: crypto.randomUUID()
  };
  const deviceKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const subject = `p0b-live-${crypto.randomUUID()}`;
  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({ client: migrationClient, applicationVersion: "p0b-live-process" }).run();
    assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);
  } finally {
    migrationClient.release();
  }
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'P0-B live process')", [organizationId]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,NULL,'P0-B live owner')", [ids.memberId]);
  await pool.query(
    "INSERT INTO upstream_identities (provider,subject,member_id) VALUES ('chatgpt',$1,$2)",
    [subject, ids.memberId]
  );
  await pool.query(
    "INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')",
    [organizationId, ids.membershipId, ids.memberId]
  );
  await pool.query(
    `INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
     VALUES ($1,$2,'P0-B live device','p256-sha256',$3,'active','{}'::jsonb)`,
    [organizationId, ids.deviceId, publicKey]
  );
  await pool.query(
    `INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
     VALUES ($1,$2,$3,'cli','P0-B live agent',$4,'active')`,
    [organizationId, ids.agentId, ids.deviceId, publicKey]
  );
  await pool.query(
    `INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
     VALUES ($1,$2,1,'P0-B live policy',$3::jsonb,'active',$4)`,
    [organizationId, ids.policyId, JSON.stringify({
      operations: ["git.commit.sign"],
      repositories: ["/work/repo"],
      branches: { allow: ["main"], deny: [] },
      remotes: { allow: ["origin"], deny: [] }
    }), ids.memberId]
  );

  const nonceCodec = createRefreshNonceCodec({
    keys: { [refreshNonceKeyId]: refreshNonceKey },
    activeKeyId: refreshNonceKeyId
  });
  const authority = createControlPlaneAuthorityRepository({
    client: pool,
    cursorSecret: Buffer.alloc(32, 0x5c),
    refreshNonceCodec: nonceCodec
  });
  const issuedAt = new Date().toISOString();
  const reduction = await authority.advanceAuthorityGenerationAndEnqueueRefresh({
    organization_id: organizationId,
    issued_at: issuedAt,
    expires_at: new Date(Date.parse(issuedAt) + 60_000).toISOString()
  });
  assert.equal(reduction.generation, 2);
  return Object.freeze({
    ...ids,
    organizationId,
    subject,
    deviceKeys,
    generation: reduction.generation
  });
}

async function consoleRead(harness, cookie, resource) {
  return requestJson(new URL(`/api/console?resource=${resource}`, harness.consoleUrl), {
    method: "GET",
    caFile: harness.caCert,
    headers: { cookie }
  });
}

async function deviceRequest(origin, input, caFile) {
  const url = new URL(input.path, origin);
  const headers = signDeviceRequest({
    method: input.method,
    path: input.path,
    body: input.body,
    device_id: input.deviceId,
    timestamp: Date.now(),
    nonce: input.nonce
  }, input.privateKey);
  if (input.method === "POST") headers["content-type"] = "application/json";
  return requestJson(url, { method: input.method, caFile, headers, body: input.body });
}

async function requestJson(url, { method, headers = {}, body = undefined, caFile }) {
  const ca = await fs.readFile(caFile, "utf8");
  return new Promise((resolve, reject) => {
    const request = https.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method,
      headers: { accept: "application/json", ...headers, ...(body === undefined ? {} : { "content-length": Buffer.byteLength(body) }) },
      ca,
      rejectUnauthorized: true
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let parsed;
        try { parsed = text.length === 0 ? null : JSON.parse(text); }
        catch (error) { reject(new Error(`P0-B response was not JSON (status ${response.statusCode}): ${error.message}`)); return; }
        resolve({ status: response.statusCode, headers: response.headers, body: parsed });
      });
    });
    request.setTimeout(15_000, () => request.destroy(new Error("P0-B request timed out")));
    request.once("error", reject);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

function sessionCookie(headers) {
  const values = headers["set-cookie"];
  const value = Array.isArray(values) ? values[0] : values;
  assert.match(value ?? "", /^__Host-agentpass_session=[A-Za-z0-9_-]{43};/u);
  return value.split(";", 1)[0];
}

function findDevice(body, deviceId) {
  assert.ok(Array.isArray(body?.devices), "Console BFF response must contain devices");
  const device = body.devices.find((item) => item.device_id === deviceId);
  assert.ok(device, `device ${deviceId} must be visible through the Console BFF`);
  return device;
}

function signAcknowledgement({ privateKey, organizationId, deviceId, sequence, statementHash, nonce, observedAt, result = "applied", reasonCode }) {
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
    const signature = crypto.sign("sha256", bundleAcknowledgementSigningData(placeholder), {
      key: privateKey,
      dsaEncoding: "ieee-p1363"
    });
    if (signature.subarray(32).compare(P256_HALF_ORDER) <= 0) {
      return normalizeBundleAcknowledgement({ ...unsigned, signature: signature.toString("base64url") });
    }
  }
  throw new Error("P0-B could not create a canonical low-S signature");
}

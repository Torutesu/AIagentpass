/*
 * M2-A2Q real-PostgreSQL HTTP qualification lane.
 *
 * Run with PostgreSQL 17+:
 *   AGENTPASS_TEST_DATABASE_URL="$DATABASE_URL" \
 *     node --test apps/cloud-api/test/postgres/agent-session-http-qualification.integration.test.mjs
 *
 * The test is intentionally skipped when the explicit integration URL is not
 * configured. Once configured, connection or migration failures are test
 * failures; silently converting an unavailable database into a pass would
 * invalidate this qualification lane.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import pg from "pg";

import { signDeviceRequest, verifyDeviceRequest } from "../../src/auth.mjs";
import { createLocalAgentSessionGrantSigner } from "../../src/agent-session-grant.mjs";
import { createHostedAgentSessionGrantSigner } from "../../src/agent-session-signer-config.mjs";
import { createAgentSessionDeviceApi } from "../../src/agent-session-device-api.mjs";
import { createCloudApi } from "../../src/server.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";
import { createControlPlaneAuthorityRepository } from "../../src/postgres/control-plane-authority-repository.mjs";
import { createPostgresControlPlaneStore } from "../../src/postgres/control-plane-store.mjs";
import { createSharedControlRepository } from "../../src/postgres/shared-control-repository.mjs";
import { createAgentSessionAuthorityRepository } from "../../src/postgres/agent-session-authority-repository.mjs";
import { createPostgresAgentSessionConsumptionRepository } from "../../src/postgres/agent-session-consumption-repository.mjs";
import {
  BUNDLE_ACK_TYPE,
  bundleAcknowledgementSigningData,
  normalizeBundleAcknowledgement
} from "../../../../packages/protocol/src/index.mjs";

const { Pool } = pg;
const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL
  ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const GRANT_KEY_ID = "m2-a2q-agent-session-v1";
const RETIRING_GRANT_KEY_ID = "m2-a2q-agent-session-v0";
const POLICY_SCOPE = Object.freeze({
  operations: ["git.commit.sign"],
  repositories: ["/qualification/repository"],
  branches: { allow: ["main"], deny: [] },
  remotes: { allow: ["origin"], deny: [] }
});
const PROCESS_BINDING = "a".repeat(64);
const ANCESTRY_BINDING = "b".repeat(64);
const CHANGED_PROCESS_BINDING = "c".repeat(64);
const HALF_ORDER = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");

test("M2-A2Q: real PostgreSQL Device HTTP consume survives restart, converges concurrent retries, and rejects weaker fallthrough", {
  skip: !DATABASE_URL,
  timeout: 45_000
}, async (t) => {
  const fixture = await createFixture(t);
  const rollbackGrant = await issueGrant(fixture);
  const rollbackAuthority = createAgentSessionAuthorityRepository({ client: fixture.pool, now: () => new Date().toISOString() });
  const failingConsumption = createPostgresAgentSessionConsumptionRepository({
    client: fixture.pool,
    authorityRepository: rollbackAuthority,
    auditRepository: {
      async appendAgentSessionGrantConsumedInTransaction() { throw new Error("injected audit failure"); }
    }
  });
  await assert.rejects(failingConsumption.consumeAgentSessionGrant({
    organization_id: fixture.ids.organization,
    device_id: fixture.ids.device,
    grant_id: rollbackGrant.statement.grant_id,
    grant: rollbackGrant,
    process_binding_sha256: PROCESS_BINDING,
    ancestry_binding_sha256: ANCESTRY_BINDING
  }));
  const rolledBack = await fixture.pool.query(`SELECT g.status,g.consumed_session_id,
      (SELECT count(*)::int FROM agent_sessions s WHERE s.organization_id=g.organization_id AND s.grant_id=g.grant_id) AS sessions,
      (SELECT count(*)::int FROM cloud_agent_audit_events e WHERE e.organization_id=g.organization_id AND e.grant_id=g.grant_id) AS events,
      (SELECT count(*)::int FROM outbox_events o WHERE o.organization_id=g.organization_id AND o.action='agent_session_grant.consumed' AND o.payload->>'grant_id'=g.grant_id::text) AS publications
    FROM agent_session_grants g WHERE g.organization_id=$1 AND g.grant_id=$2`, [fixture.ids.organization, rollbackGrant.statement.grant_id]);
  assert.deepEqual(rolledBack.rows, [{ status: "issued", consumed_session_id: null, sessions: 0, events: 0, publications: 0 }]);
  const firstGrant = await issueGrant(fixture);
  const firstServer = await fixture.startServer();

  const first = await consume(fixture, firstServer, firstGrant, {
    nonce: "m2-a2q-first-abcdefghijklmnopqrstuvwxyz-0001"
  });
  assert.equal(first.response.status, 201, JSON.stringify({ body: first.body, ...fixture.diagnostics }));
  assert.equal(first.body.lease.grant_id, firstGrant.statement.grant_id);
  assert.equal(first.body.lease.process_binding_sha256, PROCESS_BINDING);
  assert.equal(first.body.lease.ancestry_binding_sha256, ANCESTRY_BINDING);

  // Recreate the HTTP server before retrying. The retry is authenticated with
  // a fresh DB nonce, but its Grant and both process bindings are identical.
  await stopServer(firstServer);
  const restartedServer = await fixture.startServer();
  const retry = await consume(fixture, restartedServer, firstGrant, {
    nonce: "m2-a2q-restart-abcdefghijklmnopqrstuvwxyz-0001"
  });
  assert.equal(retry.response.status, 201, JSON.stringify(retry.body));
  assert.deepEqual(retry.body.lease, first.body.lease);
  assert.notEqual(retry.body.request_id, first.body.request_id, "HTTP request identity must not replace durable retry identity");

  const conflict = await consume(fixture, restartedServer, firstGrant, {
    nonce: "m2-a2q-binding-abcdefghijklmnopqrstuvwxyz-0001",
    processBinding: CHANGED_PROCESS_BINDING
  });
  assert.equal(conflict.response.status, 409, JSON.stringify(conflict.body));
  assert.equal(conflict.body.error.code, "grant_conflict");

  const retiringGrant = await issueGrant(fixture, { retiring: true });
  const retiring = await consume(fixture, restartedServer, retiringGrant, {
    nonce: "m2-a2q-retiring-abcdefghijklmnopqrstuvwxyz-0001"
  });
  assert.equal(retiring.response.status, 201, JSON.stringify(retiring.body));
  assert.equal(retiring.body.lease.grant_id, retiringGrant.statement.grant_id);

  // Two independent Node servers contend on a fresh Grant. PostgreSQL grant
  // locking and the unique consumed-session boundary must produce one Lease.
  const concurrentGrant = await issueGrant(fixture);
  const concurrentA = await fixture.startServer();
  const concurrentB = await fixture.startServer();
  const [a, b] = await Promise.all([
    consume(fixture, concurrentA, concurrentGrant, { nonce: "m2-a2q-concurrent-a-abcdefghijklmnop-0001" }),
    consume(fixture, concurrentB, concurrentGrant, { nonce: "m2-a2q-concurrent-b-abcdefghijklmnop-0001" })
  ]);
  assert.equal(a.response.status, 201, JSON.stringify(a.body));
  assert.equal(b.response.status, 201, JSON.stringify(b.body));
  assert.deepEqual(a.body.lease, b.body.lease);

  const stored = await fixture.pool.query(`SELECT g.status, g.consumed_session_id, count(s.session_id)::int AS session_count
    FROM agent_session_grants g
    LEFT JOIN agent_sessions s
      ON s.organization_id=g.organization_id AND s.grant_id=g.grant_id
    WHERE g.organization_id=$1 AND g.grant_id=$2
    GROUP BY g.status, g.consumed_session_id`, [fixture.ids.organization, concurrentGrant.statement.grant_id]);
  assert.deepEqual(stored.rows, [{
    status: "consumed",
    consumed_session_id: a.body.lease.session_id,
    session_count: 1
  }]);
  const audit = await fixture.pool.query(`SELECT
    (SELECT count(*)::int FROM cloud_agent_audit_events WHERE organization_id=$1) AS events,
    (SELECT sequence::int FROM cloud_agent_audit_heads WHERE organization_id=$1) AS head_sequence,
    (SELECT count(*)::int FROM device_audit_events WHERE organization_id=$1) AS device_events,
    (SELECT count(*)::int FROM outbox_events WHERE organization_id=$1 AND action='agent_session_grant.consumed') AS publications`, [fixture.ids.organization]);
  assert.deepEqual(audit.rows, [{ events: 3, head_sequence: 3, device_events: 0, publications: 3 }]);

  // The exact frozen path is intercepted before generic route dispatch. A
  // query-string variant must not fall through to a weaker authenticated
  // route; the generic router returns only its bounded not-found response.
  const queryVariant = await consume(fixture, restartedServer, firstGrant, {
    nonce: "m2-a2q-query-abcdefghijklmnopqrstuvwxyz-0001",
    path: `${fixture.pathFor(firstGrant)}?fallback=1`
  });
  assert.equal(queryVariant.response.status, 404, JSON.stringify(queryVariant.body));
  assert.equal(queryVariant.body.error.code, "not_found");

  const methodVariant = await fetch(`${restartedServer.base}${fixture.pathFor(firstGrant)}`, {
    method: "GET",
    headers: { accept: "application/json" }
  });
  const methodVariantBody = await readJson(methodVariant);
  assert.equal(methodVariant.status, 404, JSON.stringify(methodVariantBody));
  assert.equal(methodVariantBody.error.code, "not_found");
});

async function createFixture(t) {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const servers = new Set();
  const ids = Object.freeze({
    organization: crypto.randomUUID(),
    member: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    device: crypto.randomUUID(),
    agent: crypto.randomUUID(),
    policy: crypto.randomUUID(),
    adapter: crypto.randomUUID()
  });
  const deviceKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const grantKeys = crypto.generateKeyPairSync("ed25519");
  const retiringGrantKeys = crypto.generateKeyPairSync("ed25519");
  const devicePublicKey = deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();
  const nonceCodec = createRefreshNonceCodec({
    keys: { "refresh-nonce-v1": Buffer.alloc(32, 0x51) },
    activeKeyId: "refresh-nonce-v1"
  });
  const activePublicKey = grantKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const retiringPublicKey = retiringGrantKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const grantSigner = createHostedAgentSessionGrantSigner({
    provider: {
      async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: activePublicKey }; },
      async sign({ bytes }) { return crypto.sign(null, bytes, grantKeys.privateKey); }
    },
    env: {
      AGENTPASS_CLOUD_PROFILE: "hosted",
      AGENTPASS_CLOUD_AGENT_SESSION_VERIFICATION_KEYS_JSON: JSON.stringify({
        version: 1,
        active: { key_id: GRANT_KEY_ID, algorithm: "ed25519", public_key: activePublicKey },
        retiring: [{ key_id: RETIRING_GRANT_KEY_ID, algorithm: "ed25519", public_key: retiringPublicKey, expires_at: new Date(Date.now() + 240_000).toISOString() }]
      })
    },
    now: () => Date.now()
  });
  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "m2-a2q-agent-session-http"
    }).run();
    assert.equal(migration.currentVersion, 54);
  } finally {
    migrationClient.release();
  }

  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [ids.organization, "M2-A2Q HTTP qualification"]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [ids.member, `m2-a2q-${ids.member}`, "Qualification owner"]);
  await pool.query(`INSERT INTO memberships (organization_id,id,member_id,role,status)
    VALUES ($1,$2,$3,'owner','active')`, [ids.organization, ids.membership, ids.member]);
  await pool.query(`INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status,metadata)
    VALUES ($1,$2,'M2-A2Q device','p256-sha256',$3,'active','{}'::jsonb)`, [ids.organization, ids.device, devicePublicKey]);
  await pool.query(`INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
    VALUES ($1,$2,$3,'claude-code','M2-A2Q agent',$4,'active')`, [ids.organization, ids.agent, ids.device, devicePublicKey]);
  await pool.query(`INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
    VALUES ($1,$2,1,'m2-a2q',$3::jsonb,'active',$4)`, [ids.organization, ids.policy, JSON.stringify(POLICY_SCOPE), ids.member]);

  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const authority = createControlPlaneAuthorityRepository({
    client: pool,
    cursorSecret: Buffer.alloc(32, 0x52),
    refreshNonceCodec: nonceCodec,
    now: () => new Date().toISOString()
  });
  const advanced = await authority.advanceAuthorityGenerationAndEnqueueRefresh({
    organization_id: ids.organization,
    issued_at: nowIso,
    expires_at: new Date(nowMs + 240_000).toISOString()
  });
  assert.equal(advanced.generation, 2);
  const bundle = await authority.snapshotAndAssignBundleHead({
    organization_id: ids.organization,
    device_id: ids.device,
    minimum_sequence: 1,
    issued_at: nowIso,
    expires_at: new Date(nowMs + 240_000).toISOString(),
    statement_hash_factory: () => "d".repeat(64)
  });
  const pending = await authority.pollDeviceRefresh({
    organization_id: ids.organization,
    device_id: ids.device,
    after_generation: 0,
    wait_ms: 0
  });
  assert.ok(pending, "fixture must publish a refresh outbox row");
  const deliveredAt = new Date().toISOString();
  await authority.markDeviceRefreshDelivered({
    organization_id: ids.organization,
    device_id: ids.device,
    outbox_id: pending.outbox_id,
    desired_generation: pending.desired_generation,
    delivered_at: deliveredAt
  });
  const ackNonce = nonceCodec.derive({
    organization_id: ids.organization,
    device_id: ids.device,
    authority_generation: pending.desired_generation,
    outbox_id: pending.outbox_id,
    key_id: pending.refresh_nonce_key_id
  }).nonce_base64url;
  await authority.acknowledgeBundle(makeAppliedAcknowledgement({
    organizationId: ids.organization,
    deviceId: ids.device,
    sequence: bundle.head.sequence,
    statementHash: bundle.head.state_fingerprint,
    nonce: ackNonce,
    observedAt: deliveredAt,
    privateKey: deviceKeys.privateKey
  }));
  // The current Agent Session authority query still requires the legacy
  // bundle_acknowledgements compatibility record, while the G4 device state
  // transition above is driven by device_bundle_acknowledgements. Create both
  // through the supported repository boundary; never write either table from
  // the fixture directly.
  await authority.acknowledgeBundle({
    organization_id: ids.organization,
    device_id: ids.device,
    format_epoch: 2,
    sequence: bundle.head.sequence,
    statement_hash: bundle.head.state_fingerprint,
    status: "applied",
    applied_at: deliveredAt
  });

  const store = createPostgresControlPlaneStore({
    client: pool,
    cursorSecret: Buffer.alloc(32, 0x53),
    refreshNonceCodec: nonceCodec
  });
  const sharedControls = createSharedControlRepository({ client: pool });
  const diagnostics = {};
  const base = {
    pool,
    ids,
    deviceKeys,
    grantKeys,
    retiringGrantKeys,
    grantSigner,
    store,
    sharedControls,
    nowMs,
    nowIso,
    diagnostics,
    authorityGeneration: advanced.generation,
    controlSequence: bundle.head.sequence,
    pathFor(grant) {
      return `/v1/organizations/${ids.organization}/devices/${ids.device}/agent-session-grants/${grant.statement.grant_id}/consume`;
    },
    async startServer() {
      const authorityRepository = createAgentSessionAuthorityRepository({
        client: pool,
        now: () => new Date().toISOString()
      });
      const consumptionRepository = createPostgresAgentSessionConsumptionRepository({
        client: pool,
        authorityRepository
      });
      const repository = {
        async consumeAgentSessionGrant(input) {
          try {
            return await consumptionRepository.consumeAgentSessionGrant(input);
          } catch (error) {
            diagnostics.consumeError = { code: error?.code ?? null, name: error?.name ?? null };
            throw error;
          }
        }
      };
      const deviceApi = createAgentSessionDeviceApi({
        now: () => Date.now(),
        deviceRequestVerifier: async (request, options) => {
          try {
            const devices = await store.listDevices({ organizationId: options.organization_id });
            const principal = verifyDeviceRequest(request, devices, {
              organizationId: options.organization_id,
              now: options.now,
              deferReplayConsumption: true,
              includeAuthenticationMetadata: true
            });
            const nonce = request.headers["agentpass-nonce"] ?? request.headers["AgentPass-Nonce"];
            const consumed = await sharedControls.consumeDeviceRequestNonce({
              organizationId: options.organization_id,
              deviceId: principal.device_id,
              nonce
            });
            if (consumed.accepted !== true) {
              const error = new Error("device request replay denied");
              error.code = "ERR_REPLAY_DETECTED";
              throw error;
            }
            return principal;
          } catch (error) {
            diagnostics.deviceError = { code: error?.code ?? null, name: error?.name ?? null };
            throw error;
          }
        },
        grantVerifier: async (grant, options) => {
          try {
            await grantSigner.verificationKeyMetadata(grant?.statement?.key_id, { at: options.now });
            return grantSigner.verifyAgentSessionGrant(grant, { at: options.now });
          } catch (error) {
            diagnostics.grantError = { code: error?.code ?? null, name: error?.name ?? null };
            throw error;
          }
        },
        repository,
        rateLimiter: {
          acquire: ({ tenantId, principalType, principalId }) => sharedControls.acquireRateLimit({
            organizationId: tenantId,
            principalType,
            principalId,
            capacity: 240,
            refillPerSecond: 4,
            cost: 1
          })
        }
      });
      const server = createCloudApi({
        store,
        agentSessionDeviceApi: deviceApi,
        now: () => Date.now()
      });
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
          server.off("error", reject);
          resolve();
        });
      });
      server.base = `http://127.0.0.1:${server.address().port}`;
      servers.add(server);
      server.once("close", () => servers.delete(server));
      return server;
    }
  };
  t.after(async () => {
    let firstError;
    for (const server of [...servers]) {
      try {
        await stopServer(server);
      } catch (error) {
        firstError ??= error;
      }
    }
    try {
      await pool.end();
    } catch (error) {
      firstError ??= error;
    }
    if (firstError) throw firstError;
  });
  return Object.freeze(base);
}

async function issueGrant(fixture, { retiring = false } = {}) {
  const grantId = crypto.randomUUID();
  const nowMs = Date.now();
  const statement = {
    version: 1,
    grant_id: grantId,
    organization_id: fixture.ids.organization,
    device_id: fixture.ids.device,
    agent_id: fixture.ids.agent,
    agent_kind: "claude-code",
    adapter_id: fixture.ids.adapter,
    adapter_version: "1.0.0",
    worktree_binding_sha256: "e".repeat(64),
    process_binding_policy_id: "claude-code-v1",
    scope: POLICY_SCOPE,
    max_signatures: 2,
    not_before: new Date(nowMs - 1_000).toISOString(),
    expires_at: new Date(nowMs + 120_000).toISOString(),
    control_sequence: fixture.controlSequence,
    authority_generation: fixture.authorityGeneration,
    issuer: "agentpass-cloud",
    key_id: retiring ? RETIRING_GRANT_KEY_ID : GRANT_KEY_ID
  };
  const grant = retiring
    ? await createLocalAgentSessionGrantSigner({ privateKey: fixture.retiringGrantKeys.privateKey, keyId: RETIRING_GRANT_KEY_ID, now: () => Date.now() }).signAgentSessionGrant(statement)
    : await fixture.grantSigner.signAgentSessionGrant(statement);
  const authority = createAgentSessionAuthorityRepository({
    client: fixture.pool,
    now: () => new Date().toISOString()
  });
  await authority.issueAgentSessionGrant({
    grant,
    issued_at: new Date(nowMs).toISOString(),
    created_by: fixture.ids.member
  });
  return grant;
}

async function consume(fixture, server, grant, { nonce, processBinding = PROCESS_BINDING, path = fixture.pathFor(grant) }) {
  const body = Buffer.from(JSON.stringify({
    grant,
    process_binding_sha256: processBinding,
    ancestry_binding_sha256: ANCESTRY_BINDING
  }));
  const headers = signDeviceRequest({
    method: "POST",
    path,
    body,
    device_id: fixture.ids.device,
    timestamp: Date.now(),
    nonce
  }, fixture.deviceKeys.privateKey);
  headers["content-type"] = "application/json";
  const response = await fetch(`${server.base}${path}`, { method: "POST", headers, body });
  return { response, body: await readJson(response) };
}

function makeAppliedAcknowledgement({ organizationId, deviceId, sequence, statementHash, nonce, observedAt, privateKey }) {
  const unsigned = {
    version: 1,
    type: BUNDLE_ACK_TYPE,
    organization_id: organizationId,
    device_id: deviceId,
    device_key_epoch: 1,
    format_epoch: 2,
    sequence,
    statement_hash: statementHash,
    result: "applied",
    observed_at: observedAt,
    nonce,
    signature_algorithm: "p256-sha256"
  };
  const placeholder = { ...unsigned, signature: Buffer.alloc(64, 1).toString("base64url") };
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const signature = crypto.sign("sha256", bundleAcknowledgementSigningData(placeholder), { key: privateKey, dsaEncoding: "ieee-p1363" });
    if (signature.subarray(32).compare(HALF_ORDER) <= 0) {
      return normalizeBundleAcknowledgement({ ...unsigned, signature: signature.toString("base64url") });
    }
  }
  throw new Error("M2-A2Q could not create a canonical low-S acknowledgement");
}

async function readJson(response) {
  const text = await response.text();
  return text.length === 0 ? null : JSON.parse(text);
}

async function stopServer(server) {
  if (!server?.listening) return;
  let closed = false;
  let closeError;
  const closePromise = new Promise((resolve) => {
    try {
      server.close((error) => {
        closeError = error;
        closed = true;
        resolve();
      });
    } catch (error) {
      closeError = error;
      closed = true;
      resolve();
    }
  });
  await Promise.race([closePromise, delay(2_000)]);
  if (!closed) {
    server.closeAllConnections?.();
    server.closeIdleConnections?.();
    await Promise.race([closePromise, delay(250)]);
  }
  if (!closed) throw new Error("M2-A2Q server close timed out");
  if (closeError && closeError.code !== "ERR_SERVER_NOT_RUNNING") throw closeError;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

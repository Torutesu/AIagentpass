import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  AGENT_SIGNING_CAPABILITY_ALGORITHM,
  AGENT_SIGNING_CAPABILITY_ISSUER,
  AGENT_SIGNING_CAPABILITY_OPERATION,
  AGENT_SIGNING_CAPABILITY_TYPE,
  AGENT_SIGNING_CAPABILITY_VERSION,
  agentSigningCapabilitySigningData,
  agentSigningCapabilityStatementHash,
  normalizeAgentSigningCapabilityStatement
} from "../../src/agent-signing-capability.mjs";
import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { canonicalManagedSignerRequestDigest } from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";
import { createPostgresAgentSessionConsumptionRepository } from "../../src/postgres/agent-session-consumption-repository.mjs";
import { createAgentSessionHumanHttpFixture } from "./agent-session-human-http-fixture.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const { Pool } = DATABASE_URL ? await import("pg") : { Pool: undefined };

const RESERVATION_FUNCTIONS = Object.freeze({
  reserve: "agentpass_agent_signing_capability_reserve",
  commit: "agentpass_agent_signing_capability_commit",
  replay: "agentpass_agent_signing_capability_replay",
  uncertain: "agentpass_agent_signing_capability_uncertain"
});

const PURPOSE = AGENT_SIGNING_CAPABILITY_OPERATION;
const TEST_SIGNING_KEYS = crypto.generateKeyPairSync("ed25519");
const TEST_PUBLIC_KEY_DER = TEST_SIGNING_KEYS.publicKey.export({ type: "spki", format: "der" });
const SCOPE = Object.freeze({
  operations: [AGENT_SIGNING_CAPABILITY_OPERATION],
  repositories: ["/integration/repository"],
  branches: { allow: ["main"], deny: [] },
  remotes: { allow: ["origin"], deny: [] }
});

test("0074 real PostgreSQL migration and function-owned signing capability lifecycle", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run the real PostgreSQL qualification",
  timeout: 120_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  let client;
  t.after(async () => {
    if (client) client.release(true);
    await pool.end();
  });

  client = await pool.connect();
  const migration = await createMigrationRunner({
    client,
    applicationVersion: "agent-session-signing-capability-reservation-integration"
  }).run();
  assert.equal(migration.currentVersion, POSTGRES_SCHEMA_HEAD.version);
  assert.equal(POSTGRES_SCHEMA_HEAD.version, 76);

  const applied = await client.query(
    `SELECT version::int AS version, checksum
       FROM public.schema_migrations
      WHERE version = 74`
  );
  assert.equal(applied.rowCount, 1, "a fresh migration must record 0074 in schema_migrations");
  assert.equal(applied.rows[0].checksum, POSTGRES_SCHEMA_HEAD.migrations.find((entry) => entry.version === 74).checksum);

  const functionRows = await client.query(
    `SELECT p.proname, p.prosecdef, p.provolatile, pg_get_function_identity_arguments(p.oid) AS arguments
       FROM pg_proc AS p
       JOIN pg_namespace AS n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname = ANY($1::text[])
      ORDER BY p.proname`,
    [Object.values(RESERVATION_FUNCTIONS)]
  );
  assert.equal(functionRows.rowCount, 4);
  const expectedArguments = Object.freeze({
    [RESERVATION_FUNCTIONS.reserve]: "p_organization_id uuid, p_device_id uuid, p_session_id uuid, p_request_id uuid, p_request_digest bytea, p_reservation_id uuid, p_capability_id uuid, p_claim_token_hash bytea, p_operation text, p_key_purpose text, p_one_use boolean, p_max_signatures integer, p_ttl_ms bigint",
    [RESERVATION_FUNCTIONS.commit]: "p_organization_id uuid, p_device_id uuid, p_session_id uuid, p_request_id uuid, p_request_digest bytea, p_claim_token_hash bytea",
    [RESERVATION_FUNCTIONS.replay]: "p_organization_id uuid, p_device_id uuid, p_session_id uuid, p_request_id uuid, p_request_digest bytea",
    [RESERVATION_FUNCTIONS.uncertain]: "p_organization_id uuid, p_device_id uuid, p_session_id uuid, p_request_id uuid, p_request_digest bytea, p_claim_token_hash bytea, p_reason text"
  });
  for (const row of functionRows.rows) {
    assert.equal(row.prosecdef, true, `${row.proname} must be SECURITY DEFINER`);
    assert.equal(row.provolatile, "v", `${row.proname} must be volatile and lock state transactionally`);
    assert.equal(row.arguments, expectedArguments[row.proname], `${row.proname} signature drifted from the SQL boundary`);
  }

  await ensureSigningKey(client);

  const firstFixture = await createAgentSessionHumanHttpFixture({
    pool,
    options: { scope: SCOPE }
  });
  const firstGrant = await firstFixture.repository.issueAgentSessionGrant(firstFixture.issueInput({
    idempotency_key: `f2b-first-${firstFixture.ids.organization}`
  }));
  const firstLeaseResult = await consumeGrant({ pool, fixture: firstFixture, grant: firstGrant.grant });
  await activateSession(client, firstFixture.ids.organization, firstLeaseResult.lease.session_id);

  const firstContext = {
    organization_id: firstFixture.ids.organization,
    session_id: firstLeaseResult.lease.session_id,
    device_id: firstFixture.ids.device,
    agent_id: firstFixture.ids.agent,
    grant_id: firstGrant.grant.statement.grant_id
  };

  const first = await issueCapability(client, firstContext, "first");
  assert.equal(first.reserved.state, "reserved");
  assert.equal(first.committed.state, "committed");
  assert.equal(first.committed.capability.statement.session_id, firstContext.session_id);

  const exactReplay = await replay(client, firstContext, first.request_id);
  assert.deepEqual(exactReplay, first.committed, "replay must return the exact committed public envelope");

  const conflicting = await reserve(client, {
    ...firstContext,
    request_id: first.request_id,
    request_digest: digestJson({ request_id: crypto.randomUUID() }),
    reservation_id: crypto.randomUUID(),
    capability_id: crypto.randomUUID(),
    claim_token_hash: digestText(`conflicting-${first.request_id}`)
  });
  assert.deepEqual(conflicting, { state: "conflict" }, "same request_id with a different request must conflict");

  const second = await issueCapability(client, firstContext, "second");
  assert.equal(second.committed.state, "committed");
  assert.notEqual(second.committed.capability.statement.sequence, first.committed.capability.statement.sequence);

  const thirdRequestId = crypto.randomUUID();
  const third = await reserve(client, {
    ...firstContext,
    request_id: thirdRequestId,
    request_digest: digestJson({ request_id: thirdRequestId }),
    reservation_id: crypto.randomUUID(),
    capability_id: crypto.randomUUID(),
    claim_token_hash: digestText("third-denied")
  });
  assert.deepEqual(third, { state: "absent" }, "a two-signature session must deny a third issuance");
  const afterThird = await client.query(
    "SELECT status, used_signatures, reserved_signatures FROM public.agent_sessions WHERE organization_id=$1 AND session_id=$2",
    [firstContext.organization_id, firstContext.session_id]
  );
  assert.deepEqual(afterThird.rows[0], { status: "signed", used_signatures: 2, reserved_signatures: 0 });

  const attributed = await client.query(
    `SELECT issuer, issued_by_session_id, organization_id, agent_id, device_id, statement_hash
       FROM public.capabilities
      WHERE organization_id=$1 AND id=$2`,
    [firstContext.organization_id, first.committed.capability.statement.capability_id]
  );
  assert.equal(attributed.rowCount, 1);
  assert.equal(attributed.rows[0].issuer, AGENT_SIGNING_CAPABILITY_ISSUER);
  assert.equal(attributed.rows[0].issued_by_session_id, firstContext.session_id);
  assert.equal(attributed.rows[0].organization_id, firstContext.organization_id);
  assert.equal(attributed.rows[0].agent_id, firstContext.agent_id);
  assert.equal(attributed.rows[0].device_id, firstContext.device_id);
  assert.equal(attributed.rows[0].statement_hash, first.committed.capability.statement_hash);

  const secondFixture = await createAgentSessionHumanHttpFixture({
    pool,
    options: { scope: SCOPE }
  });
  const secondGrant = await secondFixture.repository.issueAgentSessionGrant(secondFixture.issueInput({
    idempotency_key: `f2b-uncertain-${secondFixture.ids.organization}`
  }));
  const secondLeaseResult = await consumeGrant({ pool, fixture: secondFixture, grant: secondGrant.grant });
  await activateSession(client, secondFixture.ids.organization, secondLeaseResult.lease.session_id);
  const uncertainContext = {
    organization_id: secondFixture.ids.organization,
    session_id: secondLeaseResult.lease.session_id,
    device_id: secondFixture.ids.device,
    agent_id: secondFixture.ids.agent,
    grant_id: secondGrant.grant.statement.grant_id
  };
  const uncertainRequestId = crypto.randomUUID();
  const uncertainClaimTokenHash = digestText(`uncertain-${uncertainRequestId}`);
  const uncertainReservation = await reserve(client, {
    ...uncertainContext,
    request_id: uncertainRequestId,
    request_digest: digestJson({ request_id: uncertainRequestId }),
    reservation_id: crypto.randomUUID(),
    capability_id: crypto.randomUUID(),
    claim_token_hash: uncertainClaimTokenHash
  });
  assert.equal(uncertainReservation.state, "reserved");
  const uncertain = await callUncertain(client, uncertainContext, uncertainRequestId, uncertainClaimTokenHash);
  assert.deepEqual(uncertain, { state: "uncertain" });
  assert.deepEqual(
    await replay(client, uncertainContext, uncertainRequestId),
    { state: "uncertain" },
    "uncertainty must be terminal until an explicit provider reconciliation exists"
  );

  const crossTenantRequestId = crypto.randomUUID();
  const crossTenant = await reserve(client, {
    ...firstContext,
    organization_id: crypto.randomUUID(),
    request_id: crossTenantRequestId,
    request_digest: digestJson({ request_id: crossTenantRequestId }),
    reservation_id: crypto.randomUUID(),
    capability_id: crypto.randomUUID(),
    claim_token_hash: digestText("cross-tenant")
  });
  assert.deepEqual(crossTenant, { state: "absent" }, "a session from another organization must not be addressable");

  await assertFunctionPrivileges(client);
});

async function ensureSigningKey(client) {
  const existing = await client.query(
    `SELECT key_id
       FROM public.managed_signer_keys
      WHERE purpose=$1 AND state='active'
      LIMIT 1`,
    [PURPOSE]
  );
  if (existing.rowCount === 1) return existing.rows[0].key_id;

  const keyId = `f2b-integration-${crypto.randomBytes(8).toString("hex")}`;
  await client.query("BEGIN");
  try {
    await client.query(
      `INSERT INTO public.managed_signer_key_lifecycles (purpose, algorithm, version)
       VALUES ($1,'ed25519',1)
       ON CONFLICT (purpose) DO NOTHING`,
      [PURPOSE]
    );
    await client.query(
      `INSERT INTO public.managed_signer_keys
        (purpose,key_id,key_version,algorithm,public_key_fingerprint,state,state_version,key_position)
       VALUES ($1,$2,1,'ed25519',$3,'active',1,0)`,
      [PURPOSE, keyId, digestBytes(TEST_PUBLIC_KEY_DER)]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
  return keyId;
}

async function consumeGrant({ pool, fixture, grant }) {
  const consumption = createPostgresAgentSessionConsumptionRepository({ client: pool });
  return consumption.consumeAgentSessionGrant({
    organization_id: fixture.ids.organization,
    device_id: fixture.ids.device,
    grant_id: grant.statement.grant_id,
    grant,
    process_binding_sha256: "c".repeat(64),
    ancestry_binding_sha256: "d".repeat(64)
  });
}

async function activateSession(client, organizationId, sessionId) {
  await client.query("BEGIN");
  try {
    await client.query("SELECT set_config('agentpass.organization_id',$1,true)", [organizationId]);
    const result = await client.query(
      `UPDATE public.agent_sessions
          SET status='active'
        WHERE organization_id=$1 AND session_id=$2 AND status='challenge_pending'`,
      [organizationId, sessionId]
    );
    assert.equal(result.rowCount, 1);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

async function issueCapability(client, context, label) {
  const request_id = crypto.randomUUID();
  const request_digest = digestJson({ request_id });
  const reservation_id = crypto.randomUUID();
  const capability_id = crypto.randomUUID();
  const claim_token = `${label}-${crypto.randomBytes(30).toString("base64url")}`;
  const claim_token_hash = digestText(claim_token);
  const reserved = await reserve(client, {
    ...context, request_id, request_digest, reservation_id, capability_id, claim_token_hash
  });
  assert.equal(reserved.state, "reserved");

  const metadata = await client.query(
    `SELECT key_id, key_version, algorithm, planned_provider_operation_id,
            provider_request_digest, provider_bytes_length
       FROM public.agent_session_signing_capability_reservations
      WHERE organization_id=$1 AND reservation_id=$2`,
    [context.organization_id, reservation_id]
  );
  assert.equal(metadata.rowCount, 1);
  const statement = normalizeAgentSigningCapabilityStatement({
    version: AGENT_SIGNING_CAPABILITY_VERSION,
    type: AGENT_SIGNING_CAPABILITY_TYPE,
    capability_id,
    organization_id: context.organization_id,
    session_id: context.session_id,
    device_id: context.device_id,
    agent_id: context.agent_id,
    one_use: true,
    operation: AGENT_SIGNING_CAPABILITY_OPERATION,
    scope: reserved.scope,
    key_purpose: AGENT_SIGNING_CAPABILITY_OPERATION,
    key_id: metadata.rows[0].key_id,
    algorithm: metadata.rows[0].algorithm,
    max_signatures: 1,
    issued_at: reserved.issued_at,
    not_before: reserved.not_before,
    expires_at: reserved.expires_at,
    sequence: Number(reserved.sequence),
    control_sequence: Number(reserved.control_sequence),
    authority_generation: Number(reserved.authority_generation),
    issuer: AGENT_SIGNING_CAPABILITY_ISSUER
  });
  const signingData = agentSigningCapabilitySigningData(statement);
  const signatureBytes = crypto.sign(null, signingData, TEST_SIGNING_KEYS.privateKey);
  assert.equal(crypto.verify(null, signingData, TEST_SIGNING_KEYS.publicKey, signatureBytes), true);
  const signature = signatureBytes.toString("base64url");
  const providerRequestDigest = canonicalManagedSignerRequestDigest({
    algorithm: metadata.rows[0].algorithm,
    bytes: signingData,
    key_id: metadata.rows[0].key_id,
    key_version: Number(metadata.rows[0].key_version),
    purpose: PURPOSE,
    version: 1
  });
  assert.equal(metadata.rows[0].provider_request_digest.toString("hex"), providerRequestDigest);
  assert.equal(metadata.rows[0].planned_provider_operation_id, `managed-signer-v1-${providerRequestDigest}`);
  assert.equal(Number(metadata.rows[0].provider_bytes_length), signingData.length);
  const capability = {
    version: AGENT_SIGNING_CAPABILITY_VERSION,
    type: AGENT_SIGNING_CAPABILITY_TYPE,
    statement,
    statement_hash: agentSigningCapabilityStatementHash(statement),
    signature
  };
  await client.query(
    `INSERT INTO public.managed_signer_provider_operations
      (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,
       state,provider_started_at,signature,public_key_der,provider_receipt_provider,
       provider_receipt_id,expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'committed',clock_timestamp(),$8,$9,
       'agentpass-test','f2b-integration',clock_timestamp() + interval '1 day')`,
    [PURPOSE, metadata.rows[0].planned_provider_operation_id, metadata.rows[0].algorithm,
      metadata.rows[0].provider_bytes_length, metadata.rows[0].provider_request_digest,
      metadata.rows[0].key_id, metadata.rows[0].key_version, signatureBytes, TEST_PUBLIC_KEY_DER]
  );
  const committed = await callCommit(client, context, request_id, request_digest, claim_token_hash);
  return { request_id, claim_token_hash, reserved, capability, committed };
}

async function reserve(client, input) {
  const request_id = input.request_id;
  const request_digest = input.request_digest ?? digestJson({ request_id });
  const claim_token_hash = input.claim_token_hash ?? digestText(`claim-${request_id}`);
  return call(client, RESERVATION_FUNCTIONS.reserve, [
    input.organization_id, input.device_id, input.session_id, request_id,
    request_digest, input.reservation_id, input.capability_id, claim_token_hash,
    PURPOSE, PURPOSE, true, 1, 300_000
  ]);
}

async function callCommit(client, context, request_id, request_digest, claim_token_hash) {
  return call(client, RESERVATION_FUNCTIONS.commit, [
    context.organization_id, context.device_id, context.session_id, request_id,
    request_digest, claim_token_hash
  ]);
}

async function replay(client, context, request_id) {
  return call(client, RESERVATION_FUNCTIONS.replay, [
    context.organization_id, context.device_id, context.session_id, request_id,
    digestJson({ request_id })
  ]);
}

async function callUncertain(client, context, request_id, claim_token_hash) {
  return call(client, RESERVATION_FUNCTIONS.uncertain, [
    context.organization_id, context.device_id, context.session_id, request_id,
    digestJson({ request_id }), claim_token_hash, "commit_response_lost"
  ]);
}

async function call(client, functionName, values) {
  const casts = values.map((_, index) => `$${index + 1}`).join(",");
  await client.query("BEGIN");
  try {
    await client.query("SELECT set_config('agentpass.organization_id',$1,true)", [values[0]]);
    const result = await client.query(`SELECT public.${functionName}(${casts}) AS result`, values);
    assert.equal(result.rowCount, 1, `${functionName} must return one jsonb result`);
    await client.query("COMMIT");
    return result.rows[0].result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

async function assertFunctionPrivileges(client) {
  const roles = await client.query(
    `SELECT rolname FROM pg_roles WHERE rolname IN ('agentpass_app','agentpass_signer') ORDER BY rolname`
  );
  const roleNames = new Set(roles.rows.map((row) => row.rolname));
  const privilegeRows = await client.query(
    `SELECT p.proname, p.oid,
            has_function_privilege(current_user,p.oid,'EXECUTE') AS owner_or_current_execute
       FROM pg_proc AS p
       JOIN pg_namespace AS n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND p.proname=ANY($1::text[])`,
    [Object.values(RESERVATION_FUNCTIONS)]
  );
  assert.equal(privilegeRows.rowCount, 4);
  assert.ok(privilegeRows.rows.every((row) => row.owner_or_current_execute));

  if (roleNames.has("agentpass_app")) {
    const appRows = await client.query(
      `SELECT p.proname,
              has_function_privilege('agentpass_app',p.oid,'EXECUTE') AS can_execute,
              has_table_privilege('agentpass_app','public.agent_session_signing_capability_reservations','SELECT,INSERT,UPDATE,DELETE') AS can_write
         FROM pg_proc AS p
         JOIN pg_namespace AS n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND p.proname=ANY($1::text[])`,
      [Object.values(RESERVATION_FUNCTIONS)]
    );
    assert.equal(appRows.rowCount, 4);
    assert.ok(appRows.rows.every((row) => row.can_execute));
    assert.ok(appRows.rows.every((row) => !row.can_write));
  }
  if (roleNames.has("agentpass_signer")) {
    const signerRows = await client.query(
      `SELECT p.proname, has_function_privilege('agentpass_signer',p.oid,'EXECUTE') AS can_execute
         FROM pg_proc AS p
         JOIN pg_namespace AS n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND p.proname=ANY($1::text[])`,
      [Object.values(RESERVATION_FUNCTIONS)]
    );
    assert.equal(signerRows.rowCount, 4);
    assert.ok(signerRows.rows.every((row) => !row.can_execute));
  }
}

function digestJson(value) { return digestText(canonicalJson(value)); }
function digestText(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function digestBytes(value) { return crypto.createHash("sha256").update(value).digest(); }

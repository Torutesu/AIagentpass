import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const { Pool } = DATABASE_URL ? await import("pg") : { Pool: undefined };

const OPERATION = "platform.promotion.issue";
const PURPOSE = "agentpass.promotion-evidence";
const ATOMIC_SQL = `SELECT public.agentpass_consume_platform_authorization_and_reserve(
  $1::bytea,$2::bytea,$3::uuid,$4::bytea,$5::bytea,$6::uuid,$7::text,$8::text,$9::text,$10::text,$11::bytea,
  30000,600000,NULL::text,NULL::bigint,NULL::bigint) AS result`;

function digest(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest();
}

function deterministicUuid(namespace, label) {
  const bytes = digest(`${namespace}:${label}`).subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function makeFixture() {
  const worker = process.env.NODE_UNIQUE_ID ?? process.env.TEST_WORKER_INDEX ?? "0";
  const namespace = process.env.AGENTPASS_TEST_NAMESPACE ?? `platform-authorization:${process.pid}:${worker}`;
  const id = (label) => deterministicUuid(namespace, label);
  const bytes = (label) => digest(`${namespace}:${label}`);
  const short = digest(namespace).toString("hex").slice(0, 24);
  const packageDigest = bytes("candidate-package").toString("hex");

  return {
    namespace,
    id,
    bytes,
    short,
    organizationId: id("organization"),
    wrongOrganizationId: id("wrong-organization"),
    memberId: id("member"),
    principalId: id("principal"),
    assignmentId: id("assignment"),
    deploymentId: `n3c-${short}`,
    candidateId: `release-pkg-sha256-v1-${packageDigest}`,
    sourceCommit: bytes("source-commit").toString("hex").slice(0, 40),
    sourceTree: bytes("source-tree").toString("hex").slice(0, 40),
    packageDigest,
    imageDigest: `sha256:${bytes("image").toString("hex")}`,
    sbomDigest: bytes("sbom").toString("hex"),
    manifestDigest: bytes("manifest").toString("hex"),
    reportDigest: bytes("qualification-report").toString("hex"),
    approvalDigest: bytes("authorization-evidence").toString("hex"),
    webauthnId: bytes("webauthn-id"),
    webauthnPublicKey: bytes("webauthn-public-key"),
    purpose: PURPOSE,
    keyId: `n3c-key-${short}`,
    publicKeyDer: Buffer.alloc(44, 0x48),
  };
}

async function result(client, sql, values) {
  return (await client.query(sql, values)).rows[0]?.result;
}

async function withTransaction(client, callback) {
  await client.query("BEGIN");
  try {
    const value = await callback();
    await client.query("COMMIT");
    return value;
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch { /* preserve the original failure */ }
    throw error;
  }
}

async function ensurePromotionSigner(client, fixture) {
  let active = await client.query(`SELECT lifecycle.version AS lifecycle_version,
      key.key_id, key.key_version, key.public_key_fingerprint
    FROM managed_signer_key_lifecycles AS lifecycle
    JOIN managed_signer_keys AS key
      ON key.purpose = lifecycle.purpose
     AND key.state = 'active'
     AND key.algorithm = 'ed25519'
     AND key.state_version = lifecycle.version
    WHERE lifecycle.purpose = $1`, [fixture.purpose]);
  if (active.rowCount > 0) return active.rows[0];

  const lifecycle = await client.query(`SELECT purpose, version, max_keys
    FROM managed_signer_key_lifecycles WHERE purpose=$1 FOR UPDATE`, [fixture.purpose]);
  if (lifecycle.rowCount === 0) {
    await client.query(`INSERT INTO managed_signer_key_lifecycles
      (purpose,algorithm,version) VALUES ($1,'ed25519',1)`, [fixture.purpose]);
  }
  const current = (await client.query(`SELECT purpose, version, max_keys
    FROM managed_signer_key_lifecycles WHERE purpose=$1 FOR UPDATE`, [fixture.purpose])).rows[0];
  const nextPosition = Number((await client.query(`SELECT COALESCE(max(key_position), -1) + 1 AS position
    FROM managed_signer_keys WHERE purpose=$1`, [fixture.purpose])).rows[0].position);
  assert.ok(nextPosition < current.max_keys, "promotion signer has no available key position");

  await client.query(`INSERT INTO managed_signer_keys
    (purpose,key_id,key_version,algorithm,public_key_fingerprint,state,state_version,key_position)
    VALUES ($1,$2,$3,'ed25519',$4,'active',$3,$5)`, [
    fixture.purpose,
    fixture.keyId,
    current.version,
    digest(fixture.publicKeyDer.toString("hex")),
    nextPosition,
  ]);
  active = await client.query(`SELECT lifecycle.version AS lifecycle_version,
      key.key_id, key.key_version, key.public_key_fingerprint
    FROM managed_signer_key_lifecycles AS lifecycle
    JOIN managed_signer_keys AS key
      ON key.purpose = lifecycle.purpose
     AND key.state = 'active'
     AND key.algorithm = 'ed25519'
     AND key.state_version = lifecycle.version
    WHERE lifecycle.purpose = $1`, [fixture.purpose]);
  assert.equal(active.rowCount, 1);
  return active.rows[0];
}

async function seedFixture(client, fixture) {
  await withTransaction(client, async () => {
    // Serialize only the global signer fallback. All other fixture identities
    // are namespace-scoped and can be created in parallel test processes.
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", ["agentpass:test:promotion-signer"]);
    await client.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [fixture.organizationId, `N3c ${fixture.short}`]);
    await client.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [fixture.wrongOrganizationId, `N3c wrong ${fixture.short}`]);
    await client.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [fixture.memberId, `n3c:${fixture.short}`, "N3c"]);
    await client.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [fixture.organizationId, fixture.id("membership"), fixture.memberId]);
    await client.query(`INSERT INTO webauthn_credentials
      (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state)
      VALUES ($1,$2,$3,0,ARRAY['internal']::text[],'N3c credential',false,false)`, [fixture.webauthnId, fixture.memberId, fixture.webauthnPublicKey]);
    await client.query("INSERT INTO platform_principals (principal_id,member_id,status) VALUES ($1,$2,'active')", [fixture.principalId, fixture.memberId]);
    await client.query(`INSERT INTO platform_operator_assignments
      (assignment_id,principal_id,member_id,organization_id,operation,capability,status,request_digest,requested_authority_generation,requested_at,issued_at,expires_at,activated_at)
      VALUES ($1,$2,$3,$4,$5,$5,'active',$6,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '10 minutes',clock_timestamp())`, [
      fixture.assignmentId,
      fixture.principalId,
      fixture.memberId,
      fixture.organizationId,
      OPERATION,
      digest(`${fixture.namespace}:assignment`),
    ]);
    await client.query(`INSERT INTO platform_credentials
      (credential_id,principal_id,member_id,webauthn_credential_id,label,status,backup_eligible,backup_state)
      VALUES ($1,$2,$3,$4,'N3c credential','active',false,false)`, [fixture.id("platform-credential"), fixture.principalId, fixture.memberId, fixture.webauthnId]);
    await client.query(`INSERT INTO release_candidates
      (candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id)
      VALUES ($1,$2,$3,$4,'C3TEST0001')`, [fixture.candidateId, fixture.sourceCommit, fixture.packageDigest, fixture.manifestDigest]);
    const signer = await ensurePromotionSigner(client, fixture);
    const approval = await client.query(`INSERT INTO platform_promotion_approvals
      (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
       product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,release_manifest_schema_version,
       release_manifest_sha256,policy_id,policy_version,approval_version,decision,platform_principal_ids,
       authorization_evidence_digests,approved_at,expires_at)
      VALUES (1,'agentpass.platform-promotion-approval',$1,$2,'staging',$3,$4,$5,$6,$7,$8,ARRAY[$9]::text[],4,$10,
       'n3c-policy',1,1,'approved',ARRAY['n3c-principal']::text[],ARRAY[$11]::text[],clock_timestamp(),clock_timestamp()+interval '10 minutes')
      RETURNING approval_id,record_digest`, [
      fixture.id("approval"),
      fixture.deploymentId,
      fixture.candidateId,
      fixture.sourceCommit,
      fixture.sourceTree,
      fixture.packageDigest,
      fixture.imageDigest,
      fixture.sbomDigest,
      fixture.reportDigest,
      fixture.manifestDigest,
      fixture.approvalDigest,
    ]);
    assert.equal(approval.rowCount, 1);
    fixture.approvalId = approval.rows[0].approval_id;
    fixture.approvalRecordDigest = approval.rows[0].record_digest;
    fixture.signer = signer;
  });
}

async function prepareAuthorization(client, fixture, label, intent) {
  const authorization = {
    sessionId: fixture.id(`${label}:session`),
    sessionMaterialHash: fixture.bytes(`${label}:session-material`),
    csrfHash: fixture.bytes(`${label}:csrf`),
    challengeId: fixture.id(`${label}:challenge`),
    jtiHash: fixture.bytes(`${label}:jti`),
    challengeHash: fixture.bytes(`${label}:challenge-material`),
    bindingHash: fixture.bytes(`${label}:binding`),
    claimTokenDigest: fixture.bytes(`${label}:claim-token`),
  };
  authorization.requestDigest = await result(client,
    "SELECT public.agentpass_platform_authorization_request_digest($1,$2::uuid,$3::uuid,$4,$5,$6,$7) AS result",
    [OPERATION, fixture.organizationId, intent.promotionId, intent.deploymentId, intent.environment, intent.candidateId, intent.idempotencyKey]
  );
  assert.equal(authorization.requestDigest.length, 32);

  const challenge = await result(client, `SELECT public.agentpass_platform_session_challenge_create(
    $1::uuid,$2::uuid,$3::bytea,$4::bytea,$5::bytea,$6::bytea,ARRAY[$7::bytea],$8::uuid,$9::uuid,$10::uuid,$11::uuid,$12::bigint,
    $13::text,$14::text,'console.agentpass.test','https://console.agentpass.test/','required',120000) AS result`, [
    authorization.challengeId,
    authorization.sessionId,
    authorization.jtiHash,
    authorization.challengeHash,
    authorization.bindingHash,
    authorization.requestDigest,
    fixture.webauthnId,
    fixture.principalId,
    fixture.memberId,
    fixture.organizationId,
    fixture.assignmentId,
    1,
    OPERATION,
    OPERATION,
  ]);
  assert.equal(challenge.status, "pending");
  const claimed = await result(client, `SELECT public.agentpass_platform_session_challenge_claim(
    $1::uuid,$2::bytea,$3::bytea,$4::bytea,$5::bytea) AS result`, [
    authorization.challengeId,
    authorization.jtiHash,
    authorization.challengeHash,
    authorization.bindingHash,
    authorization.requestDigest,
  ]);
  assert.equal(claimed.claimed, true);
  const issued = await result(client, `SELECT public.agentpass_platform_session_complete_and_issue(
    $1::uuid,$2::bytea,$3::bytea,$4::uuid,$5::bytea,$6::bytea,$7::bytea,$8::bytea,$9::bytea,900,300) AS result`, [
    authorization.sessionId,
    authorization.sessionMaterialHash,
    authorization.csrfHash,
    authorization.challengeId,
    authorization.jtiHash,
    authorization.challengeHash,
    authorization.bindingHash,
    authorization.requestDigest,
    fixture.webauthnId,
  ]);
  assert.equal(issued.challenge.outcome, "completed");
  assert.equal(issued.session.session_id, authorization.sessionId);
  return authorization;
}

function atomicParams(authorization, intent, overrides = {}) {
  return [
    overrides.sessionMaterialHash ?? authorization.sessionMaterialHash,
    overrides.csrfHash ?? authorization.csrfHash,
    overrides.proofId ?? authorization.challengeId,
    overrides.jtiHash ?? authorization.jtiHash,
    overrides.requestDigest ?? authorization.requestDigest,
    intent.promotionId,
    intent.deploymentId,
    intent.environment,
    intent.candidateId,
    intent.idempotencyKey,
    overrides.claimTokenDigest ?? authorization.claimTokenDigest,
  ];
}

async function runWithAdvisoryBarrier(clients, barrierName, operation) {
  const keys = clients.map((_, index) => `${barrierName}:ready:${index}`);
  await Promise.all(clients.map((client, index) => client.query(
    "SELECT pg_advisory_lock(hashtextextended($1, 0)) AS ready",
    [keys[index]]
  )));
  try {
    return await Promise.all(clients.map((client, index) => operation(client, index)));
  } finally {
    await Promise.allSettled(clients.map((client, index) => client.query(
      "SELECT pg_advisory_unlock(hashtextextended($1, 0)) AS released",
      [keys[index]]
    )));
  }
}

async function expectSqlState(operation, code, forbiddenValues = []) {
  await assert.rejects(operation, (error) => {
    assert.equal(error?.code, code);
    for (const value of forbiddenValues) assert.equal(String(error?.message ?? "").includes(value), false);
    return true;
  });
}

test("0054 real PostgreSQL authorization concurrency and denial matrix", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run the real PostgreSQL lane",
  timeout: 60_000,
}, async (t) => {
  const fixture = makeFixture();
  const poolA = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const poolB = new Pool({ connectionString: DATABASE_URL, max: 4 });
  const authorizations = [];
  t.after(async () => {
    try {
      for (const authorization of authorizations) {
        await poolA.query(`SELECT public.agentpass_platform_session_revoke(
          $1::bytea,$2::bytea,'s1 qualification cleanup') AS result`, [
          authorization.sessionMaterialHash,
          authorization.csrfHash,
        ]);
      }
    } finally {
      await Promise.all([poolA.end(), poolB.end()]);
    }
  });

  const migrationClient = await poolA.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrationClient, applicationVersion: "platform-authorization-s1-concurrency" }).run();
    assert.equal(migrated.currentVersion, 55);
  } finally {
    migrationClient.release();
  }

  const setupClient = await poolA.connect();
  try {
    await seedFixture(setupClient, fixture);
    const firstIntent = {
      promotionId: fixture.id("promotion-primary"),
      deploymentId: fixture.deploymentId,
      environment: "staging",
      candidateId: fixture.candidateId,
      idempotencyKey: `idem-${fixture.short}-primary`,
    };
    const conflictIntent = {
      ...firstIntent,
      promotionId: fixture.id("promotion-conflict"),
    };
    const secondIdempotencyIntent = {
      ...firstIntent,
      idempotencyKey: `idem-${fixture.short}-second`,
    };
    const primary = await prepareAuthorization(setupClient, fixture, "primary", firstIntent);
    authorizations.push(primary);
    const conflict = await prepareAuthorization(setupClient, fixture, "conflict", conflictIntent);
    authorizations.push(conflict);

    const concurrentClients = [await poolA.connect(), await poolB.connect()];
    try {
      const backendPids = await Promise.all(concurrentClients.map(async (client) => (
        (await client.query("SELECT pg_backend_pid() AS pid")).rows[0].pid
      )));
      assert.notEqual(backendPids[0], backendPids[1], "concurrency calls must use distinct PostgreSQL connections");
      const concurrentResults = await runWithAdvisoryBarrier(
        concurrentClients,
        `${fixture.namespace}:identical-authorization`,
        (client) => client.query(ATOMIC_SQL, atomicParams(primary, firstIntent)).then((queryResult) => queryResult.rows[0].result)
      );
      assert.deepEqual(new Set(concurrentResults.map((entry) => entry.state)), new Set(["reserved"]));
      assert.equal(concurrentResults.filter((entry) => entry.claim_issued === true).length, 1);
      assert.equal(concurrentResults.filter((entry) => entry.claim_issued === false).length, 1);
      assert.equal(new Set(concurrentResults.map((entry) => entry.promotion_id)).size, 1);
      assert.equal(concurrentResults[0].promotion_id, firstIntent.promotionId);
    } finally {
      concurrentClients.forEach((client) => client.release());
    }

    const durable = await poolA.query(`SELECT promotion_id, deployment_id, environment, candidate_id,
        idempotency_key, state, claim_token_digest IS NOT NULL AS has_claim
      FROM platform_promotion_issuances
      WHERE promotion_id=$1`, [firstIntent.promotionId]);
    assert.equal(durable.rowCount, 1, "identical authorization calls must converge to one reservation row");
    assert.deepEqual(durable.rows[0], {
      promotion_id: firstIntent.promotionId,
      deployment_id: firstIntent.deploymentId,
      environment: firstIntent.environment,
      candidate_id: firstIntent.candidateId,
      idempotency_key: firstIntent.idempotencyKey,
      state: "reserved",
      has_claim: true,
    });
    const durableCount = await poolA.query(`SELECT count(*)::integer AS count
      FROM platform_promotion_issuances
      WHERE deployment_id=$1 AND environment=$2 AND candidate_id=$3 AND idempotency_key=$4`, [
      firstIntent.deploymentId,
      firstIntent.environment,
      firstIntent.candidateId,
      firstIntent.idempotencyKey,
    ]);
    assert.equal(durableCount.rows[0].count, 1);

    await expectSqlState(
      () => poolB.query(ATOMIC_SQL, atomicParams(conflict, conflictIntent)),
      "23505",
      [conflict.claimTokenDigest.toString("hex"), conflict.jtiHash.toString("hex")],
    );

    const secondDigest = await result(setupClient,
      "SELECT public.agentpass_platform_authorization_request_digest($1,$2::uuid,$3::uuid,$4,$5,$6,$7) AS result",
      [OPERATION, fixture.organizationId, secondIdempotencyIntent.promotionId, secondIdempotencyIntent.deploymentId,
        secondIdempotencyIntent.environment, secondIdempotencyIntent.candidateId, secondIdempotencyIntent.idempotencyKey]
    );
    await expectSqlState(
      () => poolB.query(ATOMIC_SQL, atomicParams(primary, secondIdempotencyIntent, { requestDigest: secondDigest })),
      "40001",
      [primary.jtiHash.toString("hex"), secondIdempotencyIntent.idempotencyKey],
    );

    const wrongOrganizationDigest = await result(setupClient,
      "SELECT public.agentpass_platform_authorization_request_digest($1,$2::uuid,$3::uuid,$4,$5,$6,$7) AS result",
      [OPERATION, fixture.wrongOrganizationId, firstIntent.promotionId, firstIntent.deploymentId,
        firstIntent.environment, firstIntent.candidateId, firstIntent.idempotencyKey]
    );
    await expectSqlState(
      () => poolB.query(ATOMIC_SQL, atomicParams(primary, firstIntent, { requestDigest: wrongOrganizationDigest })),
      "23000",
      [fixture.wrongOrganizationId, wrongOrganizationDigest.toString("hex")],
    );

    await expectSqlState(
      () => poolB.query(ATOMIC_SQL, atomicParams(primary, firstIntent, { csrfHash: fixture.bytes("wrong-csrf") })),
      "42501",
      [fixture.bytes("wrong-csrf").toString("hex"), primary.sessionMaterialHash.toString("hex")],
    );

    const proof = await poolA.query(`SELECT status, consumed_promotion_id, consumed_idempotency_key
      FROM platform_authorization_proofs WHERE proof_id=$1`, [primary.challengeId]);
    assert.deepEqual(proof.rows[0], {
      status: "consumed",
      consumed_promotion_id: firstIntent.promotionId,
      consumed_idempotency_key: firstIntent.idempotencyKey,
    });
  } finally {
    setupClient.release();
  }
});

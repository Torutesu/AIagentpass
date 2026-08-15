import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const { Pool } = DATABASE_URL ? await import("pg") : { Pool: undefined };

const OPERATION = "platform.promotion.issue";

function digest(text) { return crypto.createHash("sha256").update(text, "utf8").digest(); }
function uuid() { return crypto.randomUUID(); }
async function result(client, sql, values) { return (await client.query(sql, values)).rows[0]?.result; }

test("0054 real PostgreSQL binds the ceremony, CSRF, request, proof, and atomic promotion", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run the real PostgreSQL lane",
  timeout: 60_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 4 });
  t.after(() => pool.end());
  const migrator = await pool.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrator, applicationVersion: "platform-authorization-0054" }).run();
    assert.equal(migrated.currentVersion, 55);
  } finally {
    migrator.release();
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const suffix = uuid().replaceAll("-", "");
    const organizationId = uuid();
    const memberId = uuid();
    const principalId = uuid();
    const assignmentId = uuid();
    const challengeId = uuid();
    const platformSessionId = uuid();
    const promotionId = uuid();
    const webauthnId = Buffer.alloc(32, 0x41);
    const bearerHash = Buffer.alloc(32, 0x42);
    const csrfHash = Buffer.alloc(32, 0x43);
    const jtiHash = Buffer.alloc(32, 0x44);
    const challengeHash = Buffer.alloc(32, 0x45);
    const bindingHash = Buffer.alloc(32, 0x46);
    const claimHash = Buffer.alloc(32, 0x47);
    const requestDigest = await result(client,
      "SELECT public.agentpass_platform_authorization_request_digest($1,$2::uuid,$3::uuid,$4,$5,$6,$7) AS result",
      [OPERATION, organizationId, promotionId, `n3c-${suffix}`, "staging", `release-pkg-sha256-v1-${"aa".repeat(32)}`, `request-${suffix}`]
    );
    const deploymentId = `n3c-${suffix}`;
    const candidateId = `release-pkg-sha256-v1-${"aa".repeat(32)}`;
    const sourceCommit = "ab".repeat(20);
    const sourceTree = "cd".repeat(20);
    const packageDigest = "aa".repeat(32);
    const imageDigest = `sha256:${"bb".repeat(32)}`;
    const sbomDigest = "cc".repeat(32);
    const manifestDigest = "dd".repeat(32);
    const reportDigest = "ee".repeat(32);
    const approvalDigest = "ff".repeat(32);
    const keyId = `n3c-key-${suffix}`;
    const publicKeyDer = Buffer.alloc(44, 0x48);
    const publicKeyFingerprint = digest(publicKeyDer.toString("hex"));

    await client.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, `N3c ${suffix}`]);
    await client.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [memberId, `n3c:${suffix}`, "N3c"]);
    await client.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, uuid(), memberId]);
    await client.query(`INSERT INTO webauthn_credentials
      (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state)
      VALUES ($1,$2,$3,0,ARRAY['internal']::text[],'N3c credential',false,false)`, [webauthnId, memberId, Buffer.alloc(32, 0x49)]);
    await client.query("INSERT INTO platform_principals (principal_id,member_id,status) VALUES ($1,$2,'active')", [principalId, memberId]);
    await client.query(`INSERT INTO platform_operator_assignments
      (assignment_id,principal_id,member_id,organization_id,operation,capability,status,request_digest,requested_authority_generation,requested_at,issued_at,expires_at,activated_at)
      VALUES ($1,$2,$3,$4,$5,$5,'active',$6,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '10 minutes',clock_timestamp())`,
    [assignmentId, principalId, memberId, organizationId, OPERATION, digest(`assignment:${suffix}`)]);
    await client.query(`INSERT INTO platform_credentials
      (credential_id,principal_id,member_id,webauthn_credential_id,label,status,backup_eligible,backup_state)
      VALUES ($1,$2,$3,$4,'N3c credential','active',false,false)`, [uuid(), principalId, memberId, webauthnId]);
    const platformCredentialId = (await client.query(
      "SELECT credential_id FROM platform_credentials WHERE webauthn_credential_id=$1", [webauthnId]
    )).rows[0].credential_id;

    await client.query(`INSERT INTO release_candidates
      (candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id)
      VALUES ($1,$2,$3,$4,'C3TEST0001')`, [candidateId, sourceCommit, packageDigest, manifestDigest]);
    await client.query(`INSERT INTO managed_signer_key_lifecycles (purpose,algorithm,version)
      VALUES ('agentpass.promotion-evidence','ed25519',1)`);
    await client.query(`INSERT INTO managed_signer_keys
      (purpose,key_id,key_version,algorithm,public_key_fingerprint,state,state_version,key_position)
      VALUES ('agentpass.promotion-evidence',$1,1,'ed25519',$2,'active',1,0)`, [keyId, publicKeyFingerprint]);
    await client.query(`INSERT INTO platform_promotion_approvals
      (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
       product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,release_manifest_schema_version,
       release_manifest_sha256,policy_id,policy_version,approval_version,decision,platform_principal_ids,
       authorization_evidence_digests,approved_at,expires_at)
      VALUES (1,'agentpass.platform-promotion-approval',$1,$2,'staging',$3,$4,$5,$6,$7,$8,ARRAY[$9]::text[],4,$10,
       'n3c-policy',1,1,'approved',ARRAY['n3c-principal']::text[],ARRAY[$11]::text[],clock_timestamp(),clock_timestamp()+interval '10 minutes')`,
    [uuid(), deploymentId, candidateId, sourceCommit, sourceTree, packageDigest, imageDigest, sbomDigest, reportDigest, manifestDigest, approvalDigest]);

    const challenge = await result(client, `SELECT public.agentpass_platform_session_challenge_create(
      $1::uuid,$2::uuid,$3::bytea,$4::bytea,$5::bytea,$6::bytea,ARRAY[$7::bytea],$8::uuid,$9::uuid,$10::uuid,$11::uuid,$12::bigint,
      $13::text,$14::text,'console.agentpass.test','https://console.agentpass.test/','required',120000) AS result`,
    [challengeId, platformSessionId, jtiHash, challengeHash, bindingHash, requestDigest, webauthnId, principalId, memberId, organizationId, assignmentId, 1, OPERATION, OPERATION]);
    assert.equal(challenge.status, "pending");
    assert.equal(challenge.request_digest_sha256, requestDigest.toString("hex"));
    assert.deepEqual(challenge.allowed_credential_ids, [webauthnId.toString("base64url")]);

    const claimed = await result(client, `SELECT public.agentpass_platform_session_challenge_claim(
      $1::uuid,$2::bytea,$3::bytea,$4::bytea,$5::bytea) AS result`,
    [challengeId, jtiHash, challengeHash, bindingHash, requestDigest]);
    assert.equal(claimed.claimed, true);
    const issued = await result(client, `SELECT public.agentpass_platform_session_complete_and_issue(
      $1::uuid,$2::bytea,$3::bytea,$4::uuid,$5::bytea,$6::bytea,$7::bytea,$8::bytea,$9::bytea,900,300) AS result`,
    [platformSessionId, bearerHash, csrfHash, challengeId, jtiHash, challengeHash, bindingHash, requestDigest, webauthnId]);
    assert.equal(issued.challenge.outcome, "completed");
    assert.equal(issued.session.session_id, platformSessionId);
    assert.equal((await client.query("SELECT csrf_token_hash,request_digest_sha256 FROM platform_sessions WHERE session_id=$1", [platformSessionId])).rows[0].csrf_token_hash.toString("hex"), csrfHash.toString("hex"));
    assert.equal((await client.query("SELECT status FROM platform_authorization_proofs WHERE proof_id=$1", [challengeId])).rows[0].status, "available");
    void platformCredentialId;

    const atomicSql = `SELECT public.agentpass_consume_platform_authorization_and_reserve(
      $1::bytea,$2::bytea,$3::uuid,$4::bytea,$5::bytea,$6::uuid,$7::text,$8::text,$9::text,$10::text,$11::bytea,30000,600000,NULL::text,NULL::bigint,NULL::bigint) AS result`;
    const atomicParams = [bearerHash, csrfHash, challengeId, jtiHash, requestDigest, promotionId, deploymentId, "staging", candidateId, `request-${suffix}`, claimHash];
    const reserved = await result(client, atomicSql, atomicParams);
    assert.equal(reserved.state, "reserved");
    assert.equal(reserved.claim_issued, true);
    assert.equal((await client.query("SELECT status FROM platform_authorization_proofs WHERE proof_id=$1", [challengeId])).rows[0].status, "consumed");
    const retry = await result(client, atomicSql, atomicParams);
    assert.equal(retry.state, "reserved");
    assert.equal(Object.hasOwn(retry, "claim_token"), false);
    const concurrentClients = await Promise.all([pool.connect(), pool.connect()]);
    try {
      const concurrentResults = await Promise.all(concurrentClients.map((concurrentClient) =>
        concurrentClient.query(atomicSql, atomicParams)
      ));
      assert.deepEqual(concurrentResults.map((entry) => entry.rows[0].result.state), ["reserved", "reserved"]);
      assert.equal(concurrentResults.every((entry) => Object.hasOwn(entry.rows[0].result, "claim_token") === false), true);
    } finally {
      concurrentClients.forEach((concurrentClient) => concurrentClient.release());
    }
    await assert.rejects(
      client.query(atomicSql, [bearerHash, Buffer.alloc(32, 0x99), challengeId, jtiHash, requestDigest, promotionId, deploymentId, "staging", candidateId, `request-${suffix}`, claimHash]),
      (error) => ["42501", "40001"].includes(error?.code)
    );
    await assert.rejects(
      client.query(atomicSql, [bearerHash, csrfHash, challengeId, jtiHash, digest("wrong-request"), promotionId, deploymentId, "production", candidateId, `request-${suffix}`, claimHash]),
      (error) => error?.code === "23000"
    );

    const privileges = await client.query(`SELECT
      has_function_privilege('agentpass_app', 'public.agentpass_platform_promotion_issuance_reserve(uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint)', 'EXECUTE') AS reserve_app,
      has_function_privilege('agentpass_app', 'public.agentpass_consume_platform_authorization_and_reserve(bytea,bytea,uuid,bytea,bytea,uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint)', 'EXECUTE') AS consume_app`);
    if (privileges.rows[0]) {
      assert.equal(privileges.rows[0].reserve_app, false);
      assert.equal(privileges.rows[0].consume_app, true);
    }

    await client.query("ROLLBACK");
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch { /* preserve original */ }
    throw error;
  } finally {
    client.release();
  }
});

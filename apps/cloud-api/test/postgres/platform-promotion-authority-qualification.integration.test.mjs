import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createMigrationRunner, loadSqlMigrations, migrationChecksum } from "../../src/postgres/migration-runner.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL ?? process.env.P0B_POSTGRES_ADMIN_URL;

const ROLE_NAMES = Object.freeze({
  app: "agentpass_app",
  migrator: "agentpass_migrator",
  backup: "agentpass_backup"
});
const SQLSTATE_PERMISSION_DENIED = new Set(["42501", "0LP01"]);
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const ROLES_SQL_PATH = path.join(REPOSITORY_ROOT, "scripts/postgres/roles.sql");

const ENTRY_FUNCTIONS = Object.freeze([
  "public.agentpass_platform_promotion_issuance_reserve(uuid,text,text,text,text,bytea,integer,integer,text,bigint,bigint)",
  "public.agentpass_platform_promotion_issuance_replay(uuid,text,text,text,text)",
  "public.agentpass_platform_promotion_issuance_commit(uuid,text,text,text,text,bytea,bytea,bytea,bytea,bytea)",
  "public.agentpass_platform_promotion_issuance_uncertain(uuid,text,text,text,text,bytea,text)",
  "public.agentpass_platform_promotion_issuance_get(uuid,text,text,text,text,boolean)"
]);
const HELPER_FUNCTIONS = Object.freeze([
  "public.agentpass_platform_promotion_issuance_result(public.platform_promotion_issuances,boolean)",
  "public.agentpass_platform_promotion_statement_canonical_json(uuid,text,text,text,text,text,text,text,text,text[],integer,text,uuid,text,bigint,text,bigint,timestamptz,timestamptz)",
  "public.agentpass_platform_promotion_request_digest(bytea,text,bigint,text,integer)"
]);
const PROTECTED_TABLES = Object.freeze([
  "platform_promotion_deployments",
  "platform_promotion_issuances",
  "platform_promotion_approvals",
  "release_candidates",
  "managed_signer_key_lifecycles",
  "managed_signer_keys",
  "managed_signer_signing_idempotency",
  "managed_signer_provider_operations"
]);

async function applyRoles(pool) {
  const sql = await readFile(ROLES_SQL_PATH, "utf8");
  const executableSql = sql.replace(/^\\set\s+ON_ERROR_STOP\s+on\s*$/mu, "").trim();
  assert.doesNotMatch(executableSql, /^\\/mu, "role policy contains an unsupported psql directive");
  const client = await pool.connect();
  try {
    await client.query(executableSql);
  } finally {
    client.release(true);
  }
}

async function withSessionAuthorization(pool, roleName, callback) {
  if (!Object.values(ROLE_NAMES).includes(roleName)) throw new TypeError("unsupported qualification role");
  const client = await pool.connect();
  try {
    await client.query(`SET SESSION AUTHORIZATION ${roleName}`);
    const principal = await client.query("SELECT session_user,current_user");
    assert.equal(principal.rows[0].session_user, roleName);
    assert.equal(principal.rows[0].current_user, roleName);
    return await callback(client);
  } finally {
    try {
      await client.query("RESET SESSION AUTHORIZATION");
    } finally {
      client.release(true);
    }
  }
}

async function expectPermissionDenied(callback) {
  await assert.rejects(callback, (error) => {
    assert.ok(SQLSTATE_PERMISSION_DENIED.has(error?.code), `unexpected denial SQLSTATE: ${error?.code ?? "unknown"}`);
    return true;
  });
}

async function assertFunctionPrivilege(client, functionSignature, expected) {
  const result = await client.query(
    "SELECT has_function_privilege(current_user, $1, 'EXECUTE') AS allowed",
    [functionSignature]
  );
  assert.equal(result.rows[0].allowed, expected, `unexpected EXECUTE privilege for ${functionSignature}`);
}

async function assertTableDmlDenied(client, tableName) {
  await expectPermissionDenied(() => client.query(`INSERT INTO public.${tableName} SELECT * FROM public.${tableName} WHERE false`));
  await expectPermissionDenied(() => client.query(`UPDATE public.${tableName} SET ${tableName === "platform_promotion_issuances" ? "idempotency_key=idempotency_key" : "deployment_id=deployment_id"} WHERE false`));
  await expectPermissionDenied(() => client.query(`DELETE FROM public.${tableName} WHERE false`));
  await expectPermissionDenied(() => client.query(`TRUNCATE public.${tableName}`));
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest();
}

test("0048 qualifies fresh PostgreSQL authority functions and least-privilege roles", {
  skip: ADMIN_DATABASE_URL ? false : "set AGENTPASS_TEST_POSTGRES_ADMIN_URL to run disposable PostgreSQL authority qualification",
  timeout: 120_000
}, async (t) => {
  const { createDisposablePostgres, P0BSkip } = await import("../../../../test/support/p0b/harness.mjs");
  let database;
  t.after(async () => { await database?.close?.(); });
  try {
    database = await createDisposablePostgres({ adminUrl: ADMIN_DATABASE_URL });
  } catch (error) {
    if (error instanceof P0BSkip) {
      t.skip(error.message);
      return;
    }
    throw error;
  }
  const pool = database.pool;
  const fixture = {
    deploymentId: `q2a-authority-${crypto.randomUUID()}`,
    promotionId: crypto.randomUUID(),
    approvalId: crypto.randomUUID(),
    candidateId: `release-pkg-sha256-v1-${crypto.randomBytes(32).toString("hex")}`,
    keyId: `q2a-authority-key-${crypto.randomUUID()}`,
    lifecyclePurpose: "agentpass.promotion-evidence",
    seeded: false
  };
  fixture.sourceCommit = crypto.randomBytes(20).toString("hex");
  fixture.sourceTree = crypto.randomBytes(20).toString("hex");
  fixture.productPackageSha256 = fixture.candidateId.slice("release-pkg-sha256-v1-".length);
  fixture.imageDigest = `sha256:${crypto.randomBytes(32).toString("hex")}`;
  fixture.sbomSha256 = crypto.randomBytes(32).toString("hex");
  fixture.manifestSha256 = crypto.randomBytes(32).toString("hex");
  fixture.qualificationDigest = crypto.randomBytes(32).toString("hex");
  fixture.authorizationDigest = crypto.randomBytes(32).toString("hex");
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  fixture.publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  fixture.publicKeyFingerprint = sha256Bytes(fixture.publicKeyDer);

  const preflight = await pool.query(`SELECT
    to_regclass('public.schema_migrations') AS schema_migrations,
    to_regclass('public.organizations') AS organizations,
    to_regclass('public.platform_promotion_issuances') AS promotion_issuances`);
  if (preflight.rows[0].schema_migrations !== null
    || preflight.rows[0].organizations !== null
    || preflight.rows[0].promotion_issuances !== null) {
    t.skip("qualification requires a fresh database with no AgentPass migrations");
    return;
  }

  await applyRoles(pool);
  await withSessionAuthorization(pool, ROLE_NAMES.migrator, async (client) => {
    const migrations = (await loadSqlMigrations()).filter(({ version }) => version <= 48);
    const migrated = await createMigrationRunner({
      client,
      applicationVersion: "q2a-platform-promotion-authority-qualification",
      migrations
    }).run();
    assert.equal(migrated.currentVersion, 48);
    assert.deepEqual(migrated.pending, []);
    assert.deepEqual(migrated.modified, []);
    assert.equal(migrated.dirty, false);
    assert.equal(migrated.applied.at(-1).version, 48);
    const history = await client.query("SELECT version,checksum FROM schema_migrations ORDER BY version");
    assert.equal(history.rowCount, 48);
    assert.deepEqual(history.rows.map((row) => Number(row.version)), Array.from({ length: 48 }, (_, index) => index + 1));
    const authoritySql = await readFile(new URL("../../../../contracts/postgres/0048_platform_promotion_authority_boundary.sql", import.meta.url), "utf8");
    assert.equal(history.rows.at(-1).checksum, migrationChecksum(authoritySql));
  });
  await applyRoles(pool);

  await withSessionAuthorization(pool, ROLE_NAMES.migrator, async (client) => {
    const now = Date.now();
    const approvedAt = new Date(now - 5_000).toISOString();
    const expiresAt = new Date(now + 10 * 60_000).toISOString();
    await client.query(`INSERT INTO release_candidates
      (candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id)
      VALUES ($1,$2,$3,$4,'C3TEST0001')`, [
      fixture.candidateId, fixture.sourceCommit, fixture.productPackageSha256, fixture.manifestSha256
    ]);
    await client.query(`INSERT INTO managed_signer_key_lifecycles (purpose,algorithm,version)
      VALUES ($1,'ed25519',1)`, [fixture.lifecyclePurpose]);
    await client.query(`INSERT INTO managed_signer_keys
      (purpose,key_id,key_version,algorithm,public_key_fingerprint,state,state_version,key_position)
      VALUES ($1,$2,1,'ed25519',$3,'active',1,0)`, [
      fixture.lifecyclePurpose, fixture.keyId, fixture.publicKeyFingerprint
    ]);
    const approval = await client.query(`INSERT INTO platform_promotion_approvals
      (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
       product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,release_manifest_schema_version,
       release_manifest_sha256,policy_id,policy_version,approval_version,decision,platform_principal_ids,
       authorization_evidence_digests,approved_at,expires_at)
      VALUES (1,'agentpass.platform-promotion-approval',$1,$2,'staging',$3,$4,$5,$6,$7,$8,ARRAY[$9]::text[],4,$10,
       'q2a-policy',1,1,'approved',ARRAY['q2a-platform-operator']::text[],ARRAY[$11]::text[],$12,$13)
      RETURNING record_digest`, [
      fixture.approvalId, fixture.deploymentId, fixture.candidateId, fixture.sourceCommit, fixture.sourceTree,
      fixture.productPackageSha256, fixture.imageDigest, fixture.sbomSha256, fixture.qualificationDigest,
      fixture.manifestSha256, fixture.authorizationDigest, approvedAt, expiresAt
    ]);
    assert.match(approval.rows[0].record_digest, /^[0-9a-f]{64}$/u);
    fixture.seeded = true;
  });

  await withSessionAuthorization(pool, ROLE_NAMES.app, async (client) => {
    for (const functionSignature of ENTRY_FUNCTIONS) await assertFunctionPrivilege(client, functionSignature, true);
    for (const functionSignature of HELPER_FUNCTIONS) await assertFunctionPrivilege(client, functionSignature, false);
    for (const tableName of PROTECTED_TABLES) {
      const privilege = await client.query(
        "SELECT has_table_privilege(current_user, $1, 'INSERT,UPDATE,DELETE') AS allowed",
        [`public.${tableName}`]
      );
      assert.equal(privilege.rows[0].allowed, false, `app retained DML on ${tableName}`);
    }

    await assertTableDmlDenied(client, "platform_promotion_deployments");
    await assertTableDmlDenied(client, "platform_promotion_issuances");
    for (const tableName of PROTECTED_TABLES) {
      await expectPermissionDenied(() => client.query(`DELETE FROM public.${tableName} WHERE false`));
    }
    await expectPermissionDenied(() => client.query(
      "INSERT INTO public.managed_signer_provider_operations (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,provider_started_at,expires_at) VALUES ($1,$2,'ed25519',1,$3,$4,1,'failed',clock_timestamp(),clock_timestamp()+interval '1 minute')",
      [fixture.lifecyclePurpose, `q2a-forbidden-${crypto.randomUUID()}`, Buffer.alloc(32, 3), fixture.keyId]
    ));
    await expectPermissionDenied(() => client.query(
      "UPDATE public.managed_signer_keys SET state=state WHERE purpose=$1 AND key_id=$2",
      [fixture.lifecyclePurpose, fixture.keyId]
    ));
    await expectPermissionDenied(() => client.query(
      "SELECT public.agentpass_platform_promotion_statement_canonical_json(NULL::uuid,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text[],NULL::integer,NULL::text,NULL::uuid,NULL::text,NULL::bigint,NULL::text,NULL::bigint,NULL::timestamptz,NULL::timestamptz)"
    ));
    await expectPermissionDenied(() => client.query(
      "SELECT public.agentpass_platform_promotion_request_digest(NULL::bytea,NULL::text,NULL::bigint,NULL::text,NULL::integer)"
    ));
    await expectPermissionDenied(() => client.query(
      "SELECT public.agentpass_platform_promotion_issuance_result(NULL::public.platform_promotion_issuances,false)"
    ));
    await expectPermissionDenied(() => client.query("SET ROLE agentpass_migrator"));

    const claimTokenDigest = Buffer.alloc(32, 0x2a);
    const identity = [fixture.promotionId, fixture.deploymentId, "staging", fixture.candidateId, "q2a-authority-request"];
    const reserved = await client.query(`SELECT public.agentpass_platform_promotion_issuance_reserve(
      $1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,30000,600000,NULL::text,NULL::bigint,NULL::bigint) AS result`, [
      ...identity, claimTokenDigest
    ]);
    assert.equal(reserved.rows[0].result.state, "reserved");
    assert.equal(reserved.rows[0].result.claim_issued, true);
    assert.equal(reserved.rows[0].result.promotion_id, fixture.promotionId);

    const replay = await client.query(
      "SELECT public.agentpass_platform_promotion_issuance_replay($1::uuid,$2::text,$3::text,$4::text,$5::text) AS result",
      identity
    );
    assert.equal(replay.rows[0].result.state, "in_progress");

    const lookup = await client.query(
      "SELECT public.agentpass_platform_promotion_issuance_get($1::uuid,$2::text,$3::text,$4::text,$5::text,false) AS result",
      identity
    );
    assert.equal(lookup.rows[0].result.state, "reserved");
    assert.equal(lookup.rows[0].result.claim_issued, undefined);

    const committedOnlyLookup = await client.query(
      "SELECT public.agentpass_platform_promotion_issuance_get($1::uuid,$2::text,$3::text,$4::text,$5::text,true) AS result",
      identity
    );
    assert.equal(committedOnlyLookup.rows[0].result, null);

    // This deliberately invalid request proves the fifth entry point is
    // executable without fabricating a signature or provider evidence.
    await assert.rejects(
      client.query(`SELECT public.agentpass_platform_promotion_issuance_commit(
        $1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,$7::bytea,$8::bytea,$9::bytea,$10::bytea)`, [
        ...identity, claimTokenDigest, Buffer.from([1]), Buffer.alloc(64, 4), Buffer.from("{}"), sha256Bytes(Buffer.from("{}"))
      ]),
      (error) => {
        assert.equal(error?.code, "23000");
        return true;
      }
    );

    const uncertain = await client.query(`SELECT public.agentpass_platform_promotion_issuance_uncertain(
      $1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,'verification_failure') AS result`, [
      ...identity, claimTokenDigest
    ]);
    assert.equal(uncertain.rows[0].result.state, "uncertain");
  });

  await withSessionAuthorization(pool, ROLE_NAMES.backup, async (client) => {
    for (const functionSignature of ENTRY_FUNCTIONS) await assertFunctionPrivilege(client, functionSignature, false);
    for (const functionSignature of HELPER_FUNCTIONS) await assertFunctionPrivilege(client, functionSignature, false);
    for (const tableName of PROTECTED_TABLES) {
      const privilege = await client.query(
        "SELECT has_table_privilege(current_user, $1, 'INSERT,UPDATE,DELETE') AS allowed",
        [`public.${tableName}`]
      );
      assert.equal(privilege.rows[0].allowed, false, `backup retained DML on ${tableName}`);
    }
    const visible = await client.query(
      "SELECT state FROM public.platform_promotion_issuances WHERE promotion_id=$1",
      [fixture.promotionId]
    );
    assert.equal(visible.rows[0].state, "uncertain");
    for (const tableName of PROTECTED_TABLES) {
      await expectPermissionDenied(() => client.query(`DELETE FROM public.${tableName} WHERE false`));
    }
    await assertTableDmlDenied(client, "platform_promotion_deployments");
    await assertTableDmlDenied(client, "platform_promotion_issuances");
    await expectPermissionDenied(() => client.query("SET ROLE agentpass_migrator"));
    await expectPermissionDenied(() => client.query(
      "SELECT public.agentpass_platform_promotion_statement_canonical_json(NULL::uuid,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text[],NULL::integer,NULL::text,NULL::uuid,NULL::text,NULL::bigint,NULL::text,NULL::bigint,NULL::timestamptz,NULL::timestamptz)"
    ));
    await expectPermissionDenied(() => client.query(
      "SELECT public.agentpass_platform_promotion_request_digest(NULL::bytea,NULL::text,NULL::bigint,NULL::text,NULL::integer)"
    ));
    await expectPermissionDenied(() => client.query(
      "SELECT public.agentpass_platform_promotion_issuance_result(NULL::public.platform_promotion_issuances,false)"
    ));
    const backupIdentity = [fixture.promotionId, fixture.deploymentId, "staging", fixture.candidateId, "q2a-authority-request"];
    const backupClaim = Buffer.alloc(32, 0x2a);
    const backupEntryCalls = [
      () => client.query(
        "SELECT public.agentpass_platform_promotion_issuance_reserve($1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,30000,600000,NULL::text,NULL::bigint,NULL::bigint)",
        [...backupIdentity, backupClaim]
      ),
      () => client.query(
        "SELECT public.agentpass_platform_promotion_issuance_replay($1::uuid,$2::text,$3::text,$4::text,$5::text)",
        backupIdentity
      ),
      () => client.query(
        "SELECT public.agentpass_platform_promotion_issuance_commit($1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,$7::bytea,$8::bytea,$9::bytea,$10::bytea)",
        [...backupIdentity, backupClaim, Buffer.from([1]), Buffer.alloc(64, 4), Buffer.from("{}"), sha256Bytes(Buffer.from("{}"))]
      ),
      () => client.query(
        "SELECT public.agentpass_platform_promotion_issuance_uncertain($1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,'verification_failure')",
        [...backupIdentity, backupClaim]
      ),
      () => client.query(
        "SELECT public.agentpass_platform_promotion_issuance_get($1::uuid,$2::text,$3::text,$4::text,$5::text,false)",
        backupIdentity
      )
    ];
    for (const call of backupEntryCalls) await expectPermissionDenied(call);
  });
});

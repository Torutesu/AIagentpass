import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createHumanAuthRuntime } from "../../src/human-auth/runtime.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createPostgresOrganizationRepository } from "../../src/postgres/organization-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const ORIGIN = "https://console.example.test";
const ISSUER = "https://console.example.test";
const AUDIENCE = "agentpass-cloud-session";
const PROVIDER = "chatgpt";
const KEY_ID = "console-integration-2026-08";
const CURSOR_SECRET = Buffer.alloc(32, 0x42).toString("base64url");

test("G1 signed session bootstrap is bound to active PostgreSQL membership and rejects replay/inactive/cross-org identities", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  t.after(() => pool.end());

  const migrationClient = await pool.connect();
  try {
    const migration = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "signed-session-bootstrap-integration"
    }).run();
    assert.equal(migration.currentVersion, 14);
  } finally {
    migrationClient.release();
  }

  const migrationState = await pool.query("SELECT count(*)::int AS count, max(version)::int AS version FROM schema_migrations");
  assert.equal(migrationState.rows[0].count, 14);
  assert.equal(migrationState.rows[0].version, 14);

  const ids = {
    organization: crypto.randomUUID(),
    otherOrganization: crypto.randomUUID(),
    activeMember: crypto.randomUUID(),
    otherMember: crypto.randomUUID(),
    inactiveMember: crypto.randomUUID(),
    activeMembership: crypto.randomUUID(),
    otherMembership: crypto.randomUUID(),
    inactiveMembership: crypto.randomUUID()
  };
  const subjects = {
    active: `siwc-active-${crypto.randomUUID()}`,
    other: `siwc-other-${crypto.randomUUID()}`,
    inactive: `siwc-inactive-${crypto.randomUUID()}`
  };

  await pool.query(
    `INSERT INTO organizations (id,name) VALUES ($1,$2),($3,$4)`,
    [ids.organization, "G1 signed session organization", ids.otherOrganization, "G1 other organization"]
  );
  await pool.query(
    `INSERT INTO members (id,github_subject,display_name) VALUES
      ($1,NULL,'G1 active member'),
      ($2,NULL,'G1 other member'),
      ($3,NULL,'G1 inactive member')`,
    [ids.activeMember, ids.otherMember, ids.inactiveMember]
  );
  await pool.query(
    `INSERT INTO upstream_identities (provider,subject,member_id) VALUES
      ($1,$2,$3),($1,$4,$5),($1,$6,$7)`,
    [PROVIDER, subjects.active, ids.activeMember, subjects.other, ids.otherMember, subjects.inactive, ids.inactiveMember]
  );
  await pool.query(
    `INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
      ($1,$2,$3,'owner','active'),
      ($4,$5,$6,'owner','active'),
      ($1,$7,$8,'viewer','revoked')`,
    [
      ids.organization,
      ids.activeMembership,
      ids.activeMember,
      ids.otherOrganization,
      ids.otherMembership,
      ids.otherMember,
      ids.inactiveMembership,
      ids.inactiveMember
    ]
  );

  const pair = crypto.generateKeyPairSync("ed25519");
  const now = Date.now();
  const runtime = createHumanAuthRuntime({
    postgresRuntime: {
      pool,
      humanRepository: createPostgresHumanRepository({ client: pool }),
      organizationRepository: createPostgresOrganizationRepository({ client: pool })
    },
    origin: ORIGIN,
    rpId: "console.example.test",
    cursorSecret: CURSOR_SECRET,
    signedConsoleIdentity: {
      issuer: ISSUER,
      audience: AUDIENCE,
      keyId: KEY_ID,
      publicKey: pair.publicKey,
      provider: PROVIDER
    },
    now: () => now
  });

  const activeAssertion = makeCompactAssertion(pair.privateKey, {
    org: ids.organization,
    sub: subjects.active,
    jti: randomJti()
  }, now);
  const issued = await requestSession(runtime, activeAssertion);
  assert.equal(issued.status, 201);
  assert.equal(issued.body.session.organization_id, ids.organization);
  assert.equal(issued.body.session.member_id, ids.activeMember);
  assert.equal(issued.body.session.role, "owner");
  assert.equal(Object.hasOwn(issued.body.session, "membership_id"), false);
  assert.equal(Object.hasOwn(issued.body.session, "token_hash"), false);
  assert.equal(Object.hasOwn(issued.body.session, "csrf_token_hash"), false);

  const sessionToken = /^__Host-agentpass_session=([^;]+)/u.exec(issued.headers["Set-Cookie"])?.[1];
  assert.match(sessionToken, /^[A-Za-z0-9_-]{43}$/u);
  assert.match(issued.body.csrf_token, /^[A-Za-z0-9_-]{43}$/u);

  const stored = await pool.query(
    `SELECT s.id,
            s.member_id,
            s.organization_id,
            s.membership_id,
            s.role,
            s.token_hash,
            s.csrf_token_hash,
            m.id AS joined_membership_id,
            m.member_id AS joined_member_id,
            m.organization_id AS joined_organization_id,
            m.role AS joined_role,
            m.status AS joined_status
       FROM human_sessions s
       JOIN memberships m
         ON m.organization_id=s.organization_id
        AND m.id=s.membership_id
      WHERE s.id=$1`,
    [issued.body.session.session_id]
  );
  assert.equal(stored.rowCount, 1);
  const row = stored.rows[0];
  assert.equal(row.member_id, ids.activeMember);
  assert.equal(row.organization_id, ids.organization);
  assert.equal(row.membership_id, ids.activeMembership);
  assert.equal(row.joined_membership_id, ids.activeMembership);
  assert.equal(row.joined_member_id, ids.activeMember);
  assert.equal(row.joined_organization_id, ids.organization);
  assert.equal(row.role, "owner");
  assert.equal(row.joined_role, "owner");
  assert.equal(row.joined_status, "active");
  assert.equal(Buffer.isBuffer(row.token_hash), true);
  assert.equal(Buffer.isBuffer(row.csrf_token_hash), true);
  assert.equal(row.token_hash.length, 32);
  assert.equal(row.csrf_token_hash.length, 32);
  assert.equal(row.token_hash.toString("hex"), crypto.createHash("sha256").update(sessionToken, "utf8").digest("hex"));
  assert.equal(row.csrf_token_hash.toString("hex"), crypto.createHash("sha256").update(issued.body.csrf_token, "utf8").digest("hex"));
  assert.notEqual(row.token_hash.toString("utf8"), sessionToken);
  assert.notEqual(row.csrf_token_hash.toString("utf8"), issued.body.csrf_token);
  const sessionSecretColumns = await pool.query(
    `SELECT column_name,data_type
       FROM information_schema.columns
      WHERE table_schema='public'
        AND table_name='human_sessions'
        AND column_name IN ('token','csrf_token','token_hash','csrf_token_hash')
      ORDER BY column_name`
  );
  assert.deepEqual(sessionSecretColumns.rows, [
    { column_name: "csrf_token_hash", data_type: "bytea" },
    { column_name: "token_hash", data_type: "bytea" }
  ]);

  const sessionCountAfterIssue = await countTestSessions(pool, ids);
  assert.equal(sessionCountAfterIssue, 1);

  const replay = await requestSession(runtime, activeAssertion);
  assert.equal(replay.status, 409);
  assert.equal(await countTestSessions(pool, ids), sessionCountAfterIssue);

  const inactive = await requestSession(runtime, makeCompactAssertion(pair.privateKey, {
    org: ids.organization,
    sub: subjects.inactive,
    jti: randomJti()
  }, now));
  assert.equal(inactive.status, 401);
  assert.equal(await countTestSessions(pool, ids), sessionCountAfterIssue);

  // A correctly signed assertion for the active subject cannot substitute a
  // different organization: the resolver must require an active membership
  // in the asserted organization before a session is created.
  const signedCrossOrganization = await requestSession(runtime, makeCompactAssertion(pair.privateKey, {
    org: ids.otherOrganization,
    sub: subjects.active,
    jti: randomJti()
  }, now));
  assert.equal(signedCrossOrganization.status, 401);
  assert.equal(await countTestSessions(pool, ids), sessionCountAfterIssue);

  // The same substitution must also fail before replay consumption when the
  // attacker only changes the organization claim without resigning.
  const [header, payload, signature] = activeAssertion.split(".");
  const tamperedPayload = decodeBase64Url(payload);
  tamperedPayload.org = ids.otherOrganization;
  const tamperedPayloadSegment = encodeBase64Url(tamperedPayload);
  const tamperedCrossOrganization = await requestSession(runtime, `${header}.${tamperedPayloadSegment}.${signature}`);
  assert.equal(tamperedCrossOrganization.status, 401);
  assert.equal(await countTestSessions(pool, ids), sessionCountAfterIssue);
});

async function requestSession(runtime, compactAssertion) {
  return runtime.api.handle({
    method: "POST",
    url: "/api/auth/session",
    headers: {
      origin: ORIGIN,
      "content-type": "application/json",
      "agentpass-console-identity": compactAssertion
    },
    body: "{}"
  });
}

async function countTestSessions(pool, ids) {
  const result = await pool.query(
    `SELECT count(*)::int AS count
       FROM human_sessions
      WHERE member_id IN ($1,$2,$3)
         OR organization_id IN ($4,$5)`,
    [ids.activeMember, ids.otherMember, ids.inactiveMember, ids.organization, ids.otherOrganization]
  );
  return result.rows[0].count;
}

function makeCompactAssertion(privateKey, overrides, now) {
  const nowSeconds = Math.floor(now / 1_000);
  const header = { alg: "EdDSA", kid: KEY_ID, typ: "agentpass.console.identity", version: 1 };
  const payload = {
    aud: AUDIENCE,
    exp: nowSeconds + 30,
    iat: nowSeconds,
    iss: ISSUER,
    jti: randomJti(),
    nbf: nowSeconds,
    org: overrides.org,
    origin: ORIGIN,
    provider: PROVIDER,
    sub: overrides.sub,
    ...overrides
  };
  const encodedHeader = encodeBase64Url(header);
  const encodedPayload = encodeBase64Url(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, "ascii"), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function randomJti() {
  return `g1-${crypto.randomBytes(18).toString("base64url")}`;
}

function encodeBase64Url(value) {
  return Buffer.from(canonicalJson(value), "utf8").toString("base64url");
}

function decodeBase64Url(value) {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

import crypto from "node:crypto";
import { Pool } from "pg";

import {
  AGENT_SESSION_GRANT_ISSUER,
  AGENT_SESSION_GRANT_TYPE,
  agentSessionGrantSigningData,
  agentSessionGrantStatementHash,
  normalizeAgentSessionGrantStatement
} from "../../src/agent-session-grant.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { canonicalJson, normalizeScope } from "../../../../packages/protocol/src/index.mjs";

const DEFAULT_DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL
  ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const DEFAULT_APPLICATION_VERSION = "agent-session-human-http-fixture";
const CONTROL_SEQUENCE = 7;
const GRANT_KEY_ID = "agent-session-human-http-fixture-v1";
const DEFAULT_SCOPE = Object.freeze({
  operations: ["git.commit.sign"],
  repositories: ["/integration/repository"],
  branches: { allow: ["main"], deny: [] },
  remotes: { allow: ["origin"], deny: [] }
});

/**
 * Run the repository migrations and assert the fixture's supported schema.
 * The migration runner receives a connected client so callers can use either
 * a Pool or an existing transaction harness.
 */
export async function migrateAgentSessionHumanHttpFixture({
  client,
  applicationVersion = DEFAULT_APPLICATION_VERSION
} = {}) {
  assertMethod(client, "query");
  try {
    const migration = await createMigrationRunner({ client, applicationVersion }).run();
    if (migration.currentVersion !== 37) throw fixtureError("unsupported_schema");
    return Object.freeze(migration);
  } catch (error) {
    if (error?.message === "agent session human HTTP fixture unsupported_schema") throw error;
    throw fixtureError("migration_failed");
  }
}

/**
 * Seed the organization, Human authority, agent audience, policy, and an
 * already-applied ControlBundle required by the real issuance repository.
 * This function assumes that the caller has already migrated the database.
 */
export async function seedAgentSessionHumanHttpFixture({
  pool,
  options = {}
} = {}) {
  assertMethod(pool, "query");
  const ids = createIds();
  const issuedAtMs = options.issuedAtMs ?? Date.now() - 30_000;
  if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs <= 0) throw fixtureError("invalid_time");
  const issuedAt = new Date(issuedAtMs).toISOString();
  const actorMembershipStatus = options.actorMembershipStatus ?? "active";
  const deviceStatus = options.deviceStatus ?? "active";
  const agentStatus = options.agentStatus ?? "active";
  const scope = normalizeScope(options.scope ?? DEFAULT_SCOPE);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString().trimEnd();

  if (!new Set(["active", "revoked"]).has(actorMembershipStatus)
    || !new Set(["active", "disabled", "revoked"]).has(deviceStatus)
    || !new Set(["active", "revoked"]).has(agentStatus)) {
    throw fixtureError("invalid_status");
  }

  try {
    await pool.query(
      "INSERT INTO organizations (id,name) VALUES ($1,$2)",
      [ids.organization, `agent-session-fixture-${ids.organization}`]
    );
    await pool.query(
      `INSERT INTO members (id,github_subject,display_name) VALUES
        ($1,$2,'agent session fixture operator'),($3,$4,'agent session fixture actor')`,
      [
        ids.operatorMember,
        `agent-session-fixture-operator-${ids.organization}`,
        ids.actorMember,
        `agent-session-fixture-actor-${ids.organization}`
      ]
    );
    await pool.query(
      `INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
        ($1,$2,$3,'owner','active'),($1,$4,$5,'admin',$6)`,
      [
        ids.organization,
        ids.operatorMembership,
        ids.operatorMember,
        ids.actorMembership,
        ids.actorMember,
        actorMembershipStatus
      ]
    );
    await pool.query(
      `INSERT INTO human_sessions
        (id,member_id,token_hash,created_at,expires_at,organization_id,membership_id,role,csrf_token_hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'admin',$8)`,
      [
        ids.session,
        ids.actorMember,
        crypto.randomBytes(32),
        new Date(issuedAtMs - 60_000).toISOString(),
        new Date(issuedAtMs + 3_600_000).toISOString(),
        ids.organization,
        ids.actorMembership,
        crypto.randomBytes(32)
      ]
    );
    await pool.query(
      `INSERT INTO webauthn_challenges
        (id,session_id,member_id,organization_id,ceremony,operation,challenge_hash,created_at,expires_at,rp_id,origin,user_verification,status,consumed_at)
        VALUES ($1,$2,$3,$4,'authentication','agent.session_grant.issue',$5,$6,$7,'console.agentpass.test','https://console.agentpass.test','required','consumed',$8)`,
      [
        ids.recentAuth,
        ids.session,
        ids.actorMember,
        ids.organization,
        crypto.randomBytes(32),
        new Date(issuedAtMs - 60_000).toISOString(),
        new Date(issuedAtMs + 300_000).toISOString(),
        issuedAt
      ]
    );
    await pool.query(
      `UPDATE human_sessions
        SET recent_auth_at=$2::timestamptz,recent_auth_challenge_id=$3,
            recent_auth_organization_id=$4,recent_auth_operation=$5,
            recent_auth_consumed_at=$2::timestamptz
        WHERE id=$1`,
      [ids.session, issuedAt, ids.recentAuth, ids.organization, "agent.session_grant.issue"]
    );
    await pool.query(
      `INSERT INTO devices (organization_id,id,label,key_algorithm,public_key_pem,status)
        VALUES ($1,$2,'agent session fixture device','ed25519',$3,$4)`,
      [ids.organization, ids.device, publicKeyPem, deviceStatus]
    );
    await pool.query(
      `INSERT INTO agents (organization_id,id,device_id,kind,name,public_key_pem,status)
        VALUES ($1,$2,$3,'claude-code','agent session fixture agent',$4,$5)`,
      [ids.organization, ids.agent, ids.device, publicKeyPem, agentStatus]
    );
    await pool.query(
      `INSERT INTO policies (organization_id,id,sequence,name,scope_json,status,created_by)
        VALUES ($1,$2,1,'agent session fixture policy',$3::jsonb,'active',$4)`,
      [ids.organization, ids.policy, JSON.stringify(scope), ids.operatorMember]
    );

    if (deviceStatus === "active") {
      await pool.query(
        `INSERT INTO bundle_heads
          (organization_id,device_id,format_epoch,sequence,statement_hash,issued_at,expires_at)
          VALUES ($1,$2,2,$3,$4,clock_timestamp(),clock_timestamp()+interval '1 hour')`,
        [ids.organization, ids.device, CONTROL_SEQUENCE, "b".repeat(64)]
      );
      await pool.query(
        `UPDATE device_control_plane_state
          SET observed_generation=1,refresh_state='applied',last_observed_at=clock_timestamp()
          WHERE organization_id=$1 AND device_id=$2`,
        [ids.organization, ids.device]
      );
      await pool.query(
        `INSERT INTO bundle_acknowledgements
          (organization_id,device_id,format_epoch,sequence,statement_hash,status,applied_at)
          VALUES ($1,$2,2,$3,$4,'applied',clock_timestamp())`,
        [ids.organization, ids.device, CONTROL_SEQUENCE, "b".repeat(64)]
      );
    }
  } catch {
    throw fixtureError("seed_failed");
  }

  const actor = Object.freeze({
    session_id: ids.session,
    member_id: ids.actorMember,
    organization_id: ids.organization,
    role: "admin"
  });
  const baseIntent = Object.freeze({
    device_id: ids.device,
    agent_kind: "claude-code",
    adapter_id: ids.adapter,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "a".repeat(64),
    process_binding_policy_id: ids.policy,
    scope,
    max_signatures: 2,
    ttl_seconds: 600
  });

  function issueInput(overrides = {}) {
    const {
      intent: intentOverrides = {},
      buildGrant: customBuilder,
      onBuildGrant,
      ...inputOverrides
    } = overrides;
    const intent = Object.freeze({ ...baseIntent, ...intentOverrides });
    const requestFingerprint = crypto.createHash("sha256")
      .update(canonicalJson({ organization_id: ids.organization, agent_id: ids.agent, ...intent }))
      .digest("hex");
    const grantId = overrides.grant_id ?? crypto.randomUUID();
    const requestId = overrides.request_id ?? crypto.randomUUID();
    const input = {
      actor,
      organization_id: ids.organization,
      agent_id: ids.agent,
      device_id: ids.device,
      intent,
      idempotency_key: overrides.idempotency_key ?? `agent-session-fixture-${ids.organization}`,
      request_fingerprint: requestFingerprint,
      request_id: requestId,
      grant_id: grantId,
      issued_at: issuedAt,
      not_before: issuedAt,
      expires_at: new Date(issuedAtMs + intent.ttl_seconds * 1_000).toISOString(),
      recent_auth: {
        authorization_id: ids.recentAuth,
        authenticated_at: issuedAtMs
      },
      buildGrant: customBuilder
        ?? ((grantOptions = {}) => buildSignedGrant({
          fixture: { ids, privateKey },
          input,
          onBuildGrant,
          ...grantOptions
        }))
    };
    return Object.freeze({ ...input, ...inputOverrides, intent, request_fingerprint: requestFingerprint });
  }

  return Object.freeze({
    ids: Object.freeze(ids),
    actor,
    intent: baseIntent,
    issuedAtMs,
    issuedAt,
    controlSequence: CONTROL_SEQUENCE,
    authorityGeneration: 1,
    publicKey,
    issueInput
  });
}

/**
 * Open (when needed), migrate, seed, and compose the real PostgreSQL
 * issuance repository. `cleanup` is idempotent and closes only a Pool owned
 * by this helper; a caller-owned Pool remains available to its test suite.
 */
export async function createAgentSessionHumanHttpFixture({
  pool = undefined,
  connectionString = DEFAULT_DATABASE_URL,
  applicationVersion = DEFAULT_APPLICATION_VERSION,
  options = {}
} = {}) {
  let fixturePool = pool;
  let ownsPool = false;
  let cleaned = false;
  if (!fixturePool) {
    if (typeof connectionString !== "string" || connectionString.length === 0) throw fixtureError("database_url_missing");
    fixturePool = new Pool({ connectionString, max: 4 });
    ownsPool = true;
  }
  assertMethod(fixturePool, "connect");
  try {
    const client = await fixturePool.connect();
    try {
      await migrateAgentSessionHumanHttpFixture({ client, applicationVersion });
    } finally {
      client.release();
    }
    const seeded = await seedAgentSessionHumanHttpFixture({ pool: fixturePool, options });
    const { createPostgresAgentSessionIssuanceRepository } = await import("../../src/postgres/agent-session-issuance-repository.mjs");
    const repository = createPostgresAgentSessionIssuanceRepository({
      client: fixturePool,
      resolveProcessBindingPolicy: () => true
    });
    const cleanup = async () => {
      if (cleaned) return;
      cleaned = true;
      if (ownsPool) {
        try {
          await fixturePool.end();
        } catch {
          throw fixtureError("cleanup_failed");
        }
      }
    };
    return Object.freeze({ ...seeded, pool: fixturePool, repository, cleanup });
  } catch (error) {
    if (ownsPool) {
      try { await fixturePool.end(); } catch { /* preserve bounded error */ }
    }
    if (error?.message?.startsWith("agent session human HTTP fixture ")) throw error;
    throw fixtureError("creation_failed");
  }
}

function createIds() {
  return {
    organization: crypto.randomUUID(),
    operatorMember: crypto.randomUUID(),
    actorMember: crypto.randomUUID(),
    operatorMembership: crypto.randomUUID(),
    actorMembership: crypto.randomUUID(),
    device: crypto.randomUUID(),
    agent: crypto.randomUUID(),
    policy: crypto.randomUUID(),
    adapter: crypto.randomUUID(),
    session: crypto.randomUUID(),
    recentAuth: crypto.randomUUID()
  };
}

async function buildSignedGrant({ fixture, input, control_sequence, authority_generation, grant_id, onBuildGrant }) {
  onBuildGrant?.();
  const controlSequence = control_sequence ?? fixture.controlSequence ?? CONTROL_SEQUENCE;
  const authorityGeneration = authority_generation ?? fixture.authorityGeneration ?? 1;
  const grantId = grant_id ?? input.grant_id;
  const statement = normalizeAgentSessionGrantStatement({
    version: 1,
    grant_id: grantId,
    organization_id: fixture.ids.organization,
    device_id: fixture.ids.device,
    agent_id: fixture.ids.agent,
    agent_kind: input.intent.agent_kind,
    adapter_id: input.intent.adapter_id,
    adapter_version: input.intent.adapter_version,
    worktree_binding_sha256: input.intent.worktree_binding_sha256,
    process_binding_policy_id: input.intent.process_binding_policy_id,
    scope: input.intent.scope,
    max_signatures: input.intent.max_signatures,
    not_before: input.not_before,
    expires_at: input.expires_at,
    control_sequence: controlSequence,
    authority_generation: authorityGeneration,
    issuer: AGENT_SESSION_GRANT_ISSUER,
    key_id: GRANT_KEY_ID
  });
  const statementHash = agentSessionGrantStatementHash(statement);
  const signature = crypto.sign(null, agentSessionGrantSigningData(statement), fixture.privateKey).toString("base64url");
  const grant = {
    version: 1,
    type: AGENT_SESSION_GRANT_TYPE,
    statement,
    statement_hash: statementHash,
    signature
  };
  return Object.freeze({
    grant,
    grant_hash: crypto.createHash("sha256").update(canonicalJson(grant)).digest("hex"),
    statement_hash: statementHash,
    control_sequence: controlSequence,
    authority_generation: authorityGeneration
  });
}

function assertMethod(value, method) {
  if (!value || typeof value[method] !== "function") throw fixtureError(`invalid_${method}`);
}

function fixtureError(code) {
  return new Error(`agent session human HTTP fixture ${code}`);
}

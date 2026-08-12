import { Pool } from "pg";
import { createMigrationRunner } from "./migration-runner.mjs";
import { createPostgresHumanRepository } from "./human-repository.mjs";
import { createPostgresOrganizationRepository } from "./organization-repository.mjs";
import { createTenantRepositoryFactory } from "./repository.mjs";

export async function createPostgresRuntime({ env = process.env, PoolClass = Pool, applicationVersion = "unknown" } = {}) {
  const config = loadPostgresConfig(env);
  const pool = new PoolClass({ connectionString: config.connectionString, ssl: { rejectUnauthorized: true }, max: config.maxConnections, connectionTimeoutMillis: config.connectionTimeoutMs, idleTimeoutMillis: config.idleTimeoutMs, statement_timeout: config.statementTimeoutMs, lock_timeout: config.lockTimeoutMs, query_timeout: config.statementTimeoutMs + 1_000, allowExitOnIdle: false });
  let client;
  try {
    client = await pool.connect();
    await client.query("SELECT set_config('statement_timeout', $1, false)", [`${config.statementTimeoutMs}ms`]);
    await client.query("SELECT set_config('lock_timeout', $1, false)", [`${config.lockTimeoutMs}ms`]);
    await createMigrationRunner({ client, applicationVersion }).run();
  } catch (error) {
    client?.release?.(true);
    await pool.end().catch(() => {});
    throw error;
  }
  client.release();
  let closed = false;
  const organizationRepository = createPostgresOrganizationRepository({ client: pool });
  return Object.freeze({
    pool,
    humanRepository: createPostgresHumanRepository({ client: pool }),
    organizationRepository,
    tenants: createTenantRepositoryFactory({ client: pool }),
    async health() {
      if (closed) return { ready: false, code: "postgres_closed" };
      const result = await pool.query("SELECT 1 AS ready", []);
      return { ready: result.rows?.[0]?.ready === 1, code: result.rows?.[0]?.ready === 1 ? "ready" : "postgres_unavailable" };
    },
    async close() { if (!closed) { closed = true; await pool.end(); } }
  });
}

export function loadPostgresConfig(env = {}) {
  const raw = env.AGENTPASS_DATABASE_URL;
  let url;
  try { url = new URL(raw); } catch { throw new TypeError("AGENTPASS_DATABASE_URL is invalid"); }
  if (url.protocol !== "postgresql:" || !url.hostname || !url.username || !url.password || url.hash) throw new TypeError("AGENTPASS_DATABASE_URL is invalid");
  const sslMode = url.searchParams.get("sslmode");
  if (sslMode !== "verify-full") throw new TypeError("PostgreSQL sslmode=verify-full is required");
  for (const key of url.searchParams.keys()) if (key !== "sslmode") throw new TypeError("AGENTPASS_DATABASE_URL contains unsupported parameters");
  return Object.freeze({
    connectionString: url.toString(),
    maxConnections: integer(env.AGENTPASS_DATABASE_MAX_CONNECTIONS ?? "10", 1, 100),
    connectionTimeoutMs: integer(env.AGENTPASS_DATABASE_CONNECT_TIMEOUT_MS ?? "5000", 250, 30_000),
    idleTimeoutMs: integer(env.AGENTPASS_DATABASE_IDLE_TIMEOUT_MS ?? "30000", 1_000, 300_000),
    statementTimeoutMs: integer(env.AGENTPASS_DATABASE_STATEMENT_TIMEOUT_MS ?? "8000", 250, 60_000),
    lockTimeoutMs: integer(env.AGENTPASS_DATABASE_LOCK_TIMEOUT_MS ?? "2000", 100, 30_000)
  });
}

function integer(value, min, max) { if (typeof value !== "string" || !/^\d+$/.test(value)) throw new TypeError("PostgreSQL timeout/limit is invalid"); const result=Number(value); if(!Number.isSafeInteger(result)||result<min||result>max) throw new TypeError("PostgreSQL timeout/limit is invalid"); return result; }

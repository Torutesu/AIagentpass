import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { Pool } from "pg";
import { loadPostgresAppConfig } from "./postgres/runtime.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/;
const SUBJECT = /^[^\u0000-\u001f\u007f]{1,512}$/u;
const REQUIRED_OPTIONS = ["provider", "subject", "member-id", "organization-id"];
const OPTION_NAMES = new Set(REQUIRED_OPTIONS.map((name) => `--${name}`));

export class IdentityBindError extends Error {
  constructor(code, cause = undefined) {
    super(code, cause === undefined ? undefined : { cause });
    this.name = "IdentityBindError";
    this.code = code;
  }
}

/**
 * Provision one immutable upstream identity into an already-migrated database.
 *
 * This function is exported for non-interactive test and operator integration.
 * The executable entry point below is deliberately the only place that writes
 * a result; database and driver errors never cross the CLI output boundary.
 */
export async function runIdentityBind({ argv = process.argv.slice(2), env = process.env, PoolClass = Pool } = {}) {
  const options = parseArguments(argv);
  if (options.help) return Object.freeze({ ok: true, command: "identity-bind", required: REQUIRED_OPTIONS.map((name) => `--${name} VALUE`), database: "AGENTPASS_DATABASE_URL" });

  const config = loadDatabaseConfig(env);
  const pool = createPool({ PoolClass, config });
  let client;
  let completed = false;
  try {
    client = await pool.connect();
    await configureConnection(client, config);
    await client.query("BEGIN");
    try {
      await lockActiveMembership(client, options);
      const result = await bindIdentity(client, options);
      await client.query("COMMIT");
      completed = true;
      return Object.freeze({
        ok: true,
        command: "identity-bind",
        result,
        provider: options.provider,
        subject: options.subject,
        member_id: options.memberId,
        organization_id: options.organizationId
      });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw toIdentityBindError(error);
    }
  } catch (error) {
    if (error instanceof IdentityBindError) throw error;
    throw toIdentityBindError(error);
  } finally {
    client?.release?.(!completed);
    await pool.end().catch(() => {});
  }
}

function parseArguments(argv) {
  if (!Array.isArray(argv)) throw new IdentityBindError("invalid_arguments");
  const values = Object.create(null);
  let help = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help") {
      if (argv.length !== 1) throw new IdentityBindError("invalid_arguments");
      help = true;
      continue;
    }
    if (typeof argument !== "string" || !OPTION_NAMES.has(argument) || Object.prototype.hasOwnProperty.call(values, argument.slice(2))) throw new IdentityBindError("invalid_arguments");
    const name = argument.slice(2);
    const value = argv[index + 1];
    if (typeof value !== "string" || value.length === 0 || value.startsWith("--")) throw new IdentityBindError("invalid_arguments");
    values[name] = value;
    index += 1;
  }
  if (help) return Object.freeze({ help: true });
  if (Object.keys(values).length !== REQUIRED_OPTIONS.length || REQUIRED_OPTIONS.some((name) => !Object.prototype.hasOwnProperty.call(values, name))) throw new IdentityBindError("invalid_arguments");

  const provider = assertProvider(values.provider);
  const subject = assertSubject(values.subject);
  const memberId = assertUuid(values["member-id"]);
  const organizationId = assertUuid(values["organization-id"]);
  return Object.freeze({ provider, subject, memberId, organizationId });
}

function loadDatabaseConfig(env) {
  if (!env || typeof env.AGENTPASS_DATABASE_URL !== "string" || env.AGENTPASS_DATABASE_URL.length === 0) throw new IdentityBindError("database_config_invalid");
  try {
    return loadPostgresAppConfig(env);
  } catch (error) {
    throw new IdentityBindError("database_config_invalid", error);
  }
}

function createPool({ PoolClass, config }) {
  try {
    return new PoolClass({
      connectionString: config.connectionString,
      ssl: { rejectUnauthorized: true },
      max: config.maxConnections,
      connectionTimeoutMillis: config.connectionTimeoutMs,
      idleTimeoutMillis: config.idleTimeoutMs,
      statement_timeout: config.statementTimeoutMs,
      lock_timeout: config.lockTimeoutMs,
      query_timeout: config.statementTimeoutMs + 1_000,
      allowExitOnIdle: false
    });
  } catch (error) {
    throw new IdentityBindError("database_unavailable", error);
  }
}

async function configureConnection(client, config) {
  await client.query("SELECT set_config('statement_timeout', $1, false)", [`${config.statementTimeoutMs}ms`]);
  await client.query("SELECT set_config('lock_timeout', $1, false)", [`${config.lockTimeoutMs}ms`]);
}

async function lockActiveMembership(client, options) {
  const result = await client.query(
    "SELECT organization_id, member_id, role FROM memberships WHERE organization_id=$1 AND member_id=$2 AND status='active' FOR UPDATE",
    [options.organizationId, options.memberId]
  );
  if (result.rowCount !== 1) throw new IdentityBindError("membership_not_active");
}

async function bindIdentity(client, options) {
  const inserted = await client.query(
    "INSERT INTO upstream_identities (provider, subject, member_id) VALUES ($1, $2, $3) ON CONFLICT (provider, subject) DO NOTHING RETURNING provider, subject, member_id",
    [options.provider, options.subject, options.memberId]
  );
  if (inserted.rowCount === 1) return "created";

  const existing = await client.query(
    "SELECT member_id FROM upstream_identities WHERE provider=$1 AND subject=$2",
    [options.provider, options.subject]
  );
  if (existing.rowCount !== 1) throw new IdentityBindError("database_operation_failed");
  const existingMemberId = String(existing.rows[0]?.member_id ?? "").toLowerCase();
  if (existingMemberId !== options.memberId) throw new IdentityBindError("identity_rebind_forbidden");
  return "already_exists";
}

function toIdentityBindError(error) {
  if (error instanceof IdentityBindError) return error;
  return new IdentityBindError("database_operation_failed", error);
}

function assertProvider(value) {
  if (typeof value !== "string" || !PROVIDER.test(value)) throw new IdentityBindError("invalid_arguments");
  return value;
}

function assertSubject(value) {
  if (typeof value !== "string" || !SUBJECT.test(value) || value.trim() !== value) throw new IdentityBindError("invalid_arguments");
  return value;
}

function assertUuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw new IdentityBindError("invalid_arguments");
  return value.toLowerCase();
}

function safeError(error) {
  return error instanceof IdentityBindError && typeof error.code === "string" ? error.code : "database_operation_failed";
}

function writeJson(stream, value) {
  stream.write(`${JSON.stringify(value)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const result = await runIdentityBind();
    writeJson(process.stdout, result);
  } catch (error) {
    writeJson(process.stderr, { ok: false, error: safeError(error) });
    process.exitCode = 1;
  }
}

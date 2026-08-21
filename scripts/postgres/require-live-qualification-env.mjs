import assert from "node:assert/strict";

const URL_KEYS = Object.freeze([
  "AGENTPASS_TEST_DATABASE_URL",
  "AGENTPASS_TEST_POSTGRES_URL",
  "AGENTPASS_TEST_POSTGRES_ADMIN_URL",
  "AGENTPASS_TEST_APP_DATABASE_URL",
]);

export class LivePostgresQualificationEnvironmentError extends Error {
  constructor(message) {
    super(message);
    this.name = "LivePostgresQualificationEnvironmentError";
  }
}

/**
 * Validate the minimum connection contract for a real PostgreSQL gate.
 *
 * The ordinary unit/integration tests intentionally skip when no DSN exists.
 * This entry point is for protected qualification jobs and must never turn a
 * missing role connection into a green, skipped run. Values are validated but
 * never echoed because DSNs may contain credentials.
 */
export function validateLivePostgresQualificationEnvironment(env = process.env) {
  assert.ok(env && typeof env === "object" && !Array.isArray(env));
  const databaseUrl = env.AGENTPASS_TEST_DATABASE_URL ?? env.AGENTPASS_TEST_POSTGRES_URL;
  const adminUrl = env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
  const appUrl = env.AGENTPASS_TEST_APP_DATABASE_URL;
  const missing = [];
  if (databaseUrl === undefined) missing.push("AGENTPASS_TEST_DATABASE_URL or AGENTPASS_TEST_POSTGRES_URL");
  if (adminUrl === undefined) missing.push("AGENTPASS_TEST_POSTGRES_ADMIN_URL");
  if (appUrl === undefined) missing.push("AGENTPASS_TEST_APP_DATABASE_URL");
  if (missing.length > 0) throw new LivePostgresQualificationEnvironmentError(`missing live PostgreSQL qualification variables: ${missing.join(", ")}`);

  for (const [name, value] of [["database", databaseUrl], ["admin", adminUrl], ["app", appUrl]]) {
    let parsed;
    try { parsed = new URL(value); } catch { throw new LivePostgresQualificationEnvironmentError(`${name} PostgreSQL qualification URL is invalid`); }
    if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
      throw new LivePostgresQualificationEnvironmentError(`${name} PostgreSQL qualification URL must use postgres or postgresql scheme`);
    }
    if (parsed.hostname === "" || parsed.pathname === "") throw new LivePostgresQualificationEnvironmentError(`${name} PostgreSQL qualification URL is incomplete`);
  }

  return Object.freeze({
    validated_keys: URL_KEYS.filter((key) => typeof env[key] === "string"),
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  validateLivePostgresQualificationEnvironment();
  process.stdout.write("live PostgreSQL qualification environment validated\n");
}

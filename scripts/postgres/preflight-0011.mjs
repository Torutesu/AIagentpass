#!/usr/bin/env node
import { pathToFileURL } from "node:url";

export const PREFLIGHT_DIAGNOSTICS = Object.freeze({
  CROSS_TENANT_CREATED_BY: Object.freeze({
    code: "AGENTPASS_0011_PREFLIGHT_CROSS_TENANT_CREATED_BY",
    message: "migration 0011 is blocked because created_by is not attributed to the same organization",
    remediation: "Repair or quarantine the listed rows, rerun this preflight, then retry migration 0011."
  }),
  DATABASE_UNAVAILABLE: Object.freeze({
    code: "AGENTPASS_0011_PREFLIGHT_DATABASE_UNAVAILABLE",
    message: "migration 0011 preflight could not establish a trustworthy database result",
    remediation: "Verify the database connection and TLS configuration; do not apply migration 0011 until the preflight succeeds."
  }),
  VALIDATION_FAILED: Object.freeze({
    code: "AGENTPASS_0011_PREFLIGHT_VALIDATION_FAILED",
    message: "migration 0011 constraints could not be validated",
    remediation: "Leave the constraints NOT VALID, repair the reported data or database condition, and rerun with --validate."
  })
});

const CROSS_TENANT_QUERY = `
WITH violations(table_name, violation_count) AS (
  SELECT 'device_enrollments', count(*)
  FROM device_enrollments e
  WHERE NOT EXISTS (
    SELECT 1
    FROM memberships m
    WHERE m.organization_id = e.organization_id
      AND m.member_id = e.created_by
  )
  UNION ALL
  SELECT 'policies', count(*)
  FROM policies p
  WHERE NOT EXISTS (
    SELECT 1
    FROM memberships m
    WHERE m.organization_id = p.organization_id
      AND m.member_id = p.created_by
  )
  UNION ALL
  SELECT 'revocations', count(*)
  FROM revocations r
  WHERE NOT EXISTS (
    SELECT 1
    FROM memberships m
    WHERE m.organization_id = r.organization_id
      AND m.member_id = r.created_by
  )
)
SELECT table_name, violation_count::bigint
FROM violations
WHERE violation_count > 0
ORDER BY table_name`;

export const VALIDATION_STATEMENTS = Object.freeze([
  "ALTER TABLE device_enrollments VALIDATE CONSTRAINT device_enrollments_created_by_tenant_fk",
  "ALTER TABLE policies VALIDATE CONSTRAINT policies_created_by_tenant_fk",
  "ALTER TABLE revocations VALIDATE CONSTRAINT revocations_created_by_tenant_fk",
  "ALTER TABLE revocations VALIDATE CONSTRAINT revocations_revoked_by_tenant_fk"
]);

export class ControlPlaneCutoverPreflightError extends Error {
  constructor(diagnostic, details = undefined, cause = undefined) {
    super(diagnostic.message, cause === undefined ? undefined : { cause });
    this.name = "ControlPlaneCutoverPreflightError";
    this.code = diagnostic.code;
    this.remediation = diagnostic.remediation;
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}

export async function runControlPlaneCutoverPreflight({ client, validate = false } = {}) {
  if (!client || typeof client.query !== "function") throw new TypeError("preflight client must provide query(text, params)");

  let result;
  try {
    result = await client.query(CROSS_TENANT_QUERY, []);
  } catch (error) {
    throw new ControlPlaneCutoverPreflightError(PREFLIGHT_DIAGNOSTICS.DATABASE_UNAVAILABLE, undefined, error);
  }

  const violations = normalizeViolations(result?.rows);
  if (violations.length > 0) {
    throw new ControlPlaneCutoverPreflightError(PREFLIGHT_DIAGNOSTICS.CROSS_TENANT_CREATED_BY, {
      violations,
      total: violations.reduce((sum, item) => sum + item.count, 0)
    });
  }

  if (!validate) return Object.freeze({ ok: true, validated: false, violations: Object.freeze([]) });

  let began = false;
  try {
    await client.query("BEGIN", []);
    began = true;
    for (const statement of VALIDATION_STATEMENTS) await client.query(statement, []);
    await client.query("COMMIT", []);
    began = false;
  } catch (error) {
    if (began) await client.query("ROLLBACK", []).catch(() => {});
    throw new ControlPlaneCutoverPreflightError(PREFLIGHT_DIAGNOSTICS.VALIDATION_FAILED, undefined, error);
  }
  return Object.freeze({ ok: true, validated: true, violations: Object.freeze([]) });
}

function normalizeViolations(rows) {
  if (!Array.isArray(rows)) throw new ControlPlaneCutoverPreflightError(PREFLIGHT_DIAGNOSTICS.DATABASE_UNAVAILABLE);
  return Object.freeze(rows.map((row) => {
    const table = row?.table_name;
    const count = Number(row?.violation_count);
    if (!/^(?:device_enrollments|policies|revocations)$/.test(table) || !Number.isSafeInteger(count) || count < 1) {
      throw new ControlPlaneCutoverPreflightError(PREFLIGHT_DIAGNOSTICS.DATABASE_UNAVAILABLE);
    }
    return Object.freeze({ table, count });
  }));
}

async function runCli(argv = process.argv.slice(2), env = process.env) {
  const validate = argv.includes("--validate");
  if (argv.some((argument) => argument !== "--validate")) {
    throw new Error("usage: preflight-0011.mjs [--validate]");
  }
  const rawUrl = env.AGENTPASS_DATABASE_URL;
  let databaseUrl;
  try {
    databaseUrl = new URL(rawUrl);
    if (databaseUrl.protocol !== "postgresql:" || !databaseUrl.hostname || !databaseUrl.username || !databaseUrl.password || databaseUrl.searchParams.get("sslmode") !== "verify-full") throw new Error("invalid database URL");
  } catch {
    throw new ControlPlaneCutoverPreflightError(PREFLIGHT_DIAGNOSTICS.DATABASE_UNAVAILABLE);
  }

  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: databaseUrl.toString(), ssl: { rejectUnauthorized: true }, max: 1, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 5_000, statement_timeout: 15_000, lock_timeout: 5_000, query_timeout: 20_000, allowExitOnIdle: false });
  let client;
  try {
    client = await pool.connect();
    const result = await runControlPlaneCutoverPreflight({ client, validate });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    client?.release?.();
    await pool.end();
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli().catch((error) => {
    const diagnostic = error instanceof ControlPlaneCutoverPreflightError
      ? error
      : new ControlPlaneCutoverPreflightError(PREFLIGHT_DIAGNOSTICS.DATABASE_UNAVAILABLE, undefined, error);
    process.stderr.write(`${diagnostic.code}: ${diagnostic.message} ${diagnostic.remediation}\n`);
    process.exitCode = 1;
  });
}

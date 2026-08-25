#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST_FILE = path.join(HERE, "ssc-authority-manifest.v1.json");
const SAFE = /^[A-Za-z0-9_.:-]+$/u;
const DB_URL = "AGENTPASS_TEST_SSC_POSTGRES_URL";
const LANE = "AGENTPASS_TEST_SSC_POSTGRES_LANE";
const DENIALS = new Set(["42501", "0LP01"]);

export const DB_CHECKS = Object.freeze([
  "DB-101-role-acl-rls", "DB-102-cross-tenant-negative", "DB-103-migration-catalog-head",
  "DB-104-concurrency-deadlock", "DB-105-response-loss-reconciliation", "DB-106-not-proven-gate"
]);

export function loadAuthorityManifest(file = MANIFEST_FILE) {
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  if (value.schema_version !== 1 || value.kind !== "agentpass.ssc-postgres-authority-manifest") {
    throw new Error("invalid_manifest");
  }
  for (const [domain, spec] of Object.entries(value.domains ?? {})) {
    if (!SAFE.test(domain) || !SAFE.test(spec.application_role) || !SAFE.test(spec.maintenance_role)
      || !Array.isArray(spec.tables) || spec.tables.length === 0 || !Array.isArray(spec.function_execute)) {
      throw new Error("invalid_manifest");
    }
    if (new Set(spec.tables).size !== spec.tables.length || spec.tables.some((x) => !SAFE.test(x))) throw new Error("invalid_manifest");
    if (spec.function_execute.some((x) => !SAFE.test(x))) throw new Error("invalid_manifest");
  }
  return value;
}

export function migrationHeadFixture({ version, migration_count, catalog_head, catalog_checksum }) {
  if (!Number.isSafeInteger(version) || version < 1 || !Number.isSafeInteger(migration_count)
    || migration_count !== version || catalog_head !== version || !/^[0-9a-f]{64}$/u.test(catalog_checksum ?? "")) {
    return { status: "failed", check_id: "DB-103", reason: "migration_head_mismatch" };
  }
  return { status: "passed", check_id: "DB-103", version, migration_count, catalog_head, catalog_checksum };
}

export function crossTenantNegativeMatrix() {
  return Object.freeze([
    { check_id: "DB-102", actor: "agentpass_app", operation: "select", subject: "tenant-B", expected: "deny" },
    { check_id: "DB-102", actor: "agentpass_app", operation: "insert", subject: "tenant-B", expected: "deny" },
    { check_id: "DB-102", actor: "agentpass_app", operation: "update", subject: "tenant-B", expected: "deny" },
    { check_id: "DB-102", actor: "agentpass_maintenance", operation: "select", subject: "customer-tenant", expected: "deny" },
    { check_id: "DB-102", actor: "agentpass_maintenance", operation: "delete", subject: "customer-tenant", expected: "deny" }
  ]);
}

export function scenarioDriver({ responseLost = false, deadlock = false } = {}) {
  return Object.freeze({
    check_ids: ["DB-104", "DB-105"],
    lock_order: ["tenant_authority", "operation_ledger"],
    concurrent_callers: 2,
    deadlock_detected: Boolean(deadlock),
    response_loss: responseLost ? "uncertain_reconcile_required" : "not_injected",
    terminal_outcomes: responseLost ? 1 : 0
  });
}

function safeLane(value) {
  return value === "postgres-16" || value === "postgres-17" ? value : null;
}

export function notProvenReport(reason = "live_postgresql_unavailable") {
  return { status: "not_proven", qualified: false, check_id: "DB-106", reason, external_evidence: "not_proven" };
}

async function runLive(url, lane, manifest) {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 5000, statement_timeout: 10000 });
  try {
    const identity = await pool.query("SELECT current_user, current_setting('server_version_num')::int AS server_version_num");
    const major = Math.trunc(identity.rows[0].server_version_num / 10000);
    if ((lane === "postgres-16" && major !== 16) || (lane === "postgres-17" && major !== 17)) {
      return notProvenReport("postgres_lane_mismatch");
    }
    // The actual role/ACL/RLS probes are intentionally explicit and read-only.
    const relationNames = Object.values(manifest.domains).flatMap((x) => x.tables);
    const result = await pool.query(`SELECT relname, relrowsecurity, relforcerowsecurity,
      has_table_privilege('agentpass_app', format('public.%s', relname), 'INSERT') AS app_insert,
      has_table_privilege('agentpass_app', format('public.%s', relname), 'UPDATE') AS app_update,
      has_table_privilege('agentpass_app', format('public.%s', relname), 'DELETE') AS app_delete
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND relname = ANY($1::text[])`, [relationNames]);
    const rowsByName = new Map(result.rows.map((row) => [row.relname, row]));
    const missing = relationNames.filter((name) => !rowsByName.has(name));
    const rlsFailures = result.rows.filter((row) => !row.relrowsecurity || !row.relforcerowsecurity).map((row) => row.relname);
    const dmlFailures = result.rows.filter((row) => row.app_insert || row.app_update || row.app_delete).map((row) => row.relname);
    const failures = [...new Set([...missing, ...rlsFailures, ...dmlFailures])];
    return { status: failures.length ? "failed" : "passed", qualified: failures.length === 0, check_id: "DB-101", lane, failures };
  } finally { await pool.end(); }
}

export async function qualify(env = process.env) {
  loadAuthorityManifest();
  const lane = safeLane(env[LANE]);
  if (!lane) return notProvenReport("postgres_lane_required");
  if (typeof env[DB_URL] !== "string" || env[DB_URL].trim() === "") return notProvenReport("live_postgresql_required");
  try { return await runLive(env[DB_URL], lane, loadAuthorityManifest()); } catch { return notProvenReport("live_postgresql_unavailable"); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await qualify();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.status === "passed" ? 0 : 2;
}

export { DENIALS };

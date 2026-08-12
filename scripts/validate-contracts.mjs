import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const contracts = path.join(root, "contracts");

function fail(message) {
  process.stderr.write(`contract validation failed: ${message}\n`);
  process.exitCode = 1;
}

function readJson(relative) {
  const absolute = path.join(contracts, relative);
  const text = fs.readFileSync(absolute, "utf8");
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${relative} must contain an object`);
  return parsed;
}

const schemaFiles = fs.readdirSync(path.join(contracts, "schemas")).filter((name) => name.endsWith(".schema.json")).sort();
const schemaIds = new Set();
for (const name of schemaFiles) {
  const schema = readJson(path.join("schemas", name));
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") fail(`${name} must use JSON Schema 2020-12`);
  if (typeof schema.$id !== "string" || schemaIds.has(schema.$id)) fail(`${name} has a missing or duplicate $id`);
  schemaIds.add(schema.$id);
  if (schema.type !== "object" || schema.additionalProperties !== false) fail(`${name} must reject unknown top-level fields`);
}

for (const name of ["human-v1.json", "device-v1.json"]) {
  const document = readJson(path.join("openapi", name));
  if (document.openapi !== "3.1.0") fail(`${name} must use OpenAPI 3.1.0`);
  if (!document.paths || Object.keys(document.paths).length === 0) fail(`${name} must declare paths`);
  const operationIds = [];
  for (const methods of Object.values(document.paths)) {
    for (const method of ["get", "post", "patch", "put", "delete"]) {
      if (methods[method]) operationIds.push(methods[method].operationId);
    }
  }
  if (operationIds.some((id) => typeof id !== "string") || new Set(operationIds).size !== operationIds.length) fail(`${name} operationId values must be present and unique`);
}

const enrollment = readJson("fixtures/device-enrollment.valid.json");
if (enrollment.version !== 1 || enrollment.platform !== "macos" || enrollment.device_key?.algorithm !== "p256-sha256") fail("device enrollment fixture does not represent the native macOS profile");
if (/PRIVATE KEY/.test(JSON.stringify(enrollment))) fail("device enrollment fixture contains private key material");

const acknowledgement = readJson("fixtures/bundle-ack.valid.json");
if (acknowledgement.format_epoch !== 2 || acknowledgement.status !== "applied" || !/^[0-9a-f]{64}$/.test(acknowledgement.statement_hash)) fail("bundle acknowledgement fixture is invalid");

const doctor = readJson("fixtures/doctor-report.valid.json");
if (doctor.schema_version !== 1 || !["healthy", "action_required", "degraded", "blocked"].includes(doctor.state) || doctor.ok !== (doctor.state === "healthy")) fail("doctor report fixture has inconsistent status");
if (!Array.isArray(doctor.checks) || doctor.checks.length === 0 || new Set(doctor.checks.map((item) => item.id)).size !== doctor.checks.length) fail("doctor report fixture checks are missing or duplicated");
if (doctor.checks.length !== Object.values(doctor.summary ?? {}).reduce((total, value) => total + value, 0)) fail("doctor report fixture summary does not match its checks");

const auditList = readJson("fixtures/device-audit-list.valid.json");
const auditRecord = auditList.events?.[0];
if (!Array.isArray(auditList.events) || auditList.events.length > 500 || !Object.hasOwn(auditList, "next_cursor")) fail("device audit list fixture has an invalid page envelope");
const publicAuditRecordKeys = ["device_id", "event", "event_id", "organization_id", "received_at"];
if (!auditRecord || JSON.stringify(Object.keys(auditRecord).sort()) !== JSON.stringify(publicAuditRecordKeys) || auditRecord.event_id !== auditRecord.event?.event_id || auditRecord.device_id !== "33333333-3333-4333-8333-333333333333") fail("device audit list fixture does not match the exact public record shape");
if (Object.hasOwn(auditRecord, "chain_status") || Object.hasOwn(auditRecord, "ingested_at")) fail("device audit list fixture leaks source-specific or health fields");
if (auditList.next_cursor !== null && !/^[A-Za-z0-9_-]{1,512}$/.test(auditList.next_cursor ?? "")) fail("device audit list fixture cursor is invalid");

const migrationNames = fs.readdirSync(path.join(contracts, "postgres")).filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name)).sort();
if (migrationNames.length < 1 || migrationNames.some((name, index) => Number(name.slice(0, 4)) !== index + 1)) fail("PostgreSQL migrations must be gap-free and ordered from 0001");
const migrations = migrationNames.map((name) => ({ name, sql: fs.readFileSync(path.join(contracts, "postgres", name), "utf8") }));
for (const migration of migrations) {
  if (!migration.sql.trim().startsWith("BEGIN;") || !migration.sql.trim().endsWith("COMMIT;")) fail(`${migration.name} must be transactional`);
  if (/\b(?:DROP\s+(?:TABLE|COLUMN)|TRUNCATE)\b/i.test(migration.sql)) fail(`${migration.name} contains a destructive statement`);
}
const sql = migrations[0].sql;
for (const table of ["organizations", "memberships", "human_sessions", "webauthn_credentials", "devices", "device_enrollments", "agents", "policies", "revocations", "capabilities", "bundle_heads", "bundle_acknowledgements", "device_audit_events", "idempotency_records", "admin_audit_events"]) {
  if (!new RegExp(`CREATE TABLE ${table} \\(`).test(sql)) fail(`PostgreSQL migration is missing ${table}`);
}
if (!/FOREIGN KEY \(organization_id, device_id\)/.test(sql)) fail("PostgreSQL migration must enforce tenant-qualified device references");
if (!/CREATE TABLE webauthn_challenges \(/.test(migrations.map((item) => item.sql).join("\n"))) fail("PostgreSQL migrations must persist one-time WebAuthn challenges");
if (!migrations.some((migration) => /CREATE INDEX device_audit_events_activity_keyset[\s\S]*redacted_json\s*->>\s*'device_timestamp'[\s\S]*event_id DESC/i.test(migration.sql))) fail("PostgreSQL migrations must index the device audit activity keyset");

if (!process.exitCode) process.stdout.write(`validated ${schemaFiles.length} schemas, 2 OpenAPI documents, 4 fixtures, and ${migrations.length} PostgreSQL migrations\n`);

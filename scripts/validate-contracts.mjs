import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const contracts = path.join(root, "contracts");
const SAFE_INTEGER_MAX = Number.MAX_SAFE_INTEGER;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const REFRESH_HINT_KEYS = ["authority_generation", "device_id", "expires_at", "key_id", "nonce", "organization_id", "published_at", "signature", "signature_algorithm", "type", "version"];
const BUNDLE_ACK_KEYS = ["device_id", "device_key_epoch", "format_epoch", "nonce", "observed_at", "organization_id", "result", "sequence", "signature", "signature_algorithm", "statement_hash", "type", "version"];
const REASON_CODES = new Set([
  "bundle_expired",
  "bundle_not_yet_valid",
  "bundle_signature_invalid",
  "bundle_signer_untrusted",
  "bundle_audience_mismatch",
  "bundle_sequence_rollback",
  "bundle_sequence_conflict",
  "bundle_storage_failed",
  "device_revoked",
  "emergency_stop",
  "internal_error"
]);

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

function exactKeys(value, expected, label) {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) fail(`${label} has an unexpected field set`);
}

function isCanonicalTimestamp(value) {
  if (typeof value !== "string" || !CANONICAL_TIMESTAMP.test(value)) return false;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString() === value;
}

function isCanonicalBase64Url(value, byteLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === byteLength && decoded.toString("base64url") === value;
  } catch {
    return false;
  }
}

function isSafePositiveInteger(value) {
  return Number.isSafeInteger(value) && value >= 1 && value <= SAFE_INTEGER_MAX;
}

function hasSecretMaterial(value) {
  return /PRIVATE KEY|private_key|secret|access_token|bearer/i.test(JSON.stringify(value));
}

function assertSignedEnvelopeBasics(value, label) {
  if (!UUID.test(value.organization_id) || !UUID.test(value.device_id)) fail(`${label} fixture identifiers are invalid`);
  if (!isCanonicalTimestamp(value.observed_at ?? value.published_at) || (value.expires_at !== undefined && !isCanonicalTimestamp(value.expires_at))) fail(`${label} fixture timestamps are invalid`);
  if (!isCanonicalBase64Url(value.nonce, 16) || !isCanonicalBase64Url(value.signature, 64)) fail(`${label} fixture signatures are not canonical base64url`);
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

const fixtureFiles = fs.readdirSync(path.join(contracts, "fixtures")).filter((name) => name.endsWith(".valid.json")).sort();
if (fixtureFiles.length !== 5) fail(`expected 5 positive fixtures, found ${fixtureFiles.length}`);
for (const name of ["bundle-ack.valid.json", "device-audit-list.valid.json", "device-enrollment.valid.json", "doctor-report.valid.json", "refresh-hint.valid.json"]) {
  if (!fixtureFiles.includes(name)) fail(`missing required positive fixture ${name}`);
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
exactKeys(acknowledgement, BUNDLE_ACK_KEYS, "bundle acknowledgement fixture");
assertSignedEnvelopeBasics(acknowledgement, "bundle acknowledgement");
if (acknowledgement.version !== 1 || acknowledgement.type !== "agentpass.bundle-ack" || !isSafePositiveInteger(acknowledgement.device_key_epoch) || acknowledgement.device_key_epoch !== 3 || acknowledgement.format_epoch !== 2 || !isSafePositiveInteger(acknowledgement.sequence) || acknowledgement.sequence !== 7 || !/^[0-9a-f]{64}$/.test(acknowledgement.statement_hash) || acknowledgement.result !== "applied" || acknowledgement.signature_algorithm !== "p256-sha256" || Object.hasOwn(acknowledgement, "reason_code")) fail("bundle acknowledgement fixture is invalid");

const refreshHint = readJson("fixtures/refresh-hint.valid.json");
exactKeys(refreshHint, REFRESH_HINT_KEYS, "refresh hint fixture");
assertSignedEnvelopeBasics({ ...refreshHint, observed_at: refreshHint.published_at }, "refresh hint");
const refreshLifetimeMs = new Date(refreshHint.expires_at).getTime() - new Date(refreshHint.published_at).getTime();
if (refreshHint.version !== 1 || refreshHint.type !== "agentpass.refresh-hint" || !isSafePositiveInteger(refreshHint.authority_generation) || refreshHint.authority_generation !== 42 || typeof refreshHint.key_id !== "string" || !SAFE_IDENTIFIER.test(refreshHint.key_id) || refreshHint.key_id !== "authority-v1" || refreshHint.signature_algorithm !== "ed25519" || refreshLifetimeMs <= 0 || refreshLifetimeMs > 5 * 60 * 1000) fail("refresh hint fixture has an invalid generation or time window");
if (["authority", "policy", "policy_scope", "capability", "capability_id", "capabilities"].some((field) => Object.hasOwn(refreshHint, field)) || hasSecretMaterial(refreshHint)) fail("refresh hint fixture contains authority, policy, capability, or secret material");
if (hasSecretMaterial(acknowledgement)) fail("bundle acknowledgement fixture contains secret material");

const acknowledgementSchema = readJson("schemas/bundle-ack-v1.schema.json");
if (JSON.stringify(acknowledgementSchema.properties.reason_code?.enum) !== JSON.stringify([...REASON_CODES])) fail("bundle acknowledgement schema reason codes are out of contract");

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

if (!process.exitCode) process.stdout.write(`validated ${schemaFiles.length} schemas, 2 OpenAPI documents, ${fixtureFiles.length} fixtures, and ${migrations.length} PostgreSQL migrations\n`);

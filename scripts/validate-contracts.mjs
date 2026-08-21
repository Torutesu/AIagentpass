import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const root = path.resolve(process.env.AGENTPASS_REPOSITORY_ROOT ?? repositoryRoot);
const contracts = path.resolve(process.env.AGENTPASS_CONTRACTS_DIR ?? path.join(root, "contracts"));
const catalogPath = path.join(contracts, "catalog-v1.json");
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
const PROMOTED_SCHEMA_FIXTURES = Object.freeze({
  "organization-v1.schema.json": "organization.valid.json",
  "membership-v1.schema.json": "membership.valid.json",
  "invitation-v1.schema.json": "invitation.valid.json",
  "webauthn-credential-v1.schema.json": "webauthn-credential.valid.json",
  "webauthn-ceremony-v1.schema.json": "webauthn-ceremony.valid.json",
  "recent-authorization-v1.schema.json": "recent-authorization.valid.json",
  "policy-v1.schema.json": "policy.valid.json",
  "capability-v1.schema.json": "capability.valid.json",
  "control-bundle-v2.schema.json": "control-bundle.valid.json",
  "audit-anchor-v1.schema.json": "audit-anchor.valid.json",
  "purge-authorization-v1.schema.json": "purge-authorization.valid.json",
  "purge-receipt-v1.schema.json": "purge-receipt.valid.json",
  "promotion-evidence-v1.schema.json": "promotion-evidence.valid.json",
  "promotion-evidence-v2.schema.json": "promotion-evidence-v2.valid.json",
  "promotion-evidence-v3.schema.json": "promotion-evidence-v3.valid.json",
  "deployment-attestation-v1.schema.json": "deployment-attestation-v1.valid.json",
  "deployment-attestation-trust-v1.schema.json": "deployment-attestation-trust-v1.valid.json",
  "database-schema-evidence-v1.schema.json": "database-schema-evidence-v1.valid.json",
  "platform-auth-qualification-v1.schema.json": "platform-auth-qualification.valid.json"
});
const BASELINE_SCHEMA_FIXTURES = Object.freeze({
  "bundle-ack-v1.schema.json": "bundle-ack.valid.json",
  "device-audit-list-v1.schema.json": "device-audit-list.valid.json",
  "device-enrollment-v1.schema.json": "device-enrollment.valid.json",
  "device-possession-receipt-verification-v1.schema.json": "device-possession-receipt-verification.valid.json",
  "doctor-report-v1.schema.json": "doctor-report.valid.json",
  "refresh-hint-v1.schema.json": "refresh-hint.valid.json"
});
const SCHEMA_FIXTURES = Object.freeze({ ...BASELINE_SCHEMA_FIXTURES, ...PROMOTED_SCHEMA_FIXTURES });

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
const schemas = new Map();
for (const name of schemaFiles) {
  const schema = readJson(path.join("schemas", name));
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") fail(`${name} must use JSON Schema 2020-12`);
  if (typeof schema.$id !== "string" || schemaIds.has(schema.$id)) fail(`${name} has a missing or duplicate $id`);
  schemaIds.add(schema.$id);
  if (schema.type !== "object" || schema.additionalProperties !== false) fail(`${name} must reject unknown top-level fields`);
  schemas.set(name, schema);
}

const schemaValidator = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(schemaValidator);
schemaValidator.addKeyword({ keyword: "x-agentpass-binding", schemaType: "object", valid: true });
for (const schema of schemas.values()) schemaValidator.addSchema(schema);

const fixtureFiles = fs.readdirSync(path.join(contracts, "fixtures")).filter((name) => name.endsWith(".valid.json")).sort();
const baselineFixtureNames = Object.values(BASELINE_SCHEMA_FIXTURES);
const expectedFixtureNames = Object.values(SCHEMA_FIXTURES).sort();
if (JSON.stringify(fixtureFiles) !== JSON.stringify(expectedFixtureNames)) fail(`positive fixture inventory is out of contract: expected ${expectedFixtureNames.length}, found ${fixtureFiles.length}`);
for (const name of baselineFixtureNames) {
  if (!fixtureFiles.includes(name)) fail(`missing required positive fixture ${name}`);
}
for (const [schemaName, fixtureName] of Object.entries(SCHEMA_FIXTURES)) {
  if (!schemaFiles.includes(schemaName)) fail(`missing promoted schema ${schemaName}`);
  if (!fixtureFiles.includes(fixtureName)) fail(`missing promoted fixture ${fixtureName}`);
  if (!schemaFiles.includes(schemaName) || !fixtureFiles.includes(fixtureName)) continue;
  const schema = schemas.get(schemaName);
  const fixture = readJson(path.join("fixtures", fixtureName));
  const allowed = new Set(Object.keys(schema.properties ?? {}));
  const required = new Set(schema.required ?? []);
  if (Object.keys(fixture).some((key) => !allowed.has(key))) fail(`${fixtureName} contains a field outside ${schemaName}`);
  if ([...required].some((key) => !Object.hasOwn(fixture, key))) fail(`${fixtureName} is missing a required field from ${schemaName}`);
  if (hasSecretMaterial(fixture)) fail(`${fixtureName} contains secret material`);
  const validate = schemaValidator.getSchema(schema.$id);
  if (!validate || !validate(fixture)) fail(`${fixtureName} does not satisfy ${schemaName}: ${schemaValidator.errorsText(validate?.errors, { separator: "; " })}`);
}

for (const name of ["human-v1.json", "device-v1.json", "operations-v1.json"]) {
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
  // A statement-level BEFORE TRUNCATE trigger is a protective constraint, not
  // a destructive migration operation. Remove only that grammar before
  // checking for executable DROP/TRUNCATE statements; an actual TRUNCATE
  // command remains rejected.
  const migrationWithoutComments = migration.sql.replace(/--[^\r\n]*/gu, "").replace(/\/\*[\s\S]*?\*\//gu, "");
  const migrationWithoutProtectiveTruncateTrigger = migrationWithoutComments
    .replace(/\bBEFORE\s+TRUNCATE\s+ON\b/giu, "BEFORE ON")
    .replace(/\bREVOKE\s+TRUNCATE\s+ON\b/giu, "REVOKE ON");
  if (/\b(?:DROP\s+(?:TABLE|COLUMN)|TRUNCATE)\b/i.test(migrationWithoutProtectiveTruncateTrigger)) fail(`${migration.name} contains a destructive statement`);
}
const sql = migrations[0].sql;
for (const table of ["organizations", "memberships", "human_sessions", "webauthn_credentials", "devices", "device_enrollments", "agents", "policies", "revocations", "capabilities", "bundle_heads", "bundle_acknowledgements", "device_audit_events", "idempotency_records", "admin_audit_events"]) {
  if (!new RegExp(`CREATE TABLE ${table} \\(`).test(sql)) fail(`PostgreSQL migration is missing ${table}`);
}
if (!/FOREIGN KEY \(organization_id, device_id\)/.test(sql)) fail("PostgreSQL migration must enforce tenant-qualified device references");
if (!/CREATE TABLE webauthn_challenges \(/.test(migrations.map((item) => item.sql).join("\n"))) fail("PostgreSQL migrations must persist one-time WebAuthn challenges");
if (!migrations.some((migration) => /CREATE INDEX device_audit_events_activity_keyset[\s\S]*redacted_json\s*->>\s*'device_timestamp'[\s\S]*event_id DESC/i.test(migration.sql))) fail("PostgreSQL migrations must index the device audit activity keyset");

function catalogEntryKey(entry) {
  return [entry.kind, entry.source, entry.method ?? "", entry.path ?? "", entry.operation_id ?? ""].join("|");
}

function containsKey(value, key) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => containsKey(item, key));
  return Object.entries(value).some(([name, child]) => name === key || containsKey(child, key));
}

function validateExactKeys(value, allowed, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return;
  const actual = Object.keys(value).sort();
  const expected = [...allowed].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${label} has an unexpected field set`);
}

function resolveReference(reference) {
  if (typeof reference !== "string" || reference.length === 0 || path.isAbsolute(reference)) return null;
  const fileReference = reference.split("#", 1)[0];
  const resolved = path.resolve(root, fileReference);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) return null;
  return resolved;
}

function validateCatalogBinding(binding, label, requiredWhenDetected = false, requireSource = false) {
  const sources = ["document", "transport", "runtime", "session", "database", "none"];
  const sourceIsValid = requireSource ? sources.includes(binding?.source) : binding?.source === undefined || sources.includes(binding.source);
  if (!binding || typeof binding !== "object" || Array.isArray(binding) || typeof binding.required !== "boolean" || !sourceIsValid || !Array.isArray(binding.paths) || binding.paths.some((item) => typeof item !== "string" || item.length === 0)) {
    fail(`${label} must declare a binding source, boolean required flag, and string paths`);
    return;
  }
  validateExactKeys(binding, requireSource ? ["required", "source", "paths"] : ["required", "paths"], label);
  if (binding.required && binding.paths.length === 0) fail(`${label} requires at least one binding path`);
  if (binding.source === "none" && (binding.required || binding.paths.length > 0)) fail(`${label} none source cannot carry a binding`);
  if (binding.source !== "none" && binding.required && binding.paths.length === 0) fail(`${label} binding source requires a path`);
  if (binding.source === "runtime" && binding.paths.some((item) => !item.startsWith("runtime."))) fail(`${label} runtime paths must use the runtime prefix`);
  if (binding.source === "session" && binding.paths.some((item) => !item.startsWith("session."))) fail(`${label} session paths must use the session prefix`);
  if (binding.source === "database" && binding.paths.some((item) => !item.startsWith("tables."))) fail(`${label} database paths must use the tables prefix`);
  if (binding.source === "transport" && binding.paths.some((item) => !item.startsWith("path.") && !item.startsWith("transport."))) fail(`${label} transport paths must identify path or transport authority`);
  if (requiredWhenDetected && !binding.required) fail(`${label} is missing a required tenant binding`);
}

function validateCatalogPolicy(entry, effective) {
  const label = `catalog entry ${entry.id}`;
  if (!["cloud", "device", "human"].includes(effective.authority_owner)) fail(`${label} has an invalid authority owner`);
  validateCatalogBinding(effective.tenant_binding, `${label}.tenant_binding`, entry.kind === "openapi-operation" && entry.path.includes("{organization_id}"), true);
  validateCatalogBinding(effective.actor_binding, `${label}.actor_binding`);
  if (!effective.signature || typeof effective.signature !== "object" || typeof effective.signature.signed !== "boolean") fail(`${label} must declare signature metadata`);
  else if (effective.signature.signed) {
    validateExactKeys(effective.signature, ["signed", "algorithm", "domain"], `${label}.signature`);
    if (typeof effective.signature.algorithm !== "string" || effective.signature.algorithm.length === 0 || typeof effective.signature.domain !== "string" || effective.signature.domain.length === 0) fail(`${label} signed contract must declare algorithm and signature domain`);
  } else {
    validateExactKeys(effective.signature, ["signed", "algorithm", "domain"], `${label}.signature`);
    if (effective.signature.algorithm !== null || effective.signature.domain !== null) fail(`${label} unsigned contract must not declare a signature domain`);
  }
  validateExactKeys(effective.idempotency, ["required", "key_paths", "scope", "replay"], `${label}.idempotency`);
  if (!effective.idempotency || typeof effective.idempotency !== "object" || typeof effective.idempotency.required !== "boolean" || !Array.isArray(effective.idempotency.key_paths) || effective.idempotency.key_paths.some((item) => typeof item !== "string" || item.length === 0)) fail(`${label} must declare idempotency metadata`);
  else if (effective.idempotency.required && (effective.idempotency.key_paths.length === 0 || typeof effective.idempotency.scope !== "string" || effective.idempotency.scope.length === 0 || typeof effective.idempotency.replay !== "string" || effective.idempotency.replay.length === 0)) fail(`${label} required idempotency must declare keys, scope, and replay behavior`);
  validateExactKeys(effective.expiry, ["required", "paths", "rule"], `${label}.expiry`);
  if (!effective.expiry || typeof effective.expiry !== "object" || typeof effective.expiry.required !== "boolean" || !Array.isArray(effective.expiry.paths) || effective.expiry.paths.some((item) => typeof item !== "string" || item.length === 0) || typeof effective.expiry.rule !== "string" || effective.expiry.rule.length === 0) fail(`${label} must declare expiry metadata`);
  else if (effective.expiry.required && effective.expiry.paths.length === 0) fail(`${label} required expiry must declare paths`);
  if (!Array.isArray(entry.implementation_refs) || entry.implementation_refs.length === 0) fail(`${label} must declare implementation references`);
  if (!Array.isArray(entry.compatibility_fixtures) || entry.compatibility_fixtures.length === 0) fail(`${label} must declare compatibility fixtures`);
  for (const field of ["implementation_refs", "compatibility_fixtures"]) {
    for (const reference of entry[field] ?? []) {
      const resolved = resolveReference(reference);
      if (!resolved || !fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) fail(`${label} references an absent or invalid ${field} file: ${reference}`);
    }
  }
}

function validateContractCatalog() {
  const catalog = readJson("catalog-v1.json");
  validateExactKeys(catalog, ["$schema", "$id", "title", "description", "catalog_id", "catalog_version", "status", "authority_owners", "profiles", "entries"], "catalog");
  if (catalog.catalog_id !== "agentpass.contract-catalog" || catalog.catalog_version !== 1 || catalog.status !== "frozen") fail("catalog must be the frozen AgentPass v1 catalog");
  if (JSON.stringify(catalog.authority_owners) !== JSON.stringify(["cloud", "device", "human"])) fail("catalog authority owners are out of contract");
  if (!catalog.profiles || typeof catalog.profiles !== "object" || Array.isArray(catalog.profiles)) fail("catalog profiles are missing");
  for (const [name, profile] of Object.entries(catalog.profiles)) {
    if (!/^[a-z0-9-]+$/.test(name)) fail(`catalog profile name is invalid: ${name}`);
    validateExactKeys(profile, ["authority_owner", "tenant_binding", "actor_binding", "signature", "idempotency", "expiry"], `catalog profile ${name}`);
    validateCatalogBinding(profile.tenant_binding, `catalog profile ${name}.tenant_binding`, false, true);
    validateCatalogBinding(profile.actor_binding, `catalog profile ${name}.actor_binding`);
    validateExactKeys(profile.signature, ["signed", "algorithm", "domain"], `catalog profile ${name}.signature`);
    validateExactKeys(profile.idempotency, ["required", "key_paths", "scope", "replay"], `catalog profile ${name}.idempotency`);
    validateExactKeys(profile.expiry, ["required", "paths", "rule"], `catalog profile ${name}.expiry`);
    if (!profile.signature || typeof profile.signature.signed !== "boolean") fail(`catalog profile ${name} has invalid signature metadata`);
    if (!profile.idempotency || typeof profile.idempotency.required !== "boolean" || !Array.isArray(profile.idempotency.key_paths)) fail(`catalog profile ${name} has invalid idempotency metadata`);
    if (!profile.expiry || typeof profile.expiry.required !== "boolean" || !Array.isArray(profile.expiry.paths)) fail(`catalog profile ${name} has invalid expiry metadata`);
  }
  if (!Array.isArray(catalog.entries) || catalog.entries.length === 0) fail("catalog entries are missing");

  const expected = new Map();
  for (const name of schemaFiles) {
    const schema = readJson(path.join("schemas", name));
    const versionMatch = name.match(/-v(\d+)\.schema\.json$/);
    expected.set(["json-schema", `schemas/${name}`, "", "", ""].join("|"), { kind: "json-schema", source: `schemas/${name}`, version: Number(versionMatch?.[1] ?? schema.properties?.version?.const ?? schema.properties?.schema_version?.const ?? 0), requiresTenant: containsKey(schema, "organization_id"), document: schema });
  }
  for (const name of ["device-v1.json", "human-v1.json", "platform-promotion-v1.json"]) {
    const document = readJson(path.join("openapi", name));
    for (const [route, methods] of Object.entries(document.paths)) {
      for (const method of ["get", "post", "patch", "put", "delete"]) {
        const operation = methods[method];
        if (!operation) continue;
        const expectedEntry = { kind: "openapi-operation", source: `openapi/${name}`, method: method.toUpperCase(), path: route, operation_id: operation.operationId, version: Number(name.match(/-v(\d+)\.json$/)?.[1] ?? 0), requiresTenant: route.includes("{organization_id}") };
        expected.set(catalogEntryKey(expectedEntry), expectedEntry);
      }
    }
  }
  for (const name of migrationNames) {
    const migration = migrations.find((item) => item.name === name);
    const version = Number(name.slice(0, 4));
    expected.set(["postgres-migration", `postgres/${name}`, "", "", ""].join("|"), { kind: "postgres-migration", source: `postgres/${name}`, version, requiresTenant: /\borganization_id\b/.test(migration.sql) });
  }

  const seenKeys = new Set();
  const ids = new Set();
  const purposes = new Set();
  for (const entry of catalog.entries) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      fail("catalog contains a non-object entry");
      continue;
    }
    const allowedKeys = ["id", "kind", "source", "method", "path", "operation_id", "version", "profile", "purpose", "implementation_status", "authority_owner", "tenant_binding", "actor_binding", "signature", "idempotency", "expiry", "implementation_refs", "compatibility_fixtures"];
    if (JSON.stringify(Object.keys(entry).sort()) !== JSON.stringify([...allowedKeys].filter((key) => Object.hasOwn(entry, key)).sort())) fail(`catalog entry ${entry.id ?? "<unknown>"} has an unexpected field set`);
    if (typeof entry.id !== "string" || entry.id.length === 0) fail("catalog entry id is missing");
    else if (ids.has(entry.id)) fail(`catalog contains a duplicate id: ${entry.id}`);
    else ids.add(entry.id);
    if (seenKeys.has(catalogEntryKey(entry))) fail(`catalog contains a duplicate entry: ${catalogEntryKey(entry)}`);
    seenKeys.add(catalogEntryKey(entry));
    const expectedEntry = expected.get(catalogEntryKey(entry));
    if (!expectedEntry) {
      fail(`catalog contains an unknown or malformed source entry: ${catalogEntryKey(entry)}`);
      continue;
    }
    if (entry.version !== expectedEntry.version) fail(`${entry.id} has version ${entry.version}, expected ${expectedEntry.version}`);
    if (typeof entry.profile !== "string" || !catalog.profiles[entry.profile]) fail(`${entry.id} references an unknown profile`);
    if (typeof entry.purpose !== "string" || entry.purpose.length === 0) fail(`${entry.id} must declare a purpose`);
    if (entry.implementation_status !== undefined && !["implemented", "specified"].includes(entry.implementation_status)) fail(`${entry.id} has an invalid implementation status`);
    if (purposes.has(entry.purpose)) fail(`catalog contains a duplicate purpose: ${entry.purpose}`);
    purposes.add(entry.purpose);
    const profile = catalog.profiles[entry.profile] ?? {};
    const effective = { ...profile };
    for (const key of ["authority_owner", "tenant_binding", "actor_binding", "signature", "idempotency", "expiry"]) if (Object.hasOwn(entry, key)) effective[key] = entry[key];
    validateCatalogPolicy(entry, effective);
    validateCatalogBinding(effective.tenant_binding, `${entry.id}.tenant_binding`, expectedEntry.requiresTenant, true);
    if (entry.kind === "json-schema" && effective.tenant_binding.source === "document") {
      for (const bindingPath of effective.tenant_binding.paths) {
        const key = bindingPath.split(".").at(-1);
        if (!containsKey(expectedEntry.document, key)) fail(`${entry.id}.tenant_binding path is absent from its JSON Schema: ${bindingPath}`);
      }
    }
  }
  for (const [key, expectedEntry] of expected) if (!seenKeys.has(key)) fail(`catalog is missing an entry for ${key}`);
  if (!process.exitCode) process.stdout.write(`validated frozen contract catalog: ${catalog.entries.length} entries (${schemaFiles.length} schemas, ${expected.size - schemaFiles.length - migrationNames.length} OpenAPI operations, ${migrationNames.length} migrations)\n`);
}

validateContractCatalog();

if (!process.exitCode) process.stdout.write(`validated ${schemaFiles.length} schemas, 3 OpenAPI documents, ${fixtureFiles.length} fixtures, and ${migrations.length} PostgreSQL migrations\n`);

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

const sql = fs.readFileSync(path.join(contracts, "postgres", "0001_control_plane.sql"), "utf8");
for (const table of ["organizations", "memberships", "human_sessions", "webauthn_credentials", "devices", "device_enrollments", "agents", "policies", "revocations", "capabilities", "bundle_heads", "bundle_acknowledgements", "device_audit_events", "idempotency_records", "admin_audit_events"]) {
  if (!new RegExp(`CREATE TABLE ${table} \\(`).test(sql)) fail(`PostgreSQL migration is missing ${table}`);
}
if (!sql.trim().startsWith("BEGIN;") || !sql.trim().endsWith("COMMIT;")) fail("PostgreSQL migration must be transactional");
if (!/FOREIGN KEY \(organization_id, device_id\)/.test(sql)) fail("PostgreSQL migration must enforce tenant-qualified device references");

if (!process.exitCode) process.stdout.write(`validated ${schemaFiles.length} schemas, 2 OpenAPI documents, 2 fixtures, and 1 PostgreSQL migration\n`);

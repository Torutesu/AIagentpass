import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");

test("machine-readable platform contracts pass the offline validator", () => {
  const result = spawnSync(process.execPath, [path.join(root, "scripts", "validate-contracts.mjs")], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /validated 5 schemas, 2 OpenAPI documents, 3 fixtures, and 3 PostgreSQL migrations/);
});

test("human high-risk operations require role and recent WebAuthn", () => {
  const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "human-v1.json"), "utf8"));
  const stop = openapi.paths["/organizations/{organization_id}/emergency-stop"].post;
  assert.equal(stop["x-agentpass-minimum-role"], "owner");
  assert.deepEqual(stop.security, [{ humanSession: [], recentWebAuthn: [] }]);
});

test("device operations use device signatures and tenant-qualified paths", () => {
  const openapi = JSON.parse(fs.readFileSync(path.join(root, "contracts", "openapi", "device-v1.json"), "utf8"));
  for (const [route, methods] of Object.entries(openapi.paths)) {
    if (route.startsWith("/enrollments/")) continue;
    assert.match(route, /\{organization_id\}/);
    for (const operation of Object.values(methods)) assert.deepEqual(operation.security, [{ deviceSignature: [] }]);
  }
});

test("PostgreSQL contract prevents cross-tenant device references", () => {
  const sql = fs.readFileSync(path.join(root, "contracts", "postgres", "0001_control_plane.sql"), "utf8");
  assert.match(sql, /PRIMARY KEY \(organization_id, id\)/);
  assert.match(sql, /FOREIGN KEY \(organization_id, device_id\) REFERENCES devices\(organization_id, id\)/);
  assert.match(sql, /PRIMARY KEY \(organization_id, principal_id, idempotency_key\)/);
});

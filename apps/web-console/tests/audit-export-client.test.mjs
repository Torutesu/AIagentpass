import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const clientPath = new URL("../app/audit-export-client.ts", import.meta.url);

async function source() {
  try {
    return await readFile(clientPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return "";
    throw error;
  }
}

test("audit-export client exposes typed create/read/verify/download operations and role visibility", async () => {
  const client = await source();

  assert.match(client, /export function createAuditExportClient/);
  assert.match(client, /AuditExportClientError/);
  for (const method of ["createAuditExport", "getAuditExport", "verifyAuditExport", "downloadAuditExport"]) {
    assert.match(client, new RegExp(method));
  }
  assert.match(client, /owner|admin/);
  assert.match(client, /auditor/);
  assert.match(client, /viewer/);
  assert.match(client, /canCreate/);
  assert.match(client, /canRead|canVerify|canDownload/);
});

test("audit-export client uses exact same-origin Console requests and operation-bound auth", async () => {
  const client = await source();

  assert.match(client, /\/api\/console\?operation=audit-export/);
  assert.match(client, /\/api\/console\?resource=audit-export/);
  assert.match(client, /export_id/);
  assert.match(client, /environment/);
  assert.match(client, /chain/);
  assert.match(client, /credentials:\s*["']same-origin["']/);
  assert.match(client, /cache:\s*["']no-store["']/);
  assert.match(client, /redirect:\s*["']error["']/);
  assert.match(client, /agentpass-csrf/);
  assert.match(client, /idempotency-key/);
  assert.match(client, /agentpass-recent-auth/);
  assert.match(client, /audit\.export\.create/);
  assert.match(client, /audit\.export\.retrieve/);
  assert.match(client, /contextHash|context_hash/);
});

test("audit-export client accepts only the Cloud envelope and returns audit_export without request_id leakage", async () => {
  const client = await source();

  assert.match(client, /audit_export/);
  assert.match(client, /request_id/);
  assert.match(client, /hasExactKeys|exactKeys|Object\.keys/);
  assert.match(client, /return .*audit_export|structuredClone\([^\n]*audit_export/);
  assert.match(client, /unknown|invalid_response|invalid response/i);
  assert.match(client, /organization_id/);
  assert.match(client, /payload_digest/);
  assert.match(client, /range/);
  assert.match(client, /audit_anchor/);
  assert.doesNotMatch(client, /return .*request_id/);
});

test("audit-export client distinguishes empty, expired, corrupt, offline, and response-loss outcomes", async () => {
  const client = await source();

  for (const code of ["empty", "expired", "corrupt", "offline", "response_loss", "response-loss"]) {
    assert.match(client, new RegExp(code));
  }
  assert.match(client, /AbortError|aborted/);
  assert.match(client, /transport_failed|offline/);
  assert.match(client, /response\.ok/);
  assert.match(client, /validity/);
  assert.match(client, /expires_at/);
});

test("audit-export client downloads canonical bytes through a revocable Blob URL", async () => {
  const client = await source();

  assert.match(client, /new Blob\(/);
  assert.match(client, /URL\.createObjectURL\(/);
  assert.match(client, /URL\.revokeObjectURL\(/);
  assert.match(client, /document\.createElement\(["']a["']\)/);
  assert.match(client, /download\s*=/);
  assert.match(client, /\.click\(\)/);
  assert.match(client, /try\s*\{|finally\s*\{/);
  assert.doesNotMatch(client, /data:application\/json|window\.location|location\.href/);
});

test("audit-export client has no browser persistence or telemetry path for payload material", async () => {
  const client = await source();

  assert.doesNotMatch(client, /localStorage|sessionStorage|indexedDB|indexedDb/i);
  assert.doesNotMatch(client, /console\.(?:log|info|warn|error|debug)|sendBeacon|analytics|track\(/i);
  assert.doesNotMatch(client, /window\.location|document\.location|location\.(?:search|hash)|history\.(?:pushState|replaceState)/i);
  assert.doesNotMatch(client, /claim[_-]?token|private[_-]?key|raw[_-]?(?:signing|signature)|secret/i);
});

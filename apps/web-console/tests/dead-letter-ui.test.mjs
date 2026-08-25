import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const panelPath = new URL("../app/components/OwnerRecoveryDeadLetterPanel.tsx", import.meta.url);
const ownerRecoveryPath = new URL("../app/components/OwnerRecoveryPanel.tsx", import.meta.url);

test("dead-letter UI exposes a tenant-scoped injected API boundary", async () => {
  const source = await readFile(panelPath, "utf8");
  assert.match(source, /export type OwnerRecoveryDeadLetterApi/);
  assert.match(source, /listDeadLetters\(input: RecoveryDeadLetterListInput\)/);
  assert.match(source, /redriveDeadLetter\(input: RecoveryDeadLetterMutationInput\)/);
  assert.match(source, /suppressDeadLetter\(input: RecoveryDeadLetterSuppressInput\)/);
  assert.match(source, /data-organization-id=\{organizationId\}/);
  assert.match(source, /organizationId, limit: 25/);
  assert.match(source, /requestRecentAuth\?: RequestRecoveryRecentAuth/);
  assert.doesNotMatch(source, /startAuthentication|navigator\.credentials|localStorage|sessionStorage/);
});

test("dead-letter UI covers operational states and safe mutations", async () => {
  const source = await readFile(panelPath, "utf8");
  for (const state of ["loading", "empty", "error", "list", "unavailable", "forbidden"]) assert.match(source, new RegExp(`data-state="${state}"`));
  for (const marker of ["再送", "抑制", "抑制理由", "operationLabel", "を確定", "managementVersion", "totalAttempts", "redriveCount"]) assert.match(source, new RegExp(marker));
  assert.match(source, /isStaleVersion/);
  assert.match(source, /await load\(undefined, \{ preserveNotice: true \}\)/);
  assert.match(source, /最新の状態に更新しました/);
  assert.match(source, /operation: confirmation\.action === "redrive"/);
  assert.match(source, /role === "owner" \|\| role === "admin"/);
  assert.match(source, /aria-live="assertive"/);
});

test("owner recovery page mounts the dead-letter surface with production defaults and injectable seams", async () => {
  const source = await readFile(ownerRecoveryPath, "utf8");
  assert.match(source, /OwnerRecoveryDeadLetterPanel/);
  assert.match(source, /deadLetterApi\?: OwnerRecoveryDeadLetterApi/);
  assert.match(source, /requestRecentAuth\?: RequestRecoveryRecentAuth/);
  assert.match(source, /createOwnerRecoveryDeadLetterClient/);
  assert.match(source, /ownerRecoveryDeadLetterContextHash/);
  assert.match(source, /contextHash/);
  assert.match(source, /api=\{effectiveDeadLetterApi\}/);
  assert.match(source, /requestRecentAuth=\{effectiveRecentAuth\}/);
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/OrganizationPanel.tsx", import.meta.url);

async function source() {
  return readFile(componentPath, "utf8");
}

test("organization destructive confirmations expose a labelled dialog and deterministic focus targets", async () => {
  const value = await source();

  assert.match(value, /role="dialog" aria-labelledby=\{removalDialogTitleId\} aria-describedby=\{removalDialogDescriptionId\}/);
  assert.match(value, /role="dialog" aria-labelledby=\{reissueDialogTitleId\}/);
  assert.match(value, /removalConfirmRef/);
  assert.match(value, /reissueInputRef/);
  assert.match(value, /focusAfterPaint\(removalConfirmRef\)/);
  assert.match(value, /focusAfterPaint\(reissueInputRef\)/);
  assert.match(value, /pendingAction === actionKey \? memberDetailsRef : removalTriggerRef/);
  assert.match(value, /pendingAction === reissueActionKey \? invitationDetailsRef : reissueTriggerRef/);
  assert.match(value, /window\.addEventListener\("keydown", onEscape\)/);
  assert.match(value, /event\.key !== "Escape"/);
  assert.match(value, /aria-keyshortcuts="Escape"/);
});

test("organization failures have a safe English recovery instruction and a visible non-CLI action", async () => {
  const value = await source();

  assert.match(value, /lang="en"/);
  assert.match(value, /safeEnglishRecoveryCopy/);
  assert.match(value, /Refresh the latest state in this console/);
  assert.match(value, /Ask an organization administrator to issue a new invitation/);
  assert.match(value, /const recoveryAction =/);
  assert.match(value, /onClick=\{recoveryAction\.run\}/);
  assert.match(value, /最新情報を読み込む/);
  assert.match(value, /再送していません/);
});

test("organization UI never persists or places invitation/session material in URLs or browser storage", async () => {
  const value = await source();

  assert.doesNotMatch(value, /localStorage|sessionStorage|document\.cookie/);
  assert.doesNotMatch(value, /location\.(?:href|assign|replace)/);
  assert.doesNotMatch(value, /URLSearchParams\([^)]*(?:token|csrf|authorization)/i);
  assert.equal((value.match(/\{oneTimeToken\}/g) ?? []).length, 1);
  assert.match(value, /招待トークンは発行時のコンポーネントメモリにのみ保持します/);
});

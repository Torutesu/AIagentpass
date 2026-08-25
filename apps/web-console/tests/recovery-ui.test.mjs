import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const panelPath = new URL("../app/components/OwnerRecoveryPanel.tsx", import.meta.url);
const consolePath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);

test("Console wires the recovery lane as a dedicated view", async () => {
  const source = await readFile(consolePath, "utf8");
  assert.match(source, /OwnerRecoveryPanel/);
  assert.match(source, /\| "recovery"/);
  assert.match(source, /id: "recovery"/);
  assert.match(source, /activeView === "recovery" \? <OwnerRecoveryPanel \/> : null/);
});

test("recovery panel gives owners the full flow and admins only dead-letter operations", async () => {
  const source = await readFile(panelPath, "utf8");
  for (const marker of ["復旧リクエストを作成", "最新状態を確認", "Ownerとして承認する", "復旧をキャンセル", "一度だけ表示された交換値を使う", "新しいパスキーを有効化"]) assert.match(source, new RegExp(marker));
  assert.match(source, /getOwnerRecoveryVisibility/);
  assert.match(source, /if \(loading\) return null/);
  assert.match(source, /role === "admin" \? <main/);
  assert.match(source, /OwnerRecoveryDeadLetterPanel/);
  assert.match(source, /registrationOptions\(requestId\)/);
  assert.match(source, /activate\(organizationId, activation\.challengeId, assertion\)/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|console\.(?:log|info|warn|error)|support|サポート/i);
});

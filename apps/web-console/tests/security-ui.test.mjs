import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);
const panelPath = new URL("../app/components/SecurityPanel.tsx", import.meta.url);

test("Console exposes a Japanese Security surface with bounded loading, empty, error, rename, and revoke states", async () => {
  const source = await readFile(componentPath, "utf8");
  const panel = await readFile(panelPath, "utf8");
  assert.match(source, /id: "security", label: "セキュリティ"/);
  assert.match(source, /<SecurityPanel onSessionEnded=\{expireSession\} \/>/);
  assert.match(panel, /REGISTERED PASSKEYS/);
  assert.match(panel, /ACTIVE SESSIONS/);
  assert.match(panel, /読み込み中/);
  assert.match(panel, /登録済みのパスキーはありません/);
  assert.match(panel, /セキュリティ操作を完了できませんでした/);
  assert.match(panel, /renamePasskey\(/);
  assert.match(panel, /revokePasskey\(/);
  assert.match(panel, /revokeSession\(/);
  assert.match(panel, /createSecurityClient\(/);
  assert.match(panel, /revokeCurrentSession\(/);
  assert.match(panel, /revokeOtherSessions\(/);
  assert.match(panel, /サインアウト/);
  assert.match(source, /activeView === "security"/);
  assert.doesNotMatch(panel, /localStorage|sessionStorage|console\.(?:log|info|warn|error)|public_key|credentialPublicKey|clientDataJSON/);
});

test("SecurityPanel covers the Human session management flow without handling ceremony material", async () => {
  const source = await readFile(panelPath, "utf8");
  for (const marker of ["addPasskey", "renamePasskey", "revokePasskey", "revokeCurrentSession", "revokeOtherSessions", "もう一度試す", "登録済みのパスキーはありません", "アクティブなセッションはありません", "サインアウト", "処理中…"]) assert.match(source, new RegExp(marker));
  assert.match(source, /role="status"/);
  assert.match(source, /role="alert"/);
  assert.match(source, /Touch IDまたはパスキー/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|document\.cookie|console\.(?:log|info|warn|error)/);
  assert.doesNotMatch(source, /csrfToken|csrf_token|credentialPublicKey|clientDataJSON|attestationObject|authorization_id/);
});

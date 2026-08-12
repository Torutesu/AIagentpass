import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);

test("Console exposes a Japanese Security surface with bounded loading, empty, error, rename, and revoke states", async () => {
  const source = await readFile(componentPath, "utf8");
  assert.match(source, /id: "security", label: "セキュリティ"/);
  assert.match(source, /function SecuritySurface\(\)/);
  assert.match(source, /REGISTERED PASSKEYS/);
  assert.match(source, /ACTIVE SESSIONS/);
  assert.match(source, /読み込み中/);
  assert.match(source, /登録済みのパスキーはありません/);
  assert.match(source, /セキュリティ情報を取得できませんでした/);
  assert.match(source, /renamePasskey\(/);
  assert.match(source, /revokePasskey\(/);
  assert.match(source, /revokeSession\(/);
  assert.match(source, /createSecurityClient\(/);
  assert.match(source, /revokeCurrentSession\(/);
  assert.match(source, /revokeOtherSessions\(/);
  assert.match(source, /サインアウト/);
  assert.match(source, /activeView === "security"/);
  const securityBody = source.slice(source.indexOf("function SecuritySurface"), source.indexOf("function EmergencySurface"));
  assert.doesNotMatch(securityBody, /localStorage|sessionStorage|console\.(?:log|info|warn|error)|public_key|credentialPublicKey|clientDataJSON/);
});

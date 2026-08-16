import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);
const panelPath = new URL("../app/components/SecurityPanel.tsx", import.meta.url);
const playwrightConfigPath = new URL("../playwright.config.ts", import.meta.url);

test("Console exposes a Japanese Security surface with bounded loading, empty, error, rename, and revoke states", async () => {
  const source = await readFile(componentPath, "utf8");
  const panel = await readFile(panelPath, "utf8");
  assert.match(source, /id: "security", label: "セキュリティ"/);
  assert.match(source, /<SecurityPanel securityClient=\{securityClient\} onSessionExpired=\{expireSession\} onSessionSignedOut=\{markSessionSignedOut\} \/>/);
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

test("current-session revoke reports signed-out separately from expired-session fail-closed handling", async () => {
  const panel = await readFile(panelPath, "utf8");
  const consoleSource = await readFile(componentPath, "utf8");
  assert.match(panel, /onSessionExpired\?: \(\) => void/);
  assert.match(panel, /onSessionSignedOut\?: \(\) => void/);
  assert.match(panel, /handleSessionFailure\(caught, onSessionExpired\)/);
  assert.match(panel, /setSignedOut\(true\); onSessionSignedOut\?\./);
  assert.doesNotMatch(panel, /onSessionEnded/);
  assert.match(consoleSource, /const endSession = useCallback\(\(nextState: "expired" \| "signed-out"\)/);
  assert.match(consoleSource, /const markSessionSignedOut = useCallback\(\(\) => endSession\("signed-out"\)/);
  assert.match(consoleSource, /<SecurityPanel securityClient=\{securityClient\} onSessionExpired=\{expireSession\} onSessionSignedOut=\{markSessionSignedOut\} \/>/);
});

test("last active passkey protection is based on a complete inventory and is accessible", async () => {
  const panel = await readFile(panelPath, "utf8");
  assert.match(panel, /passkeysComplete && passkeys\.length === 1/);
  assert.match(panel, /security-passkey-revoke-guidance/);
  assert.match(panel, /唯一の利用可能なパスキーです/);
  assert.match(panel, /disabled=\{actionKey !== null \|\| lastUsable\}/);
  assert.match(panel, /role="note"/);
  assert.match(panel, /role="status" aria-live="polite"/);
  assert.match(panel, /human_management_last_active_credential/);
  assert.match(panel, /err_sole_active_credential/);
  assert.doesNotMatch(panel, /window\.location|location\.reload|setTimeout\([^)]*revoke/);
});

test("ambiguous and conflicting Security mutations reconcile without automatic replay", async () => {
  const panel = await readFile(panelPath, "utf8");
  assert.match(panel, /isAmbiguousSecurityMutationError\(caught\)/);
  assert.match(panel, /const reconciled = await load\(\)/);
  assert.match(panel, /最新の権威状態を再取得しました。操作は自動再送していません/);
  assert.match(panel, /情報が更新されていたため、最新の権威状態を再取得しました/);
  assert.doesNotMatch(panel, /setTimeout\([^)]*(?:revokePasskey|revokeSession|revokeOtherSessions)/);
});

test("committed Security mutations retain their outcome when reconciliation is unavailable", async () => {
  const panel = await readFile(panelPath, "utf8");
  const mutationCommit = panel.indexOf("await action();");
  const successNotice = panel.indexOf("setNotice(successMessage);", mutationCommit);
  const reconciliation = panel.indexOf("if (reload) await load(undefined, false);", successNotice);
  assert.ok(mutationCommit >= 0);
  assert.ok(successNotice > mutationCommit);
  assert.ok(reconciliation > successNotice);
  assert.match(panel, /if \(sessionError && onSessionExpired !== undefined\) return false;/);
  assert.match(panel, /if \(isSessionError\(caught\) && onSessionExpired !== undefined\) return;/);
});

test("stale Security inventory loads cannot overwrite a committed mutation outcome", async () => {
  const panel = await readFile(panelPath, "utf8");
  assert.match(panel, /const loadEpochRef = useRef\(0\);/);
  assert.match(panel, /const loadEpoch = \+\+loadEpochRef\.current;/);
  assert.match(panel, /if \(loadEpoch !== loadEpochRef\.current\) return false;/);
  assert.match(panel, /loadEpochRef\.current \+= 1;/);
  const staleLoadCatch = panel.indexOf("const sessionError = isSessionError(caught);");
  const staleLoadGuard = panel.indexOf("if (loadEpoch !== loadEpochRef.current) return false;", staleLoadCatch);
  assert.ok(staleLoadCatch >= 0);
  assert.ok(staleLoadGuard > staleLoadCatch);
  assert.ok(panel.indexOf("if (sessionError) handleSessionFailure(caught, onSessionExpired);", staleLoadCatch) < staleLoadGuard);
});

test("browser failure output is not retained outside the supported artifact contract", async () => {
  const config = await readFile(playwrightConfigPath, "utf8");
  assert.match(config, /preserveOutput:\s*"never"/);
  assert.match(config, /trace:\s*"off"/);
  assert.match(config, /video:\s*"off"/);
  assert.match(config, /screenshot:\s*"off"/);
});

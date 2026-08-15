import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AuditExportPanel.tsx", import.meta.url);
const consolePath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);
const stylesPath = new URL("../app/globals.css", import.meta.url);

async function source(path) {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return "";
    throw error;
  }
}

test("Audit Exports is a Japanese, role-scoped Console surface", async () => {
  const panel = await source(componentPath);
  const consoleSource = await source(consolePath);

  assert.match(panel, /export function AuditExportPanel/);
  assert.match(consoleSource, /AuditExportPanel/);
  assert.match(consoleSource, /id: "audit-exports"/);
  assert.match(consoleSource, /監査エクスポート/);
  assert.match(panel, /role === "owner" \|\| role === "admin"/);
  assert.match(panel, /role === "owner" \|\| role === "admin" \|\| role === "auditor"/);
  assert.match(panel, /auditor/);
  assert.match(panel, /viewer/);
  assert.match(panel, /監査エクスポートを表示する権限がありません|閲覧権限がありません|role_denied/);
  assert.match(panel, /エクスポートを作成/);
  assert.match(panel, /検証|ダウンロード/);
});

test("Audit Exports explains environment and chain choices in Japanese", async () => {
  const panel = await source(componentPath);

  assert.match(panel, /htmlFor=["']audit-export-environment["']/);
  assert.match(panel, /環境/);
  assert.match(panel, /staging/);
  assert.match(panel, /production/);
  assert.match(panel, /htmlFor=["']audit-export-chain["']/);
  assert.match(panel, /チェーン|対象/);
  assert.match(panel, /admin/);
  assert.match(panel, /device/);
  assert.match(panel, /cloud_agent/);
  assert.match(panel, /管理操作|端末操作|Cloud Agent/);
  assert.doesNotMatch(panel, /private_key|claim_token|raw_signing|credential/);
});

test("Audit Exports has explicit loading, empty, success, expiry, corruption, offline, and response-loss states", async () => {
  const panel = await source(componentPath);

  for (const state of ["loading", "empty", "success", "expired", "corrupt", "offline", "response-loss"]) {
    assert.match(panel, new RegExp(state));
  }
  for (const message of [
    "読み込み中",
    "監査エクスポートはまだありません",
    "検証済み",
    "有効期限が切れています",
    "内容を検証できません",
    "接続できません",
    "応答を確認できません",
  ]) assert.match(panel, new RegExp(message));
  assert.match(panel, /data-state=\{state\}/);
  assert.match(panel, /再試行|もう一度試す/);
});

test("creating and retrieving an audit export require operation-bound passkey step-up", async () => {
  const panel = await source(componentPath);

  assert.match(panel, /authenticateRecentAuth/);
  assert.match(panel, /audit\.export\.create/);
  assert.match(panel, /audit\.export\.retrieve/);
  assert.match(panel, /contextHash|context_hash/);
  assert.match(panel, /Touch ID|パスキー/);
  assert.match(panel, /認証して作成|確認して作成|再認証/);
  assert.doesNotMatch(panel, /useState\([^\n]*(?:authorization|recent_auth|context_hash|claim_token)/i);
});

test("verification details expose evidence without exposing signing or claim material", async () => {
  const panel = await source(componentPath);

  for (const field of ["payload_digest", "range", "audit_anchor", "key_id", "key_version", "lifecycle_version", "validity", "expires_at", "environment", "chain"]) {
    assert.match(panel, new RegExp(field));
  }
  assert.match(panel, /検証結果|検証の詳細|署名|監査範囲/);
  assert.doesNotMatch(panel, /private[_-]?key|claim[_-]?token|clear claim|raw[_-]?(?:signing|signature)|secret|credential/i);
});

test("download uses a bounded Blob URL and always revokes it", async () => {
  const panel = await source(componentPath);

  assert.match(panel, /new Blob\(/);
  assert.match(panel, /URL\.createObjectURL\(/);
  assert.match(panel, /download\s*=/);
  assert.match(panel, /\.click\(\)/);
  assert.match(panel, /URL\.revokeObjectURL\(/);
  assert.match(panel, /try\s*\{|finally\s*\{/);
  assert.doesNotMatch(panel, /data:application\/json|window\.location\s*=|location\.href\s*=/i);
});

test("Audit Exports is keyboard and screen-reader usable", async () => {
  const panel = await source(componentPath);
  const styles = await source(stylesPath);

  assert.match(panel, /<label[^>]+htmlFor=/);
  assert.match(panel, /<select[^>]+id=/);
  assert.match(panel, /type="button"/);
  assert.match(panel, /aria-busy=/);
  assert.match(panel, /aria-live="polite"/);
  assert.match(panel, /role="status"/);
  assert.match(panel, /role="alert"/);
  assert.match(panel, /aria-describedby=/);
  assert.match(panel, /onKeyDown|Escape/);
  assert.match(styles, /audit-export|export/);
  assert.match(styles, /:focus-visible/);
});

test("the Audit Exports surface never persists payloads in browser storage, URLs, logs, or analytics", async () => {
  const panel = await source(componentPath);

  assert.doesNotMatch(panel, /localStorage|sessionStorage|indexedDB|indexedDb/i);
  assert.doesNotMatch(panel, /console\.(?:log|info|warn|error|debug)|sendBeacon|analytics|track\(/i);
  assert.doesNotMatch(panel, /window\.location|document\.location|location\.(?:search|hash)|history\.(?:pushState|replaceState)/i);
  assert.doesNotMatch(panel, /URLSearchParams|new URL\(/);
});

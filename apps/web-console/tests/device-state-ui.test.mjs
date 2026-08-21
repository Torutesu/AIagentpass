import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);
const summaryParserPath = new URL("../app/console-summary.ts", import.meta.url);
const stylesPath = new URL("../app/globals.css", import.meta.url);

test("Console maps the safe device control-plane shape without exposing raw payloads", async () => {
  const source = await readFile(componentPath, "utf8");
  const parserSource = await readFile(summaryParserPath, "utf8");
  for (const field of [
    "desired_generation",
    "observed_generation",
    "refresh_state",
    "bundle_sequence",
    "bundle_expires_at",
    "last_ack_at",
    "blocked_reason",
  ]) assert.match(parserSource, new RegExp(field));
  assert.match(parserSource, /nullablePositiveInteger\(object\.desired_generation/);
  assert.match(parserSource, /nullablePositiveInteger\(object\.observed_generation/);
  assert.match(source, /device\.desiredGeneration/);
  assert.match(source, /device\.observedGeneration/);
  assert.doesNotMatch(source, /device\.private_key|device\.secret|device\.credential/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|console\.(?:log|info|warn|error)/);
});

test("device UI has a readable label for every state and does not rely on color alone", async () => {
  const source = await readFile(componentPath, "utf8");
  for (const label of ["同期済み", "反映待ち", "ブロック中", "古い状態", "オフライン", "失効済み"]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /aria-label={`同期状態: \$\{label\}`}/);
  assert.match(source, /data-state=\{state\}/);
  assert.match(source, /deviceStateDescription\(state\)/);
});

test("device UI renders expiry, ACK, sequence, and desired/observed progress accessibly", async () => {
  const source = await readFile(componentPath, "utf8");
  for (const label of ["Bundle sequence", "Bundle有効期限", "最終ACK", "Cloud desired世代", "端末 observed世代"]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /role="progressbar"/);
  assert.match(source, /aria-valuemin=\{0\}/);
  assert.match(source, /aria-valuemax=\{desired\}/);
  assert.match(source, /aria-valuenow=\{Math\.min\(observed, desired\)\}/);
  assert.match(source, /<time dateTime=\{device\.bundleExpiresAt\}>/);
  assert.match(source, /device\.blockedReason/);
});

test("device state cards expose wake only for actionable non-synced states and use operation-bound WebAuthn", async () => {
  const source = await readFile(componentPath, "utf8");
  assert.match(source, /operate\("revoke-device", \{ target_id: device\.deviceId/);
  assert.match(source, /DEVICE_REVOKE_RECENT_AUTH_OPERATION = "device\.revoke"/);
  assert.match(source, /DEVICE_REFRESH_REQUEST_RECENT_AUTH_OPERATION = "device\.refresh\.request"/);
  assert.match(source, /authenticateRecentAuth\(\{ operation: DEVICE_REFRESH_REQUEST_RECENT_AUTH_OPERATION/);
  assert.match(source, /\["pending", "blocked", "stale", "offline"\]\.includes\(state\)/);
  assert.match(source, /const canRequestRefresh = Boolean\(device\.deviceId/);
  assert.match(source, /Wake requestを依頼/);
  assert.match(source, /Wake requestを送信中…/);
  assert.match(source, /role="status" aria-live="polite"/);
  assert.match(source, /role="alert"/);
  assert.match(source, /accepted: "依頼を受け付けました。端末への配信は未確認です。"/);
  assert.match(source, /coalesced: "既存の依頼へ統合し、再通知しました。端末への配信は未確認です。"/);
  assert.match(source, /no_pending_refresh: "反映待ちの更新はなく、通知は送信していません。"/);
  assert.match(source, /適用・同期の完了を示す操作ではありません。/);
  assert.match(source, /parseDeviceRefreshResponse\(payload, deviceId\)/);
  const requestRefreshSource = source.slice(source.indexOf("const requestDeviceRefresh"), source.indexOf("const currentLabel"));
  assert.doesNotMatch(requestRefreshSource, /refreshSummary\(\)|capabilit(?:y|ies)/i);
  const deviceStateSource = source.slice(source.indexOf("function deviceState"), source.indexOf("function SetupSurface"));
  assert.doesNotMatch(deviceStateSource, /generation:|outbox:|nonce:|bundle:|policy:|secret:/);
});

test("wake mutation keeps the WebAuthn session snapshot through the BFF request", async () => {
  const source = await readFile(componentPath, "utf8");
  const fetchConsole = source.slice(source.indexOf("async function fetchConsole"), source.indexOf("function supportsWebAuthn"));
  const requestRefresh = source.slice(source.indexOf("const requestDeviceRefresh"), source.indexOf("const currentLabel"));

  assert.match(fetchConsole, /sessionOverride\?: ConsoleSession/);
  assert.match(fetchConsole, /const session = sessionOverride \?\? await consoleSessionContext\.get/);
  assert.match(requestRefresh, /const session = await consoleSessionContext\.get\(\)/);
  assert.match(requestRefresh, /const \{ organizationId, csrfToken \} = session/);
  assert.match(requestRefresh, /authenticateRecentAuth\(\{ operation: DEVICE_REFRESH_REQUEST_RECENT_AUTH_OPERATION, organizationId, csrfToken \}\)/);
  assert.match(requestRefresh, /body: JSON\.stringify\(\{ target_id: deviceId \}\),\s+\}, session\);/);
});

test("state-specific styling preserves a text/status hook in the stylesheet", async () => {
  const styles = await readFile(stylesPath, "utf8");
  for (const state of ["synced", "pending", "blocked", "stale", "offline", "revoked"]) {
    assert.match(styles, new RegExp(`data-state="${state}"`));
  }
  assert.match(styles, /\.device-state-badge/);
  assert.match(styles, /\.device-sync-track/);
  assert.match(styles, /\.device-state-details/);
  assert.match(styles, /\.device-wake-action/);
  assert.match(styles, /\.device-wake-button/);
  assert.match(styles, /\.device-wake-outcome/);
  assert.match(styles, /\.device-wake-error/);
});

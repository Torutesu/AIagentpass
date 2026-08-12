import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);
const stylesPath = new URL("../app/globals.css", import.meta.url);

test("Console maps the safe device control-plane shape without exposing raw payloads", async () => {
  const source = await readFile(componentPath, "utf8");
  for (const field of [
    "desired_generation",
    "observed_generation",
    "refresh_state",
    "bundle_sequence",
    "bundle_expires_at",
    "last_ack_at",
    "blocked_reason",
  ]) assert.match(source, new RegExp(field));
  assert.match(source, /Number\.isSafeInteger\(device\.desired_generation\)/);
  assert.match(source, /Number\.isSafeInteger\(device\.observed_generation\)/);
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

test("device state cards stay read-only while the existing setup revoke uses operation-bound WebAuthn", async () => {
  const source = await readFile(componentPath, "utf8");
  assert.match(source, /operate\("revoke-device", \{ target_id: device\.deviceId/);
  assert.match(source, /operation: DEVICE_REVOKE_RECENT_AUTH_OPERATION/);
  assert.match(source, /DEVICE_REVOKE_RECENT_AUTH_OPERATION = "device\.revoke"/);
  assert.doesNotMatch(source, /device-revoke-button/);
  assert.doesNotMatch(source, /operation=refresh-device|operate\("refresh-device"|device\.refresh\(/);
  assert.doesNotMatch(source.slice(source.indexOf("function DeviceStateCard"), source.indexOf("function Overview")), /operate\(|<button/);
});

test("state-specific styling preserves a text/status hook in the stylesheet", async () => {
  const styles = await readFile(stylesPath, "utf8");
  for (const state of ["synced", "pending", "blocked", "stale", "offline", "revoked"]) {
    assert.match(styles, new RegExp(`data-state="${state}"`));
  }
  assert.match(styles, /\.device-state-badge/);
  assert.match(styles, /\.device-sync-track/);
  assert.match(styles, /\.device-state-details/);
});

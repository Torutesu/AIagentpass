import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);

test("setup surface exposes a bounded install and helper-connection state", async () => {
  const source = await readFile(componentPath, "utf8");
  const installBody = source.slice(source.indexOf("type InstallGuidanceState"), source.indexOf("function SetupSurface"));

  for (const state of ["not-detected", "checking", "connected", "delivered", "failed"]) {
    assert.match(installBody, new RegExp(`state: "${state}"`));
  }
  assert.match(installBody, /data-install-state=\{guidance\.state\}/);
  assert.match(installBody, /署名済みAgentPassパッケージをインストール/);
  assert.match(installBody, /管理者から案内されたセットアップコマンド/);
  assert.match(installBody, /候補ID、指紋、招待JSONを自分で入力する必要はありません/);
  assert.match(installBody, /自動接続できない場合の復旧/);
  assert.match(source, /<InstallStatusCard status=\{liveHandoffStatus\} \/>/);
});

test("install guidance is accessible and never introduces browser persistence", async () => {
  const source = await readFile(componentPath, "utf8");
  const installBody = source.slice(source.indexOf("type InstallGuidanceState"), source.indexOf("function SetupSurface"));

  assert.match(installBody, /role="status" aria-live="polite"/);
  assert.doesNotMatch(installBody, /role=\{isFailure \? "alert" : "status"\}/);
  assert.doesNotMatch(installBody, /localStorage|sessionStorage|indexedDB|window\.location\.(?:search|hash)/);
  assert.doesNotMatch(installBody, /private[_ ]key|credential|authorization_id|nonce|challenge/iu);
});

test("install states are advanced by the handoff contract and the loopback is one-consume", async () => {
  const source = await readFile(componentPath, "utf8");

  assert.match(source, /transitionBrowserCliHandoffState\(current, event\)/);
  assert.match(source, /createLiveHandoffDelivery\(\{ handoff, preflight \}\)/);
  assert.match(source, /createLiveHandoffDelivery = createBrowserCliHandoffDelivery as unknown as/);
  assert.match(source, /liveHandoff\.delivery\.deliver\(invitation\)/);
  assert.match(source, /BROWSER_CLI_HANDOFF_EVENTS\.PREFLIGHT_SUCCEEDED/);
  assert.match(source, /BROWSER_CLI_HANDOFF_EVENTS\.DELIVERY_SUCCEEDED/);
  assert.doesNotMatch(source, /setLiveHandoffStatus\("(?:connected|delivered|failed)"\)/);
  assert.doesNotMatch(source, /postBrowserCliHandoff\(/);
});

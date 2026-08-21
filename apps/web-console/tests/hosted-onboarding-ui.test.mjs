import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentUrl = new URL("../app/components/HostedOnboarding.tsx", import.meta.url);
const pageUrl = new URL("../app/onboarding/page.tsx", import.meta.url);

test("Hosted onboarding exposes the complete first-user journey", async () => {
  const [component, page] = await Promise.all([readFile(componentUrl, "utf8"), readFile(pageUrl, "utf8")]);
  assert.match(page, /HostedOnboarding/);
  assert.match(page, /robots: \{ index: false, follow: false \}/);
  assert.match(component, /\/api\/auth\/bootstrap\/github\/start/);
  assert.match(component, /clientRef\.current!\.status/);
  assert.match(component, /clientRef\.current!\.createOrganization/);
  assert.match(component, /clientRef\.current!\.registerPasskey/);
  assert.doesNotMatch(component, /registerPasskey\(\);\s*await loadStatus\(\)/);
  assert.match(component, /GitHubで本人確認/);
  assert.match(component, /最初のワークスペースを作成/);
  assert.match(component, /パスキーで管理者アカウントを保護/);
  assert.match(component, /準備ができました/);
  assert.match(component, /data-onboarding-state/);
  assert.match(component, /data-device-handoff="ready"/);
  assert.match(component, /端末をAgentへ引き渡す/);
  assert.match(component, /セットアップを再開してください/);
  assert.match(component, /retryable/);
  assert.match(component, /terminal/);
});

test("Hosted onboarding keeps ceremony authority out of React and browser storage", async () => {
  const source = await readFile(componentUrl, "utf8");
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|caches\.|console\.(?:log|info|warn|error)/);
  assert.doesNotMatch(source, /useState[^\n]*(?:csrf|challenge|credential|attestation|sessionToken)/i);
  assert.doesNotMatch(source, /organization_id|member_id|membership_id|["']role["']\s*:/);
  assert.match(source, /clientRef = useRef/);
  assert.match(source, /const controller = new AbortController/);
  assert.match(source, /return \(\) => \{[\s\S]*?controller\.abort\(\);[\s\S]*?\}/);
  assert.match(source, /Reconcile once from the authoritative status/);
  assert.match(source, /The boolean is ephemeral UI state/);
});

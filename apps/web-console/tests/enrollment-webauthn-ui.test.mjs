import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);

test("enrollment UI uses a session-bound WebAuthn ceremony instead of manual proof", async () => {
  const source = await readFile(componentPath, "utf8");

  assert.match(source, /import \{ authenticateRecentAuth, registerPasskey, WebAuthnClientError \} from "\.\.\/webauthn-client"/);
  assert.match(source, /const SESSION_BOOTSTRAP_PATH = "\/api\/auth\/session"/);
  assert.match(source, /fetch\(SESSION_BOOTSTRAP_PATH, \{[\s\S]*?method: "POST"[\s\S]*?body: "\{\}"[\s\S]*?cache: "no-store"[\s\S]*?credentials: "same-origin"/);
  assert.match(source, /hasExactKeys\(value, \["session", "csrf_token"\]\)/);
  assert.match(source, /UUID\.test\(session\.organization_id\)/);
  assert.match(source, /BASE64URL_CSRF = \/\^\[A-Za-z0-9_-\]\{43\}\$\//);
  assert.match(source, /authenticateRecentAuth\(\{[\s\S]*?operation: RECENT_AUTH_OPERATION[\s\S]*?organizationId[\s\S]*?csrfToken/);
  assert.match(source, /"agentpass-recent-auth": authorization_id/);
  assert.match(source, /enrollmentInFlight\.current/);
  assert.match(source, /Touch ID\/パスキー確認して発行/);
  assert.match(source, /registerPasskey\(\{ organizationId, csrfToken \}\)/);
  assert.match(source, /Touch ID \/ パスキーを登録/);

  assert.doesNotMatch(source, /\[recentAuth,\s*setRecentAuth\]/);
  assert.doesNotMatch(source, /setRecentAuth/);
  assert.doesNotMatch(source, /直近のWebAuthn証明/);
  assert.doesNotMatch(source, /本番のWebAuthnダイアログ接続までは/);
  assert.doesNotMatch(source, /autoComplete="off" value=\{recentAuth\}/);
});

test("guided enrollment imports one strict public preflight and keeps the advanced fallback explicit", async () => {
  const source = await readFile(componentPath, "utf8");

  assert.match(source, /parsePublicEnrollmentPreflight\(preflightText\)/);
  assert.match(source, /version: 1,[\s\S]*platform: "macos"/);
  assert.match(source, /publicEnrollmentPreflight as publicBrowserCliEnrollmentPreflight/);
  assert.match(source, /liveHandoffRef/);
  assert.match(source, /PUBLIC ONLY/);
  assert.match(source, /上級者向け：preflight JSONを使えない場合の手入力/);
  assert.match(source, /candidate_binding\.candidate_id !== expectedPreflight\.candidate_id/);
  assert.match(source, /candidate_binding\.device_key_fingerprint !== expectedPreflight\.device_key_fingerprint/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|window\.location\.search|console\.(?:log|info|warn|error)/);
  assert.doesNotMatch(source, /enrollmentStores|allocateEnrollmentStoreId/);
  assert.doesNotMatch(source, /useState<Record<string, unknown> \| null>/);
});

test("enrollment ceremony material is not placed in React state or browser storage", async () => {
  const source = await readFile(componentPath, "utf8");
  const setupBody = source.slice(source.indexOf("function SetupSurface"), source.indexOf("function AgentsSurface"));

  assert.doesNotMatch(setupBody, /useState\([^\n]*(?:csrf|challenge|assertion|proof|authorization)/i);
  assert.doesNotMatch(setupBody, /localStorage|sessionStorage|console\.(?:log|info|warn|error)/);
  assert.match(setupBody, /const \{ organizationId, csrfToken \} = await consoleSessionContext\.get\(\)/);
  assert.match(setupBody, /const \{ authorization_id \} = await authenticateRecentAuth/);
  assert.match(setupBody, /await registerPasskey\(\{ organizationId, csrfToken \}\)/);
  assert.doesNotMatch(setupBody, /useState\([^\n]*(?:credential|attestation|assertion|challenge|label)/i);
});

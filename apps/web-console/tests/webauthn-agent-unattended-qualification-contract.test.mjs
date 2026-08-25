import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const e2ePath = new URL("../e2e/webauthn-agent-unattended-qualification.spec.ts", import.meta.url);
const docsPath = new URL("../../../docs/qualification/webauthn-agent-unattended-e2e.md", import.meta.url);

test("WebAuthn unattended qualification is a real-browser-only typed evidence contract", async () => {
  const source = await readFile(e2ePath, "utf8");
  for (const checkId of ["authenticator_origin_rp", "durable_one_time_consumption", "replay_rejection", "stale_context_rejection", "outage_fail_closed"]) {
    assert.match(source, new RegExp(`\\"${checkId}\\"`));
  }
  for (const binding of ["organization_id", "agentpass-csrf", "agentpass-recent-auth", "challenge_id", "clientDataJSON", "authenticatorData"]) {
    assert.match(source, new RegExp(binding));
  }
  assert.match(source, /navigator\.credentials\?\.get/);
  assert.match(source, /installVirtualAuthenticator/);
  assert.match(source, /value\.id === CREDENTIAL_ID/);
  assert.match(source, /decodeBase64Url\(value\.rawId\)\.equals\(CREDENTIAL_ID_BYTES\)/);
  assert.match(source, /testInfo\.attach\("webauthn-agent-unattended-qualification\.json"/);
  assert.match(source, /real_execution:\s*true/);
  assert.match(source, /Object\.values\(values\)\.some\(\(value\) => value === undefined\)/);
  assert.doesNotMatch(source, /credential:\s*\{\s*(?:id|rawId|response)/u);
  assert.doesNotMatch(source, /status:\s*"passed"[\s\S]{0,120}qualified:\s*true[\s\S]{0,120}checks:\s*\[\]/u);
  assert.doesNotMatch(source, /localStorage\.(?:setItem|getItem)|sessionStorage\.(?:setItem|getItem)/u);
});

test("qualification evidence does not claim a static or local pass", async () => {
  const source = await readFile(e2ePath, "utf8");
  assert.match(source, /AGENTPASS_QUALIFICATION_RUNNER_ID/);
  assert.match(source, /AGENTPASS_SOURCE_TREE/);
  assert.match(source, /AGENTPASS_QUALIFICATION_ARTIFACT_SHA256/);
  assert.match(source, /AGENTPASS_WEBAUTHN_QUALIFICATION_MODE/);
  assert.match(source, /EXTERNAL_QUALIFICATION_MODE = "external"/);
  assert.match(source, /AGENTPASS_QUALIFICATION_EVIDENCE_PATH/);
  assert.match(source, /O_EXCL/);
  assert.match(source, /O_NOFOLLOW/);
  assert.match(source, /if \(!execution\) \{[\s\S]*return;\s*\}/u);
  assert.match(source, /if \(externalQualification\) throw new Error\("external WebAuthn qualification bindings are required"\)/);
  assert.match(source, /local\|static\|unit\|mock\|fixture\|fake\|simulator\|emulator\|test\|macos-latest/u);
  assert.match(source, /staleChallengeStatus === 409 && state\.crossTenantStatus === 403/);
});

test("qualification documentation freezes the external and local evidence boundary", async () => {
  const source = await readFile(docsPath, "utf8");
  assert.match(source, /real browser execution/u);
  assert.match(source, /typed observations/u);
  assert.match(source, /tenant/u);
  assert.match(source, /session/u);
  assert.match(source, /challenge/u);
  assert.match(source, /RP/u);
  assert.match(source, /origin/u);
  assert.match(source, /replay/u);
  assert.match(source, /static.*cannot.*pass|static-only.*not.*pass/isu);
  assert.match(source, /authenticator_origin_rp/);
  assert.match(source, /outage_fail_closed/);
  assert.match(source, /npm run qualification:webauthn/);
  assert.match(source, /deterministic route harness/);
  assert.match(source, /not evidence that a\s+production deployment/u);
  assert.doesNotMatch(source, /JSON\.stringify\(\{[^}]*credential\s*:/u);
});

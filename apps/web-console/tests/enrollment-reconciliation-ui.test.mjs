import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentPath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);

test("Mac enrollment reconciliation is bounded and uses the authoritative summary read", async () => {
  const source = await readFile(componentPath, "utf8");
  const reconciliation = source.slice(source.indexOf("type EnrollmentReconciliationState"), source.indexOf("type InstallGuidanceState"));

  for (const state of ["checking", "pending", "enrolled", "response-loss", "timed-out"]) {
    assert.match(reconciliation, new RegExp(`\\"${state}\\"`));
  }
  assert.match(reconciliation, /ENROLLMENT_RECONCILIATION_MAX_ATTEMPTS = 5/);
  assert.match(reconciliation, /ENROLLMENT_RECONCILIATION_RETRY_DELAY_MS = 2_500/);
  assert.match(reconciliation, /refresh\(\)/);
  assert.match(reconciliation, /result !== "ready"/);
  assert.match(reconciliation, /setState\("response-loss"\)/);
  assert.match(reconciliation, /操作は再送していません/);
  assert.match(reconciliation, /状態を再確認/);
  assert.match(reconciliation, /role=\{failure \? "alert" : "status"\}/);
  assert.match(reconciliation, /aria-live=\{failure \? "assertive" : "polite"\}/);
});

test("enrollment reconciliation does not add a second mutation path or browser persistence", async () => {
  const source = await readFile(componentPath, "utf8");
  const reconciliation = source.slice(source.indexOf("function EnrollmentReconciliationCard"), source.indexOf("type InstallGuidanceState"));

  assert.doesNotMatch(reconciliation, /fetchConsole\(/);
  assert.doesNotMatch(reconciliation, /issue-device-enrollment/);
  assert.doesNotMatch(reconciliation, /localStorage|sessionStorage|indexedDB|navigator\.clipboard/);
  assert.match(source, /<SetupSurface[\s\S]*refresh=\{refreshSummary\}/);
  assert.match(source, /<EnrollmentReconciliationCard key=\{`\$\{issuedEnrollment\.enrollmentId\}:\$\{progress\}`\}/);
});

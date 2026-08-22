import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const config = fs.readFileSync(path.join(root, "playwright.config.ts"), "utf8");
const packageManifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const runner = fs.readFileSync(path.join(root, "scripts", "run-browser-e2e.mjs"), "utf8");
const ciWorkflow = fs.readFileSync(path.resolve(root, "..", "..", ".github/workflows/ci.yml"), "utf8");
const preflight = fs.readFileSync(path.resolve(root, "..", "..", "scripts/release/ci-preflight.mjs"), "utf8");
const qualificationSpec = fs.readFileSync(path.join(root, "e2e", "webauthn-agent-unattended-qualification.spec.ts"), "utf8");

test("browser E2E has a deterministic loopback server contract", () => {
  assert.match(config, /--hostname 127\.0\.0\.1/);
  assert.match(config, /baseURL: `http:\/\/127\.0\.0\.1:\$\{e2ePort\}`/);
  assert.match(config, /url: `http:\/\/127\.0\.0\.1:\$\{e2ePort\}\/`/);
  assert.match(config, /reuseExistingServer: false/);
  assert.match(config, /env -u NODE_OPTIONS -u NODE_DEBUG/);
  assert.match(runner, /spawn\([^\n]+\["run", "dev", "--", "--hostname", "127\.0\.0\.1", "--port", String\(port\)\]/u);
  assert.match(packageManifest.scripts.e2e, /env -u NODE_OPTIONS -u NODE_DEBUG/);
  assert.match(runner, /delete env\.NODE_OPTIONS/);
  assert.match(runner, /delete env\.NODE_DEBUG/);
  assert.match(runner, /server\.once\("error"/u);
  assert.match(runner, /child\.once\("error"/u);
  assert.match(runner, /port_collision/);
  assert.match(runner, /sandbox_eperm/);
  assert.match(runner, /status: "not_run"/);
  assert.match(runner, /expectedTests/);
  assert.match(runner, /\?\? "83"/u);
  assert.match(runner, /incomplete_execution/);
  assert.match(runner, /AGENTPASS_BROWSER_E2E_RESULT_PATH/);
  assert.match(config, /retries: 0/);
  assert.match(config, /AGENTPASS_PLAYWRIGHT_OUTPUT_DIR/);
});

test("the CI E2E command cannot report success without executed browser tests", () => {
  assert.equal(packageManifest.scripts.e2e, "env -u NODE_OPTIONS -u NODE_DEBUG node scripts/run-browser-e2e.mjs");
  assert.match(runner, /executed > 0/);
  assert.match(runner, /!passed/);
  assert.match(runner, /executed === expectedTests/);
});

test("CI binds the complete browser E2E result to source, run, attempt, job, and upload success", () => {
  assert.match(preflight, /assertTerminalResults/u);
  assert.match(preflight, /terminal results (?:require|contain)/u);
  assert.match(ciWorkflow, /ci-preflight\.mjs browser-e2e/u);
  assert.match(ciWorkflow, /GITHUB_RUN_ATTEMPT/u);
  assert.match(ciWorkflow, /GITHUB_JOB/u);
  assert.match(ciWorkflow, /Retain typed browser E2E result\n\s+if: success\(\)/u);
  assert.equal((ciWorkflow.match(/AGENTPASS_EXPECTED_BROWSER_E2E_TESTS: "83"/gu) ?? []).length, 2);
});

test("WebAuthn unattended qualification is a dedicated fail-closed execution within browser-e2e", () => {
  assert.match(qualificationSpec, /AGENTPASS_WEBAUTHN_QUALIFICATION_MODE/);
  assert.match(qualificationSpec, /external WebAuthn qualification bindings are required/);
  assert.match(qualificationSpec, /AGENTPASS_QUALIFICATION_EVIDENCE_PATH/);
  assert.match(ciWorkflow, /browser-e2e:\n[\s\S]*Run dedicated WebAuthn unattended qualification \(external bindings required\)/u);
  assert.match(ciWorkflow, /AGENTPASS_WEBAUTHN_QUALIFICATION_MODE: external/u);
  assert.match(ciWorkflow, /AGENTPASS_WEBAUTHN_QUALIFICATION_RUNNER_ID: \$\{\{ vars\.AGENTPASS_WEBAUTHN_QUALIFICATION_RUNNER_ID \}\}/u);
  assert.match(ciWorkflow, /AGENTPASS_WEBAUTHN_QUALIFICATION_ARTIFACT_SHA256: \$\{\{ vars\.AGENTPASS_WEBAUTHN_QUALIFICATION_ARTIFACT_SHA256 \}\}/u);
  assert.match(ciWorkflow, /: "\$\{AGENTPASS_WEBAUTHN_QUALIFICATION_RUNNER_ID:\?protected WebAuthn qualification runner binding is required\}"/u);
  assert.match(ciWorkflow, /npx playwright test e2e\/webauthn-agent-unattended-qualification\.spec\.ts --reporter=json/u);
  assert.match(ciWorkflow, /dedicated WebAuthn qualification did not execute exactly one passing test/u);
  assert.match(ciWorkflow, /WebAuthn qualification evidence is not bound to the external run/u);
  assert.match(ciWorkflow, /webauthn-agent-unattended-qualification\.evidence\.json/u);
  assert.doesNotMatch(ciWorkflow, /webauthn-qualification:\s*$/mu);
});

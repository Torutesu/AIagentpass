import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const workflow = fs.readFileSync(path.join(root, ".github", "workflows", "ci.yml"), "utf8");
const packageManifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));

function job(name) {
  const start = workflow.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing CI job ${name}`);
  const rest = workflow.slice(start + 1);
  const next = rest.search(/^  [A-Za-z0-9_-]+:/m);
  return workflow.slice(start, next === -1 ? workflow.length : start + 1 + next);
}

test("published package retains the W1.6 operational policy and evidence gates", () => {
  assert.ok(packageManifest.files.includes("ops"));
  assert.ok(packageManifest.files.includes("scripts/owner-recovery"));
});

test("main CI validates the machine-readable contract inventory before product tests", () => {
  const section = job("test");
  const install = section.indexOf("- run: npm ci");
  const consoleInstall = section.indexOf("- run: npm ci --prefix apps/web-console");
  const contracts = section.indexOf("- run: npm run contracts:validate");
  const platformContracts = section.indexOf("- run: npm run contracts:validate:platform");
  const identityBootstrapContracts = section.indexOf("- run: npm run contracts:validate:hosted-identity-bootstrap");
  const w16 = section.indexOf("- run: npm run test:w16");
  const nodeTests = section.indexOf("- run: npm test");
  assert.ok(install >= 0 && consoleInstall > install && contracts > consoleInstall && platformContracts > contracts && identityBootstrapContracts > platformContracts && w16 > identityBootstrapContracts && nodeTests > w16);
  assert.equal(section.match(/^\s*- run: npm run contracts:validate$/gmu)?.length, 1);
  assert.equal(section.match(/^\s*- run: npm run contracts:validate:platform$/gmu)?.length, 1);
  assert.equal(section.match(/^\s*- run: npm run contracts:validate:hosted-identity-bootstrap$/gmu)?.length, 1);
  assert.equal(section.match(/npm run test:w16/g)?.length, 1);
});

test("native qualification is serialized at the top level", () => {
  const section = job("test");
  assert.equal(
    packageManifest.scripts["test:native"],
    "node scripts/ci/run-native-tests.mjs -- swift test --package-path native/macos --no-parallel",
  );
  assert.match(section, /runs-on: macos-latest\n    timeout-minutes: 60/u);
  for (const [name, minutes, command] of [
    ["Run bounded native unit tests", 30, "npm run test:native"],
    ["Run bounded native app bundle tests", 10, "npm run test:native-app"],
    ["Run bounded installer preservation tests", 5, "npm run test:native-installer-preservation"],
    ["Run bounded native durability model", 10, "npm run test:native-durability-model"],
  ]) {
    assert.match(section, new RegExp(`- name: ${name}\\n        timeout-minutes: ${minutes}\\n[\\s\\S]*?run: ${command}(?:\\n|$)`, "u"));
  }
  assert.match(section, /NATIVE_TEST_TIMEOUT_MS: 1500000/u);
});

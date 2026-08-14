import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const workflow = fs.readFileSync(path.join(root, ".github", "workflows", "ci.yml"), "utf8");

function job(name) {
  const start = workflow.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing CI job ${name}`);
  const rest = workflow.slice(start + 1);
  const next = rest.search(/^  [A-Za-z0-9_-]+:/m);
  return workflow.slice(start, next === -1 ? workflow.length : start + 1 + next);
}

test("main CI validates the machine-readable contract inventory before product tests", () => {
  const section = job("test");
  const install = section.indexOf("- run: npm ci");
  const consoleInstall = section.indexOf("- run: npm ci --prefix apps/web-console");
  const contracts = section.indexOf("- run: npm run contracts:validate");
  const nodeTests = section.indexOf("- run: npm test");
  assert.ok(install >= 0 && consoleInstall > install && contracts > consoleInstall && nodeTests > contracts);
  assert.equal(section.match(/npm run contracts:validate/g)?.length, 1);
});

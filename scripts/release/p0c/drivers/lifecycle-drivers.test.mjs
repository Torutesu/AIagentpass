import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const driversDirectory = dirname(fileURLToPath(import.meta.url));

const cases = [
  {
    file: "policy-reduction-refresh-ack",
    gate: "policy-reduction-refresh-ack",
    tests: ["policy-reduction-denied"],
    scenario: "policy-reduction-refresh-ack"
  },
  {
    file: "offline-expiry",
    gate: "offline-expiry",
    tests: ["offline-expiry-denied"],
    scenario: "offline-expiry"
  },
  {
    file: "revoke-emergency-stop",
    gate: "revoke-emergency-stop",
    tests: ["revoke-denied", "emergency-stop-denied"],
    scenario: "revoke-emergency-stop"
  },
  {
    file: "crash-restart-recovery",
    gate: "crash-restart-recovery",
    tests: ["service-crash-recovery", "os-reboot-recovery"],
    scenario: "crash-restart-recovery"
  },
  {
    file: "sleep-wake-network-clock",
    gate: "sleep-wake-network-clock",
    tests: ["sleep-wake-recovery", "network-clock-failure"],
    scenario: "sleep-wake-network-clock"
  },
  {
    file: "upgrade-preserves-state",
    gate: "upgrade-preserves-state",
    tests: ["upgrade-preserves-state"],
    scenario: "upgrade-preserves-state"
  },
  {
    file: "uninstall-reinstall-recovery",
    gate: "uninstall-reinstall-recovery",
    tests: ["uninstall-reinstall-recovery"],
    scenario: "uninstall-reinstall-recovery"
  },
  {
    file: "current-user-purge",
    gate: "current-user-purge",
    tests: ["current-user-purge"],
    scenario: "current-user-purge"
  }
];

function sourceFor(file) {
  return fs.readFileSync(join(driversDirectory, file), "utf8");
}

function callFor(source, expected) {
  const call = source.match(/runGateDriver\(\{([\s\S]*?)\}\);/u);
  assert.ok(call, `${expected.file} must invoke runGateDriver`);
  const body = call[1];
  assert.match(body, new RegExp(`gate: "${expected.gate}"`));
  assert.match(body, new RegExp(`scenario: "${expected.scenario}"`));
  const testsMatch = body.match(/tests: \[([\s\S]*?)\]/u);
  assert.ok(testsMatch, `${expected.file} must declare its test mapping`);
  return {
    gate: body.match(/gate: "([^"]+)"/u)?.[1],
    scenario: body.match(/scenario: "([^"]+)"/u)?.[1],
    tests: [...testsMatch[1].matchAll(/"([^"]+)"/gu)].map((match) => match[1])
  };
}

test("lifecycle drivers are executable entrypoints with no local pass path", () => {
  for (const expected of cases) {
    const path = join(driversDirectory, expected.file);
    const stat = fs.statSync(path);
    assert.equal(stat.isFile(), true, expected.file);
    assert.equal((stat.mode & 0o111) !== 0, true, `${expected.file} must be executable`);

    const source = sourceFor(expected.file);
    assert.match(source, /^#!\/usr\/bin\/env node\n/u);
    assert.match(source, /from "\.\.\/lib\/driver-runtime\.mjs"/u);
    assert.doesNotMatch(source, /process\.stdout\.write|console\.log|status: "passed"/u);
    assert.deepEqual(callFor(source, expected), {
      gate: expected.gate,
      scenario: expected.scenario,
      tests: expected.tests
    });
  }
});

test("lifecycle test coverage is one-to-one and complete", () => {
  const testNames = cases.flatMap(({ tests }) => tests);
  assert.equal(new Set(testNames).size, testNames.length);
  assert.deepEqual(testNames.sort(), [
    "current-user-purge",
    "emergency-stop-denied",
    "network-clock-failure",
    "offline-expiry-denied",
    "os-reboot-recovery",
    "policy-reduction-denied",
    "revoke-denied",
    "service-crash-recovery",
    "sleep-wake-recovery",
    "uninstall-reinstall-recovery",
    "upgrade-preserves-state"
  ].sort());
});

test("lifecycle drivers use fixed scenario identifiers and do not accept input", () => {
  for (const expected of cases) {
    const source = sourceFor(expected.file);
    assert.doesNotMatch(source, /process\.argv|process\.env|readFileSync|spawn|exec|eval\(/u);
    assert.doesNotMatch(source, /scenario:\s*(?:process\.|process\[|[A-Za-z_$][A-Za-z0-9_$]*\.)/u);
  }
});

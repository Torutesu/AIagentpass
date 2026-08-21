import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const documentPath = path.join(root, "docs", "PLATFORM_THREAT_MODEL.md");

const REQUIRED_THREATS = [
  "browser-compromise-or-extension",
  "platform-session-theft",
  "confused-deputy",
  "proof-replay",
  "tenant-substitution",
  "local-malware",
  "signer-uncertainty",
  "database-rollback",
  "supply-chain-compromise",
  "downgrade",
  "physical-device-compromise",
  "cloud-provider-or-production-topology-compromise"
];

function readLedger() {
  const source = fs.readFileSync(documentPath, "utf8");
  const match = source.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(match, "Platform threat model must contain a JSON evidence ledger");
  const ledger = JSON.parse(match[1]);
  assert.equal(ledger.schema, "agentpass.platform-threat-ledger.v1");
  assert.ok(Array.isArray(ledger.threats));
  return { source, ledger };
}

function testDeclaration(source, name) {
  return source.includes(`test("${name}"`) || source.includes(`test('${name}'`);
}

test("every required Platform threat is classified and every local abuse case links to an executable test", () => {
  const { source, ledger } = readLedger();
  const byName = new Map();
  for (const threat of ledger.threats) {
    assert.match(threat.id, /^PTM-[0-9]{2}$/);
    assert.match(threat.name, /^[a-z0-9-]+$/);
    assert.ok(threat.abuse_case);
    assert.ok(!byName.has(threat.name), `duplicate threat: ${threat.name}`);
    byName.set(threat.name, threat);

    if (threat.scope === "local") {
      assert.ok(Array.isArray(threat.local_tests) && threat.local_tests.length > 0, `${threat.name} needs local test links`);
      for (const link of threat.local_tests) {
        assert.match(link.file, /\.test\.mjs$/);
        const absolute = path.join(root, link.file);
        assert.ok(fs.statSync(absolute).isFile(), `${threat.name} points to missing test: ${link.file}`);
        const testSource = fs.readFileSync(absolute, "utf8");
        assert.ok(testDeclaration(testSource, link.name), `${threat.name} points to missing test declaration: ${link.name}`);
      }
    } else {
      assert.equal(threat.scope, "external");
      assert.deepEqual(threat.local_tests, []);
      assert.ok(threat.external_release_evidence);
    }

    const evidence = threat.external_release_evidence;
    assert.ok(evidence?.artifact, `${threat.name} needs an evidence artifact`);
    assert.ok(evidence?.owner, `${threat.name} needs an evidence owner`);
    assert.ok(evidence?.exit_condition, `${threat.name} needs an evidence exit condition`);
  }
  assert.deepEqual([...byName.keys()].sort(), [...REQUIRED_THREATS].sort());
});

test("physical and cloud-only threats are explicitly external release evidence", () => {
  const { ledger } = readLedger();
  for (const name of [
    "physical-device-compromise",
    "cloud-provider-or-production-topology-compromise",
    "supply-chain-compromise"
  ]) {
    const threat = ledger.threats.find((entry) => entry.name === name);
    assert.ok(threat);
    assert.equal(threat.scope, "external");
    assert.equal(threat.local_tests.length, 0);
    assert.match(threat.external_release_evidence.artifact, /\.json$/);
  }
});

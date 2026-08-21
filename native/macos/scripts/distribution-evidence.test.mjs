import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const dir = () => fs.mkdtempSync(join(os.tmpdir(), 'agentpass-macos-evidence-'));
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const writeJSON = (path, value) => fs.writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });
const scripts = new URL('.', import.meta.url).pathname;
const run = (script, args) => execFileSync(process.execPath, [join(scripts, script), ...args], { encoding: 'utf8' });
const fixture = () => {
  const root = dir(); const evidenceRoot = dir(); const payload = join(root, 'payload.txt'); const artifact = join(root, 'AgentPass-1.0.0-macos-universal.pkg');
  fs.writeFileSync(payload, 'payload\n'); fs.writeFileSync(artifact, 'pkg\n');
  const inventoryPath = join(evidenceRoot, 'artifact-inventory.json'); run('generate-artifact-inventory.mjs', [root, artifact, inventoryPath]);
  const inventoryBytes = fs.readFileSync(inventoryPath); const inventory = JSON.parse(inventoryBytes); const artifactDescriptor = inventory.artifact;
  const notary = { status: 'Accepted', id: '01234567-89ab-cdef-0123-456789abcdef', artifact_sha256: artifactDescriptor.sha256 };
  const staple = { status: 'validated', artifact_sha256: artifactDescriptor.sha256 }; const gatekeeper = { assessment: 'accepted', artifact_sha256: artifactDescriptor.sha256 };
  writeJSON(join(evidenceRoot, 'notary.json'), notary); writeJSON(join(evidenceRoot, 'staple.json'), staple); writeJSON(join(evidenceRoot, 'gatekeeper.json'), gatekeeper);
  const evidence = { schema_version: 1, kind: 'agentpass.macos-distribution-evidence', artifact: artifactDescriptor, inventory: { name: 'artifact-inventory.json', bytes: inventoryBytes.length, sha256: sha(inventoryBytes) }, signature: { format: 'Developer ID Installer', identity: 'Developer ID Installer: Release (TEAM123456)', team_id: 'TEAM123456', verified: true }, notarization: { status: 'Accepted', submission_id: notary.id, artifact_sha256: artifactDescriptor.sha256, evidence_file: 'notary.json' }, staple: { status: 'validated', artifact_sha256: artifactDescriptor.sha256, evidence_file: 'staple.json' }, gatekeeper: { assessment: 'accepted', artifact_sha256: artifactDescriptor.sha256, evidence_file: 'gatekeeper.json' } };
  const evidencePath = join(evidenceRoot, 'distribution-evidence.json'); writeJSON(evidencePath, evidence); return { root, evidenceRoot, artifact, evidencePath, evidence };
};

test('generates and verifies a deterministic inventory-bound Developer ID evidence set', () => { const f = fixture(); const secondInventory = join(f.evidenceRoot, 'artifact-inventory-second.json'); run('generate-artifact-inventory.mjs', [f.root, f.artifact, secondInventory]); assert.deepEqual(fs.readFileSync(join(f.evidenceRoot, 'artifact-inventory.json')), fs.readFileSync(secondInventory)); const output = run('verify-distribution-evidence.mjs', [f.evidencePath, join(f.evidenceRoot, 'artifact-inventory.json'), f.root, f.evidenceRoot]); assert.match(output, /"status":"verified"/u); });
test('fails closed for missing or mismatched evidence', () => { const f = fixture(); fs.unlinkSync(join(f.evidenceRoot, 'staple.json')); assert.throws(() => run('verify-distribution-evidence.mjs', [f.evidencePath, join(f.evidenceRoot, 'artifact-inventory.json'), f.root, f.evidenceRoot])); const g = fixture(); fs.appendFileSync(g.artifact, 'tampered'); assert.throws(() => run('verify-distribution-evidence.mjs', [g.evidencePath, join(g.evidenceRoot, 'artifact-inventory.json'), g.root, g.evidenceRoot])); });
test('does not allow evidence paths to escape the evidence directory', () => { const f = fixture(); f.evidence.notarization.evidence_file = '../notary.json'; fs.writeFileSync(f.evidencePath, `${JSON.stringify(f.evidence, null, 2)}\n`); assert.throws(() => run('verify-distribution-evidence.mjs', [f.evidencePath, join(f.evidenceRoot, 'artifact-inventory.json'), f.root, f.evidenceRoot])); });

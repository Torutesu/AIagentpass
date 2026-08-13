import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const service = fs.readFileSync(new URL('../native/macos/Sources/AgentPassNativeService/main.swift', import.meta.url), 'utf8');
const example = JSON.parse(fs.readFileSync(new URL('../native/macos/Resources/native-service.example.json', import.meta.url), 'utf8'));

test('native service requires the exact Team ID, Developer ID leaf, and approval entitlement requirement', () => {
  assert.match(service, /NativeClientCodeRequirement\.requirement\(serviceAccessGroup: serviceAccessGroup\)/u);
  assert.match(service, /value\.clientCodeSigningRequirement\s*==/u);
  assert.match(example.client_code_signing_requirement, /certificate leaf\[field\.1\.2\.840\.113635\.100\.6\.1\.13\] exists/u);
  assert.ok(example.client_code_signing_requirement.includes('certificate leaf[subject.OU] = "TEAMID"'));
  assert.ok(example.client_code_signing_requirement.includes('entitlement["keychain-access-groups"] = "TEAMID.dev.agentpass.approval-keys"'));
});

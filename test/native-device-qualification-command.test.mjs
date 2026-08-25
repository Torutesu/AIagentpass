import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const serviceSource = fs.readFileSync(new URL('../native/macos/Sources/AgentPassNativeService/main.swift', import.meta.url), 'utf8');
const enrollmentSource = fs.readFileSync(new URL('../native/macos/Sources/AgentPassNativeCore/NativeEnrollmentKey.swift', import.meta.url), 'utf8');

test('qualification command preserves the fixed ControlBundle device-key binding', () => {
  assert.match(serviceSource, /value\.controlV2DeviceKeyTag\s*==\s*NativeEnrollmentKeyMaterial\.fixedApplicationTag/u);
  assert.match(enrollmentSource, /fixedApplicationTag\s*=\s*"dev\.agentpass\.device-auth\.v1"/u);
});

test('device-auth qualify is root-bound, wired to the qualification snapshot, and cannot create a key', () => {
  assert.match(serviceSource, /guard geteuid\(\) == 0 else \{/u);
  assert.match(serviceSource, /let configuration = try ServiceConfiguration\.load\(path: configPath\)/u);
  assert.match(serviceSource, /guard let accessGroup = configuration\.keychainAccessGroup, !accessGroup\.isEmpty/u);
  assert.match(serviceSource, /case "qualify":\s*\n\s*let snapshot = try SecureEnclaveNativeEnrollmentKeyStore\(accessGroup: accessGroup\)\.qualificationSnapshot\(\)/u);
  assert.match(serviceSource, /try emitQualificationSnapshot\(snapshot\)/u);
  assert.match(serviceSource, /--device-auth key\|sign\|qualify --config PATH/u);

  const qualifyBranch = serviceSource.match(/case "qualify":([\s\S]*?)\n\s*default:/u)?.[1];
  assert.ok(qualifyBranch, 'qualify branch must be present');
  assert.doesNotMatch(qualifyBranch, /loadOrCreate|createPublicKeyX963|SecKeyCreateRandomKey/u);
  assert.match(serviceSource, /"private_exportable"/u);
  assert.match(serviceSource, /Set\(object\.keys\) == qualificationSnapshotKeys/u);
});

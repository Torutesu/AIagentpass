import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const serviceSource = fs.readFileSync(new URL('../native/macos/Sources/AgentPassNativeService/main.swift', import.meta.url), 'utf8');
const provisioningSource = fs.readFileSync(new URL('../native/macos/Sources/AgentPassNativeCore/NativeControlProvisioning.swift', import.meta.url), 'utf8');
const enrollmentSource = fs.readFileSync(new URL('../native/macos/Sources/AgentPassNativeCore/NativeEnrollmentKey.swift', import.meta.url), 'utf8');
const example = JSON.parse(fs.readFileSync(new URL('../native/macos/Resources/native-service.example.json', import.meta.url), 'utf8'));

test('enrollment, provisioning, service validation, and example use one fixed device key tag', () => {
  const fixed = enrollmentSource.match(/fixedApplicationTag\s*=\s*"([^"]+)"/u)?.[1];
  assert.equal(fixed, 'dev.agentpass.device-auth.v1');
  assert.match(provisioningSource, /updated\["control_v2_device_key_tag"\]\s*=\s*NativeEnrollmentKeyMaterial\.fixedApplicationTag/u);
  assert.match(serviceSource, /value\.controlV2DeviceKeyTag\s*==\s*NativeEnrollmentKeyMaterial\.fixedApplicationTag/u);
  assert.equal(example.control_v2_device_key_tag, fixed);
});

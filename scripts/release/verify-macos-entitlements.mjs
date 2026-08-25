#!/usr/bin/env node
import fs from 'node:fs';

const [role, expectedGroup, expectedControllerPrefix] = process.argv.slice(2);
const expectedArgumentCount = role === 'service' || role === 'client' ? 2 : role === 'controller' ? 3 : 1;
if (!['service', 'client', 'manager', 'outer', 'controller'].includes(role) || process.argv.slice(2).length !== expectedArgumentCount) {
  throw new Error('Usage: verify-macos-entitlements.mjs service|client EXPECTED-GROUP | controller TEAM-ID APP-IDENTIFIER-PREFIX | manager|outer');
}
if ((role === 'service' || role === 'client') && !/^[A-Z0-9]{10}\.dev\.agentpass\.(?:service|approval)-keys$/.test(expectedGroup)) {
  throw new Error('invalid expected keychain access group');
}
if (role === 'controller' && (!/^[A-Z0-9]{10}$/.test(expectedGroup) || !/^[A-Z0-9]{10}$/.test(expectedControllerPrefix))) throw new Error('invalid controller signing identifiers');

const input = fs.readFileSync(0);
if (input.length === 0 || input.length > 1024 * 1024) throw new Error('invalid signed entitlements input size');
let value;
try { value = JSON.parse(input.toString('utf8')); } catch { throw new Error('signed entitlements are not valid JSON'); }
if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('signed entitlements must be a dictionary');

const dangerous = [
  'com.apple.security.get-task-allow',
  'get-task-allow',
  'com.apple.security.cs.disable-library-validation'
];
if (dangerous.some((key) => value[key] === true)) throw new Error(`${role} carries a dangerous signed entitlement`);

const keys = Object.keys(value);
if (role === 'service' || role === 'client') {
  const groups = value['keychain-access-groups'];
  if (keys.length !== 1 || keys[0] !== 'keychain-access-groups' || !Array.isArray(groups) || groups.length !== 1 || groups[0] !== expectedGroup) {
    throw new Error(`${role} signed entitlements do not exactly match its expected keychain group`);
  }
} else if (role === 'controller') {
  const expected = ['application-identifier', 'com.apple.developer.team-identifier', 'dev.agentpass.qualification-control'];
  if (JSON.stringify([...keys].sort()) !== JSON.stringify(expected) || value['application-identifier'] !== `${expectedControllerPrefix}.dev.agentpass.qualification-controller` || value['com.apple.developer.team-identifier'] !== expectedGroup || value['dev.agentpass.qualification-control'] !== true) {
    throw new Error('controller signed entitlements do not exactly match its dedicated authority');
  }
} else if (keys.length !== 0) {
  throw new Error(`${role} signed entitlements must be empty`);
}

process.stdout.write(`${JSON.stringify({ role, valid: true })}\n`);

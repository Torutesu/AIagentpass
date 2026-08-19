import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { REQUIRED_SIGNING_INPUTS, SigningInputError, validateSigningInputs } from './validate-signing-inputs.mjs';

const validEnvironment = () => ({
  AGENTPASS_SIGNING_CERTIFICATE_P12_BASE64: 'cA==',
  AGENTPASS_SIGNING_CERTIFICATE_PASSWORD: 'certificate-password',
  AGENTPASS_SIGNING_IDENTITY: 'Developer ID Application: AgentPass Release (ABCDE12345)',
  AGENTPASS_INSTALLER_SIGNING_IDENTITY: 'Developer ID Installer: AgentPass Release (ABCDE12345)',
  AGENTPASS_TEAM_ID: 'ABCDE12345',
  AGENTPASS_APP_IDENTIFIER_PREFIX: 'ABCDE12345',
  AGENTPASS_SERVICE_PROFILE_BASE64: 'cA==',
  AGENTPASS_CLIENT_PROFILE_BASE64: 'cA==',
  AGENTPASS_AGENT_PROFILE_BASE64: 'cA==',
  AGENTPASS_QUALIFICATION_CLIENT_PROFILE_BASE64: 'cA==',
  AGENTPASS_CONTROLLER_PROFILE_BASE64: 'cA==',
  AGENTPASS_EPHEMERAL_KEYCHAIN_PASSWORD: 'keychain-password',
  AGENTPASS_RELEASE_MANIFEST_PRIVATE_KEY_BASE64: 'cA==',
  AGENTPASS_RELEASE_MANIFEST_PUBLIC_KEY_BASE64: 'cA==',
  AGENTPASS_NOTARY_KEY_ID: 'ABCDE12345',
  AGENTPASS_NOTARY_ISSUER_ID: '01234567-89ab-cdef-0123-456789abcdef',
  AGENTPASS_NOTARY_PRIVATE_KEY_BASE64: 'cA=='
});

test('dry-run is credential-free, performs no external action, and never proves production readiness', () => {
  const result = validateSigningInputs({}, { mode: 'dry-run' });
  assert.equal(result.status, 'dry_run_not_proven');
  assert.equal(result.production_ready, false);
  assert.deepEqual(result.missing_inputs, [...REQUIRED_SIGNING_INPUTS]);
  assert.deepEqual(result.external_actions_not_run, ['codesign', 'xcrun notarytool', 'xcrun stapler', 'spctl']);
});

test('production mode fails closed when any required input is absent', () => {
  const environment = validEnvironment();
  delete environment.AGENTPASS_CONTROLLER_PROFILE_BASE64;
  assert.throws(
    () => validateSigningInputs(environment),
    (error) => error instanceof SigningInputError && error.message.includes('AGENTPASS_CONTROLLER_PROFILE_BASE64')
  );
});

test('ad-hoc and development identities are rejected before signing', () => {
  const environment = validEnvironment();
  environment.AGENTPASS_SIGNING_IDENTITY = '-';
  assert.throws(() => validateSigningInputs(environment), /AGENTPASS_SIGNING_IDENTITY.*Developer ID.*ad-hoc/iu);
  environment.AGENTPASS_SIGNING_IDENTITY = 'Apple Development: AgentPass (ABCDE12345)';
  assert.throws(() => validateSigningInputs(environment), /AGENTPASS_SIGNING_IDENTITY.*Developer ID/iu);
  environment.AGENTPASS_INSTALLER_SIGNING_IDENTITY = 'Developer ID Application: AgentPass Release (ABCDE12345)';
  assert.throws(() => validateSigningInputs(environment), /AGENTPASS_INSTALLER_SIGNING_IDENTITY.*Developer ID/iu);
});

test('Developer ID identities must bind to the configured Team ID', () => {
  const environment = validEnvironment();
  environment.AGENTPASS_INSTALLER_SIGNING_IDENTITY = 'Developer ID Installer: AgentPass Release (ZZZZZ99999)';
  assert.throws(() => validateSigningInputs(environment), /Team ID does not match/iu);
});

test('CLI dry-run works without credentials and production invocation does not', () => {
  const script = new URL('./validate-signing-inputs.mjs', import.meta.url);
  const shell = new URL('./require-credentials.sh', import.meta.url);
  const env = { PATH: process.env.PATH, NODE_PATH: process.env.NODE_PATH };
  const dryRun = spawnSync(process.execPath, [script.pathname, '--dry-run'], { env, encoding: 'utf8' });
  assert.equal(dryRun.status, 0, dryRun.stderr);
  assert.equal(JSON.parse(dryRun.stdout).status, 'dry_run_not_proven');
  const production = spawnSync('bash', [shell.pathname], { env, encoding: 'utf8' });
  assert.equal(production.status, 1);
  assert.match(production.stderr, /required release signing inputs are missing/iu);
});

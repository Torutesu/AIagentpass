#!/usr/bin/env node

const TEAM_ID = /^[A-Z0-9]{10}$/u;
const NOTARY_KEY_ID = /^[A-Z0-9]{10}$/u;
const ISSUER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const DEVELOPER_ID_APPLICATION = /^Developer ID Application: .+ \(([A-Z0-9]{10})\)$/u;
const DEVELOPER_ID_INSTALLER = /^Developer ID Installer: .+ \(([A-Z0-9]{10})\)$/u;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

export const REQUIRED_SIGNING_INPUTS = Object.freeze([
  'AGENTPASS_SIGNING_CERTIFICATE_P12_BASE64',
  'AGENTPASS_SIGNING_CERTIFICATE_PASSWORD',
  'AGENTPASS_SIGNING_IDENTITY',
  'AGENTPASS_INSTALLER_SIGNING_IDENTITY',
  'AGENTPASS_TEAM_ID',
  'AGENTPASS_APP_IDENTIFIER_PREFIX',
  'AGENTPASS_SERVICE_PROFILE_BASE64',
  'AGENTPASS_CLIENT_PROFILE_BASE64',
  'AGENTPASS_AGENT_PROFILE_BASE64',
  'AGENTPASS_QUALIFICATION_CLIENT_PROFILE_BASE64',
  'AGENTPASS_CONTROLLER_PROFILE_BASE64',
  'AGENTPASS_EPHEMERAL_KEYCHAIN_PASSWORD',
  'AGENTPASS_RELEASE_MANIFEST_PRIVATE_KEY_BASE64',
  'AGENTPASS_RELEASE_MANIFEST_PUBLIC_KEY_BASE64',
  'AGENTPASS_NOTARY_KEY_ID',
  'AGENTPASS_NOTARY_ISSUER_ID',
  'AGENTPASS_NOTARY_PRIVATE_KEY_BASE64'
]);

const BASE64_INPUTS = new Set([
  'AGENTPASS_SIGNING_CERTIFICATE_P12_BASE64',
  'AGENTPASS_SERVICE_PROFILE_BASE64',
  'AGENTPASS_CLIENT_PROFILE_BASE64',
  'AGENTPASS_AGENT_PROFILE_BASE64',
  'AGENTPASS_QUALIFICATION_CLIENT_PROFILE_BASE64',
  'AGENTPASS_CONTROLLER_PROFILE_BASE64',
  'AGENTPASS_RELEASE_MANIFEST_PRIVATE_KEY_BASE64',
  'AGENTPASS_RELEASE_MANIFEST_PUBLIC_KEY_BASE64',
  'AGENTPASS_NOTARY_PRIVATE_KEY_BASE64'
]);

export class SigningInputError extends Error {
  constructor(messages) {
    super(messages.join('; '));
    this.name = 'SigningInputError';
    this.messages = messages;
  }
}

const present = (value) => typeof value === 'string' && value.length > 0;

const validateIdentity = (value, pattern, label, teamID, errors) => {
  if (!present(value)) return;
  const match = pattern.exec(value);
  if (!match) {
    errors.push(`${label} must be a Developer ID identity bound to Team ID ${teamID || '<missing>'}; ad-hoc and development identities are not accepted`);
    return;
  }
  if (present(teamID) && match[1] !== teamID) errors.push(`${label} Team ID does not match AGENTPASS_TEAM_ID`);
};

const validateBase64 = (value, name, errors) => {
  if (!present(value)) return;
  if (!BASE64.test(value)) errors.push(`${name} is not canonical base64`);
  else {
    try {
      if (Buffer.from(value, 'base64').length === 0) errors.push(`${name} decodes to empty input`);
    } catch { errors.push(`${name} is not decodable base64`); }
  }
};

export function validateSigningInputs(environment = process.env, { mode = 'production' } = {}) {
  if (!['production', 'dry-run'].includes(mode)) throw new TypeError(`unsupported signing input validation mode: ${mode}`);
  const env = environment && typeof environment === 'object' ? environment : {};
  const errors = [];
  const missing = REQUIRED_SIGNING_INPUTS.filter((name) => !present(env[name]));

  if (mode === 'production' && missing.length > 0) errors.push(`required release signing inputs are missing: ${missing.join(', ')}`);

  const teamID = env.AGENTPASS_TEAM_ID;
  if (present(teamID) && !TEAM_ID.test(teamID)) errors.push('AGENTPASS_TEAM_ID must be exactly 10 uppercase alphanumeric characters');
  const prefix = env.AGENTPASS_APP_IDENTIFIER_PREFIX;
  if (present(prefix) && !TEAM_ID.test(prefix)) errors.push('AGENTPASS_APP_IDENTIFIER_PREFIX must be exactly 10 uppercase alphanumeric characters');
  validateIdentity(env.AGENTPASS_SIGNING_IDENTITY, DEVELOPER_ID_APPLICATION, 'AGENTPASS_SIGNING_IDENTITY', teamID, errors);
  validateIdentity(env.AGENTPASS_INSTALLER_SIGNING_IDENTITY, DEVELOPER_ID_INSTALLER, 'AGENTPASS_INSTALLER_SIGNING_IDENTITY', teamID, errors);

  if (present(env.AGENTPASS_NOTARY_KEY_ID) && !NOTARY_KEY_ID.test(env.AGENTPASS_NOTARY_KEY_ID)) errors.push('AGENTPASS_NOTARY_KEY_ID must be exactly 10 uppercase alphanumeric characters');
  if (present(env.AGENTPASS_NOTARY_ISSUER_ID) && !ISSUER_ID.test(env.AGENTPASS_NOTARY_ISSUER_ID)) errors.push('AGENTPASS_NOTARY_ISSUER_ID must be a UUID');
  for (const name of BASE64_INPUTS) validateBase64(env[name], name, errors);

  if (errors.length > 0) throw new SigningInputError(errors);
  if (mode === 'dry-run') {
    return {
      status: 'dry_run_not_proven',
      verification_mode: 'credential_shape_only',
      production_ready: false,
      required_inputs: [...REQUIRED_SIGNING_INPUTS],
      missing_inputs: missing,
      external_actions_not_run: ['codesign', 'xcrun notarytool', 'xcrun stapler', 'spctl']
    };
  }
  return {
    status: 'inputs_present',
    verification_mode: 'credential_shape_only',
    production_ready: false,
    required_inputs: [...REQUIRED_SIGNING_INPUTS],
    missing_inputs: []
  };
}

const args = process.argv.slice(2);
if (import.meta.url === `file://${process.argv[1]}`) {
  if (args.length > 1 || (args.length === 1 && args[0] !== '--dry-run')) {
    console.error('Usage: validate-signing-inputs.mjs [--dry-run]');
    process.exitCode = 2;
  } else {
    try {
      const result = validateSigningInputs(process.env, { mode: args[0] === '--dry-run' ? 'dry-run' : 'production' });
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } catch (error) {
      console.error(`Release signing input validation failed: ${error.message}`);
      process.exitCode = 1;
    }
  }
}

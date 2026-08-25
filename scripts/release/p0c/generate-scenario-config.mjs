#!/usr/bin/env node
import fs from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { canonicalJSON, readProtectedFile, validateScenarioConfig } from './lib/scenario-runtime.mjs';

const EXECUTABLE_FLAGS = Object.freeze({
  '--native-client': 'native_client', '--native-manager': 'native_manager', '--native-service': 'native_service',
  '--claude-code': 'claude_code', '--cursor': 'cursor', '--qualification-grant-client': 'qualification_grant_client'
});
const VALUE_FLAGS = new Set([...Object.keys(EXECUTABLE_FLAGS), '--test-repository', '--cloud-probe-url', '--checkpoint-directory', '--output']);

const protectedDirectory = (input, label) => {
  if (typeof input !== 'string' || !isAbsolute(input)) throw new Error(`${label} must be an absolute path`);
  const path = resolve(input); let stat; try { stat = fs.lstatSync(path); } catch { throw new Error(`${label} is unavailable`); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) throw new Error(`${label} is unsafe`);
  return path;
};

const parseArgs = (args) => {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index]; const value = args[index + 1];
    if (!VALUE_FLAGS.has(key) || !value || value.startsWith('--') || values.has(key)) throw new Error('invalid scenario config arguments');
    values.set(key, value);
  }
  if (values.size !== VALUE_FLAGS.size) throw new Error('all scenario config arguments are required');
  return values;
};

const writeExclusive = (input, bytes) => {
  if (!isAbsolute(input)) throw new Error('scenario config output must be absolute'); const path = resolve(input); let descriptor;
  try { descriptor = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600); let offset = 0; while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset); fs.fsyncSync(descriptor); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
  const stat = fs.lstatSync(path); if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.size !== bytes.length) throw new Error('scenario config output is unsafe');
  return path;
};

export const generateScenarioConfig = ({ nativeClient, nativeManager, nativeService, claudeCode, cursor, qualificationGrantClient, testRepository, cloudProbeURL, checkpointDirectory, outputPath } = {}) => {
  const inputs = { native_client: nativeClient, native_manager: nativeManager, native_service: nativeService, claude_code: claudeCode, cursor, qualification_grant_client: qualificationGrantClient };
  const executables = Object.fromEntries(Object.entries(inputs).map(([name, path]) => { const snapshot = readProtectedFile(path, { maximum: 64 * 1024 * 1024, executable: true, production: false }); return [name, { path: name === 'qualification_grant_client' ? '/opt/agentpass/p0c/qualification-client/agentpass-qualification-grant-client' : snapshot.path, sha256: snapshot.sha256 }]; }));
  const value = {
    schema_version: 1,
    application_path: '/Applications/AgentPass.app',
    executables,
    service_label: 'dev.agentpass.native-service',
    service_config_path: '/Library/Application Support/AgentPass/native-service.json',
    test_repository: protectedDirectory(testRepository, 'qualification test repository'),
    cloud_probe_url: cloudProbeURL,
    checkpoint_directory: protectedDirectory(checkpointDirectory, 'qualification checkpoint directory')
  };
  validateScenarioConfig(value); const bytes = canonicalJSON(value); const output = writeExclusive(outputPath, bytes);
  return Object.freeze({ output, bytes: bytes.length });
};

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const values = parseArgs(process.argv.slice(2));
    const result = generateScenarioConfig({ nativeClient: values.get('--native-client'), nativeManager: values.get('--native-manager'), nativeService: values.get('--native-service'), claudeCode: values.get('--claude-code'), cursor: values.get('--cursor'), qualificationGrantClient: values.get('--qualification-grant-client'), testRepository: values.get('--test-repository'), cloudProbeURL: values.get('--cloud-probe-url'), checkpointDirectory: values.get('--checkpoint-directory'), outputPath: values.get('--output') });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch { process.stderr.write('P0-C scenario config generation refused\n'); process.exitCode = 1; }
}

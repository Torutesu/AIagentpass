export const SCHEMA_VERSION = 2;
export const MANIFEST_KIND = 'agentpass-n3e-controller-candidate';
export const QUALIFICATION_MODE = 'n3e-qualification';
export const QUALIFICATION_MACH_SERVICE = 'dev.agentpass.n3e-qualification';
export const MAX_LIFETIME_SECONDS = 15 * 60;
export const OUTPUT_FILES = Object.freeze([
  'controller-candidate.json',
  'controller-candidate.sig',
  'release-public.pem'
]);

const DIGEST = /^[0-9a-f]{64}$/u;
const CDHASH = /^[0-9a-f]{40}$/u;
const QUALIFICATION_FIELDS = Object.freeze([
  'qualification_mode', 'qualification_mach_service_name', 'qualification_candidate_sha256',
  'qualification_source_commit_sha256', 'qualification_code_identities_sha256',
  'qualification_controller_cdhash', 'qualification_run_id_sha256',
  'qualification_expires_at_epoch_seconds', 'qualification_scenario', 'qualification_phase'
]);
const SCENARIO_PHASE = new Map([
  ['pre-cloud-kill', 'pre-cloud'],
  ['post-cloud-pre-local-kill', 'post-cloud-pre-local'],
  ['post-activation-pre-audit-kill', 'post-activation-pre-audit'],
  ['post-audit-pre-reply-loss', 'post-audit-pre-reply'],
  ['audit-fsync-failure', 'audit-fsync'],
  ['transport-reply-loss', 'transport-reply']
]);

const fail = (message) => { throw new Error(message); };
const digest = (value, field) => {
  if (typeof value !== 'string' || !DIGEST.test(value) || /^0+$/u.test(value)) fail(`${field} is invalid`);
  return value;
};
const cdhash = (value) => {
  if (typeof value !== 'string' || !CDHASH.test(value) || /^0+$/u.test(value)) fail('controller_cdhash is invalid');
  return value;
};
const integer = (value, field) => {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${field} is invalid`);
  return value;
};

export const readQualification = (serviceBytes, nowEpochSeconds = Date.now() / 1000) => {
  let service;
  try { service = JSON.parse(serviceBytes.toString('utf8')); } catch { fail('service config is not valid JSON'); }
  if (!service || typeof service !== 'object' || Array.isArray(service)) fail('service config must be an object');
  const values = Object.create(null);
  for (const field of QUALIFICATION_FIELDS) {
    if (!Object.hasOwn(service, field)) fail(`service config is missing ${field}`);
    values[field] = service[field];
  }
  if (values.qualification_mode !== QUALIFICATION_MODE) fail('service config mode is invalid');
  if (values.qualification_mach_service_name !== QUALIFICATION_MACH_SERVICE) fail('service config service is invalid');
  const candidate = digest(values.qualification_candidate_sha256, 'candidate_sha256');
  const source = digest(values.qualification_source_commit_sha256, 'source_commit_sha256');
  const identities = digest(values.qualification_code_identities_sha256, 'code_identities_sha256');
  const controller = cdhash(values.qualification_controller_cdhash);
  const run = digest(values.qualification_run_id_sha256, 'run_id_sha256');
  const expiry = integer(values.qualification_expires_at_epoch_seconds, 'expires_at_epoch_seconds');
  if (!Number.isFinite(nowEpochSeconds) || !(expiry > nowEpochSeconds) || expiry - nowEpochSeconds > MAX_LIFETIME_SECONDS) fail('service config expiry is invalid');
  const scenario = values.qualification_scenario;
  const phase = values.qualification_phase;
  if (typeof scenario !== 'string' || SCENARIO_PHASE.get(scenario) !== phase) fail('service config scenario/phase pair is invalid');
  return Object.freeze({ candidate, source, identities, controller, run, expiry, scenario, phase });
};

const sortedValue = (value) => {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedValue(value[key])]));
  return value;
};

export const canonicalJSON = (value) => Buffer.from(JSON.stringify(sortedValue(value)), 'utf8');

export const makeControllerCandidate = (qualification) => ({
  schema_version: SCHEMA_VERSION,
  kind: MANIFEST_KIND,
  candidate_sha256: qualification.candidate,
  source_commit_sha256: qualification.source,
  code_identities_sha256: qualification.identities,
  controller_cdhash: qualification.controller,
  run_id_sha256: qualification.run,
  expires_at_epoch_seconds: qualification.expiry,
  scenario: qualification.scenario,
  phase: qualification.phase
});

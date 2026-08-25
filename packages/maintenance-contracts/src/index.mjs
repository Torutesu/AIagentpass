import crypto from 'node:crypto';

export const MAINTENANCE_CONTRACT_VERSION = 1;
export const ADVISORY_SIGNATURE_DOMAIN = 'agentpass.maintenance.advisory/v1';
export const EVENT_SIGNATURE_DOMAIN = 'agentpass.maintenance.provider-key-event/v1';
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PATH = /^\/(?:[^\0\n\r]+)$/;
const METHODS = new Set(['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS']);
const SELECTOR_TYPES = new Set(['endpoint','method','field','sdk_symbol','pagination','version_header','webhook_field','error']);

export class MaintenanceContractError extends Error { constructor(code, message) { super(message); this.name = 'MaintenanceContractError'; this.code = code; } }
const fail = (code, message) => { throw new MaintenanceContractError(code, message); };
function object(value, label) { if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_object', `${label} must be an object`); return value; }
function closed(value, allowed, label) { for (const key of Object.keys(value)) if (!allowed.has(key)) fail('unknown_field', `${label} contains an unknown field`); }
function id(value, label) { if (typeof value !== 'string' || !ID.test(value)) fail('invalid_identifier', `${label} is invalid`); return value; }
function digest(value, label) { if (typeof value !== 'string' || !DIGEST.test(value)) fail('invalid_digest', `${label} is invalid`); return value; }
function timestamp(value, label) { if (typeof value !== 'string' || !TS.test(value) || Number.isNaN(Date.parse(value))) fail('invalid_timestamp', `${label} is invalid`); return value; }

export function canonicalJson(value) {
  const seen = new Set();
  const walk = (v) => {
    if (v === null || typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
    if (typeof v === 'number' && Number.isFinite(v)) return JSON.stringify(v);
    if (!v || typeof v !== 'object' || seen.has(v)) fail('noncanonical_value', 'value is not canonical JSON');
    seen.add(v);
    const out = Array.isArray(v) ? `[${v.map(walk).join(',')}]` : `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${walk(v[k])}`).join(',')}}`;
    seen.delete(v); return out;
  }; return walk(value);
}
export const canonicalize = canonicalJson;
export function sha256(value) { return crypto.createHash('sha256').update(typeof value === 'string' ? value : canonicalJson(value)).digest('hex'); }

export function validateProviderIdentity(value) {
  const v = object(value, 'provider'); closed(v, new Set(['schema_version','kind','provider_id','display_name','publisher_origin','identity_digest','key_ids']), 'provider');
  if (v.schema_version !== 1 || v.kind !== 'agentpass.maintenance.provider-identity') fail('unknown_version', 'unsupported provider contract');
  id(v.provider_id, 'provider_id'); if (typeof v.display_name !== 'string' || !v.display_name || v.display_name.length > 200) fail('invalid_display_name', 'display_name is invalid');
  if (typeof v.publisher_origin !== 'string' || !/^https:\/\/[^/\s]+$/.test(v.publisher_origin)) fail('invalid_origin', 'publisher_origin must be HTTPS origin'); digest(v.identity_digest, 'identity_digest');
  if (!Array.isArray(v.key_ids) || !v.key_ids.length || v.key_ids.length > 32 || new Set(v.key_ids).size !== v.key_ids.length) fail('invalid_keys', 'key_ids must be unique and bounded'); v.key_ids.forEach((x) => id(x, 'key_id')); return v;
}

export function validateSelector(value) {
  const v = object(value, 'selector'); closed(v, new Set(['type','operation','path','field','symbol','from','to']), 'selector');
  if (!SELECTOR_TYPES.has(v.type)) fail('invalid_selector', 'unknown selector type');
  if (v.operation !== undefined && !METHODS.has(v.operation)) fail('invalid_selector', 'invalid method');
  if (v.path !== undefined && (typeof v.path !== 'string' || !PATH.test(v.path) || v.path.includes('*') || v.path.includes('..'))) fail('overbroad_selector', 'path selector must be exact and absolute');
  for (const k of ['field','symbol','from','to']) if (v[k] !== undefined && (typeof v[k] !== 'string' || !v[k].length || v[k].length > 200 || /[*\n\r]/.test(v[k]))) fail('invalid_selector', `${k} is invalid`);
  if (v.type === 'endpoint' && (!v.path || v.operation)) fail('invalid_selector', 'endpoint requires exact path only');
  if (v.type === 'method' && (!v.path || !v.operation)) fail('invalid_selector', 'method requires exact path and method');
  if (['field','webhook_field'].includes(v.type) && (!v.path || !v.field)) fail('invalid_selector', 'field requires exact path and field');
  if (v.type === 'sdk_symbol' && !v.symbol) fail('invalid_selector', 'SDK symbol is required');
  return v;
}

export function validateAdvisory(value) {
  const v = object(value, 'advisory'); closed(v, new Set(['schema_version','kind','advisory_id','provider_id','provider_key_id','sequence','event','severity','published_at','effective_at','selectors','old_contract_digest','new_contract_digest','migration_attachment','statement_digest','signature_algorithm','signature']), 'advisory');
  if (v.schema_version !== 1 || v.kind !== 'agentpass.maintenance.advisory') fail('unknown_version', 'unsupported advisory contract'); id(v.advisory_id, 'advisory_id'); id(v.provider_id, 'provider_id'); id(v.provider_key_id, 'provider_key_id');
  if (!Number.isSafeInteger(v.sequence) || v.sequence < 1) fail('invalid_sequence', 'sequence must be positive'); if (!['publish','correction','withdrawal'].includes(v.event)) fail('invalid_event', 'event is invalid'); if (!['low','medium','high','critical'].includes(v.severity)) fail('invalid_severity', 'severity is invalid'); timestamp(v.published_at, 'published_at'); timestamp(v.effective_at, 'effective_at');
  if (Date.parse(v.effective_at) < Date.parse(v.published_at)) fail('invalid_time_order', 'effective_at precedes publication'); if (!Array.isArray(v.selectors) || !v.selectors.length || v.selectors.length > 64) fail('invalid_selectors', 'selectors are bounded'); if (new Set(v.selectors.map(x => canonicalJson(validateSelector(x)))).size !== v.selectors.length) fail('duplicate_selector', 'selectors must be unique');
  v.selectors.forEach(validateSelector); digest(v.old_contract_digest, 'old_contract_digest'); digest(v.new_contract_digest, 'new_contract_digest'); if (v.migration_attachment !== undefined) { const a = object(v.migration_attachment, 'migration_attachment'); closed(a, new Set(['uri','digest','media_type','executable']), 'migration_attachment'); if (a.executable !== false) fail('executable_attachment', 'executable migration material is never trusted'); if (typeof a.uri !== 'string' || !/^https:\/\//.test(a.uri)) fail('invalid_attachment', 'attachment URI must be HTTPS'); digest(a.digest, 'attachment digest'); if (typeof a.media_type !== 'string' || a.media_type.length > 128) fail('invalid_attachment', 'attachment media type invalid'); }
  if (v.statement_digest !== undefined) digest(v.statement_digest, 'statement_digest'); if (v.signature_algorithm !== 'ed25519' || typeof v.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(v.signature)) fail('invalid_signature', 'signature is invalid'); return v;
}

export function validateProviderKeyEvent(value) { const v = object(value, 'provider key event'); closed(v, new Set(['schema_version','kind','event_id','provider_id','provider_key_id','event','reason','occurred_at','statement_digest','signature_algorithm','signature']), 'provider key event'); if (v.schema_version !== 1 || v.kind !== 'agentpass.maintenance.provider-key-event') fail('unknown_version', 'unsupported key event'); id(v.event_id, 'event_id'); id(v.provider_id, 'provider_id'); id(v.provider_key_id, 'provider_key_id'); if (!['activate','revoke','rotate'].includes(v.event)) fail('invalid_event', 'event is invalid'); if (typeof v.reason !== 'string' || !v.reason || v.reason.length > 500) fail('invalid_reason', 'reason is invalid'); timestamp(v.occurred_at, 'occurred_at'); digest(v.statement_digest, 'statement_digest'); if (v.signature_algorithm !== 'ed25519' || typeof v.signature !== 'string') fail('invalid_signature', 'signature is invalid'); return v; }

export function validateUsageAttestation(v) { return validateSimple(v, 'agentpass.maintenance.usage-attestation', new Set(['schema_version','kind','attestation_id','organization_id','app_id','provider_id','source_digest','observed_at','usages'])); }
export function validateMaintenancePolicy(v) { const x = validateSimple(v, 'agentpass.maintenance.policy', new Set(['schema_version','kind','policy_id','organization_id','mode','allowed_provider_ids','allowed_branches','allowed_paths','max_files','expires_at'])); if (!['notify','draft_pr'].includes(x.mode)) fail('invalid_policy', 'private-alpha supports notify and draft_pr only'); if (!Array.isArray(x.allowed_provider_ids) || !Array.isArray(x.allowed_branches) || !Array.isArray(x.allowed_paths)) fail('invalid_policy', 'policy arrays required'); x.allowed_paths.forEach((p) => { if (!PATH.test(p) || p.includes('*') || p.includes('..')) fail('overbroad_policy', 'paths must be exact'); }); return x; }
export function validateMaintenancePlan(v) { return validateSimple(v, 'agentpass.maintenance.plan', new Set(['schema_version','kind','plan_id','organization_id','app_id','repository_id','branch','advisory_id','selector_digests','files','authority'])); }
export function validateMaintenanceGrant(v) { const x = validateSimple(v, 'agentpass.maintenance.grant', new Set(['schema_version','kind','grant_id','organization_id','repository_id','branch','job_id','issued_at','expires_at','operations','provider_id'])); if (x.provider_id !== undefined) fail('provider_authority_boundary', 'provider cannot select grant authority'); if (!Array.isArray(x.operations) || x.operations.some(o => ['approve','select_repository','select_app'].includes(o))) fail('invalid_grant', 'grant operation is prohibited'); timestamp(x.issued_at, 'issued_at'); timestamp(x.expires_at, 'expires_at'); return x; }
export function validateMaintenanceReceipt(v) { return validateSimple(v, 'agentpass.maintenance.receipt', new Set(['schema_version','kind','receipt_id','organization_id','job_id','source_commit','patch_digest','verification_status','created_at','uncertainty'])); }
function validateSimple(v, kind, allowed) { const x = object(v, kind); closed(x, allowed, kind); if (x.schema_version !== 1 || x.kind !== kind) fail('unknown_version', `unsupported ${kind}`); for (const k of ['organization_id','app_id','repository_id','branch','plan_id','grant_id','job_id','policy_id','attestation_id','provider_id','advisory_id','receipt_id']) if (x[k] !== undefined) id(x[k], k); for (const k of ['source_digest','patch_digest']) if (x[k] !== undefined) digest(x[k], k); return x; }

export function signAdvisory(statement, privateKey) { const v = validateAdvisory(statement); return crypto.sign(null, Buffer.from(ADVISORY_SIGNATURE_DOMAIN + '\n' + canonicalJson(v), 'utf8'), privateKey).toString('base64url'); }
export function verifyAdvisory(statement, signature, publicKey) { try { validateAdvisory(statement); return crypto.verify(null, Buffer.from(ADVISORY_SIGNATURE_DOMAIN + '\n' + canonicalJson(statement), 'utf8'), publicKey, Buffer.from(signature, 'base64url')); } catch { return false; } }
export function advisoryDigest(statement) { validateAdvisory(statement); return sha256(ADVISORY_SIGNATURE_DOMAIN + '\n' + canonicalJson(statement)); }

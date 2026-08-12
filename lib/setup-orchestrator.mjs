import crypto from "node:crypto";

import { canonicalJson } from "./identity.mjs";
import { SETUP_STATES, SetupJournalError, loadSetupJournal, nextActionsForState } from "./setup-journal.mjs";

export const SETUP_ORCHESTRATOR_VERSION = 1;
export const SETUP_EVIDENCE_VERSION = 1;

export class SetupOrchestratorError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "SetupOrchestratorError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

const ACTIONS = new Map();
for (const state of SETUP_STATES) {
  const action = nextActionsForState(state)[0];
  if (action) ACTIONS.set(action.id, { ...action, from_state: state });
}

// Evidence is deliberately a small, versioned envelope. Native/CLI adapters may
// put richer native artifacts behind their own storage, but the journal transition
// is allowed only after this exact, non-secret proof has been checked.
const EVIDENCE_CONTRACTS = Object.freeze({
  app_verified: { keys: ["application", "verification"], strings: ["application", "verification"] },
  local_config_initialized: { keys: ["directory", "config_version"], strings: ["directory"], integers: ["config_version"] },
  native_bridge_selected: { keys: ["bridge", "client", "manager"], strings: ["bridge", "client", "manager"] },
  service_registered: { keys: ["service", "status"], strings: ["service", "status"], allowed: { status: ["enabled"] } },
  bootstrap_started: { keys: ["approval_fingerprint", "lifecycle_head", "sequence"], strings: ["approval_fingerprint", "lifecycle_head"], integers: ["sequence"], ranges: { sequence: [1, 6] } },
  approval_key_enrolled: { keys: ["fingerprint", "generation", "lifecycle_head", "sequence"], strings: ["fingerprint", "lifecycle_head"], integers: ["generation", "sequence"], exact: { generation: 1 }, ranges: { sequence: [2, 6] } },
  service_keys_activated: {
    keys: ["roles", "generation", "lifecycle_head", "sequence"],
    strings: ["lifecycle_head"],
    integers: ["generation", "sequence"],
    exact: { generation: 1, sequence: 6 },
    roles: "roles"
  },
  device_enrolled: { keys: ["organization_id", "device_id", "enrollment_id", "key_fingerprint"], strings: ["organization_id", "device_id", "enrollment_id", "key_fingerprint"] },
  editor_connected: { keys: ["client", "project"], strings: ["client", "project"] },
  test_commit_verified: { keys: ["commit", "verification"], strings: ["commit", "verification"] },
  complete: { keys: ["completion"], strings: ["completion"] }
});

const ENVELOPE_KEYS = ["version", "from_state", "to_state", "action", "operation_id", "outcome", "proof"];
const OUTCOMES = new Set(["completed", "already_completed"]);
const SAFE_STRING = /^[^\u0000-\u001f\u007f]{1,1024}$/;
const HASH = /^[0-9a-f]{64}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fail(code, message, details) {
  throw new SetupOrchestratorError(code, message, details);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function exactKeys(value, keys, label) {
  if (!isObject(value)) fail("INVALID_EVIDENCE", `${label} must be an object`);
  const expected = new Set(keys);
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !expected.has(key))) {
    fail("INVALID_EVIDENCE", `${label} contains unknown or missing fields`);
  }
}

function safeString(value, label) {
  if (typeof value !== "string" || !SAFE_STRING.test(value)) fail("INVALID_EVIDENCE", `${label} must be a bounded string`);
}

function validateProof(proof, targetState) {
  const contract = EVIDENCE_CONTRACTS[targetState];
  if (!contract) fail("UNSUPPORTED_STATE", `No evidence contract exists for ${targetState}`);
  exactKeys(proof, contract.keys, `${targetState} evidence`);
  for (const key of contract.strings ?? []) safeString(proof[key], `${targetState} evidence ${key}`);
  for (const key of Object.keys(proof).filter((name) => name === "fingerprint" || name.endsWith("_fingerprint"))) {
    if (!FINGERPRINT.test(proof[key])) fail("INVALID_EVIDENCE", `${targetState} evidence ${key} must be an SSH SHA-256 fingerprint`);
  }
  for (const key of Object.keys(proof).filter((name) => name.endsWith("_id"))) {
    if (!UUID.test(proof[key])) fail("INVALID_EVIDENCE", `${targetState} evidence ${key} must be a UUID`);
  }
  for (const key of Object.keys(proof).filter((name) => name.endsWith("_head"))) {
    if (!HASH.test(proof[key])) fail("INVALID_EVIDENCE", `${targetState} evidence ${key} must be a SHA-256 hash`);
  }
  for (const key of contract.integers ?? []) {
    if (!Number.isSafeInteger(proof[key]) || proof[key] < 1) fail("INVALID_EVIDENCE", `${targetState} evidence ${key} must be a positive integer`);
  }
  for (const [key, values] of Object.entries(contract.allowed ?? {})) {
    if (!values.includes(proof[key])) fail("INVALID_EVIDENCE", `${targetState} evidence ${key} is not allowed`);
  }
  for (const [key, expected] of Object.entries(contract.exact ?? {})) {
    if (proof[key] !== expected) fail("INVALID_EVIDENCE", `${targetState} evidence ${key} is invalid`);
  }
  for (const [key, [minimum, maximum]] of Object.entries(contract.ranges ?? {})) {
    if (proof[key] < minimum || proof[key] > maximum) fail("INVALID_EVIDENCE", `${targetState} evidence ${key} is out of range`);
  }
  if (contract.roles) {
    if (!Array.isArray(proof[contract.roles]) || proof[contract.roles].length !== 2 ||
        proof[contract.roles].some((role) => typeof role !== "string" || !SAFE_STRING.test(role)) ||
        new Set(proof[contract.roles]).size !== proof[contract.roles].length ||
        !proof[contract.roles].includes("git_signing") || !proof[contract.roles].includes("audit_checkpoint")) {
      fail("INVALID_EVIDENCE", `${targetState} evidence roles must include the service key roles exactly once`);
    }
  }
}

function validateEvidence(value, action, operationId, currentState) {
  exactKeys(value, ENVELOPE_KEYS, "Handler evidence");
  if (value.version !== SETUP_EVIDENCE_VERSION) fail("INVALID_EVIDENCE", "Handler evidence version is unsupported");
  if (value.from_state !== currentState) fail("EVIDENCE_STATE_MISMATCH", "Handler evidence does not name the current journal state");
  if (value.to_state !== action.target_state) fail("EVIDENCE_STATE_MISMATCH", "Handler evidence does not name the next journal state");
  if (value.action !== action.id) fail("EVIDENCE_ACTION_MISMATCH", "Handler evidence does not name the dispatched action");
  if (value.operation_id !== operationId) fail("EVIDENCE_OPERATION_MISMATCH", "Handler evidence belongs to a different setup operation");
  if (!OUTCOMES.has(value.outcome)) fail("INVALID_EVIDENCE", "Handler evidence outcome is invalid");
  validateProof(value.proof, action.target_state);
  return clone(value);
}

function operationId(status, action) {
  return `setup:${status.journal_id}:${status.revision + 1}:${action.id}`;
}

function evidenceHash(evidence) {
  return crypto.createHash("sha256").update(canonicalJson(evidence)).digest("hex");
}

function publicAction(status, action, operationIdValue) {
  return {
    id: action.id,
    from_state: status.state,
    target_state: action.target_state,
    command: action.command,
    description: action.description,
    operation_id: operationIdValue
  };
}

function normalizeHandlers(handlers) {
  if (handlers === undefined) return new Map();
  if (!(handlers instanceof Map) && !isObject(handlers)) fail("INVALID_HANDLERS", "handlers must be an object or Map");
  const entries = handlers instanceof Map ? [...handlers.entries()] : Object.entries(handlers);
  const normalized = new Map();
  for (const [id, handler] of entries) {
    if (!ACTIONS.has(id)) fail("UNKNOWN_HANDLER", `No setup action exists for handler ${String(id)}`);
    if (typeof handler !== "function") fail("INVALID_HANDLER", `Handler ${id} must be a function`);
    normalized.set(id, handler);
  }
  return normalized;
}

function readOnlyContext(value) {
  if (!isObject(value)) return value;
  for (const child of Object.values(value)) readOnlyContext(child);
  return Object.freeze(value);
}

export function setupEvidenceContract(targetState) {
  if (!EVIDENCE_CONTRACTS[targetState]) fail("UNSUPPORTED_STATE", `No evidence contract exists for ${targetState}`);
  return clone({ version: SETUP_EVIDENCE_VERSION, target_state: targetState, ...EVIDENCE_CONTRACTS[targetState] });
}

export const SETUP_EVIDENCE_CONTRACTS = Object.freeze(Object.fromEntries(
  Object.keys(EVIDENCE_CONTRACTS).map((state) => [state, setupEvidenceContract(state)])
));

export class SetupOrchestrator {
  constructor({ journal = undefined, journalOptions = {}, handlers = undefined } = {}) {
    this.journal = journal ?? loadSetupJournal(journalOptions);
    this.handlers = normalizeHandlers(handlers);
  }

  status() {
    return this.journal.status();
  }

  preview() {
    const status = this.journal.status();
    const action = status.next_actions[0];
    if (!action) return { version: SETUP_ORCHESTRATOR_VERSION, dry_run: true, execute: false, changed: false, state: status.state, journal: status };
    const opId = operationId(status, action);
    return {
      version: SETUP_ORCHESTRATOR_VERSION,
      dry_run: true,
      execute: false,
      changed: false,
      current_state: status.state,
      current_revision: status.revision,
      action: publicAction(status, action, opId),
      handler_available: this.handlers.has(action.id),
      journal: status
    };
  }

  async execute() {
    return this.continue({ execute: true });
  }

  async continue({ execute = false } = {}) {
    if (typeof execute !== "boolean") fail("INVALID_REQUEST", "execute must be a boolean");
    if (!execute) return this.preview();
    const status = this.journal.status();
    const action = status.next_actions[0];
    if (!action) {
      return { version: SETUP_ORCHESTRATOR_VERSION, dry_run: false, execute: true, changed: false, state: status.state, journal: status };
    }

    const opId = operationId(status, action);
    const actionView = publicAction(status, action, opId);

    const handler = this.handlers.get(action.id);
    if (!handler) fail("HANDLER_MISSING", `No handler is registered for setup action ${action.id}`, { action: action.id, state: status.state });

    const context = readOnlyContext({
      version: SETUP_ORCHESTRATOR_VERSION,
      execute: true,
      dry_run: false,
      journal_id: status.journal_id,
      revision: status.revision,
      current_state: status.state,
      target_state: action.target_state,
      operation_id: opId,
      action: clone(actionView)
    });
    let response;
    try {
      response = await handler(context);
    } catch (error) {
      fail("HANDLER_FAILED", `Setup handler ${action.id} failed`, { action: action.id, cause_code: error?.code ?? "HANDLER_ERROR" });
    }
    if (!isObject(response) || Object.keys(response).length !== 1 || !Object.hasOwn(response, "evidence")) {
      fail("AMBIGUOUS_HANDLER_RESPONSE", `Setup handler ${action.id} did not return the exact evidence envelope`);
    }

    let evidence;
    try {
      evidence = validateEvidence(response.evidence, action, opId, status.state);
    } catch (error) {
      if (error instanceof SetupOrchestratorError) throw error;
      fail("INVALID_EVIDENCE", `Setup handler ${action.id} returned invalid evidence`);
    }

    // A handler may have completed work before the process crashed. Re-read the
    // durable tip before committing so a concurrent/recovered invocation cannot
    // skip or reorder a state.
    const latest = this.journal.status();
    if (latest.state !== status.state || latest.revision !== status.revision) {
      return {
        version: SETUP_ORCHESTRATOR_VERSION,
        dry_run: false,
        execute: true,
        changed: false,
        stale: true,
        action: actionView,
        journal: latest
      };
    }

    const transition = this.journal.transition(action.target_state, {
      details: {
        action: action.id,
        operation_id: opId,
        outcome: evidence.outcome,
        evidence_hash: evidenceHash(evidence)
      }
    });
    return {
      version: SETUP_ORCHESTRATOR_VERSION,
      dry_run: false,
      execute: true,
      changed: transition.changed,
      action: actionView,
      evidence,
      journal: transition
    };
  }
}

export function createSetupOrchestrator(options = {}) {
  return new SetupOrchestrator(options);
}

export async function continueSetup(options = {}) {
  const { execute = false, ...orchestratorOptions } = options;
  return createSetupOrchestrator(orchestratorOptions).continue({ execute });
}

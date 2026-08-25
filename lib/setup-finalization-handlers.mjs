import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./identity.mjs";

export const SETUP_FINALIZATION_VERSION = 1;
export const TEST_COMMIT_VERIFICATION_MARKER = "agentpass.git.verify.v1";

const CLIENT_FILES = Object.freeze({
  "claude-code": ".mcp.json",
  cursor: path.join(".cursor", "mcp.json")
});
const HASH = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SAFE_STRING = /^[^\u0000-\u001f\u007f]{1,1024}$/;
const MAX_CONFIG_BYTES = 1024 * 1024;

export class SetupFinalizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SetupFinalizationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new SetupFinalizationError(code, message);
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys, label) {
  if (!object(value)) fail("INVALID_INPUT", `${label} must be an object`);
  const expected = new Set(keys);
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !expected.has(key))) {
    fail("INVALID_INPUT", `${label} has unknown or missing fields`);
  }
}

function boundedString(value, label) {
  if (typeof value !== "string" || !SAFE_STRING.test(value)) fail("INVALID_INPUT", `${label} must be a bounded string`);
  return value;
}

function absolutePath(value, label) {
  boundedString(value, label);
  if (!path.isAbsolute(value) || value.includes("\0")) fail("INVALID_INPUT", `${label} must be an absolute path`);
  return value;
}

function contextFor(context, action, fromState, toState) {
  if (!object(context) || !object(context.action) || context.action.id !== action ||
      context.current_state !== fromState || context.target_state !== toState ||
      typeof context.operation_id !== "string" || !SAFE_STRING.test(context.operation_id)) {
    fail("INVALID_SETUP_CONTEXT", `${action} was dispatched outside its exact setup state`);
  }
}

function envelope(context, action, proof) {
  exactKeys(proof, action === "connect_editor" ? ["client", "project"] : action === "verify_test_commit" ? ["commit", "verification"] : ["completion"], "setup proof");
  return {
    evidence: {
      version: SETUP_FINALIZATION_VERSION,
      from_state: context.current_state,
      to_state: context.target_state,
      action: context.action.id,
      operation_id: context.operation_id,
      outcome: "completed",
      proof
    }
  };
}

function scanJsonForDuplicateKeys(source) {
  let index = 0;
  const whitespace = () => { while (/\s/.test(source[index] ?? "")) index += 1; };
  const string = () => {
    const start = index;
    if (source[index++] !== '"') fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains an invalid string");
    let escaped = false;
    while (index < source.length) {
      const character = source[index++];
      if (escaped) { escaped = false; continue; }
      if (character === "\\") { escaped = true; continue; }
      if (character === '"') {
        try { return JSON.parse(source.slice(start, index)); }
        catch { fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains an invalid string"); }
      }
      if (character < " ") fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains a control character");
    }
    fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains an unterminated string");
  };
  const value = () => {
    whitespace();
    if (source[index] === '"') { string(); return; }
    if (source[index] === "{") {
      index += 1;
      const keys = new Set();
      whitespace();
      if (source[index] === "}") { index += 1; return; }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains duplicate object keys");
        keys.add(key);
        whitespace();
        if (source[index++] !== ":") fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains an invalid object");
        value();
        whitespace();
        if (source[index] === "}") { index += 1; return; }
        if (source[index++] !== ",") fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains an invalid object");
      }
    }
    if (source[index] === "[") {
      index += 1;
      whitespace();
      if (source[index] === "]") { index += 1; return; }
      while (true) {
        value();
        whitespace();
        if (source[index] === "]") { index += 1; return; }
        if (source[index++] !== ",") fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains an invalid array");
      }
    }
    const start = index;
    while (index < source.length && !/[\s,\]}]/.test(source[index])) index += 1;
    if (start === index) fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains an invalid value");
    try { JSON.parse(source.slice(start, index)); }
    catch { fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains an invalid value"); }
  };
  value();
  whitespace();
  if (index !== source.length) fail("INVALID_EDITOR_CONFIGURATION", "Integration JSON contains trailing data");
}

function readJsonFile(target, readFile = (file) => fs.readFileSync(file, "utf8"), statFile = (file) => fs.lstatSync(file)) {
  let stat;
  try { stat = statFile(target); }
  catch { fail("EDITOR_CONFIGURATION_UNAVAILABLE", "The onboarding MCP configuration is unavailable"); }
  const uid = process.getuid?.();
  if (!stat?.isFile?.() || stat.isSymbolicLink?.() || stat.nlink !== 1 || stat.size > MAX_CONFIG_BYTES ||
      (uid !== undefined && stat.uid !== uid) || (stat.mode & 0o022) !== 0) {
    fail("UNSAFE_EDITOR_CONFIGURATION", "The onboarding MCP configuration is not a safe regular file");
  }
  let source;
  try { source = readFile(target); }
  catch { fail("EDITOR_CONFIGURATION_UNAVAILABLE", "The onboarding MCP configuration is unavailable"); }
  if (typeof source !== "string" || Buffer.byteLength(source, "utf8") > MAX_CONFIG_BYTES) fail("UNSAFE_EDITOR_CONFIGURATION", "The onboarding MCP configuration is too large");
  try {
    scanJsonForDuplicateKeys(source);
    return JSON.parse(source);
  } catch (error) {
    if (error instanceof SetupFinalizationError) throw error;
    fail("INVALID_EDITOR_CONFIGURATION", "The onboarding MCP configuration is not valid JSON");
  }
}

function validateOnboardingDescriptor(descriptor, realpath = (value) => fs.realpathSync(value)) {
  exactKeys(descriptor, ["version", "client", "target", "server_name", "server"], "onboarding descriptor");
  if (descriptor.version !== 1 || !Object.hasOwn(CLIENT_FILES, descriptor.client)) fail("INVALID_ONBOARDING_DESCRIPTOR", "The onboarding descriptor version or client is unsupported");
  absolutePath(descriptor.target, "onboarding target");
  if (descriptor.server_name !== "agentpass") fail("INVALID_ONBOARDING_DESCRIPTOR", "The onboarding descriptor does not name AgentPass");
  exactKeys(descriptor.server, ["command", "args", "env"], "onboarding server");
  absolutePath(descriptor.server.command, "onboarding command");
  if (!Array.isArray(descriptor.server.args) || descriptor.server.args.length === 0 || descriptor.server.args.some((value) => typeof value !== "string" || !SAFE_STRING.test(value))) fail("INVALID_ONBOARDING_DESCRIPTOR", "Onboarding server arguments are invalid");
  exactKeys(descriptor.server.env, ["AGENTPASS_PROJECT_DIR"], "onboarding environment");
  absolutePath(descriptor.server.env.AGENTPASS_PROJECT_DIR, "onboarding project");
  let project;
  try { project = realpath(descriptor.server.env.AGENTPASS_PROJECT_DIR); }
  catch { fail("INVALID_ONBOARDING_DESCRIPTOR", "The onboarding project does not exist"); }
  const expectedTarget = path.join(project, CLIENT_FILES[descriptor.client]);
  let target;
  try { target = realpath(descriptor.target); }
  catch { fail("EDITOR_CONFIGURATION_UNAVAILABLE", "The onboarding MCP configuration is unavailable"); }
  if (target !== expectedTarget || path.dirname(target) !== path.join(project, path.dirname(CLIENT_FILES[descriptor.client]))) fail("INVALID_ONBOARDING_DESCRIPTOR", "The onboarding target is not the exact client configuration path");
  return { descriptor, project, target };
}

function validateVerifierResult(result, label = "verifier result") {
  try { exactKeys(result, ["commit", "verification"], label); }
  catch { fail("INVALID_VERIFIER_RESULT", `${label} has unknown or missing fields`); }
  if (typeof result.commit !== "string" || !HASH.test(result.commit)) fail("INVALID_VERIFIER_RESULT", `${label} must contain a full lowercase git commit hash`);
  if (result.verification !== TEST_COMMIT_VERIFICATION_MARKER) fail("INVALID_VERIFIER_RESULT", `${label} is missing the exact AgentPass verification marker`);
  return { commit: result.commit, verification: result.verification };
}

export function createEditorConnectedHandler({ onboarding, readFile, statFile, realpath } = {}) {
  const descriptor = validateOnboardingDescriptor(onboarding, realpath);
  return async function connectEditor(context) {
    contextFor(context, "connect_editor", "device_enrolled", "editor_connected");
    const document = readJsonFile(descriptor.target, readFile, statFile);
    if (!object(document) || !object(document.mcpServers) || !Object.hasOwn(document.mcpServers, "agentpass") || !object(document.mcpServers.agentpass)) fail("EDITOR_NOT_CONNECTED", "The exact AgentPass MCP entry is not present");
    let expected;
    let actual;
    try {
      expected = canonicalJson(descriptor.descriptor.server);
      actual = canonicalJson(document.mcpServers.agentpass);
    } catch { fail("EDITOR_NOT_CONNECTED", "The AgentPass MCP entry cannot be compared safely"); }
    if (actual !== expected) fail("EDITOR_NOT_CONNECTED", "The MCP entry is not the exact AgentPass-owned onboarding entry");
    return envelope(context, "connect_editor", { client: descriptor.descriptor.client, project: descriptor.project });
  };
}

export function createTestCommitVerifiedHandler({ verifierResult } = {}) {
  const proof = validateVerifierResult(verifierResult);
  return async function verifyTestCommit(context) {
    contextFor(context, "verify_test_commit", "editor_connected", "test_commit_verified");
    return envelope(context, "verify_test_commit", { ...proof });
  };
}

export function createCompleteSetupHandler({ priorVerificationProof } = {}) {
  const proof = validateVerifierResult(priorVerificationProof, "prior verification proof");
  return async function completeSetup(context) {
    contextFor(context, "complete_setup", "test_commit_verified", "complete");
    if (proof.verification !== TEST_COMMIT_VERIFICATION_MARKER || !HASH.test(proof.commit)) fail("PRIOR_VERIFICATION_REQUIRED", "Setup completion requires prior verified commit proof");
    return envelope(context, "complete_setup", { completion: "test_commit_verified" });
  };
}

export function createSetupFinalizationHandlers(options = {}) {
  return {
    connect_editor: createEditorConnectedHandler(options),
    verify_test_commit: createTestCommitVerifiedHandler(options),
    complete_setup: createCompleteSetupHandler({ priorVerificationProof: options.priorVerificationProof ?? options.verifierResult })
  };
}

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const HASH = /^[0-9a-f]{64}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const ROLE = new Set(["session_approval", "git_signing", "audit_checkpoint"]);
const SERVICE_ROLE = new Set(["git_signing", "audit_checkpoint"]);
const TAG = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,255}$/;
const APPROVAL_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}\.g1$/;
const FIXED_CONFIG = "/Library/Application Support/AgentPass/native-service.json";
const FIXED_APPLICATION = "/Applications/AgentPass.app";
const FIXED_STATE_ROOT = "/Library/Application Support/AgentPass";
const MAX_OUTPUT = 256 * 1024;

export class NativeBootstrapError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "NativeBootstrapError";
    this.code = code;
  }
}

function fail(code, message) { throw new NativeBootstrapError(code, message); }
function object(value) { return value && typeof value === "object" && !Array.isArray(value); }
function exact(value, keys, label) {
  if (!object(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) fail("INVALID_RESPONSE", `${label} has an invalid schema`);
}
function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function parseCanonical(text, label) {
  if (typeof text !== "string" || Buffer.byteLength(text) > MAX_OUTPUT) fail("INVALID_RESPONSE", `${label} output is invalid`);
  const trimmed = text.trim();
  let value;
  try { value = JSON.parse(trimmed); } catch { fail("INVALID_RESPONSE", `${label} did not return JSON`); }
  if (canonical(value) !== trimmed) fail("INVALID_RESPONSE", `${label} JSON is non-canonical or contains duplicate fields`);
  return value;
}
function base64(value, label) {
  if (typeof value !== "string" || value.length < 4 || value.length > 64 * 1024 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail("INVALID_RESPONSE", `${label} is not canonical base64`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) fail("INVALID_RESPONSE", `${label} is not canonical base64`);
  return value;
}
function hash(value, label) { if (typeof value !== "string" || !HASH.test(value)) fail("INVALID_RESPONSE", `${label} is invalid`); return value; }
function fingerprint(value, label) { if (typeof value !== "string" || !FINGERPRINT.test(value)) fail("INVALID_RESPONSE", `${label} is invalid`); return value; }
function integer(value, min, max, label) { if (!Number.isSafeInteger(value) || value < min || value > max) fail("INVALID_RESPONSE", `${label} is invalid`); return value; }

function trustedFile(file, expectedOwner, executable = false, privateFile = false) {
  if (typeof file !== "string" || !path.isAbsolute(file)) fail("UNSAFE_PATH", "Native bootstrap paths must be absolute");
  let stat;
  try { stat = fs.lstatSync(file); } catch { fail("UNSAFE_PATH", `Native bootstrap input is missing: ${file}`); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== expectedOwner || (stat.mode & (privateFile ? 0o077 : 0o022)) !== 0 || (executable && (stat.mode & 0o111) === 0)) fail("UNSAFE_PATH", `Native bootstrap input is unsafe: ${file}`);
}

function trustedAncestry(file, boundary, expectedOwner) {
  if (typeof boundary !== "string" || !path.isAbsolute(boundary) || (file !== boundary && !file.startsWith(`${boundary}${path.sep}`))) fail("UNSAFE_PATH", "Native bootstrap input escapes its ownership boundary");
  let current = path.dirname(file);
  while (true) {
    let stat;
    try { stat = fs.lstatSync(current); } catch { fail("UNSAFE_PATH", "Native bootstrap ancestry is missing"); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedOwner || (stat.mode & 0o022) !== 0) fail("UNSAFE_PATH", "Native bootstrap ancestry is unsafe");
    if (current === boundary) return;
    const parent = path.dirname(current);
    if (parent === current || current.length < boundary.length) fail("UNSAFE_PATH", "Native bootstrap input escapes its ownership boundary");
    current = parent;
  }
}

function defaultAuthenticate() {
  return spawnSync("/usr/bin/sudo", ["-v"], {
    stdio: ["inherit", "ignore", "inherit"],
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    timeout: 120_000
  });
}

function defaultRun({ executable, args, input, inputBytes, privileged }) {
  const command = privileged ? "/usr/bin/sudo" : executable;
  const commandArgs = privileged ? ["-n", "--", executable, ...args] : args;
  return spawnSync(command, commandArgs, {
    encoding: "utf8",
    input: inputBytes ?? (input === undefined ? undefined : `${canonical(input)}\n`),
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    maxBuffer: MAX_OUTPUT,
    timeout: 120_000
  });
}

function unwrapClient(result, label) {
  const envelope = parseCanonical(result.stdout, label);
  exact(envelope, ["ok", "stdout_base64"], `${label} envelope`);
  if (envelope.ok !== true) fail("NATIVE_FAILURE", `${label} failed`);
  const encoded = base64(envelope.stdout_base64, `${label} payload`);
  return parseCanonical(Buffer.from(encoded, "base64").toString("utf8"), `${label} payload`);
}

function approval(value) {
  exact(value, ["application_tag", "authorized_key", "fingerprint", "public_key_base64", "version"], "approval key response");
  if (value.version !== 1 || !TAG.test(value.application_tag) || typeof value.authorized_key !== "string" || value.authorized_key.length > 4096) fail("INVALID_RESPONSE", "Approval key response is invalid");
  fingerprint(value.fingerprint, "approval fingerprint"); base64(value.public_key_base64, "approval public key");
  return value;
}
function signature(value) {
  exact(value, ["generation", "role", "signature_base64", "signer_fingerprint", "signer_public_key_base64", "statement_base64", "version"], "approval signature response");
  if (value.version !== 1 || !ROLE.has(value.role) || value.generation !== 1) fail("INVALID_RESPONSE", "Approval signature response is invalid");
  fingerprint(value.signer_fingerprint, "signer fingerprint");
  for (const key of ["signature_base64", "signer_public_key_base64", "statement_base64"]) base64(value[key], key);
  return value;
}
function plan(value, expectedRole) {
  exact(value, ["application_tag", "configuration_pin_update_required", "fingerprint", "generation", "lifecycle_head_hash", "role", "statement_base64", "version"], "bootstrap plan");
  if (value.version !== 1 || value.role !== expectedRole || value.generation !== 1 || value.configuration_pin_update_required !== true || !TAG.test(value.application_tag)) fail("INVALID_RESPONSE", "Bootstrap plan is invalid");
  fingerprint(value.fingerprint, "plan fingerprint"); hash(value.lifecycle_head_hash, "lifecycle head"); base64(value.statement_base64, "bootstrap statement");
  return value;
}
function snapshot(value) {
  exact(value, ["bootstrap_complete", "configuration_pin_update_required", "fingerprints", "lifecycle_head_hash", "roles", "sequence", "version"], "bootstrap snapshot");
  if (value.version !== 1 || typeof value.bootstrap_complete !== "boolean" || value.configuration_pin_update_required !== true) fail("INVALID_RESPONSE", "Bootstrap snapshot is invalid");
  integer(value.sequence, 0, 6, "bootstrap sequence"); hash(value.lifecycle_head_hash, "lifecycle head");
  exact(value.roles, ["audit_checkpoint", "git_signing", "session_approval"], "bootstrap roles");
  exact(value.fingerprints, ["audit_checkpoint", "git_signing", "session_approval"], "bootstrap fingerprints");
  if (Object.values(value.roles).some((state) => !["absent", "staged", "active"].includes(state))) fail("INVALID_RESPONSE", "Bootstrap role state is invalid");
  for (const role of ROLE) {
    const fingerprint = value.fingerprints[role];
    if ((value.roles[role] === "absent") !== (fingerprint === null) || (fingerprint !== null && !FINGERPRINT.test(fingerprint))) fail("INVALID_RESPONSE", "Bootstrap role fingerprint is invalid");
  }
  const approval = value.roles.session_approval;
  const services = [value.roles.git_signing, value.roles.audit_checkpoint];
  const active = services.filter((state) => state === "active").length;
  const staged = services.filter((state) => state === "staged").length;
  const present = services.filter((state) => state !== "absent").length;
  const legal = [
    approval === "absent" && present === 0,
    approval === "staged" && present === 0,
    approval === "active" && present === 0,
    approval === "active" && present === 1 && staged === 1,
    approval === "active" && present === 1 && active === 1,
    approval === "active" && present === 2 && active === 1 && staged === 1,
    approval === "active" && present === 2 && active === 2
  ][value.sequence];
  if (!legal) fail("INVALID_RESPONSE", "Bootstrap role state does not match its sequence");
  if (value.bootstrap_complete !== (value.sequence === 6)) fail("INVALID_RESPONSE", "Bootstrap completion does not match its sequence");
  return value;
}

export function createNativeBootstrapRunner(options = {}) {
  const client = options.clientPath;
  const service = options.servicePath;
  const config = options.configPath ?? FIXED_CONFIG;
  const applicationRoot = options.applicationRoot ?? FIXED_APPLICATION;
  const stateRoot = options.stateRoot ?? FIXED_STATE_ROOT;
  const expectedOwner = options.expectedOwner ?? 0;
  const run = options.run ?? defaultRun;
  const authenticate = options.authenticate ?? (options.run ? () => ({ status: 0 }) : defaultAuthenticate);
  let privilegedSessionAuthenticated = false;
  trustedAncestry(client, applicationRoot, expectedOwner); trustedAncestry(service, applicationRoot, expectedOwner); trustedAncestry(config, stateRoot, expectedOwner);
  trustedFile(client, expectedOwner, true); trustedFile(service, expectedOwner, true); trustedFile(config, expectedOwner, false, true);

  function invoke(executable, args, input, privileged, label) {
    if (privileged && !privilegedSessionAuthenticated) {
      const authentication = authenticate();
      if (!object(authentication) || authentication.error || authentication.signal || authentication.status !== 0) {
        fail(authentication?.status === null ? "NATIVE_TIMEOUT" : "PRIVILEGE_AUTHENTICATION_FAILED", "Administrator authentication failed without changing the setup journal");
      }
      privilegedSessionAuthenticated = true;
    }
    const result = run({ executable, args, input, privileged });
    if (!object(result) || result.error || result.signal || result.status !== 0 || typeof result.stdout !== "string" || Buffer.byteLength(result.stdout) > MAX_OUTPUT) {
      fail(result?.status === null ? "NATIVE_TIMEOUT" : "NATIVE_FAILURE", `${label} failed without changing the setup journal`);
    }
    return result;
  }
  function invokeBytes(executable, args, inputBytes, label) {
    const result = run({ executable, args, inputBytes, privileged: false });
    if (!object(result) || result.error || result.signal || result.status !== 0 || typeof result.stdout !== "string" || Buffer.byteLength(result.stdout) > MAX_OUTPUT) {
      fail(result?.status === null ? "NATIVE_TIMEOUT" : "NATIVE_FAILURE", `${label} failed without changing the setup journal`);
    }
    return result;
  }
  function serviceCall(action, input) {
    return parseCanonical(invoke(service, ["--bootstrap", action, "--config", config], input, true, `bootstrap ${action}`).stdout, `bootstrap ${action}`);
  }
  return Object.freeze({
    status() { return snapshot(serviceCall("status")); },
    createApproval(applicationTag) {
      if (!APPROVAL_TAG.test(applicationTag)) fail("INVALID_INPUT", "Approval key tag is invalid");
      return approval(unwrapClient(invoke(client, ["bootstrap-approval-create", applicationTag], undefined, false, "approval key creation"), "approval key creation"));
    },
    prepareApproval(publicKeyBase64) {
      base64(publicKeyBase64, "approval public key");
      return plan(serviceCall("prepare-approval", { public_key_base64: publicKeyBase64, version: 1 }), "session_approval");
    },
    sign(applicationTag, statementBase64) {
      if (!APPROVAL_TAG.test(applicationTag)) fail("INVALID_INPUT", "Approval key tag is invalid");
      const statement = Buffer.from(base64(statementBase64, "bootstrap statement"), "base64");
      // The signed client accepts canonical statement bytes rather than JSON.
      const signed = invokeBytes(client, ["bootstrap-sign", applicationTag], statement, "bootstrap approval signing");
      return signature(unwrapClient(signed, "bootstrap approval signing"));
    },
    commitApproval(signed) {
      const value = signature(signed);
      if (value.role !== "session_approval") fail("INVALID_INPUT", "Approval bootstrap signature has the wrong role");
      return snapshot(serviceCall("commit-approval", { signature_base64: value.signature_base64, statement_base64: value.statement_base64, version: 1 }));
    },
    prepareService(role) {
      if (!SERVICE_ROLE.has(role)) fail("INVALID_INPUT", "Service bootstrap role is invalid");
      return plan(serviceCall("prepare-service", { role, version: 1 }), role);
    },
    commitService(signed) {
      const value = signature(signed);
      if (!SERVICE_ROLE.has(value.role)) fail("INVALID_INPUT", "Service bootstrap signature has the wrong role");
      return snapshot(serviceCall("commit-service", { approval_public_key_base64: value.signer_public_key_base64, approval_signature_base64: value.signature_base64, statement_base64: value.statement_base64, version: 1 }));
    }
  });
}

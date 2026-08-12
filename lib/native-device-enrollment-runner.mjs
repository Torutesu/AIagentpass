import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const FIXED_APPLICATION = "/Applications/AgentPass.app";
const MAX_OUTPUT = 32 * 1024;
const MAX_PROOF = 16 * 1024;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const BASE64_64 = /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/;

export class NativeDeviceEnrollmentError extends Error {
  constructor(code, message) { super(message); this.name = "NativeDeviceEnrollmentError"; this.code = code; }
}

function fail(code, message) { throw new NativeDeviceEnrollmentError(code, message); }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
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
  if (canonical(value) !== trimmed) fail("INVALID_RESPONSE", `${label} JSON is non-canonical`);
  return value;
}
function decodeEnvelope(stdout, label) {
  const envelope = parseCanonical(stdout, label);
  exact(envelope, ["ok", "stdout_base64"], `${label} envelope`);
  if (envelope.ok !== true || typeof envelope.stdout_base64 !== "string") fail("NATIVE_FAILURE", `${label} failed`);
  const bytes = Buffer.from(envelope.stdout_base64, "base64");
  if (bytes.toString("base64") !== envelope.stdout_base64 || bytes.length > MAX_OUTPUT) fail("INVALID_RESPONSE", `${label} payload is invalid`);
  return parseCanonical(bytes.toString("utf8"), `${label} payload`);
}
function trustedClient(filesystem, client, applicationRoot, expectedOwner) {
  if (typeof client !== "string" || !path.isAbsolute(client) || client === applicationRoot || !client.startsWith(`${applicationRoot}${path.sep}`)) fail("UNSAFE_PATH", "Native enrollment client escapes the application boundary");
  let current = client;
  while (true) {
    let stat;
    try { stat = filesystem.lstatSync(current); } catch { fail("UNSAFE_PATH", "Native enrollment client path is missing"); }
    const leaf = current === client;
    if ((leaf ? !stat.isFile() || (stat.mode & 0o111) === 0 : !stat.isDirectory()) || stat.isSymbolicLink() || stat.uid !== expectedOwner || (stat.mode & 0o022) !== 0 || (leaf && stat.nlink !== 1)) fail("UNSAFE_PATH", "Native enrollment client path is unsafe");
    if (current === applicationRoot) return;
    const parent = path.dirname(current);
    if (parent === current || !current.startsWith(`${applicationRoot}${path.sep}`)) fail("UNSAFE_PATH", "Native enrollment client escapes the application boundary");
    current = parent;
  }
}
function defaultRun(client, command, input) {
  return spawnSync(client, [command], { encoding: "utf8", input, env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }, shell: false, timeout: 30_000, maxBuffer: MAX_OUTPUT });
}
function invoke(run, client, command, input, label) {
  const result = run(client, command, input);
  if (!object(result) || result.error || result.signal || result.status !== 0 || typeof result.stdout !== "string") fail(result?.status === null ? "NATIVE_TIMEOUT" : "NATIVE_FAILURE", `${label} failed`);
  return decodeEnvelope(result.stdout, label);
}

/** Use the fixed Secure Enclave enrollment key through the signed native client. */
export function createNativeDeviceEnrollmentRunner(options = {}) {
  const client = options.clientPath;
  const applicationRoot = options.applicationRoot ?? FIXED_APPLICATION;
  const expectedOwner = options.expectedOwner ?? 0;
  const filesystem = options.fs ?? fs;
  const run = options.run ?? defaultRun;
  trustedClient(filesystem, client, applicationRoot, expectedOwner);
  return Object.freeze({
    publicKey() {
      const value = invoke(run, client, "device-auth-key", undefined, "device enrollment key");
      exact(value, ["fingerprint", "public_key_pem"], "device enrollment key");
      if (!FINGERPRINT.test(value.fingerprint) || typeof value.public_key_pem !== "string" || Buffer.byteLength(value.public_key_pem) > 8192 || /PRIVATE\s+KEY/i.test(value.public_key_pem)) fail("INVALID_RESPONSE", "Device enrollment key is invalid");
      let key;
      try { key = crypto.createPublicKey(value.public_key_pem); } catch { fail("INVALID_RESPONSE", "Device enrollment public key is invalid"); }
      if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1" || key.export({ type: "spki", format: "pem" }).toString() !== value.public_key_pem) fail("INVALID_RESPONSE", "Device enrollment key is not canonical P-256 SPKI");
      const actual = `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
      if (actual !== value.fingerprint) fail("INVALID_RESPONSE", "Device enrollment fingerprint does not match its public key");
      return Object.freeze({ algorithm: "p256-sha256", spki_pem: value.public_key_pem, fingerprint: value.fingerprint });
    },
    sign({ bytes } = {}) {
      if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) fail("INVALID_INPUT", "Enrollment proof must be bytes");
      const input = Buffer.from(bytes);
      if (input.length === 0 || input.length > MAX_PROOF) fail("INVALID_INPUT", "Enrollment proof size is invalid");
      const value = invoke(run, client, "device-auth-sign", input, "device enrollment signing");
      exact(value, ["signature_base64"], "device enrollment signature");
      if (!BASE64_64.test(value.signature_base64)) fail("INVALID_RESPONSE", "Device enrollment signature is not raw P-256 IEEE-P1363");
      const signature = Buffer.from(value.signature_base64, "base64");
      if (signature.length !== 64 || signature.toString("base64") !== value.signature_base64) fail("INVALID_RESPONSE", "Device enrollment signature is invalid");
      return signature;
    }
  });
}

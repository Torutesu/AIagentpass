import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { atomicWrite, controlBundlePath, secureMkdir } from "./config.mjs";
import { canonicalJson } from "./identity.mjs";

const MAX_BUNDLE_BYTES = 256 * 1024;
const MAX_BUNDLE_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const ZERO_FINGERPRINT = "SHA256:";

export function generateControlKeyPair(directory) {
  secureMkdir(directory);
  const privateFile = path.join(directory, "control-private.pem");
  const publicFile = path.join(directory, "control-public.pem");
  if (fs.existsSync(privateFile) || fs.existsSync(publicFile)) throw new Error("Control key files already exist");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(privateFile, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
  fs.writeFileSync(publicFile, publicKey.export({ type: "spki", format: "pem" }), { flag: "wx", mode: 0o644 });
  return { private_file: privateFile, public_file: publicFile, fingerprint: controlKeyFingerprint(publicKey) };
}

export function signControlBundle({ sequence, expiresAt, globalRevoked = false, revokedAgents = [] }, privateFile, now = Date.now()) {
  assertPrivateKey(privateFile);
  const statement = normalizeStatement({
    version: 1,
    sequence: Number(sequence),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(expiresAt).toISOString(),
    global_revoked: Boolean(globalRevoked),
    revoked_agents: revokedAgents
  }, now);
  const privateKey = crypto.createPrivateKey(fs.readFileSync(privateFile));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Control signing key must be Ed25519");
  const publicKey = crypto.createPublicKey(privateKey);
  const signature = crypto.sign(null, bundleBytes(statement), privateKey).toString("base64");
  return { ...statement, key_fingerprint: controlKeyFingerprint(publicKey), signature };
}

export function verifyControlBundle(bundle, publicKey, { now = Date.now(), highestSequence = 0 } = {}) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("Remote control bundle must be an object");
  const { signature, key_fingerprint: fingerprint, ...rawStatement } = bundle;
  const statement = normalizeStatement(rawStatement, now);
  if (statement.sequence < highestSequence) throw new Error("Remote control sequence rollback detected");
  if (fingerprint !== controlKeyFingerprint(publicKey)) throw new Error("Remote control key fingerprint mismatch");
  if (typeof signature !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(signature)) throw new Error("Remote control signature encoding is invalid");
  if (!crypto.verify(null, bundleBytes(statement), publicKey, Buffer.from(signature, "base64"))) throw new Error("Remote control signature is invalid");
  return { ...statement, key_fingerprint: fingerprint, signature };
}

export function loadControlBundle(config, dir, cache = { highestSequence: 0 }, now = Date.now()) {
  if (!config.control) return null;
  const file = controlBundlePath(dir);
  if (!fs.existsSync(file)) throw new Error("Required remote control bundle is missing; run agentpass control apply or fetch");
  assertOwnedFile(file);
  let bundle;
  try { bundle = JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error("Remote control bundle contains invalid JSON"); }
  const verified = verifyControlBundle(bundle, config.control.public_key, { now, highestSequence: cache.highestSequence ?? 0 });
  cache.highestSequence = Math.max(cache.highestSequence ?? 0, verified.sequence);
  cache.bundle = verified;
  return verified;
}

export function applyControlBundle(bundle, config, dir, cache = { highestSequence: 0 }, now = Date.now()) {
  if (!config.control) throw new Error("No remote control trust root is configured");
  const existing = loadExistingBundle(config, dir);
  const verified = verifyControlBundle(bundle, config.control.public_key, { now, highestSequence: cache.highestSequence ?? 0 });
  if (existing && verified.sequence < existing.sequence) throw new Error("Remote control sequence rollback detected");
  if (existing && verified.sequence === existing.sequence) {
    if (canonicalJson(verified) !== canonicalJson(existing)) throw new Error("Remote control sequence equivocation detected");
    cache.highestSequence = Math.max(cache.highestSequence ?? 0, verified.sequence);
    cache.bundle = verified;
    return verified;
  }
  atomicWrite(controlBundlePath(dir), `${JSON.stringify(verified, null, 2)}\n`, 0o600);
  cache.highestSequence = verified.sequence;
  cache.bundle = verified;
  return verified;
}

export function evaluateRemoteControl(bundle, agentId) {
  if (!bundle) return { allowed: true, reason: "not_configured" };
  if (bundle.global_revoked) return { allowed: false, reason: "remote_global_revocation", sequence: bundle.sequence };
  if (bundle.revoked_agents.includes(agentId)) return { allowed: false, reason: "remote_agent_revoked", sequence: bundle.sequence };
  return { allowed: true, reason: "remote_allowed", sequence: bundle.sequence };
}

export async function fetchControlBundle(url, { timeoutMs = 10_000, fetchImpl = fetch } = {}) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") throw new Error("Remote control fetch requires HTTPS");
  const response = await fetchImpl(parsed, { redirect: "error", signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`Remote control fetch failed with HTTP ${response.status}`);
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > MAX_BUNDLE_BYTES) throw new Error("Remote control response is too large");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > MAX_BUNDLE_BYTES) throw new Error("Remote control response size is invalid");
  try { return JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error("Remote control response contains invalid JSON"); }
}

export function startControlRefresh(config, dir, cache, { fetchImpl = fetch, onEvent = () => {} } = {}) {
  if (!config.control?.url) return null;
  let refreshing = false;
  const refresh = async () => {
    if (refreshing) return;
    refreshing = true;
    try {
      const previousSequence = cache.highestSequence ?? 0;
      const bundle = await fetchControlBundle(config.control.url, { fetchImpl });
      const verified = applyControlBundle(bundle, config, dir, cache);
      if (verified.sequence !== previousSequence) onEvent({ result: "updated", sequence: verified.sequence, expires_at: verified.expires_at, global_revoked: verified.global_revoked, revoked_agents: verified.revoked_agents });
      cache.last_fetch_error = null;
      cache.last_fetch_at = new Date().toISOString();
    } catch (error) {
      if (cache.last_fetch_error !== error.message) onEvent({ result: "error", error: error.message });
      cache.last_fetch_error = error.message;
    } finally {
      refreshing = false;
    }
  };
  void refresh();
  const timer = setInterval(refresh, config.control.refresh_seconds * 1000);
  timer.unref?.();
  return timer;
}

export function controlKeyFingerprint(publicKey) {
  const key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Control public key must be Ed25519");
  const der = key.export({ type: "spki", format: "der" });
  return `${ZERO_FINGERPRINT}${crypto.createHash("sha256").update(der).digest("base64url")}`;
}

function normalizeStatement(statement, now) {
  if (statement.version !== 1) throw new Error("Unsupported remote control bundle version");
  if (!Number.isSafeInteger(statement.sequence) || statement.sequence < 1) throw new Error("Remote control sequence must be a positive integer");
  const issued = Date.parse(statement.issued_at);
  const expires = Date.parse(statement.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) throw new Error("Remote control timestamps are invalid");
  if (issued > now + 60_000) throw new Error("Remote control bundle was issued in the future");
  if (expires <= now) throw new Error("Remote control bundle has expired");
  if (expires <= issued || expires - issued > MAX_BUNDLE_LIFETIME_MS) throw new Error("Remote control bundle lifetime must not exceed 7 days");
  if (typeof statement.global_revoked !== "boolean" || !Array.isArray(statement.revoked_agents)) throw new Error("Remote control revocation fields are invalid");
  const revoked = [...new Set(statement.revoked_agents)].sort();
  if (revoked.some((id) => typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id))) throw new Error("Remote control contains an invalid agent ID");
  return { version: 1, sequence: statement.sequence, issued_at: new Date(issued).toISOString(), expires_at: new Date(expires).toISOString(), global_revoked: statement.global_revoked, revoked_agents: revoked };
}

function loadExistingBundle(config, dir) {
  const file = controlBundlePath(dir);
  if (!fs.existsSync(file)) return null;
  assertOwnedFile(file);
  let bundle;
  try { bundle = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new Error("Existing remote control bundle is invalid"); }
  const issued = Date.parse(bundle.issued_at);
  if (!Number.isFinite(issued)) throw new Error("Existing remote control bundle timestamp is invalid");
  return verifyControlBundle(bundle, config.control.public_key, { now: issued });
}

function bundleBytes(statement) {
  return Buffer.from(canonicalJson(statement));
}

function assertPrivateKey(file) {
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Control private key must be a regular file");
  if (uid !== undefined && stat.uid !== uid) throw new Error("Control private key is not owned by the current user");
  if ((stat.mode & 0o077) !== 0) throw new Error("Control private key permissions are too permissive");
}

function assertOwnedFile(file) {
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Remote control bundle must be a regular file");
  if (uid !== undefined && stat.uid !== uid) throw new Error("Remote control bundle is not owned by the current user");
  if ((stat.mode & 0o077) !== 0) throw new Error("Remote control bundle permissions are too permissive");
}

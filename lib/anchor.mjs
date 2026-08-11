import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { atomicWrite, secureMkdir } from "./config.mjs";
import { publicKeyFingerprint, verifyCheckpointRecord } from "./audit.mjs";
import { canonicalJson } from "./identity.mjs";

const ZERO_HASH = "0".repeat(64);
const MAX_BODY_BYTES = 512 * 1024;

export function initializeAnchor(directory) {
  secureMkdir(directory);
  const privateFile = path.join(directory, "anchor-private.pem");
  const publicFile = path.join(directory, "anchor-public.pem");
  if (fs.existsSync(privateFile) || fs.existsSync(publicFile)) throw new Error("Anchor key files already exist");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(privateFile, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
  fs.writeFileSync(publicFile, publicKey.export({ type: "spki", format: "pem" }), { flag: "wx", mode: 0o644 });
  secureMkdir(path.join(directory, "tenants"));
  return { private_file: privateFile, public_file: publicFile, fingerprint: publicKeyFingerprint(publicKey) };
}

export function enrollAnchorTenant(directory, tenant, auditPublicKey) {
  assertTenant(tenant);
  loadAnchorPrivateKey(directory);
  assertEd25519PublicKey(auditPublicKey, "Audit checkpoint public key");
  const tenantDir = path.join(directory, "tenants", tenant);
  secureMkdir(tenantDir);
  const configFile = path.join(tenantDir, "config.json");
  if (fs.existsSync(configFile)) throw new Error("Anchor tenant is already enrolled");
  const config = { version: 1, tenant, audit_public_key: String(auditPublicKey), audit_key_fingerprint: publicKeyFingerprint(auditPublicKey), enrolled_at: new Date().toISOString() };
  atomicWrite(configFile, `${JSON.stringify(config, null, 2)}\n`, 0o600);
  return config;
}

export function submitAnchorCheckpoint(directory, tenant, checkpoint, now = Date.now()) {
  const tenantConfig = loadTenant(directory, tenant);
  const verifiedCheckpoint = verifyCheckpointRecord(checkpoint, tenantConfig.audit_public_key);
  const recordsFile = path.join(directory, "tenants", tenant, "records.jsonl");
  const lock = acquireTenantLock(`${recordsFile}.lock`);
  try {
    const records = readRecords(recordsFile);
    verifyAnchorRecords(records, tenantConfig.audit_public_key, readAnchorPublicKey(directory), tenant);
    const existing = records.find((record) => record.checkpoint.checkpoint_hash === verifiedCheckpoint.checkpoint_hash);
    if (existing) {
      if (canonicalJson(existing.checkpoint) !== canonicalJson(verifiedCheckpoint)) throw new Error("Checkpoint hash equivocation detected");
      return existing.receipt;
    }
    const previous = records.at(-1);
    if (!previous && verifiedCheckpoint.previous_checkpoint_hash !== ZERO_HASH) throw new Error("First anchored checkpoint must start at the checkpoint chain origin");
    if (previous && verifiedCheckpoint.previous_checkpoint_hash !== previous.checkpoint.checkpoint_hash) throw new Error("Checkpoint does not extend the anchored chain");
    if (previous && verifiedCheckpoint.entries < previous.checkpoint.entries) throw new Error("Checkpoint entry count rollback detected");
    const receiptStatement = {
      version: 1,
      tenant,
      index: records.length + 1,
      checkpoint_hash: verifiedCheckpoint.checkpoint_hash,
      received_at: new Date(Math.max(now, previous ? Date.parse(previous.receipt.received_at) : 0)).toISOString(),
      previous_receipt_hash: previous?.receipt.receipt_hash ?? ZERO_HASH
    };
    const privateKey = loadAnchorPrivateKey(directory);
    const anchorPublicKey = crypto.createPublicKey(privateKey);
    const signature = crypto.sign(null, receiptBytes(receiptStatement), privateKey).toString("base64");
    const receipt = { ...receiptStatement, anchor_key_fingerprint: publicKeyFingerprint(anchorPublicKey), signature };
    receipt.receipt_hash = hash(receipt);
    durableAppend(recordsFile, `${JSON.stringify({ checkpoint: verifiedCheckpoint, receipt })}\n`);
    return receipt;
  } finally {
    releaseTenantLock(`${recordsFile}.lock`, lock);
  }
}

export function verifyAnchorReceipt(receipt, anchorPublicKey, { tenant, checkpointHash, previousReceiptHash } = {}) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("Anchor receipt must be an object");
  const verificationKey = assertEd25519PublicKey(anchorPublicKey, "Anchor receipt public key");
  const statement = { version: receipt.version, tenant: receipt.tenant, index: receipt.index, checkpoint_hash: receipt.checkpoint_hash, received_at: receipt.received_at, previous_receipt_hash: receipt.previous_receipt_hash };
  if (statement.version !== 1 || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(statement.tenant ?? "") || !Number.isSafeInteger(statement.index) || statement.index < 1 || !/^[0-9a-f]{64}$/.test(statement.checkpoint_hash ?? "") || !Number.isFinite(Date.parse(statement.received_at)) || !/^[0-9a-f]{64}$/.test(statement.previous_receipt_hash ?? "")) throw new Error("Anchor receipt statement is invalid");
  if (tenant !== undefined && statement.tenant !== tenant) throw new Error("Anchor receipt tenant mismatch");
  if (checkpointHash !== undefined && statement.checkpoint_hash !== checkpointHash) throw new Error("Anchor receipt checkpoint mismatch");
  if (previousReceiptHash !== undefined && statement.previous_receipt_hash !== previousReceiptHash) throw new Error("Anchor receipt chain mismatch");
  if (receipt.anchor_key_fingerprint !== publicKeyFingerprint(verificationKey)) throw new Error("Anchor receipt key fingerprint mismatch");
  if (typeof receipt.signature !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(receipt.signature)) throw new Error("Anchor receipt signature is invalid");
  let signatureValid = false;
  try {
    const signature = Buffer.from(receipt.signature, "base64");
    signatureValid = signature.length === 64 && crypto.verify(null, receiptBytes(statement), verificationKey, signature);
  } catch {}
  if (!signatureValid) throw new Error("Anchor receipt signature is invalid");
  const copy = { ...statement, anchor_key_fingerprint: receipt.anchor_key_fingerprint, signature: receipt.signature };
  if (hash(copy) !== receipt.receipt_hash) throw new Error("Anchor receipt hash is invalid");
  return { ...copy, receipt_hash: receipt.receipt_hash };
}

export function verifyAnchorRecords(records, auditPublicKey, anchorPublicKey, tenant) {
  let previousCheckpoint = ZERO_HASH;
  let previousReceipt = ZERO_HASH;
  let previousEntries = 0;
  let previousReceivedAt = 0;
  for (let index = 0; index < records.length; index += 1) {
    const checkpoint = verifyCheckpointRecord(records[index].checkpoint, auditPublicKey, { previousCheckpointHash: previousCheckpoint });
    const receipt = verifyAnchorReceipt(records[index].receipt, anchorPublicKey, { tenant, checkpointHash: checkpoint.checkpoint_hash, previousReceiptHash: previousReceipt });
    if (receipt.index !== index + 1) throw new Error("Anchor receipt index is invalid");
    if (checkpoint.entries < previousEntries) throw new Error("Anchor checkpoint entry count rollback detected");
    if (Date.parse(receipt.received_at) < previousReceivedAt) throw new Error("Anchor receipt timestamp rollback detected");
    previousCheckpoint = checkpoint.checkpoint_hash;
    previousReceipt = receipt.receipt_hash;
    previousEntries = checkpoint.entries;
    previousReceivedAt = Date.parse(receipt.received_at);
  }
  return { valid: true, records: records.length, latest_checkpoint: records.length ? previousCheckpoint : null, latest_receipt: records.length ? previousReceipt : null };
}

export function createAnchorServer(directory) {
  loadAnchorPrivateKey(directory);
  const server = http.createServer((request, response) => handleRequest(directory, request, response));
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  return server;
}

export function verifyAnchorTenant(directory, tenant) {
  loadAnchorPrivateKey(directory);
  const tenantConfig = loadTenant(directory, tenant);
  const records = readRecords(path.join(directory, "tenants", tenant, "records.jsonl"));
  return verifyAnchorRecords(records, tenantConfig.audit_public_key, readAnchorPublicKey(directory), tenant);
}

async function handleRequest(directory, request, response) {
  try {
    if (request.method === "GET" && request.url === "/v1/public-key") {
      return json(response, 200, { public_key: readAnchorPublicKey(directory) });
    }
    const match = /^\/v1\/checkpoints\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?:\/latest)?$/.exec(request.url ?? "");
    if (!match) return json(response, 404, { error: "not_found" });
    const tenant = match[1];
    if (request.method === "GET" && request.url.endsWith("/latest")) {
      const records = readRecords(path.join(directory, "tenants", tenant, "records.jsonl"));
      const tenantConfig = loadTenant(directory, tenant);
      verifyAnchorRecords(records, tenantConfig.audit_public_key, readAnchorPublicKey(directory), tenant);
      return records.length ? json(response, 200, records.at(-1)) : json(response, 404, { error: "no_checkpoint" });
    }
    if (request.method !== "POST" || request.url.endsWith("/latest")) return json(response, 405, { error: "method_not_allowed" });
    const body = await readBody(request);
    const parsed = JSON.parse(body.toString("utf8"));
    const receipt = submitAnchorCheckpoint(directory, tenant, parsed.checkpoint);
    return json(response, 200, { receipt });
  } catch (error) {
    return json(response, 400, { error: error.message });
  }
}

function loadTenant(directory, tenant) {
  assertTenant(tenant);
  const file = path.join(directory, "tenants", tenant, "config.json");
  if (!fs.existsSync(file)) throw new Error("Anchor tenant is not enrolled");
  let config;
  try { config = JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error("Anchor tenant configuration is invalid"); }
  if (config?.version !== 1 || config.tenant !== tenant) throw new Error("Anchor tenant configuration is invalid");
  const key = assertEd25519PublicKey(config.audit_public_key, "Audit checkpoint public key");
  if (config.audit_key_fingerprint !== publicKeyFingerprint(key)) throw new Error("Anchor tenant audit key fingerprint mismatch");
  return config;
}

function loadAnchorPrivateKey(directory) {
  const file = path.join(directory, "anchor-private.pem");
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error("Anchor private key permissions are unsafe");
  const key = crypto.createPrivateKey(fs.readFileSync(file));
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Anchor private key must be Ed25519");
  const expected = publicKeyFingerprint(readAnchorPublicKey(directory));
  if (publicKeyFingerprint(crypto.createPublicKey(key)) !== expected) throw new Error("Anchor private and public keys do not match");
  return key;
}

function readAnchorPublicKey(directory) {
  return fs.readFileSync(path.join(directory, "anchor-public.pem"), "utf8");
}

function readRecords(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    request.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) request.destroy(new Error("Request body is too large"));
      else chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function acquireTenantLock(file) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const lease = { pid: process.pid, nonce: crypto.randomBytes(16).toString("hex"), created_at: Date.now() };
    try {
      const fd = fs.openSync(file, "wx", 0o600);
      fs.writeFileSync(fd, JSON.stringify(lease));
      fs.closeSync(fd);
      return lease;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let existing;
      try { existing = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new Error("Anchor tenant lock is invalid; inspect it before removal"); }
      if (!Number.isInteger(existing.pid)) throw new Error("Anchor tenant lock is invalid; inspect it before removal");
      try {
        process.kill(existing.pid, 0);
        throw new Error("Another anchor process is updating this tenant");
      } catch (probeError) {
        if (probeError.code !== "ESRCH") throw probeError;
        const stat = fs.lstatSync(file);
        const uid = process.getuid?.();
        if (!stat.isFile() || stat.isSymbolicLink() || (uid !== undefined && stat.uid !== uid)) throw new Error("Refusing to replace an unsafe anchor tenant lock");
        fs.unlinkSync(file);
      }
    }
  }
  throw new Error("Unable to acquire the anchor tenant lock");
}

function releaseTenantLock(file, lease) {
  try {
    const current = JSON.parse(fs.readFileSync(file, "utf8"));
    if (current.pid === lease.pid && current.nonce === lease.nonce) fs.unlinkSync(file);
  } catch {}
}

function durableAppend(file, content) {
  const existed = fs.existsSync(file);
  const fd = fs.openSync(file, "a", 0o600);
  try {
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(file, 0o600);
  if (!existed) {
    const directoryFd = fs.openSync(path.dirname(file), "r");
    try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
  }
}

function assertEd25519PublicKey(value, label) {
  let key;
  try { key = value instanceof crypto.KeyObject && value.type === "public" ? value : crypto.createPublicKey(value); }
  catch { throw new Error(`${label} is invalid`); }
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be Ed25519`);
  return key;
}

function json(response, status, value) {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  response.writeHead(status, { "content-type": "application/json", "content-length": body.length, "cache-control": "no-store" });
  response.end(body);
}

function assertTenant(tenant) {
  if (typeof tenant !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(tenant)) throw new Error("Anchor tenant slug is invalid");
}

function receiptBytes(statement) {
  return Buffer.from(canonicalJson(statement));
}

function hash(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

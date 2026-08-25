#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { createCloudRuntime } from "../../../apps/cloud-api/src/runtime.mjs";

// The supervisor deliberately discards arbitrary child output. Preserve only
// a fixed startup class when the Cloud runtime rejects before it can listen.
process.on("uncaughtExceptionMonitor", (error) => {
  process.stderr.write(`${startupFailureMarker(error)}\n`);
});
process.on("unhandledRejection", (reason) => {
  process.stderr.write(`${startupFailureMarker(reason)}\n`);
  process.exitCode = 1;
});

if (process.env.P0B_LIVE_BROWSER !== "1" || process.env.AGENTPASS_CLOUD_PROFILE !== "hosted") {
  throw new Error("P0-B Cloud process is not enabled");
}

const controlBundleSignerProvider = loadProvider({
  privateKeyPath: process.env.P0B_CONTROL_BUNDLE_PRIVATE_KEY_PATH,
  publicKeyPem: process.env.AGENTPASS_CLOUD_CONTROL_BUNDLE_PUBLIC_KEY,
  version: 2
});
const capabilitySignerProvider = loadProvider({
  privateKeyPath: process.env.P0B_CAPABILITY_PRIVATE_KEY_PATH,
  publicKeyPem: process.env.AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY
});
const auditAnchorSignerProvider = loadProvider({
  privateKeyPath: process.env.P0B_AUDIT_ANCHOR_PRIVATE_KEY_PATH,
  publicKeyPem: process.env.AGENTPASS_CLOUD_AUDIT_ANCHOR_PUBLIC_KEY
});
const promotionEvidenceSignerProvider = loadProvider({
  privateKeyPath: process.env.P0B_PROMOTION_EVIDENCE_PRIVATE_KEY_PATH,
  publicKeyPem: process.env.AGENTPASS_CLOUD_PROMOTION_EVIDENCE_PUBLIC_KEY,
  version: 2
});
const agentSessionSignerProvider = loadProvider({
  privateKeyPath: process.env.P0B_AGENT_SESSION_PRIVATE_KEY_PATH,
  publicKeyPem: process.env.AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY
});
const qualificationManifestSignerProvider = loadProvider({
  privateKeyPath: process.env.P0B_QUALIFICATION_MANIFEST_PRIVATE_KEY_PATH,
  publicKeyPem: process.env.AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY,
  version: 2
});
const possessionReceiptSignerProvider = loadProvider({
  privateKeyPath: process.env.P0B_POSSESSION_RECEIPT_PRIVATE_KEY_PATH,
  publicKeyPem: process.env.AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY
});
const refreshHintSignerProvider = loadProvider({
  privateKeyPath: process.env.P0B_REFRESH_HINT_PRIVATE_KEY_PATH,
  publicKeyPem: process.env.AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY
});
const env = Object.freeze({ ...process.env });

const runtime = await createCloudRuntime({
  env,
  agentSessionSignerProvider,
  qualificationManifestSignerProvider,
  possessionReceiptSignerProvider,
  refreshHintSignerProvider,
  controlBundleSignerProvider,
  capabilitySignerProvider,
  auditAnchorSignerProvider,
  promotionEvidenceSignerProvider
});
await runtime.listen();

let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  try {
    await runtime.close();
    process.exitCode = 0;
  } catch {
    process.exitCode = 1;
  }
}
process.once("SIGINT", () => void stop());
process.once("SIGTERM", () => void stop());

function loadProvider({ privateKeyPath, publicKeyPem, version = 1 }) {
  const privateKey = readPrivateKey(privateKeyPath);
  let publicKey;
  try { publicKey = crypto.createPublicKey(publicKeyPem); }
  catch { throw new Error("P0-B signer public key is invalid"); }
  if (publicKey.asymmetricKeyType !== "ed25519"
    || !crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" }).equals(publicKey.export({ type: "spki", format: "der" }))) {
    throw new Error("P0-B signer key binding is invalid");
  }
  const normalizedPublicKey = publicKey.export({ type: "spki", format: "pem" }).toString();
  return Object.freeze({
    provider_id: "p0b-kms-ledger-v1",
    version,
    async publicKeyMetadata(input) {
      return Object.freeze({ key_id: input.key_id, algorithm: "ed25519", public_key: normalizedPublicKey });
    },
    async sign({ bytes }) { return crypto.sign(null, bytes, privateKey); }
  });
}

function startupFailureMarker(error) {
  const message = typeof error?.message === "string" ? error.message : String(error ?? "");
  if (/ERR_MODULE_NOT_FOUND|Cannot find package/u.test(message)) return "P0B_CLOUD_START_DEPENDENCY_FAILED";
  if (/ERR_KMS_PROVIDER_RUNTIME_CONFIG|configuration is invalid|profile is required/u.test(message)) return "P0B_CLOUD_START_CONFIG_FAILED";
  if (/PostgreSQL|postgres|database|migration|repository/iu.test(message)) return "P0B_CLOUD_START_POSTGRES_FAILED";
  if (/signer|signature|key|Ed25519/u.test(message)) return "P0B_CLOUD_START_SIGNER_FAILED";
  if (/Platform Session|platform session|WebAuthn/u.test(message)) return "P0B_CLOUD_START_PLATFORM_SESSION_FAILED";
  return "P0B_CLOUD_START_UNKNOWN_FAILED";
}

function readPrivateKey(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new Error("P0-B signer path is invalid");
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const metadata = fs.fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o077) !== 0 || metadata.size > 16 * 1024
      || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) throw new Error("unsafe signer file");
    const key = crypto.createPrivateKey(fs.readFileSync(descriptor));
    if (key.asymmetricKeyType !== "ed25519") throw new Error("wrong signer key type");
    return key;
  } catch {
    throw new Error("P0-B signer private key is invalid");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

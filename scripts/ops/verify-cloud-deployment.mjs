#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import process from "node:process";

const REJECTION_PREFIX = "cloud deployment evidence rejected";

export function verifyCloudDeploymentEvidence(evidence, { publicKey, expectedFingerprint } = {}) {
  const fail = (message) => { throw new Error(`${REJECTION_PREFIX}: ${message}`); };
  const keys = Object.keys(evidence ?? {}).sort().join(",");
  if (keys !== "artifact_digest,commit_sha,environment,health,revision,service,signature,status") fail("unexpected evidence shape");
  if (!/^[A-Za-z0-9+/]{86,88}={0,2}$/u.test(evidence.signature)) fail("signature must be base64 Ed25519");
  if (!(publicKey instanceof Uint8Array)) fail("pinned public key is unavailable");
  if (!/^[0-9a-f]{64}$/u.test(expectedFingerprint)) fail("pinned public key fingerprint is required");
  if (crypto.createHash("sha256").update(publicKey).digest("hex") !== expectedFingerprint) fail("pinned public key fingerprint mismatch");
  const unsigned = { ...evidence };
  delete unsigned.signature;
  const signedBytes = Buffer.from(JSON.stringify(unsigned) + "\n", "utf8");
  if (!crypto.verify(null, signedBytes, publicKey, Buffer.from(evidence.signature, "base64"))) fail("signature does not verify");
  if (evidence.status !== "verified") fail("status must be verified");
  if (evidence.environment !== "production") fail("environment must be production");
  if (!/^sha256:[0-9a-f]{64}$/u.test(evidence.artifact_digest)) fail("artifact_digest must be a sha256 digest");
  if (!/^[0-9a-f]{40}$/u.test(evidence.commit_sha)) fail("commit_sha must be a full git SHA");
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u.test(evidence.service)) fail("service is invalid");
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u.test(evidence.revision)) fail("revision is invalid");
  if (!evidence.health || Object.keys(evidence.health).sort().join(",") !== "checked_at,status,url") fail("health evidence is incomplete");
  if (evidence.health.status !== "ready") fail("health status must be ready");
  if (!/^https:\/\/[A-Za-z0-9][A-Za-z0-9.-]{0,251}(?::[0-9]{1,5})?\/health\/ready$/u.test(evidence.health.url)) fail("health URL must be an HTTPS readiness endpoint");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(evidence.health.checked_at)) fail("health timestamp must be UTC RFC3339");
  return Object.freeze({ ...evidence });
}

export function readCloudDeploymentEvidence(evidencePath, publicKeyPath) {
  let evidence;
  let publicKey;
  try { evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8")); } catch { throw new Error(`${REJECTION_PREFIX}: evidence is not readable JSON`); }
  try { publicKey = fs.readFileSync(publicKeyPath); } catch { throw new Error(`${REJECTION_PREFIX}: pinned public key is not readable`); }
  return { evidence, publicKey };
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  const [evidencePath = "", publicKeyPath = "", expectedFingerprint = ""] = process.argv.slice(2);
  if (!evidencePath) throw new Error(`${REJECTION_PREFIX}: evidence path is required`);
  if (!publicKeyPath) throw new Error(`${REJECTION_PREFIX}: pinned public key path is required`);
  const { evidence, publicKey } = readCloudDeploymentEvidence(evidencePath, publicKeyPath);
  const verified = verifyCloudDeploymentEvidence(evidence, { publicKey, expectedFingerprint });
  const canonical = JSON.stringify(verified) + "\n";
  process.stdout.write(JSON.stringify({ status: "verified", evidence_sha256: crypto.createHash("sha256").update(canonical).digest("hex"), service: verified.service, revision: verified.revision }) + "\n");
}

#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, open, readFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

const [artifactArg, inventoryArg, evidenceRootArg, notaryArg, stapleArg, gatekeeperArg, identityArg, verificationArg, outputArg] = process.argv.slice(2);
if ([artifactArg, inventoryArg, evidenceRootArg, notaryArg, stapleArg, gatekeeperArg, identityArg, verificationArg, outputArg].some((value) => !value)) {
  throw new Error("Usage: create-macos-distribution-evidence.mjs ARTIFACT INVENTORY EVIDENCE_ROOT NOTARY STAPLE GATEKEEPER IDENTITY VERIFICATION OUTPUT");
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const TEAM = /^[A-Z0-9]{10}$/u;
const DEVELOPER_ID_INSTALLER = /^Developer ID Installer: [^\r\n()]+ \([A-Z0-9]{10}\)$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const root = resolve(evidenceRootArg);
const artifact = resolve(artifactArg);
const inventoryPath = resolve(inventoryArg);
const verificationPath = resolve(verificationArg);
const output = resolve(outputArg);

function fail(message) { throw new Error(message); }
function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail(`${label} schema is invalid`);
}
async function regularFile(file, label) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail(`${label} must be a regular single-link file`);
  return stat;
}
async function canonicalJson(file, label) {
  await regularFile(file, label);
  const bytes = await readFile(file);
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { fail(`${label} must be JSON`); }
  if (bytes.toString("utf8") !== `${JSON.stringify(value, null, 2)}\n`) fail(`${label} must be canonical JSON`);
  return value;
}
async function digest(file, label) {
  await regularFile(file, label);
  const bytes = await readFile(file);
  return { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
}
async function writeOnce(file, value, label) {
  if (resolve(file) !== file) fail(`${label} path is not canonical`);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  let handle;
  try {
    handle = await open(file, "wx", 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    if (error?.code === "EEXIST") fail(`${label} already exists`);
    throw error;
  } finally {
    await handle?.close();
  }
}
function rooted(name, label) {
  if (typeof name !== "string" || !SAFE_NAME.test(name)) fail(`${label} name is unsafe`);
  return resolve(root, name);
}

const rootStat = await lstat(root);
if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("evidence root must be a real directory");
if (dirname(output) !== root) fail("distribution evidence output must be inside evidence root");

const artifactDigest = await digest(artifact, "artifact");
const inventory = await canonicalJson(inventoryPath, "inventory");
exact(inventory, ["schema_version", "kind", "artifact", "root_entries"], "inventory");
if (inventory.schema_version !== 1 || inventory.kind !== "agentpass.macos-artifact-inventory" || inventory.artifact?.name !== basename(artifact)
  || inventory.artifact.bytes !== artifactDigest.bytes || inventory.artifact.sha256 !== artifactDigest.sha256 || !Array.isArray(inventory.root_entries)) fail("inventory is not bound to the artifact");

const notaryRaw = await canonicalJson(resolve(notaryArg), "notary input");
exact(notaryRaw, ["status", "id"], "notary input");
if (notaryRaw.status !== "Accepted" || !UUID.test(String(notaryRaw.id))) fail("notary input is not an accepted submission");
const stapleRaw = await canonicalJson(resolve(stapleArg), "staple input");
exact(stapleRaw, ["status", "artifact_sha256"], "staple input");
if (stapleRaw.status !== "validated" || stapleRaw.artifact_sha256 !== artifactDigest.sha256) fail("staple input is not bound to the artifact");
const gatekeeperRaw = await canonicalJson(resolve(gatekeeperArg), "Gatekeeper input");
exact(gatekeeperRaw, ["assessment", "artifact_sha256"], "Gatekeeper input");
if (gatekeeperRaw.assessment !== "accepted" || gatekeeperRaw.artifact_sha256 !== artifactDigest.sha256) fail("Gatekeeper input is not bound to the artifact");
const identity = await canonicalJson(resolve(identityArg), "signature identity");
exact(identity, ["format", "identity", "team_id", "verified"], "signature identity");
const identityTeam = typeof identity.identity === "string" ? identity.identity.match(/\(([A-Z0-9]{10})\)$/u)?.[1] : undefined;
if (identity.format !== "Developer ID Installer" || !DEVELOPER_ID_INSTALLER.test(identity.identity ?? "") || !TEAM.test(identity.team_id) || identity.team_id !== identityTeam || identity.verified !== true) fail("signature identity is not verified and artifact-bound");

const notary = { status: "Accepted", id: String(notaryRaw.id), artifact_sha256: artifactDigest.sha256 };
await writeOnce(rooted("notary.json", "notary"), notary, "notary evidence");
await writeOnce(rooted("staple.json", "staple"), stapleRaw, "staple evidence");
await writeOnce(rooted("gatekeeper.json", "gatekeeper"), gatekeeperRaw, "Gatekeeper evidence");
const verification = await canonicalJson(verificationPath, "independent verification");
exact(verification, ["schema_version", "kind", "status", "artifact_sha256", "signature_verified", "notarization_verified", "staple_verified", "gatekeeper_verified"], "independent verification");
if (verification.schema_version !== 1 || verification.kind !== "agentpass.macos-distribution-verification-v1" || verification.status !== "verified"
  || verification.artifact_sha256 !== artifactDigest.sha256 || verification.signature_verified !== true || verification.notarization_verified !== true
  || verification.staple_verified !== true || verification.gatekeeper_verified !== true) fail("independent verification is not bound to the artifact");
const verificationFile = await digest(verificationPath, "independent verification");
const inventoryFile = await digest(inventoryPath, "inventory");
const evidence = {
  schema_version: 1,
  kind: "agentpass.macos-distribution-evidence",
  artifact: { name: basename(artifact), bytes: artifactDigest.bytes, sha256: artifactDigest.sha256 },
  inventory: { name: basename(inventoryPath), bytes: inventoryFile.bytes, sha256: inventoryFile.sha256 },
  signature: identity,
  notarization: { status: "Accepted", submission_id: notary.id, artifact_sha256: artifactDigest.sha256, evidence_file: "notary.json" },
  staple: { status: "validated", artifact_sha256: artifactDigest.sha256, evidence_file: "staple.json" },
  gatekeeper: { assessment: "accepted", artifact_sha256: artifactDigest.sha256, evidence_file: "gatekeeper.json" },
  verification: { name: basename(verificationPath), bytes: verificationFile.bytes, sha256: verificationFile.sha256 }
};
await writeOnce(output, evidence, "distribution evidence");
process.stdout.write(`${JSON.stringify({ status: "written", artifact_sha256: artifactDigest.sha256, evidence: output })}\n`);

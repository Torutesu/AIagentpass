#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createApiTokenRecord, generateApiToken } from "./auth.mjs";
import { createCloudStore } from "./store.mjs";

export async function bootstrapCloud({ outputDir, dataDir = path.join(outputDir ?? "", "data"), organizationName, principalId, organizationId = crypto.randomUUID(), memberId = crypto.randomUUID() } = {}) {
  if (typeof outputDir !== "string" || !path.isAbsolute(outputDir) || typeof dataDir !== "string" || !path.isAbsolute(dataDir)) throw new Error("Bootstrap output and data directories must be absolute");
  if (typeof organizationName !== "string" || organizationName.trim().length < 1 || organizationName.length > 128 || typeof principalId !== "string" || principalId.length < 1 || principalId.length > 256) throw new Error("Bootstrap organization and principal are invalid");
  fs.mkdirSync(outputDir, { recursive: false, mode: 0o700 });
  fs.chmodSync(outputDir, 0o700);
  const tokenPath = path.join(outputDir, "token-records.json");
  const privateKeyPath = path.join(outputDir, "bundle-private.pem");
  const publicKeyPath = path.join(outputDir, "bundle-public.pem");
  for (const file of [tokenPath, privateKeyPath, publicKeyPath]) if (fs.existsSync(file)) throw new Error("Bootstrap refuses to replace existing credentials");
  const token = generateApiToken();
  const tokenRecord = createApiTokenRecord({ token, organizationId, memberId, role: "owner" });
  const keys = crypto.generateKeyPairSync("ed25519");
  writeExclusive(tokenPath, `${JSON.stringify([tokenRecord], null, 2)}\n`, 0o600);
  writeExclusive(privateKeyPath, keys.privateKey.export({ type: "pkcs8", format: "pem" }), 0o600);
  writeExclusive(publicKeyPath, keys.publicKey.export({ type: "spki", format: "pem" }), 0o644);
  const store = await createCloudStore({ dataDir });
  try {
    await store.createOrganization({ organizationId, name: organizationName.trim(), idempotencyKey: `bootstrap-org-${organizationId}` });
    await store.createMembership({ organizationId, memberId, principalId, role: "owner", idempotencyKey: `bootstrap-member-${memberId}` });
  } catch (error) {
    for (const file of [tokenPath, privateKeyPath, publicKeyPath]) try { fs.unlinkSync(file); } catch {}
    throw error;
  } finally { await store.close(); }
  return Object.freeze({ organization_id: organizationId, member_id: memberId, principal_id: principalId, api_token: token, token_records_path: tokenPath, bundle_private_key_path: privateKeyPath, bundle_public_key_path: publicKeyPath, data_dir: dataDir });
}

function writeExclusive(file, value, mode) {
  const descriptor = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode);
  try { fs.writeFileSync(descriptor, value); fs.fsyncSync(descriptor); }
  finally { fs.closeSync(descriptor); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = Object.fromEntries(process.argv.slice(2).map((value, index, all) => value.startsWith("--") ? [value.slice(2), all[index + 1]] : null).filter(Boolean));
  const required = ["output-dir", "organization-name", "principal-id"];
  if (required.some((key) => !options[key])) throw new Error("Usage: node src/bootstrap.mjs --output-dir ABSOLUTE_DIR --organization-name NAME --principal-id SIWC_USER_ID [--data-dir ABSOLUTE_DIR]");
  const result = await bootstrapCloud({ outputDir: options["output-dir"], dataDir: options["data-dir"] ?? path.join(options["output-dir"], "data"), organizationName: options["organization-name"], principalId: options["principal-id"] });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.stderr.write("Save api_token now; it is shown only by this bootstrap command.\n");
}

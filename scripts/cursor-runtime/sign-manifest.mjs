#!/usr/bin/env node

import { fileURLToPath } from "node:url";

import { createCursorAgentRuntimeManifest } from "./materialize.mjs";

function run() {
  const args = process.argv.slice(2);
  if (args.length !== 7 || args.some((value) => value.startsWith("-"))) {
    process.stderr.write("cursor-runtime-sign: usage SOURCE_RUNTIME_DIR OUTPUT_MANIFEST PRIVATE_KEY_PKCS8_DER KEY_ID RUNTIME_VERSION RELEASE_DIGEST MATERIALIZATION_EPOCH\n");
    process.exitCode = 2;
    return;
  }
  try {
    const result = createCursorAgentRuntimeManifest({
      sourceRuntimeDirectory: args[0],
      outputFile: args[1],
      privateKeyFile: args[2],
      keyId: args[3],
      runtimeVersion: args[4],
      releaseDigest: args[5],
      materializationEpoch: Number(args[6])
    });
    process.stdout.write(`${JSON.stringify({ ok: true, manifest_file: result.manifestFile, public_key_der_base64url: result.publicKeyDER.toString("base64url") })}\n`);
  } catch (error) {
    const code = error?.code && /^[a-z][a-z0-9_]*$/u.test(error.code) ? error.code : "manifest_signing_failed";
    process.stderr.write(`cursor-runtime-sign: ${code}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) run();

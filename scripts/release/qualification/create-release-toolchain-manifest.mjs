#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// This inventory is intentionally small and closed. The protected aggregate
// runner must install these bytes out-of-band; the candidate checkout is only
// used to produce the expected digest during a controlled provisioning job.
export const RELEASE_TOOLCHAIN_FILES = Object.freeze([
  "verify-installed-toolchain.mjs",
  "verify-external-qualification-signature.mjs",
  "external-qualification-trust.mjs",
  "verify-hardware-qualification-set.mjs",
  "validate-hardware-qualification.mjs",
  "generate-hardware-qualification-template.mjs",
  "run-p0c-qualification.mjs",
  "sign-hardware-qualification.mjs",
  "p0c/verify-runner-attestation.mjs",
  "n3e/controller-identity-contract.mjs",
  "n3e/qualification-suite-evidence.mjs",
  "lib/release-candidate-identity.mjs"
]);

const digest = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const safeRelative = (value) => path.posix.normalize(value) === value && !value.startsWith("/") && !value.includes("..") && /^[A-Za-z0-9._/-]+$/u.test(value);

export function createReleaseToolchainManifest(root) {
  if (typeof root !== "string" || !path.isAbsolute(root) || path.resolve(root) !== root) throw new Error("release toolchain root must be a normalized absolute path");
  const files = RELEASE_TOOLCHAIN_FILES.map((name) => {
    if (!safeRelative(name)) throw new Error("release toolchain inventory contains an unsafe path");
    const file = path.join(root, name);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) throw new Error(`release toolchain file is unavailable or writable: ${name}`);
    return { path: name, sha256: digest(file) };
  });
  return { schema_version: 1, entrypoint: "verify-hardware-qualification-set.mjs", verifier: "verify-installed-toolchain.mjs", files };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.stdout.write(canonical(createReleaseToolchainManifest(path.resolve(process.argv[2])))); }
  catch (error) { process.stderr.write(`${error instanceof Error ? error.message : "release toolchain manifest generation failed"}\n`); process.exitCode = 1; }
}

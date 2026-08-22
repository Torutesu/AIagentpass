#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const FILES = Object.freeze([
  "run-hardware-qualification.sh",
  "hardware-qualification.mjs",
  "hardware-qualification.schema.json",
  "nsxpc-host-control-probe.mjs",
  "verify-installed-toolchain.mjs"
]);
const digest = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const canonical = (value) => `${JSON.stringify(value)}\n`;

export function createToolchainManifest(root) {
  if (typeof root !== "string" || !path.isAbsolute(root) || path.resolve(root) !== root) throw new Error("toolchain root must be a normalized absolute path");
  const files = FILES.map((name) => {
    const file = path.join(root, name); const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`toolchain file is unavailable: ${name}`);
    return { path: name, sha256: digest(file) };
  });
  return { schema_version: 1, entrypoint: "run-hardware-qualification.sh", verifier: "hardware-qualification.mjs", files };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.stdout.write(canonical(createToolchainManifest(path.resolve(process.argv[2])))); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}

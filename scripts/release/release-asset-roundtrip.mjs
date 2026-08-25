#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

const NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
const MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024;

export function snapshotReleaseAsset(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) || typeof input.name !== "string" || typeof input.path !== "string" || !NAME.test(input.name) || input.name !== path.basename(input.name) || !path.isAbsolute(input.path)) throw new TypeError("release asset input is invalid");
  const fd = fs.openSync(input.path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(MAX_FILE_BYTES)) throw new TypeError("release asset is unsafe");
    const hash = crypto.createHash("sha256");
    let offset = 0;
    const size = Number(before.size);
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    while (offset < size) {
      const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (count <= 0) throw new TypeError("release asset changed while reading");
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if (["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"].some((key) => before[key] !== after[key])) throw new TypeError("release asset changed while reading");
    return Object.freeze({ name: input.name, bytes: size, sha256: hash.digest("hex") });
  } finally { fs.closeSync(fd); }
}

export function buildReleaseAssetInventory(inputs) {
  if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length > 512) throw new TypeError("release asset inventory is invalid");
  const assets = inputs.map(snapshotReleaseAsset).sort((left, right) => left.name.localeCompare(right.name, "en"));
  if (new Set(assets.map((asset) => asset.name)).size !== assets.length) throw new TypeError("release asset inventory has duplicate names");
  return Object.freeze({ version: 1, type: "agentpass.release-asset-inventory", assets: Object.freeze(assets) });
}

export function verifyReleaseAssetRoundTrip(inventory, remoteDirectory) {
  if (!inventory || inventory.version !== 1 || inventory.type !== "agentpass.release-asset-inventory" || !Array.isArray(inventory.assets) || !path.isAbsolute(remoteDirectory)) throw new TypeError("release round-trip inventory is invalid");
  const expected = new Map(inventory.assets.map((asset) => [asset.name, asset]));
  const actualEntries = fs.readdirSync(remoteDirectory, { withFileTypes: true });
  if (actualEntries.some((entry) => !entry.isFile())) throw new TypeError("release asset directory contains a non-regular entry");
  const actualNames = actualEntries.map((entry) => entry.name).sort((a, b) => a.localeCompare(b, "en"));
  if (actualNames.length !== expected.size || actualNames.some((name) => !expected.has(name))) throw new TypeError("release asset set mismatch");
  const observed = actualNames.map((name) => snapshotReleaseAsset({ name, path: path.join(remoteDirectory, name) }));
  for (const asset of observed) {
    const expectedAsset = expected.get(asset.name);
    if (asset.bytes !== expectedAsset.bytes || asset.sha256 !== expectedAsset.sha256) throw new TypeError(`release asset digest mismatch: ${asset.name}`);
  }
  return Object.freeze({ version: 1, type: "agentpass.release-asset-roundtrip", inventory_sha256: crypto.createHash("sha256").update(canonicalJson(inventory), "utf8").digest("hex"), assets: Object.freeze(observed) });
}

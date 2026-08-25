#!/usr/bin/env node
import fs from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { assertReleaseCandidateIdMatchesProduct, RELEASE_MANIFEST_SCHEMA_VERSION } from '../../lib/release-candidate-identity.mjs';

const [destinationInput, manifestInput, signatureInput, publicKeyInput] = process.argv.slice(2);
if (!destinationInput || !manifestInput || !signatureInput || !publicKeyInput || process.argv.slice(2).length !== 4) {
  throw new Error('Usage: stage-release.mjs PRIVATE-DIRECTORY RELEASE-MANIFEST.json SIGNATURE PUBLIC-KEY');
}
if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');

const destination = resolve(destinationInput);
const destinationStat = fs.lstatSync(destination, { bigint: true });
if (!destinationStat.isDirectory() || destinationStat.isSymbolicLink() || (destinationStat.mode & 0o077n) !== 0n) {
  throw new Error('release staging directory must be a private non-symlink directory');
}
if (fs.readdirSync(destination).length !== 0) throw new Error('release staging directory must be empty');

const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const copySnapshot = (input, outputName, maximum) => {
  const source = resolve(input);
  const descriptor = fs.openSync(source, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let output;
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum)) {
      throw new Error(`unsafe release staging input: ${input}`);
    }
    output = fs.openSync(join(destination, outputName), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0n;
    while (offset < before.size) {
      const wanted = Number(before.size - offset > BigInt(buffer.length) ? BigInt(buffer.length) : before.size - offset);
      const count = fs.readSync(descriptor, buffer, 0, wanted, Number(offset));
      if (count === 0) throw new Error(`release staging input changed while reading: ${input}`);
      let written = 0;
      while (written < count) written += fs.writeSync(output, buffer, written, count - written);
      offset += BigInt(count);
    }
    fs.fsyncSync(output);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (identity(before) !== identity(after)) throw new Error(`release staging input changed while reading: ${input}`);
  } finally {
    if (output !== undefined) fs.closeSync(output);
    fs.closeSync(descriptor);
  }
};

const manifestName = 'release-manifest.json';
copySnapshot(manifestInput, manifestName, 16 * 1024 * 1024);
let manifest;
try { manifest = JSON.parse(fs.readFileSync(join(destination, manifestName), 'utf8')); } catch { throw new Error('staged release manifest is not valid JSON'); }

const safeName = (name) => typeof name === 'string' && /^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(name) && name === basename(name);
const declared = [];
if (manifest?.schema_version !== RELEASE_MANIFEST_SCHEMA_VERSION || !Array.isArray(manifest?.artifacts) || !Array.isArray(manifest?.evidence?.notarization?.evidence) || !Array.isArray(manifest?.external_qualification_controller?.notarization?.evidence)) throw new Error('staged release manifest cannot enumerate release files');
const products = manifest.artifacts.filter((item) => item?.role === 'product');
if (products.length !== 1 || typeof products[0].name !== 'string' || !products[0].name.endsWith('.pkg')) throw new Error('staged release manifest requires exactly one product PKG artifact');
assertReleaseCandidateIdMatchesProduct(manifest.candidate_id, products[0].sha256);
for (const item of manifest.artifacts) declared.push(item?.name);
declared.push(manifest?.evidence?.checksums?.name);
for (const item of manifest.evidence.notarization.evidence) declared.push(item?.name);
declared.push(manifest.external_qualification_controller?.identity_document?.name);
for (const item of manifest.external_qualification_controller.notarization.evidence) declared.push(item?.name);
const reserved = new Set([manifestName, 'release-manifest.sig', 'release-public.pem']);
const unique = new Set();
for (const name of declared) {
  if (!safeName(name) || reserved.has(name) || unique.has(name)) throw new Error('release manifest declares an unsafe, duplicate, or reserved file name');
  unique.add(name);
}

const sourceDirectory = dirname(resolve(manifestInput));
for (const name of unique) copySnapshot(join(sourceDirectory, name), name, 16 * 1024 * 1024 * 1024);
copySnapshot(signatureInput, 'release-manifest.sig', 1024);
copySnapshot(publicKeyInput, 'release-public.pem', 16 * 1024);
for (const name of fs.readdirSync(destination)) fs.chmodSync(join(destination, name), 0o400);
const directoryDescriptor = fs.openSync(destination, fs.constants.O_RDONLY);
try { fs.fsyncSync(directoryDescriptor); } finally { fs.closeSync(directoryDescriptor); }
fs.chmodSync(destination, 0o500);

process.stdout.write(`${JSON.stringify({
  manifest: join(destination, manifestName),
  signature: join(destination, 'release-manifest.sig'),
  public_key: join(destination, 'release-public.pem'),
  declared_files: unique.size
})}\n`);

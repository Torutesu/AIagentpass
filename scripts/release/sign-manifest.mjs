#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { resolve } from 'node:path';

const [manifestArg, privateKeyArg, signatureArg] = process.argv.slice(2);
if (!manifestArg || !privateKeyArg || !signatureArg || process.argv.slice(2).length !== 3) throw new Error('Usage: sign-manifest.mjs MANIFEST PRIVATE-KEY SIGNATURE');
if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');
const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const readRegular = (value, maximum, requirePrivate) => {
  const path = resolve(value); const descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`unsafe release input: ${value}`);
    if (requirePrivate && ((before.mode & 0o077n) !== 0n || before.uid !== BigInt(process.getuid()))) throw new Error(`release private key must be owner-only and owned by the current user: ${value}`);
    const data = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < data.length) { const count = fs.readSync(descriptor, data, offset, data.length - offset, offset); if (!count) throw new Error(`truncated release input: ${value}`); offset += count; }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`release input changed while reading: ${value}`);
    return data;
  } finally { fs.closeSync(descriptor); }
};
const manifest = readRegular(manifestArg, 16 * 1024 * 1024, false);
let parsedManifest;
try { parsedManifest = JSON.parse(manifest.toString('utf8')); } catch { throw new Error('release manifest is not valid UTF-8 JSON'); }
const expectedTopLevel = ['artifacts', 'evidence', 'generated_at', 'product', 'schema_version', 'source', 'version'];
if (JSON.stringify(Object.keys(parsedManifest).sort()) !== JSON.stringify(expectedTopLevel) || parsedManifest.schema_version !== 2 || parsedManifest.product !== 'AgentPass' || !manifest.equals(Buffer.from(`${JSON.stringify(parsedManifest, null, 2)}\n`, 'utf8'))) throw new Error('refusing to sign a noncanonical or unsupported release manifest');
const privateBytes = readRegular(privateKeyArg, 16 * 1024, true);
let key;
try { key = crypto.createPrivateKey(privateBytes); }
finally { privateBytes.fill(0); }
if (key.asymmetricKeyType !== 'ed25519') throw new Error('Release manifest key must be Ed25519');
const signature = crypto.sign(null, manifest, key);
fs.writeFileSync(resolve(signatureArg), `${signature.toString('base64')}\n`, { flag: 'wx', mode: 0o644 });
console.log(JSON.stringify({ ok: true, signature_bytes: signature.length }));

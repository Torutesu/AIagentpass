import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  CURSOR_AGENT_RUNTIME_DESTINATION_PARENT,
  CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES,
  CURSOR_AGENT_RUNTIME_MAX_FILE_BYTES,
  CURSOR_AGENT_RUNTIME_SIGNATURE_DOMAIN,
  CURSOR_AGENT_RUNTIME_TRUST_CONFIG_NAME,
  CursorRuntimeMaterializerError,
  createCursorAgentRuntimeManifest,
  materializeCursorAgentRuntime
} from "./materialize.mjs";

const ORIGINAL_AGENT = Buffer.from("runtime-body");

function fixture({ files = { node: { bytes: ORIGINAL_AGENT, executable: true }, "index.js": { bytes: Buffer.from("module.exports = 1;\n"), executable: false } }, trustedKey = null, runtimeVersion = "2026.08.17", keyId = "cursor-runtime-release-2026-08", sizeOverrides = {} } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cursor-runtime-")));
  const source = path.join(root, "source");
  const destinationParent = path.join(root, "destination");
  const trustParent = path.join(root, "trust");
  const manifest = path.join(root, "runtime-manifest.input.json");
  const trustedKeyFile = path.join(root, "trusted-public-key.der");
  const privateKeyFile = path.join(root, "runtime-signing-key.pk8.der");
  fs.mkdirSync(source, { mode: 0o700 });
  fs.mkdirSync(destinationParent, { mode: 0o700 });
  fs.mkdirSync(trustParent, { mode: 0o700 });

  for (const [relativePath, value] of Object.entries(files)) {
    const target = path.join(source, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
    fs.writeFileSync(target, value.bytes, { mode: value.executable ? 0o755 : 0o644 });
    fs.chmodSync(target, value.executable ? 0o755 : 0o644);
  }
  const signingKey = crypto.generateKeyPairSync("ed25519");
  const trusted = trustedKey ?? signingKey;
  fs.writeFileSync(trustedKeyFile, trusted.publicKey.export({ type: "spki", format: "der" }), { mode: 0o444 });
  fs.chmodSync(trustedKeyFile, 0o444);
  fs.writeFileSync(privateKeyFile, signingKey.privateKey.export({ type: "pkcs8", format: "der" }), { mode: 0o600 });
  fs.chmodSync(privateKeyFile, 0o600);
  writeManifest({ source, manifest, signingKey, files, runtimeVersion, keyId, sizeOverrides });
  return { root, source, destinationParent, trustParent, manifest, trustedKeyFile, privateKeyFile, signingKey, trusted, keyId, runtimeVersion };
}

function writeManifest({ source, manifest, signingKey, files, runtimeVersion = "2026.08.17", keyId = "cursor-runtime-release-2026-08", sizeOverrides = {} }) {
  const entries = Object.entries(files).map(([relativePath, value]) => ({
    relative_path: relativePath,
    sha256: crypto.createHash("sha256").update(value.bytes).digest("hex"),
    size: sizeOverrides[relativePath] ?? value.bytes.length,
    executable: value.executable
  })).sort((left, right) => left.relative_path.localeCompare(right.relative_path));
  const core = {
    schema_version: 1,
    runtime_id: "cursor-agent",
    runtime_version: runtimeVersion,
    release_digest: `sha256:${"a".repeat(64)}`,
    materialization_epoch: 1,
    files: entries
  };
  const signature = crypto.sign(
    null,
    Buffer.concat([Buffer.from(CURSOR_AGENT_RUNTIME_SIGNATURE_DOMAIN, "utf8"), Buffer.from(canonicalJson(core), "utf8")]),
    signingKey.privateKey
  ).toString("base64url");
  const value = {
    core,
    signature: {
      algorithm: "ed25519",
      domain: CURSOR_AGENT_RUNTIME_SIGNATURE_DOMAIN,
      key_id: keyId,
      signature_base64url: signature
    }
  };
  fs.writeFileSync(manifest, `${canonicalJson(value)}\n`, { mode: 0o600 });
  fs.chmodSync(manifest, 0o600);
  void source;
  return value;
}

function materialize(value, extra = {}) {
  return materializeCursorAgentRuntime({
    sourceRuntimeDirectory: value.source,
    signedManifestFile: value.manifest,
    trustedPublicKeyFile: value.trustedKeyFile,
    trustedKeyId: value.keyId,
    destinationParent: value.destinationParent,
    trustParent: value.trustParent,
    production: false,
    platform: "test",
    ...extra
  });
}

function trustConfigPath(value) {
  return path.join(value.trustParent, CURSOR_AGENT_RUNTIME_TRUST_CONFIG_NAME);
}

function expectedTrustConfig(value) {
  return Buffer.from(canonicalJson({
    schema_version: 1,
    key_id: value.keyId,
    public_key_der_base64url: value.trusted.publicKey.export({ type: "spki", format: "der" }).toString("base64url")
  }));
}

function assertCode(code, operation) {
  assert.throws(operation, (error) => error instanceof CursorRuntimeMaterializerError && error.code === code);
}

function cleanup(value) {
  const remove = (target) => {
    let stat;
    try { stat = fs.lstatSync(target); } catch { return; }
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      fs.chmodSync(target, 0o700);
      for (const name of fs.readdirSync(target)) remove(path.join(target, name));
      fs.rmdirSync(target);
    } else {
      if (stat.isFile()) fs.chmodSync(target, 0o600);
      fs.unlinkSync(target);
    }
  };
  remove(value.root);
}

test("materializes a valid closed runtime tree with exact destination modes", () => {
  const value = fixture();
  try {
    const result = materialize(value);
    assert.equal(fs.readFileSync(path.join(result.runtimeDirectory, "node")).toString(), ORIGINAL_AGENT.toString());
    assert.equal(fs.statSync(path.join(result.runtimeDirectory, "node")).mode & 0o777, 0o555);
    assert.equal(fs.statSync(path.join(result.runtimeDirectory, "index.js")).mode & 0o777, 0o444);
    assert.deepEqual(fs.readFileSync(result.manifestFile), fs.readFileSync(value.manifest));
    assert.deepEqual(fs.readFileSync(result.trustConfigFile), expectedTrustConfig(value));
    assert.equal(fs.readFileSync(result.trustConfigFile).at(-1), 0x7d);
    assert.equal(result.runtimeVersion, "2026.08.17");
  } finally { cleanup(value); }
});

test("creates a signed manifest from the closed source tree and materializes it", () => {
  const value = fixture();
  const generatedManifest = path.join(value.root, "generated-manifest.json");
  try {
    const generated = createCursorAgentRuntimeManifest({
      sourceRuntimeDirectory: value.source,
      outputFile: generatedManifest,
      privateKeyFile: value.privateKeyFile,
      keyId: value.keyId,
      runtimeVersion: value.runtimeVersion,
      releaseDigest: `sha256:${"c".repeat(64)}`,
      materializationEpoch: 7
    });
    assert.equal(generated.publicKeyDER.length, 44);
    assert.equal(fs.readFileSync(generatedManifest).at(-1), 0x0a);
    const result = materialize(value, { signedManifestFile: generatedManifest });
    assert.equal(result.runtimeVersion, value.runtimeVersion);
    assert.equal(result.releaseDigest, `sha256:${"c".repeat(64)}`);
    assert.equal(result.materializationEpoch, 7);
    assert.throws(() => createCursorAgentRuntimeManifest({
      sourceRuntimeDirectory: value.source,
      outputFile: generatedManifest,
      privateKeyFile: value.privateKeyFile,
      keyId: value.keyId,
      runtimeVersion: value.runtimeVersion,
      releaseDigest: `sha256:${"c".repeat(64)}`,
      materializationEpoch: 7
    }), (error) => error instanceof CursorRuntimeMaterializerError && error.code === "manifest_exists");
  } finally { cleanup(value); }
});

test("requires executable node and non-executable index.js", () => {
  const missingNode = fixture({ files: { "index.js": { bytes: Buffer.from("module.exports = 1;\n"), executable: false } } });
  try { assertCode("invalid_manifest", () => materialize(missingNode)); } finally { cleanup(missingNode); }

  const executableIndex = fixture({ files: { node: { bytes: ORIGINAL_AGENT, executable: true }, "index.js": { bytes: Buffer.from("module.exports = 1;\n"), executable: true } } });
  try { assertCode("invalid_manifest", () => materialize(executableIndex)); } finally { cleanup(executableIndex); }
  const nonExecutableNode = fixture({ files: { node: { bytes: ORIGINAL_AGENT, executable: false }, "index.js": { bytes: Buffer.from("module.exports = 1;\n"), executable: false } } });
  try { assertCode("invalid_manifest", () => materialize(nonExecutableNode)); } finally { cleanup(nonExecutableNode); }
});

test("enforces the 2 MiB manifest bound and conservative version/key identifiers", () => {
  const oversized = fixture();
  try {
    fs.writeFileSync(oversized.manifest, Buffer.alloc(CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES + 1, 0x20));
    assertCode("unsafe_input", () => materialize(oversized));
  } finally { cleanup(oversized); }

  const version = fixture({ runtimeVersion: "2026:08" });
  try { assertCode("invalid_manifest", () => materialize(version)); } finally { cleanup(version); }

  const keyId = fixture({ keyId: "cursor:key" });
  try { assertCode("invalid_manifest", () => materialize(keyId)); } finally { cleanup(keyId); }
});

test("uses the closed manifest path and per-file size bounds", () => {
  const invalidPath = fixture({ files: {
    node: { bytes: ORIGINAL_AGENT, executable: true },
    "index with space.js": { bytes: Buffer.from("module.exports = 1;\n"), executable: false }
  } });
  try { assertCode("invalid_manifest", () => materialize(invalidPath)); } finally { cleanup(invalidPath); }

  const oversizedFile = fixture({ sizeOverrides: { node: CURSOR_AGENT_RUNTIME_MAX_FILE_BYTES + 1 } });
  try { assertCode("invalid_manifest", () => materialize(oversizedFile)); } finally { cleanup(oversizedFile); }
});

test("rejects non-ASCII and overlong runtime paths", () => {
  const nonASCII = fixture({ files: {
    node: { bytes: ORIGINAL_AGENT, executable: true },
    "index.js": { bytes: Buffer.from("module.exports = 1;\n"), executable: false },
    "chunks/é.js": { bytes: Buffer.from("x"), executable: false }
  } });
  try { assertCode("invalid_manifest", () => materialize(nonASCII)); } finally { cleanup(nonASCII); }

  const longPath = `${"abcdefgh/".repeat(114)}payload.js`;
  assert.ok(Buffer.byteLength(longPath) > 1024);
  const overlong = fixture();
  try {
    const envelope = JSON.parse(fs.readFileSync(overlong.manifest, "utf8"));
    envelope.core.files[0].relative_path = longPath;
    envelope.core.files.sort((left, right) => left.relative_path.localeCompare(right.relative_path));
    envelope.signature.signature_base64url = crypto.sign(
      null,
      Buffer.concat([
        Buffer.from(CURSOR_AGENT_RUNTIME_SIGNATURE_DOMAIN, "utf8"),
        Buffer.from(canonicalJson(envelope.core), "utf8")
      ]),
      overlong.signingKey.privateKey
    ).toString("base64url");
    fs.writeFileSync(overlong.manifest, `${canonicalJson(envelope)}\n`);
    assertCode("invalid_manifest", () => materialize(overlong));
  } finally { cleanup(overlong); }
});

test("rejects an extra source file and never creates a destination", () => {
  const value = fixture();
  try {
    fs.writeFileSync(path.join(value.source, "extra.txt"), "extra", { mode: 0o644 });
    assertCode("inventory_mismatch", () => materialize(value));
    assert.equal(fs.existsSync(path.join(value.destinationParent, "runtime")), false);
  } finally { cleanup(value); }
});

test("rejects a missing source file", () => {
  const value = fixture();
  try {
    fs.unlinkSync(path.join(value.source, "index.js"));
    assertCode("inventory_mismatch", () => materialize(value));
  } finally { cleanup(value); }
});

test("rejects source symlinks before copying", () => {
  const value = fixture();
  try {
    const target = path.join(value.source, "index.js");
    fs.unlinkSync(target);
    fs.symlinkSync("node", target);
    assertCode("source_symlink", () => materialize(value));
  } finally { cleanup(value); }
});

test("rejects source hard links even when the inventory is otherwise closed", () => {
  const value = fixture();
  try {
    fs.linkSync(path.join(value.source, "node"), path.join(value.source, "linked-copy"));
    assertCode("source_invalid", () => materialize(value));
  } finally { cleanup(value); }
});

test("rejects content tampering after the signed manifest was created", () => {
  const value = fixture();
  try {
    fs.writeFileSync(path.join(value.source, "node"), Buffer.from("tamper-body!"));
    fs.chmodSync(path.join(value.source, "node"), 0o755);
    assertCode("digest_mismatch", () => materialize(value));
  } finally { cleanup(value); }
});

test("rejects a manifest signed by a self-signed but untrusted key", () => {
  const value = fixture({ trustedKey: crypto.generateKeyPairSync("ed25519") });
  try {
    assertCode("invalid_signature", () => materialize(value));
  } finally { cleanup(value); }
});

test("rejects credential and log paths instead of copying them", () => {
  const value = fixture({ files: { "credentials.json": { bytes: Buffer.from("nope"), executable: false } } });
  try {
    assertCode("forbidden_runtime_path", () => materialize(value));
  } finally { cleanup(value); }

  const logged = fixture({ files: { "agent.log": { bytes: Buffer.from("nope"), executable: false } } });
  try {
    assertCode("forbidden_runtime_path", () => materialize(logged));
  } finally { cleanup(logged); }
});

test("refuses no-clobber reruns and preserves the first publication", () => {
  const value = fixture();
  try {
    const first = materialize(value);
    const firstRuntime = fs.readFileSync(path.join(first.runtimeDirectory, "node"));
    assertCode("destination_exists", () => materialize(value));
    assert.deepEqual(fs.readFileSync(path.join(first.runtimeDirectory, "node")), firstRuntime);
    assert.deepEqual(fs.readFileSync(first.manifestFile), fs.readFileSync(value.manifest));
  } finally { cleanup(value); }
});

test("rejects a mismatched pre-existing trust config without overwriting it", () => {
  const value = fixture();
  const destination = trustConfigPath(value);
  const other = crypto.generateKeyPairSync("ed25519");
  const original = Buffer.from(`${canonicalJson({
    schema_version: 1,
    key_id: "other-release",
    public_key_der_base64url: other.publicKey.export({ type: "spki", format: "der" }).toString("base64url")
  })}\n`);
  try {
    fs.writeFileSync(destination, original, { mode: 0o444 });
    assertCode("trust_config_mismatch", () => materialize(value));
    assert.deepEqual(fs.readFileSync(destination), original);
    assert.equal(fs.existsSync(path.join(value.destinationParent, "runtime")), false);
  } finally { cleanup(value); }
});

test("rejects a mismatched pre-existing manifest without publishing trust metadata", () => {
  const value = fixture();
  const destination = path.join(value.destinationParent, "runtime-manifest.json");
  const original = Buffer.from("not-the-signed-manifest\n");
  try {
    fs.writeFileSync(destination, original, { mode: 0o444 });
    assertCode("manifest_mismatch", () => materialize(value));
    assert.deepEqual(fs.readFileSync(destination), original);
    assert.equal(fs.existsSync(trustConfigPath(value)), false);
    assert.equal(fs.existsSync(path.join(value.destinationParent, "runtime")), false);
  } finally { cleanup(value); }
});

test("resumes from exact pre-existing trust config and manifest metadata", () => {
  const value = fixture();
  const trustPath = trustConfigPath(value);
  const manifestPath = path.join(value.destinationParent, "runtime-manifest.json");
  try {
    fs.writeFileSync(trustPath, expectedTrustConfig(value), { mode: 0o444 });
    fs.writeFileSync(manifestPath, fs.readFileSync(value.manifest), { mode: 0o444 });
    const trustBefore = fs.lstatSync(trustPath);
    const manifestBefore = fs.lstatSync(manifestPath);
    const result = materialize(value);
    assert.equal(fs.lstatSync(trustPath).ino, trustBefore.ino);
    assert.equal(fs.lstatSync(manifestPath).ino, manifestBefore.ino);
    assert.equal(fs.existsSync(result.runtimeDirectory), true);
  } finally { cleanup(value); }
});

test("supports an injected trustConfigPath for library callers", () => {
  const value = fixture();
  const injected = path.join(value.trustParent, "injected-cursor-key.json");
  try {
    const result = materialize(value, { trustConfigPath: injected });
    assert.equal(result.trustConfigFile, injected);
    assert.deepEqual(fs.readFileSync(injected), expectedTrustConfig(value));
    assert.equal(fs.existsSync(trustConfigPath(value)), false);
  } finally { cleanup(value); }
});

test("treats an existing runtime as terminal even when metadata is mismatched", () => {
  const value = fixture();
  const runtime = path.join(value.destinationParent, "runtime");
  const sentinel = path.join(runtime, "sentinel");
  try {
    fs.mkdirSync(runtime, { mode: 0o700 });
    fs.writeFileSync(sentinel, "must remain", { mode: 0o600 });
    fs.writeFileSync(path.join(value.destinationParent, "runtime-manifest.json"), "wrong\n", { mode: 0o444 });
    assertCode("destination_exists", () => materialize(value));
    assert.equal(fs.readFileSync(sentinel, "utf8"), "must remain");
  } finally { cleanup(value); }
});

test("refuses a pre-existing destination symlink without touching its target", () => {
  const value = fixture();
  const outside = path.join(value.root, "outside");
  try {
    fs.mkdirSync(outside, { mode: 0o700 });
    fs.symlinkSync(outside, path.join(value.destinationParent, "runtime"));
    assertCode("destination_exists", () => materialize(value));
    assert.equal(fs.readdirSync(outside).length, 0);
  } finally { cleanup(value); }
});

test("requires root and macOS for the production policy", () => {
  const value = fixture();
  try {
    assertCode("root_required", () => materialize(value, {
      production: true,
      platform: "darwin",
      effectiveUserId: 501,
      destinationParent: CURSOR_AGENT_RUNTIME_DESTINATION_PARENT
    }));
  } finally { cleanup(value); }
});

test("rejects noncanonical manifest bytes and signature tampering", () => {
  const value = fixture();
  try {
    const bytes = fs.readFileSync(value.manifest, "utf8");
    fs.writeFileSync(value.manifest, ` ${bytes}`);
    assertCode("noncanonical_manifest", () => materialize(value));
    fs.writeFileSync(value.manifest, bytes);
    const tampered = JSON.parse(bytes);
    tampered.signature.signature_base64url = `${tampered.signature.signature_base64url.slice(0, -1)}${tampered.signature.signature_base64url.endsWith("A") ? "B" : "A"}`;
    fs.writeFileSync(value.manifest, `${canonicalJson(tampered)}\n`);
    assertCode("invalid_signature", () => materialize(value));
  } finally { cleanup(value); }
});

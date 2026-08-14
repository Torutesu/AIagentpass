import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  SETUP_PREFLIGHT_ERROR_CODES,
  SETUP_PREFLIGHT_HANDOFF_KEYS,
  parseValidatedInstallReceipt,
  parseSetupPreflightHandoff,
  prepareSetupPreflight,
  serializeSetupPreflightHandoff
} from "../lib/setup-preflight.mjs";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, "bin", "agentpass.mjs");

function p256() {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  return { pair, publicKey, fingerprint };
}

function binding(overrides = {}) {
  return {
    version: 1,
    kind: "agentpass.installed-release-receipt",
    candidate_id: "release-2026-08-15-01",
    manifest_sha256: "a".repeat(64),
    artifact_sha256: "b".repeat(64),
    source_commit: "c".repeat(40),
    team_id: "ABCDE12345",
    release_signer_fingerprint: `SHA256:${"d".repeat(43)}`,
    ...overrides
  };
}

function nativeRunner(key) {
  return { publicKey: () => ({ algorithm: "p256-sha256", spki_pem: key.publicKey, fingerprint: key.fingerprint }) };
}

test("produces the exact public handoff from a verified candidate-bound receipt", async () => {
  const key = p256();
  const receipt = binding();
  let receiptReads = 0;
  let releaseVerifications = 0;
  let keyReads = 0;
  const result = await prepareSetupPreflight({
    readInstalledReleaseReceipt: () => { receiptReads += 1; return structuredClone(receipt); },
    verifyInstalledRelease: () => { releaseVerifications += 1; return structuredClone(receipt); },
    nativeRunner: { publicKey: () => { keyReads += 1; return nativeRunner(key).publicKey(); } }
  });
  assert.deepEqual(Object.keys(result).sort(), [...SETUP_PREFLIGHT_HANDOFF_KEYS].sort());
  assert.deepEqual(result, { version: 1, platform: "macos", candidate_id: receipt.candidate_id, device_key_fingerprint: key.fingerprint });
  assert.equal(receiptReads, 1);
  assert.equal(releaseVerifications, 1);
  assert.equal(keyReads, 1);
});

test("rejects a candidate substitution between the validated release and installed receipt", async () => {
  const key = p256();
  const verified = binding();
  const substituted = binding({ candidate_id: "release-attacker" });
  await assert.rejects(
    () => prepareSetupPreflight({
      readInstalledReleaseReceipt: () => substituted,
      verifyInstalledRelease: () => verified,
      nativeRunner: nativeRunner(key)
    }),
    (error) => error.code === SETUP_PREFLIGHT_ERROR_CODES.CANDIDATE_BINDING_MISMATCH
  );
});

test("fails closed when candidate identity is missing", () => {
  assert.throws(
    () => parseValidatedInstallReceipt({ ...binding(), candidate_id: undefined }),
    (error) => error.code === SETUP_PREFLIGHT_ERROR_CODES.CANDIDATE_MISSING
  );
});

test("rejects malformed native output and private key material", async () => {
  const verified = binding();
  const key = p256();
  const privateKey = key.pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  await assert.rejects(
    () => prepareSetupPreflight({
      readInstalledReleaseReceipt: () => verified,
      verifyInstalledRelease: () => verified,
      nativeRunner: { publicKey: () => ({ algorithm: "p256-sha256", spki_pem: privateKey, fingerprint: key.fingerprint }) }
    }),
    (error) => error.code === SETUP_PREFLIGHT_ERROR_CODES.NATIVE_KEY_INVALID
  );
});

test("serializes only public handoff fields and excludes secrets and paths", async () => {
  const key = p256();
  const receipt = binding({ candidate_id: "release-public" });
  const result = await prepareSetupPreflight({
    readInstalledReleaseReceipt: () => receipt,
    verifyInstalledRelease: () => receipt,
    nativeRunner: nativeRunner(key)
  });
  const output = serializeSetupPreflightHandoff(result);
  assert.deepEqual(JSON.parse(output), result);
  assert.equal(output.includes("PRIVATE KEY"), false);
  assert.equal(output.includes("/Library/"), false);
  assert.equal(output.includes("/tmp/"), false);
  assert.equal(output.includes("credential"), false);
  assert.equal(output.includes("manifest"), false);
});

test("base DTO requires macOS platform and reserves correlation_id for live handoff", () => {
  const key = p256();
  const valid = { version: 1, platform: "macos", candidate_id: "release-public", device_key_fingerprint: key.fingerprint };
  assert.deepEqual(parseSetupPreflightHandoff(valid), valid);
  assert.throws(() => parseSetupPreflightHandoff({ ...valid, platform: "linux" }), (error) => error.code === SETUP_PREFLIGHT_ERROR_CODES.HANDOFF_INVALID);
  assert.throws(() => parseSetupPreflightHandoff({ ...valid, correlation_id: "reserved" }), (error) => error.code === SETUP_PREFLIGHT_ERROR_CODES.HANDOFF_INVALID);
});

test("preview performs no persistence or filesystem mutation", async () => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-preflight-")));
  const sentinel = path.join(directory, "sentinel");
  fs.writeFileSync(sentinel, "unchanged\n", { mode: 0o600 });
  const before = fs.readdirSync(directory);
  const beforeBytes = fs.readFileSync(sentinel);
  const key = p256();
  const receipt = binding();
  await prepareSetupPreflight({
    readInstalledReleaseReceipt: () => receipt,
    verifyInstalledRelease: () => receipt,
    nativeRunner: nativeRunner(key)
  });
  assert.deepEqual(fs.readdirSync(directory), before);
  assert.deepEqual(fs.readFileSync(sentinel), beforeBytes);
});

test("CLI JSON mode fails closed without an installed proof and never prints a path", () => {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-preflight-cli-")));
  const result = spawnSync(process.execPath, [cli, "setup", "prepare", "--json"], { encoding: "utf8", env: { ...process.env, HOME: home } });
  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.equal(output.error.code, SETUP_PREFLIGHT_ERROR_CODES.INSTALL_PROOF_UNAVAILABLE);
  assert.equal(JSON.stringify(output).includes(home), false);
  assert.equal(JSON.stringify(output).includes("/Library/"), false);
  assert.equal(JSON.stringify(output).includes("PRIVATE KEY"), false);
});

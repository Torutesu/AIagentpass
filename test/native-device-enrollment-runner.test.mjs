import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createNativeDeviceEnrollmentRunner } from "../lib/native-device-enrollment-runner.mjs";

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function envelope(value) { return canonical({ ok: true, stdout_base64: Buffer.from(canonical(value)).toString("base64") }); }
function fakeFs(owner) {
  return { lstatSync(target) {
    const leaf = target.endsWith("agentpass-native-client");
    return { uid: owner, mode: leaf ? 0o100755 : 0o040755, nlink: 1, isFile: () => leaf, isDirectory: () => !leaf, isSymbolicLink: () => false };
  } };
}

test("validates the native P-256 identity and returns raw signatures", () => {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const calls = [];
  const runner = createNativeDeviceEnrollmentRunner({
    clientPath: "/test/AgentPass.app/Contents/MacOS/agentpass-native-client",
    applicationRoot: "/test/AgentPass.app",
    expectedOwner: process.getuid(),
    fs: fakeFs(process.getuid()),
    run: (_client, command, input) => {
      calls.push({ command, input });
      const value = command === "device-auth-key"
        ? { fingerprint, public_key_pem: pem }
        : { signature_base64: crypto.sign("sha256", input, { key: pair.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64") };
      return { status: 0, stdout: envelope(value) };
    }
  });
  assert.deepEqual(runner.publicKey(), { algorithm: "p256-sha256", spki_pem: pem, fingerprint });
  const proof = Buffer.from("AgentPass-Enrollment-Proof-v1\nPOST\n/v1/enrollments/test\nabc");
  const signature = runner.sign({ bytes: proof });
  assert.equal(crypto.verify("sha256", proof, { key: pair.publicKey, dsaEncoding: "ieee-p1363" }, signature), true);
  assert.equal(calls[1].input.equals(proof), true);
});

test("rejects substituted fingerprints and malformed native signatures", () => {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const make = (payload) => createNativeDeviceEnrollmentRunner({
    clientPath: "/test/AgentPass.app/Contents/MacOS/agentpass-native-client",
    applicationRoot: "/test/AgentPass.app",
    expectedOwner: process.getuid(),
    fs: fakeFs(process.getuid()),
    run: (_client, command) => ({ status: 0, stdout: envelope(command === "device-auth-key" ? payload : { signature_base64: "AA==" }) })
  });
  assert.throws(() => make({ fingerprint: `SHA256:${"A".repeat(43)}`, public_key_pem: pem }).publicKey(), /fingerprint/);
  assert.throws(() => make({ fingerprint: `SHA256:${crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`, public_key_pem: pem }).sign({ bytes: Buffer.from("proof") }), /signature/);
});

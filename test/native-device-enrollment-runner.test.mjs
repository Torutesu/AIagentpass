import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createNativeDeviceEnrollmentRunner } from "../lib/native-device-enrollment-runner.mjs";

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function fakeFs(owner) {
  return { lstatSync(target) {
    const leaf = target.endsWith("agentpass-native-service");
    return { uid: owner, mode: leaf ? 0o100755 : 0o040755, nlink: 1, isFile: () => leaf, isDirectory: () => !leaf, isSymbolicLink: () => false };
  } };
}

test("validates the native P-256 identity and returns raw signatures", () => {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const calls = [];
  const runner = createNativeDeviceEnrollmentRunner({
    servicePath: "/test/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service",
    configPath: "/test/native-service.json",
    applicationRoot: "/test/AgentPass.app",
    expectedOwner: process.getuid(),
    fs: fakeFs(process.getuid()),
    run: (_service, command, config, input) => {
      calls.push({ command, input });
      assert.equal(config, "/test/native-service.json");
      const value = command === "key"
        ? { fingerprint, public_key_pem: pem }
        : { signature_base64: crypto.sign("sha256", input, { key: pair.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64") };
      return { status: 0, stdout: canonical(value) };
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
    servicePath: "/test/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app/Contents/MacOS/agentpass-native-service",
    configPath: "/test/native-service.json",
    applicationRoot: "/test/AgentPass.app",
    expectedOwner: process.getuid(),
    fs: fakeFs(process.getuid()),
    run: (_service, command) => ({ status: 0, stdout: canonical(command === "key" ? payload : { signature_base64: "AA==" }) })
  });
  assert.throws(() => make({ fingerprint: `SHA256:${"A".repeat(43)}`, public_key_pem: pem }).publicKey(), /fingerprint/);
  assert.throws(() => make({ fingerprint: `SHA256:${crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`, public_key_pem: pem }).sign({ bytes: Buffer.from("proof") }), /signature/);
});

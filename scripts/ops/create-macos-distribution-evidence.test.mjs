import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const opsDir = dirname(fileURLToPath(import.meta.url));
const producer = join(opsDir, "create-macos-distribution-evidence.mjs");
const verifier = join(opsDir, "verify-macos-release-evidence.mjs");
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture() {
  const base = await mkdtemp(join("/tmp", "agentpass-macos-distribution-producer-"));
  const artifactRoot = join(base, "artifact");
  const inputs = join(base, "inputs");
  const evidenceRoot = join(base, "evidence");
  await Promise.all([mkdir(artifactRoot), mkdir(inputs), mkdir(evidenceRoot)]);

  const artifactPath = join(artifactRoot, "AgentPass.pkg");
  const artifactBytes = Buffer.from("candidate package bytes\n");
  await writeFile(artifactPath, artifactBytes, { mode: 0o600 });
  const artifact = { name: "AgentPass.pkg", bytes: artifactBytes.length, sha256: sha256(artifactBytes) };

  const inventoryPath = join(inputs, "inventory.json");
  const notaryPath = join(inputs, "notary.json");
  const staplePath = join(inputs, "staple.json");
  const gatekeeperPath = join(inputs, "gatekeeper.json");
  const identityPath = join(inputs, "identity.json");
  const verificationPath = join(inputs, "verification.json");
  await Promise.all([
    writeFile(inventoryPath, canonical({
      schema_version: 1,
      kind: "agentpass.macos-artifact-inventory",
      artifact,
      root_entries: [{ path: artifact.name, bytes: artifact.bytes, sha256: artifact.sha256 }]
    }), { mode: 0o600 }),
    writeFile(notaryPath, canonical({ status: "Accepted", id: "01234567-89ab-4def-8123-456789abcdef" }), { mode: 0o600 }),
    writeFile(staplePath, canonical({ status: "validated", artifact_sha256: artifact.sha256 }), { mode: 0o600 }),
    writeFile(gatekeeperPath, canonical({ assessment: "accepted", artifact_sha256: artifact.sha256 }), { mode: 0o600 }),
    writeFile(identityPath, canonical({
      format: "Developer ID Installer",
      identity: "Developer ID Installer: AgentPass Release (TEAM123456)",
      team_id: "TEAM123456",
      verified: true
    }), { mode: 0o600 }),
    writeFile(verificationPath, canonical({
      schema_version: 1,
      kind: "agentpass.macos-distribution-verification-v1",
      status: "verified",
      artifact_sha256: artifact.sha256,
      signature_verified: true,
      notarization_verified: true,
      staple_verified: true,
      gatekeeper_verified: true
    }), { mode: 0o600 })
  ]);

  return {
    base,
    artifactRoot,
    artifactPath,
    inventoryPath,
    notaryPath,
    staplePath,
    gatekeeperPath,
    identityPath,
    verificationPath,
    evidenceRoot,
    outputPath: join(evidenceRoot, "distribution-evidence.json")
  };
}

function producerArgs(value) {
  return [
    producer,
    value.artifactPath,
    value.inventoryPath,
    value.evidenceRoot,
    value.notaryPath,
    value.staplePath,
    value.gatekeeperPath,
    value.identityPath,
    value.verificationPath,
    value.outputPath
  ];
}

function verifierArgs(value) {
  return [verifier, value.outputPath, value.inventoryPath, value.artifactRoot, value.evidenceRoot, value.verificationPath];
}

function run(args) {
  return execFileSync(process.execPath, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function rejectsWith(args, message) {
  assert.throws(
    () => run(args),
    (error) => {
      assert.notEqual(error.status, 0);
      assert.match(`${error.stdout ?? ""}\n${error.stderr ?? ""}`, message);
      return true;
    }
  );
}

async function withFixture(callback) {
  const value = await fixture();
  try {
    return await callback(value);
  } finally {
    await rm(value.base, { recursive: true, force: true });
  }
}

test("producer output is accepted by the independent macOS release verifier", async () => {
  await withFixture(async (value) => {
    const produced = JSON.parse(run(producerArgs(value)));
    assert.equal(produced.status, "written");
    assert.equal(produced.evidence, value.outputPath);

    const verified = JSON.parse(run(verifierArgs(value)));
    assert.equal(verified.status, "verified");
    assert.equal(verified.artifact_sha256, produced.artifact_sha256);
    assert.equal(verified.signature_verified, true);
    assert.equal(verified.notarization_verified, true);
    assert.equal(verified.staple_verified, true);
    assert.equal(verified.gatekeeper_verified, true);
  });
});

test("independent verification rejects a tampered artifact", async () => {
  await withFixture(async (value) => {
    run(producerArgs(value));
    await writeFile(value.artifactPath, "tampered package bytes\n");

    rejectsWith(verifierArgs(value), /candidate artifact digest mismatch/u);
  });
});

test("independent verification rejects tampered staple evidence", async () => {
  await withFixture(async (value) => {
    run(producerArgs(value));
    await writeFile(join(value.evidenceRoot, "staple.json"), canonical({
      status: "validated",
      artifact_sha256: "0".repeat(64)
    }));

    rejectsWith(verifierArgs(value), /staple result is absent or mismatched/u);
  });
});

test("producer refuses to overwrite an existing distribution evidence output", async () => {
  await withFixture(async (value) => {
    const sentinel = "existing evidence must remain unchanged\n";
    await writeFile(value.outputPath, sentinel, { mode: 0o600 });

    rejectsWith(producerArgs(value), /distribution evidence already exists/u);
    assert.equal(await readFile(value.outputPath, "utf8"), sentinel);
  });
});

test("producer fails closed when notarization or Developer ID identity is incomplete", async () => {
  await withFixture(async (value) => {
    await writeFile(value.notaryPath, canonical({ status: "Accepted", id: "01234567-89ab-4def-8123-456789abcdef", unexpected: true }));
    rejectsWith(producerArgs(value), /notary input schema is invalid/u);
  });

  await withFixture(async (value) => {
    await writeFile(value.identityPath, canonical({
      format: "Developer ID Installer",
      identity: "Developer ID Installer:  (TEAM123456)",
      team_id: "TEAM123456",
      verified: true
    }));
    rejectsWith(producerArgs(value), /signature identity is not verified/u);
  });

  await withFixture(async (value) => {
    await writeFile(value.identityPath, canonical({
      format: "Developer ID Installer",
      identity: "Developer ID Installer: AgentPass Release (OTHER12345)",
      team_id: "TEAM123456",
      verified: true
    }));
    rejectsWith(producerArgs(value), /signature identity is not verified/u);
  });
});

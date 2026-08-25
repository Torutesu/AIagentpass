import assert from "node:assert/strict";
import test from "node:test";
import {
  buildNegativeProbeManifest,
  canonicalNegativeProbeManifest,
  createNegativeProbeManifest,
  parseNegativeProbeManifest,
  verifyNegativeProbeIdentity,
  verifyNegativeProbeManifest
} from "../native/macos/Qualification/negative-probe-manifest.mjs";

const release = {
  sourceCommit: "a".repeat(40),
  artifactSha256: "b".repeat(64),
  releaseManifestSha256: "c".repeat(64),
  teamId: "ABCDE12345",
  wrongTeamId: "ZYXWV98765"
};

const makeManifest = () => createNegativeProbeManifest(release);

test("builds the four exact declarative probe roles and binds their identity expectations", () => {
  const manifest = buildNegativeProbeManifest(release);
  assert.deepEqual(manifest.probes.map((probe) => probe.role), ["approved", "missing-entitlement", "wrong-team", "ad-hoc"]);
  assert.equal(manifest.service.bundle_id, "dev.agentpass.native-service");
  assert.equal(manifest.client.bundle_id, "dev.agentpass.native-client");
  assert.equal(manifest.probes[0].team_id_expectation.value, release.teamId);
  assert.deepEqual(manifest.probes[1].entitlement_expectation.values, {});
  assert.equal(manifest.probes[2].team_id_expectation.value, release.wrongTeamId);
  assert.equal(manifest.probes[3].team_id_expectation.mode, "absent");
  assert.equal(manifest.probes[3].designated_requirement_expectation.mode, "not-release");
  assert.equal(manifest.probes[0].authorization_expectation, "allowlisted-methods-only");
  assert.equal(manifest.probes[1].authorization_expectation, "deny-before-signing");
});

test("canonical serialization is strict and release verification returns only bounded metadata", () => {
  const manifest = makeManifest();
  const bytes = canonicalNegativeProbeManifest(manifest);
  assert.equal(bytes.toString("utf8").endsWith("\n"), true);
  assert.deepEqual(parseNegativeProbeManifest(bytes), manifest);
  const result = verifyNegativeProbeManifest(bytes, {
    artifact_sha256: release.artifactSha256,
    release_manifest_sha256: release.releaseManifestSha256,
    source_commit: release.sourceCommit,
    team_id: release.teamId
  });
  assert.match(result.manifest_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(result.roles, ["approved", "missing-entitlement", "wrong-team", "ad-hoc"]);
  assert.equal(Object.hasOwn(result, "xpc_denied"), false);
});

test("rejects unknown and missing fields at every strict contract boundary", () => {
  const manifest = makeManifest();
  assert.throws(() => verifyNegativeProbeManifest({ ...manifest, unexpected: true }), /missing or unknown fields/);
  const missingRelease = structuredClone(manifest);
  delete missingRelease.release.team_id;
  assert.throws(() => verifyNegativeProbeManifest(missingRelease), /missing or unknown fields/);
  const nestedUnknown = structuredClone(manifest);
  nestedUnknown.probes[0].entitlement_expectation.unexpected = true;
  assert.throws(() => verifyNegativeProbeManifest(nestedUnknown), /missing or unknown fields/);
  const invalidBytes = Buffer.from(JSON.stringify(manifest));
  assert.throws(() => parseNegativeProbeManifest(invalidBytes), /canonical JSON/);
});

test("rejects duplicate roles, role order changes, and fixed-identity substitutions", () => {
  const duplicate = structuredClone(makeManifest());
  duplicate.probes[1].role = "approved";
  assert.throws(() => verifyNegativeProbeManifest(duplicate), /unique|complete/);

  const reordered = structuredClone(makeManifest());
  [reordered.probes[0], reordered.probes[1]] = [reordered.probes[1], reordered.probes[0]];
  assert.throws(() => verifyNegativeProbeManifest(reordered), /canonical order/);

  for (const mutate of [
    (value) => { value.probes[0].relative_path = "probes/substituted.app"; },
    (value) => { value.probes[0].bundle_id = "dev.agentpass.native-client-copy"; },
    (value) => { value.probes[0].designated_requirement_expectation.value = "anchor apple generic"; },
    (value) => { value.client.required_entitlements["keychain-access-groups"][0] = "SUBSTITUTED.dev.agentpass.approval-keys"; },
    (value) => { value.probes[0].entitlement_expectation.values["keychain-access-groups"] = ["SUBSTITUTED.dev.agentpass.approval-keys"]; }
  ]) {
    const substituted = structuredClone(makeManifest());
    mutate(substituted);
    assert.throws(() => verifyNegativeProbeManifest(substituted), /substitution|entitlement/);
  }
});

test("rejects release mismatches and cannot turn the wrong team into the release team", () => {
  const manifest = makeManifest();
  const releaseBinding = {
    source_commit: release.sourceCommit,
    artifact_sha256: release.artifactSha256,
    release_manifest_sha256: release.releaseManifestSha256,
    team_id: release.teamId
  };
  for (const key of ["source_commit", "artifact_sha256", "release_manifest_sha256", "team_id"]) {
    const mismatched = { ...releaseBinding, [key]: key === "team_id" ? "AAAAA11111" : "d".repeat(key === "source_commit" ? 40 : 64) };
    assert.throws(() => verifyNegativeProbeManifest(manifest, mismatched), new RegExp(`release mismatch: ${key}`));
  }
  const sameTeam = { ...release, wrongTeamId: release.teamId };
  assert.throws(() => createNegativeProbeManifest(sameTeam), /wrongTeamId must differ/);
  const changedWrongTeam = structuredClone(manifest);
  changedWrongTeam.release.wrong_team_id = release.teamId;
  assert.throws(() => verifyNegativeProbeManifest(changedWrongTeam), /wrong_team_id must differ/);
});

test("identity verifier checks only normalized identity facts and exposes no physical denial claim", () => {
  const manifest = makeManifest();
  const approved = manifest.probes[0];
  const result = verifyNegativeProbeIdentity(manifest, "approved", {
    bundle_id: approved.bundle_id,
    signature_kind: approved.signature_kind,
    team_id: approved.team_id_expectation.value,
    designated_requirement: approved.designated_requirement_expectation.value,
    entitlements: approved.entitlement_expectation.values
  });
  assert.equal(result.identity_verified, true);
  assert.equal(result.authorization_expectation, "allowlisted-methods-only");
  assert.equal(Object.hasOwn(result, "xpc_denied"), false);

  const adHoc = manifest.probes[3];
  assert.equal(verifyNegativeProbeIdentity(manifest, "ad-hoc", {
    bundle_id: adHoc.bundle_id,
    signature_kind: adHoc.signature_kind,
    team_id: null,
    designated_requirement: `identifier "${adHoc.bundle_id}" and cdhash H"${"1".repeat(40)}"`,
    entitlements: {}
  }).identity_verified, true);
  assert.throws(() => verifyNegativeProbeIdentity(manifest, "ad-hoc", {
    bundle_id: adHoc.bundle_id,
    signature_kind: adHoc.signature_kind,
    team_id: null,
    designated_requirement: manifest.client.designated_requirement,
    entitlements: {}
  }), /release designated requirement/);

  const wrongTeam = manifest.probes[2];
  assert.throws(() => verifyNegativeProbeIdentity(manifest, "wrong-team", {
    bundle_id: wrongTeam.bundle_id,
    signature_kind: wrongTeam.signature_kind,
    team_id: manifest.release.team_id,
    designated_requirement: wrongTeam.designated_requirement_expectation.value,
    entitlements: wrongTeam.entitlement_expectation.values
  }), /Team ID mismatch/);
});

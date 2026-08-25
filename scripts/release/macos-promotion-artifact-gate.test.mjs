import assert from "node:assert/strict";
import test from "node:test";
import { validateArtifactObservation } from "./macos-promotion-artifact-gate.mjs";

const team = "ABCDE12345";
const base = {
  artifact_sha256: "a".repeat(64),
  kind: "installer",
  name: "AgentPass-macos-universal.pkg",
  signature: { authority: "Developer ID Installer", status: "valid", team_id: team, timestamp: true },
  notarization: { status: "accepted" },
  staple: { status: "valid" },
  gatekeeper: { assessment: "accepted", source: "Notarized Developer ID", type: "install" }
};

test("accepts only a digest-bound, Developer ID, notarized, stapled, Gatekeeper-trusted installer", () => {
  assert.equal(validateArtifactObservation(base, team).artifact_sha256, base.artifact_sha256);
});

for (const [label, mutate, expected] of [
  ["unsigned artifact", (value) => { value.signature.status = "invalid"; }, /not validly signed/u],
  ["wrong Developer ID team", (value) => { value.signature.team_id = "ZZZZZ99999"; }, /wrong signing Team ID/u],
  ["unstapled artifact", (value) => { value.staple.status = "missing"; }, /not stapled/u],
  ["untrusted Gatekeeper source", (value) => { value.gatekeeper.source = "Developer ID"; }, /not trusted by Gatekeeper/u],
  ["missing digest", (value) => { delete value.artifact_sha256; }, /artifact observation has unknown or missing fields/u]
]) {
  test(`rejects ${label}`, () => {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => validateArtifactObservation(candidate, team), expected);
  });
}

test("requires the correct Gatekeeper assessment type for an application", () => {
  const candidate = structuredClone(base);
  candidate.kind = "application";
  candidate.name = "AgentPass.app";
  candidate.signature.authority = "Developer ID Application";
  candidate.gatekeeper.type = "install";
  assert.throws(() => validateArtifactObservation(candidate, team), /not trusted by Gatekeeper/u);
});

test("accepts an independently verified application observation with an execute assessment", () => {
  const candidate = structuredClone(base);
  candidate.kind = "application";
  candidate.name = "AgentPass.app";
  candidate.signature.authority = "Developer ID Application";
  candidate.gatekeeper.type = "execute";
  assert.equal(validateArtifactObservation(candidate, team).kind, "application");
});

for (const [label, mutate, expected] of [
  ["application without a secure timestamp", (value) => { value.kind = "application"; value.name = "AgentPass.app"; value.signature.authority = "Developer ID Application"; value.signature.timestamp = false; value.gatekeeper.type = "execute"; }, /secure signing timestamp/u],
  ["installer with an affirmative-invalid timestamp", (value) => { value.signature.timestamp = false; }, /invalid signing timestamp state/u]
]) {
  test(`rejects ${label}`, () => {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => validateArtifactObservation(candidate, team), expected);
  });
}

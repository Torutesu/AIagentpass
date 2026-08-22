#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const TEAM_ID = /^[A-Z0-9]{10}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export class MacosPromotionArtifactError extends Error {
  constructor(message) {
    super(message);
    this.name = "MacosPromotionArtifactError";
  }
}

function fail(message) {
  throw new MacosPromotionArtifactError(message);
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has unknown or missing fields`);
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} is required`);
  return value;
}

/**
 * Validate the only observation shape accepted for promotion. This is kept
 * separate from command execution so the contract can be tested off macOS.
 * Every state is explicit: a missing or affirmative-looking alternative is
 * never treated as success.
 */
export function validateArtifactObservation(observation, expectedTeamId) {
  if (!TEAM_ID.test(expectedTeamId ?? "")) fail("expected Team ID is invalid");
  exactKeys(observation, ["artifact_sha256", "kind", "name", "signature", "notarization", "staple", "gatekeeper"], "artifact observation");
  if (!SHA256.test(observation.artifact_sha256)) fail("artifact digest is invalid");
  const kind = requireString(observation.kind, "artifact kind");
  if (!new Set(["application", "installer"]).has(kind)) fail("artifact kind is invalid");
  requireString(observation.name, "artifact name");

  exactKeys(observation.signature, ["authority", "status", "team_id", "timestamp"], "signature observation");
  if (observation.signature.status !== "valid") fail(`${observation.name} is not validly signed`);
  const expectedAuthority = kind === "application" ? "Developer ID Application" : "Developer ID Installer";
  if (observation.signature.authority !== expectedAuthority) fail(`${observation.name} does not have a ${expectedAuthority} signature`);
  if (observation.signature.team_id !== expectedTeamId) fail(`${observation.name} has the wrong signing Team ID`);
  if (kind === "application" && observation.signature.timestamp !== true) fail(`${observation.name} lacks a secure signing timestamp`);
  if (kind === "installer" && observation.signature.timestamp !== null && observation.signature.timestamp !== true) fail(`${observation.name} has an invalid signing timestamp state`);

  exactKeys(observation.notarization, ["status"], "notarization observation");
  if (observation.notarization.status !== "accepted") fail(`${observation.name} is not notarization-accepted`);
  exactKeys(observation.staple, ["status"], "staple observation");
  if (observation.staple.status !== "valid") fail(`${observation.name} is not stapled`);
  exactKeys(observation.gatekeeper, ["assessment", "source", "type"], "Gatekeeper observation");
  const expectedType = kind === "application" ? "execute" : "install";
  if (observation.gatekeeper.type !== expectedType || observation.gatekeeper.assessment !== "accepted" || observation.gatekeeper.source !== "Notarized Developer ID") {
    fail(`${observation.name} is not trusted by Gatekeeper as a notarized Developer ID artifact`);
  }
  return Object.freeze(observation);
}

function regularArtifact(file) {
  const resolved = path.resolve(file);
  if (!path.isAbsolute(file)) fail("artifact paths must be absolute");
  const stat = fs.lstatSync(resolved);
  if (stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || (!stat.isFile() && !(stat.isDirectory() && resolved.endsWith(".app")))) fail(`unsafe artifact input: ${file}`);
  if (stat.isDirectory()) {
    const visit = (directory) => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const child = path.join(directory, entry.name);
        const childStat = fs.lstatSync(child);
        if (childStat.isSymbolicLink() || (childStat.mode & 0o022) !== 0 || (!childStat.isDirectory() && !childStat.isFile())) fail(`unsafe artifact bundle entry: ${child}`);
        if (childStat.isDirectory()) visit(child);
      }
    };
    visit(resolved);
  } else if (stat.nlink !== 1) fail(`unsafe artifact input: ${file}`);
  return resolved;
}

function run(command, args, label) {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.error || result.status !== 0) fail(`${label} failed: ${output.trim() || result.error?.message || `exit ${result.status}`}`);
  return output;
}

function digest(file) {
  const hash = crypto.createHash("sha256");
  const stat = fs.lstatSync(file);
  if (stat.isFile()) hash.update(fs.readFileSync(file));
  else {
    const visit = (directory) => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
        const child = path.join(directory, entry.name);
        hash.update(path.relative(file, child));
        const childStat = fs.lstatSync(child);
        if (childStat.isDirectory()) visit(child);
        else hash.update(fs.readFileSync(child));
      }
    };
    visit(file);
  }
  return hash.digest("hex");
}

function observe(file, expectedTeamId) {
  const name = path.basename(file);
  const isPackage = file.endsWith(".pkg");
  const isApplication = file.endsWith(".app");
  if (!isPackage && !isApplication) fail(`${name} must be a .pkg or .app artifact`);
  const kind = isApplication ? "application" : "installer";
  const signatureOutput = isPackage
    ? run("/usr/sbin/pkgutil", ["--check-signature", file], `${name} package signature check`)
    : run("/usr/bin/codesign", ["--verify", "--strict", "--verbose=4", file], `${name} code signature check`);
  const identityOutput = isPackage ? signatureOutput : run("/usr/bin/codesign", ["-d", "--verbose=4", file], `${name} signing identity check`);
  const authority = isPackage ? "Developer ID Installer" : "Developer ID Application";
  const authorityPattern = isPackage ? `(?:^|\\n)${authority}: .*\\(${expectedTeamId}\\)` : `(?:^|\\n)Authority=${authority}: .*\\(${expectedTeamId}\\)`;
  if (!new RegExp(authorityPattern, "u").test(identityOutput)) fail(`${name} is not signed by the expected ${authority}`);
  if (isPackage && !/Status: signed by a certificate trusted by Mac OS X/u.test(signatureOutput)) fail(`${name} package signature is not trusted by macOS`);
  if (!isPackage && !new RegExp(`(?:^|\\n)TeamIdentifier=${expectedTeamId}(?:\\n|$)`, "u").test(identityOutput)) fail(`${name} code signature Team ID is not trusted`);
  if (!/Timestamp=/u.test(identityOutput) && !isPackage) fail(`${name} lacks a secure signing timestamp`);
  const staplerOutput = run("/usr/bin/xcrun", ["stapler", "validate", file], `${name} staple validation`);
  if (!/The validate action worked!/u.test(staplerOutput)) fail(`${name} staple validation was not affirmative`);
  const gatekeeperOutput = run("/usr/sbin/spctl", ["--assess", "--type", isApplication ? "execute" : "install", "--verbose=4", file], `${name} Gatekeeper assessment`);
  if (!/source=Notarized Developer ID/u.test(gatekeeperOutput)) fail(`${name} Gatekeeper did not report Notarized Developer ID`);
  return validateArtifactObservation({
    artifact_sha256: digest(file),
    kind,
    name,
    signature: { authority, status: "valid", team_id: expectedTeamId, timestamp: isApplication ? true : null },
    notarization: { status: "accepted" },
    staple: { status: "valid" },
    gatekeeper: { assessment: "accepted", source: "Notarized Developer ID", type: isApplication ? "execute" : "install" }
  }, expectedTeamId);
}

export function verifyPromotionArtifacts(expectedTeamId, artifacts) {
  if (!TEAM_ID.test(expectedTeamId ?? "") || !Array.isArray(artifacts) || artifacts.length === 0) fail("expected Team ID and at least one artifact are required");
  const observations = artifacts.map((artifact) => observe(regularArtifact(artifact), expectedTeamId));
  return Object.freeze({ schema_version: 1, kind: "agentpass-macos-promotion-artifact-gate", team_id: expectedTeamId, artifacts: observations });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const [teamId, ...artifacts] = process.argv.slice(2);
    process.stdout.write(`${JSON.stringify(verifyPromotionArtifacts(teamId, artifacts))}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

import { createHash } from "node:crypto";

export const NEGATIVE_PROBE_MANIFEST_KIND = "agentpass.negative-identity-probe-manifest";
export const NEGATIVE_PROBE_MANIFEST_SCHEMA_VERSION = 1;

const TEAM_ID = /^[A-Z0-9]{10}$/;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const BUNDLE_ID = /^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$/;
const ROLE_PATH = /^probes\/[a-z0-9-]+\.app$/;
const ROLES = ["approved", "missing-entitlement", "wrong-team", "ad-hoc"];
const RELEASE_KEYS = ["artifact_sha256", "release_manifest_sha256", "source_commit", "team_id"];
const MANIFEST_KEYS = ["client", "kind", "probes", "release", "schema_version", "service"];
const SERVICE_BUNDLE_ID = "dev.agentpass.native-service";
const CLIENT_BUNDLE_ID = "dev.agentpass.native-client";
const CLIENT_ACCESS_GROUP_SUFFIX = ".dev.agentpass.approval-keys";

const ROLE_DEFINITIONS = Object.freeze({
  approved: Object.freeze({
    relative_path: "probes/approved-client.app",
    signature_kind: "developer-id",
    authorization_expectation: "allowlisted-methods-only"
  }),
  "missing-entitlement": Object.freeze({
    relative_path: "probes/missing-entitlement-client.app",
    signature_kind: "developer-id",
    authorization_expectation: "deny-before-signing"
  }),
  "wrong-team": Object.freeze({
    relative_path: "probes/wrong-team-client.app",
    signature_kind: "developer-id",
    authorization_expectation: "deny-before-signing"
  }),
  "ad-hoc": Object.freeze({
    relative_path: "probes/ad-hoc-client.app",
    signature_kind: "ad-hoc",
    authorization_expectation: "deny-before-signing"
  })
});

export const NEGATIVE_PROBE_ROLES = Object.freeze(ROLES.map((role) => role));

const exactKeys = (value, expected, label) => {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has missing or unknown fields`);
  }
};

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function requireBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} is invalid`);
  return value;
}

function canonicalString(value) {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalString(item)).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalString(value[key])}`).join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("manifest contains a non-JSON value");
  return encoded;
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalString(value)}\n`, "utf8");
}

function assertCanonicalJsonBytes(bytes) {
  if (!Buffer.isBuffer(bytes)) throw new Error("manifest bytes are required");
  if (bytes.length === 0 || bytes.length > 256 * 1024) throw new Error("manifest size is invalid");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("manifest is not valid UTF-8");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("manifest is not valid JSON");
  }
  validateNegativeProbeManifest(value);
  if (!bytes.equals(canonicalBytes(value))) throw new Error("manifest is not canonical JSON");
  return value;
}

function validateRelease(release, label = "release") {
  exactKeys(release, RELEASE_KEYS, label);
  requireString(release.source_commit, SOURCE_COMMIT, `${label} source_commit`);
  requireString(release.artifact_sha256, SHA256, `${label} artifact_sha256`);
  requireString(release.release_manifest_sha256, SHA256, `${label} release_manifest_sha256`);
  requireString(release.team_id, TEAM_ID, `${label} team_id`);
  if (release.source_commit === "0".repeat(40) || release.artifact_sha256 === "0".repeat(64) || release.release_manifest_sha256 === "0".repeat(64)) {
    throw new Error(`${label} contains a zero release binding`);
  }
  return release;
}

function designatedRequirement(bundleId, teamId) {
  return `anchor apple generic and identifier "${bundleId}" and certificate leaf[subject.OU] = "${teamId}"`;
}

function validateExpectation(value, role, release, client) {
  exactKeys(value, ["authorization_expectation", "bundle_id", "designated_requirement_expectation", "entitlement_expectation", "relative_path", "role", "signature_kind", "team_id_expectation"], `probe ${role}`);
  const definition = ROLE_DEFINITIONS[role];
  if (value.relative_path !== definition.relative_path || !ROLE_PATH.test(value.relative_path)) throw new Error(`probe ${role} path substitution`);
  if (value.bundle_id !== client.bundle_id || !BUNDLE_ID.test(value.bundle_id)) throw new Error(`probe ${role} bundle identifier substitution`);
  if (value.signature_kind !== definition.signature_kind) throw new Error(`probe ${role} signature kind mismatch`);
  if (value.authorization_expectation !== definition.authorization_expectation) throw new Error(`probe ${role} authorization expectation mismatch`);

  exactKeys(value.team_id_expectation, ["mode", "value"], `probe ${role} Team ID expectation`);
  if (role === "ad-hoc") {
    if (value.team_id_expectation.mode !== "absent" || value.team_id_expectation.value !== null) throw new Error("ad-hoc probe Team ID expectation must be absent");
  } else {
    if (value.team_id_expectation.mode !== "exact" || !TEAM_ID.test(value.team_id_expectation.value)) throw new Error(`probe ${role} Team ID expectation is invalid`);
    const expectedTeam = role === "wrong-team" ? release.wrong_team_id : release.team_id;
    if (value.team_id_expectation.value !== expectedTeam) throw new Error(`probe ${role} Team ID substitution`);
  }

  exactKeys(value.designated_requirement_expectation, ["mode", "value"], `probe ${role} designated requirement expectation`);
  if (role === "ad-hoc") {
    if (value.designated_requirement_expectation.mode !== "not-release" || value.designated_requirement_expectation.value !== null) throw new Error("ad-hoc probe designated requirement must not match the release requirement");
  } else {
    if (value.designated_requirement_expectation.mode !== "exact" || typeof value.designated_requirement_expectation.value !== "string") throw new Error(`probe ${role} designated requirement is invalid`);
    const expectedTeam = role === "wrong-team" ? release.wrong_team_id : release.team_id;
    if (value.designated_requirement_expectation.value !== designatedRequirement(client.bundle_id, expectedTeam)) throw new Error(`probe ${role} designated requirement substitution`);
  }

  exactKeys(value.entitlement_expectation, ["mode", "values"], `probe ${role} entitlement expectation`);
  if (value.entitlement_expectation.mode !== "exact" || !isRecord(value.entitlement_expectation.values)) throw new Error(`probe ${role} entitlement expectation is invalid`);
  const expectedEntitlements = role === "approved"
    ? client.required_entitlements
    : role === "wrong-team"
      ? { "keychain-access-groups": [`${release.wrong_team_id}${CLIENT_ACCESS_GROUP_SUFFIX}`] }
      : {};
  exactKeys(value.entitlement_expectation.values, Object.keys(expectedEntitlements), `probe ${role} entitlement values`);
  if (canonicalString(value.entitlement_expectation.values) !== canonicalString(expectedEntitlements)) throw new Error(`probe ${role} entitlement substitution`);
  return value;
}

function validateProbe(roleValue, release, client) {
  if (!isRecord(roleValue) || typeof roleValue.role !== "string" || !ROLES.includes(roleValue.role)) throw new Error("probe role is unknown");
  validateExpectation(roleValue, roleValue.role, release, client);
  return roleValue;
}

export function validateNegativeProbeManifest(value) {
  exactKeys(value, MANIFEST_KEYS, "negative probe manifest");
  if (value.schema_version !== NEGATIVE_PROBE_MANIFEST_SCHEMA_VERSION) throw new Error("negative probe manifest schema version is unsupported");
  if (value.kind !== NEGATIVE_PROBE_MANIFEST_KIND) throw new Error("negative probe manifest kind is invalid");

  exactKeys(value.release, [...RELEASE_KEYS, "wrong_team_id"], "manifest release");
  const { wrong_team_id: _wrongTeamId, ...releaseWithoutWrongTeam } = value.release;
  validateRelease(releaseWithoutWrongTeam, "manifest release");
  requireString(value.release.wrong_team_id, TEAM_ID, "manifest release wrong_team_id");
  if (value.release.wrong_team_id === value.release.team_id) throw new Error("wrong_team_id must differ from release team_id");

  exactKeys(value.service, ["bundle_id", "designated_requirement"], "manifest service");
  if (value.service.bundle_id !== SERVICE_BUNDLE_ID) throw new Error("service bundle identifier substitution");
  requireString(value.service.bundle_id, BUNDLE_ID, "service bundle_id");
  if (value.service.designated_requirement !== designatedRequirement(SERVICE_BUNDLE_ID, value.release.team_id)) throw new Error("service designated requirement substitution");

  exactKeys(value.client, ["bundle_id", "designated_requirement", "required_entitlements"], "manifest client");
  if (value.client.bundle_id !== CLIENT_BUNDLE_ID) throw new Error("client bundle identifier substitution");
  requireString(value.client.bundle_id, BUNDLE_ID, "client bundle_id");
  if (value.client.designated_requirement !== designatedRequirement(CLIENT_BUNDLE_ID, value.release.team_id)) throw new Error("client designated requirement substitution");
  exactKeys(value.client.required_entitlements, ["keychain-access-groups"], "client required entitlements");
  if (!Array.isArray(value.client.required_entitlements["keychain-access-groups"]) || value.client.required_entitlements["keychain-access-groups"].length !== 1 || value.client.required_entitlements["keychain-access-groups"][0] !== `${value.release.team_id}${CLIENT_ACCESS_GROUP_SUFFIX}`) {
    throw new Error("client required entitlement substitution");
  }

  if (!Array.isArray(value.probes) || value.probes.length !== ROLES.length) throw new Error("negative probe manifest must contain exactly four probes");
  const seen = new Set();
  value.probes.forEach((probe) => {
    if (!isRecord(probe)) throw new Error("probe must be an object");
    exactKeys(probe, ["authorization_expectation", "bundle_id", "designated_requirement_expectation", "entitlement_expectation", "relative_path", "role", "signature_kind", "team_id_expectation"], "probe");
    if (seen.has(probe.role)) throw new Error("negative probe roles must be unique");
    seen.add(probe.role);
    validateProbe(probe, value.release, value.client);
  });
  if (seen.size !== ROLES.length || ROLES.some((role, index) => value.probes[index].role !== role)) throw new Error("negative probe roles must be complete and in canonical order");
  return value;
}

export function createNegativeProbeManifest({ sourceCommit, artifactSha256, releaseManifestSha256, teamId, wrongTeamId } = {}) {
  const release = {
    source_commit: sourceCommit,
    artifact_sha256: artifactSha256,
    release_manifest_sha256: releaseManifestSha256,
    team_id: teamId,
    wrong_team_id: wrongTeamId
  };
  const { wrong_team_id: _wrongTeamId, ...releaseWithoutWrongTeam } = release;
  validateRelease(releaseWithoutWrongTeam, "release");
  requireString(wrongTeamId, TEAM_ID, "wrongTeamId");
  if (wrongTeamId === teamId) throw new Error("wrongTeamId must differ from teamId");

  const client = {
    bundle_id: CLIENT_BUNDLE_ID,
    designated_requirement: designatedRequirement(CLIENT_BUNDLE_ID, teamId),
    required_entitlements: { "keychain-access-groups": [`${teamId}${CLIENT_ACCESS_GROUP_SUFFIX}`] }
  };
  const signed = (role, expectedTeam, entitlements) => ({
    role,
    relative_path: ROLE_DEFINITIONS[role].relative_path,
    bundle_id: client.bundle_id,
    signature_kind: ROLE_DEFINITIONS[role].signature_kind,
    team_id_expectation: { mode: "exact", value: expectedTeam },
    designated_requirement_expectation: { mode: "exact", value: designatedRequirement(client.bundle_id, expectedTeam) },
    entitlement_expectation: { mode: "exact", values: entitlements },
    authorization_expectation: ROLE_DEFINITIONS[role].authorization_expectation
  });
  const absent = (role) => ({
    role,
    relative_path: ROLE_DEFINITIONS[role].relative_path,
    bundle_id: client.bundle_id,
    signature_kind: ROLE_DEFINITIONS[role].signature_kind,
    team_id_expectation: { mode: "absent", value: null },
    designated_requirement_expectation: { mode: "not-release", value: null },
    entitlement_expectation: { mode: "exact", values: {} },
    authorization_expectation: ROLE_DEFINITIONS[role].authorization_expectation
  });
  const manifest = {
    schema_version: NEGATIVE_PROBE_MANIFEST_SCHEMA_VERSION,
    kind: NEGATIVE_PROBE_MANIFEST_KIND,
    release,
    service: { bundle_id: SERVICE_BUNDLE_ID, designated_requirement: designatedRequirement(SERVICE_BUNDLE_ID, teamId) },
    client,
    probes: [
      signed("approved", teamId, client.required_entitlements),
      signed("missing-entitlement", teamId, {}),
      signed("wrong-team", wrongTeamId, { "keychain-access-groups": [`${wrongTeamId}${CLIENT_ACCESS_GROUP_SUFFIX}`] }),
      absent("ad-hoc")
    ]
  };
  validateNegativeProbeManifest(manifest);
  return manifest;
}

export function canonicalNegativeProbeManifest(value) {
  validateNegativeProbeManifest(value);
  return canonicalBytes(value);
}

export function parseNegativeProbeManifest(input) {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return assertCanonicalJsonBytes(bytes);
}

export function verifyNegativeProbeManifest(input, releaseBindings) {
  const manifest = Buffer.isBuffer(input) || typeof input === "string" ? parseNegativeProbeManifest(input) : validateNegativeProbeManifest(input);
  if (releaseBindings !== undefined) {
    exactKeys(releaseBindings, RELEASE_KEYS, "release binding");
    validateRelease(releaseBindings, "release binding");
    for (const key of RELEASE_KEYS) if (manifest.release[key] !== releaseBindings[key]) throw new Error(`negative probe manifest release mismatch: ${key}`);
  }
  const { wrong_team_id: _wrongTeamId, ...releaseWithoutWrongTeam } = manifest.release;
  return {
    manifest_sha256: createHash("sha256").update(canonicalBytes(manifest)).digest("hex"),
    release: releaseWithoutWrongTeam,
    roles: [...ROLES]
  };
}

export function verifyNegativeProbeIdentity(input, role, observation) {
  const manifest = Buffer.isBuffer(input) || typeof input === "string" ? parseNegativeProbeManifest(input) : validateNegativeProbeManifest(input);
  if (!ROLES.includes(role)) throw new Error("probe role is unknown");
  exactKeys(observation, ["bundle_id", "designated_requirement", "entitlements", "signature_kind", "team_id"], "probe identity observation");
  const probe = manifest.probes.find((item) => item.role === role);
  if (observation.bundle_id !== probe.bundle_id) throw new Error(`probe ${role} observed bundle identifier mismatch`);
  if (observation.signature_kind !== probe.signature_kind) throw new Error(`probe ${role} observed signature kind mismatch`);
  const team = probe.team_id_expectation;
  if (team.mode === "absent") {
    if (observation.team_id !== null) throw new Error(`probe ${role} unexpectedly has a Team ID`);
  } else if (observation.team_id !== team.value) {
    throw new Error(`probe ${role} observed Team ID mismatch`);
  }
  const requirement = probe.designated_requirement_expectation;
  if (requirement.mode === "not-release") {
    if (typeof observation.designated_requirement !== "string" || observation.designated_requirement.length === 0 || observation.designated_requirement === manifest.client.designated_requirement) throw new Error(`probe ${role} unexpectedly has the release designated requirement`);
  } else if (observation.designated_requirement !== requirement.value) {
    throw new Error(`probe ${role} observed designated requirement mismatch`);
  }
  if (!isRecord(observation.entitlements) || canonicalString(observation.entitlements) !== canonicalString(probe.entitlement_expectation.values)) throw new Error(`probe ${role} observed entitlement mismatch`);
  return {
    manifest_sha256: createHash("sha256").update(canonicalBytes(manifest)).digest("hex"),
    role,
    identity_verified: true,
    authorization_expectation: probe.authorization_expectation
  };
}

export const buildNegativeProbeManifest = createNegativeProbeManifest;
export const canonicalManifest = canonicalNegativeProbeManifest;
export const parseManifest = parseNegativeProbeManifest;
export const verifyManifest = verifyNegativeProbeManifest;

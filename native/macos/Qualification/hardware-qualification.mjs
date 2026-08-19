import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const REPORT_SCHEMA_VERSION = 2;
const RELEASE_MANIFEST_SCHEMA_VERSION = 4;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const DEVELOPER_ID_APPLICATION = /^Developer ID Application: [^\r\n()]+ \([A-Z0-9]{10}\)$/u;
const SAFE_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
const MAX_OUTPUT = 128 * 1024;
const MAX_INPUT = 16 * 1024 * 1024 * 1024;
const CHECKS = ["launchd_host_child_identity", "nsxpc", "crash_restart"];
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const sorted = (value) => Array.isArray(value) ? value.map(sorted) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])])) : value;
export const canonicalJSON = (value) => `${JSON.stringify(sorted(value))}\n`;
const releaseManifestJSON = (value) => `${JSON.stringify(value, null, 2)}\n`;
const fail = (message) => { throw new Error(message); };
const exact = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown fields`);
};
const absolute = (value, label) => {
  if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0") || path.resolve(value) !== value) fail(`${label} must be a normalized absolute path`);
  return value;
};
const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");

function snapshotFile(input, { maximum = MAX_INPUT, protectedOwner = false, label = "input" } = {}) {
  absolute(input, label);
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) fail("O_NOFOLLOW is unavailable");
  let descriptor;
  try { descriptor = fs.openSync(input, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { fail(`cannot open ${label}`); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${label} is not a bounded single-link regular file`);
    if ((before.mode & 0o022n) !== 0n) fail(`${label} is group/world writable`);
    if (protectedOwner && before.uid !== 0n) fail(`${label} is not root-owned`);
    const size = Number(before.size);
    const bytes = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const count = fs.readSync(descriptor, bytes, offset, size - offset, offset);
      if (count === 0) fail(`${label} changed while reading`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) fail(`${label} changed while reading`);
    return { path: input, bytes, size, sha256: sha256(bytes), mode: Number(before.mode & 0o777n), uid: Number(before.uid), identity: statIdentity(before) };
  } finally { fs.closeSync(descriptor); }
}

function parseJSON(snapshot, label) {
  try { return JSON.parse(snapshot.bytes.toString("utf8")); } catch { fail(`${label} is not valid UTF-8 JSON`); }
}

function verifyDetached(payload, signatureSnapshot, publicKeySnapshot, expectedFingerprint, label) {
  if (!FINGERPRINT.test(expectedFingerprint ?? "")) fail(`${label} key fingerprint is invalid`);
  let publicKey;
  try { publicKey = crypto.createPublicKey(publicKeySnapshot.bytes); } catch { fail(`${label} public key is invalid`); }
  if (publicKey.asymmetricKeyType !== "ed25519") fail(`${label} public key must be Ed25519`);
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  if (fingerprint !== expectedFingerprint) fail(`${label} public key fingerprint mismatch`);
  const encoded = signatureSnapshot.bytes.toString("ascii");
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) fail(`${label} signature encoding is invalid`);
  const signature = Buffer.from(encoded.trim(), "base64");
  if (signature.length !== 64 || !crypto.verify(null, payload, publicKey, signature)) fail(`${label} signature is invalid`);
  return { fingerprint, signature_sha256: signatureSnapshot.sha256 };
}

function validateTimestamp(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) fail(`${label} is invalid`);
}

function validateRunnerAttestation(value) {
  exact(value, ["schema_version", "kind", "runner_id", "architecture", "hardware_class", "model_identifier", "native_execution", "vm_detected", "rosetta_detected", "attested_at"], "runner attestation");
  if (value.schema_version !== 1 || value.kind !== "agentpass.macos.protected-runner-attestation" || typeof value.runner_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u.test(value.runner_id) || !["arm64", "x86_64"].includes(value.architecture) || !["apple_silicon", "intel"].includes(value.hardware_class) || typeof value.model_identifier !== "string" || !/^[A-Za-z0-9,._-]{3,80}$/u.test(value.model_identifier) || value.native_execution !== true || value.vm_detected !== false || value.rosetta_detected !== false) fail("runner attestation facts are invalid");
  validateTimestamp(value.attested_at, "runner attestation timestamp");
  if ((value.architecture === "arm64") !== (value.hardware_class === "apple_silicon")) fail("runner attestation architecture is inconsistent");
  return value;
}

const runnerAttestationPayload = (value) => Object.fromEntries(["schema_version", "kind", "runner_id", "architecture", "hardware_class", "model_identifier", "native_execution", "vm_detected", "rosetta_detected", "attested_at"].map((key) => [key, value[key]]));

function readRunnerAttestation(attestationPath, signaturePath, publicKeyPath, fingerprint) {
  const attestation = snapshotFile(attestationPath, { maximum: 64 * 1024, protectedOwner: true, label: "runner attestation" });
  const value = parseJSON(attestation, "runner attestation");
  if (canonicalJSON(value) !== attestation.bytes.toString("utf8")) fail("runner attestation is not canonical JSON");
  validateRunnerAttestation(value);
  const signature = snapshotFile(signaturePath, { maximum: 1024, protectedOwner: true, label: "runner attestation signature" });
  const publicKey = snapshotFile(publicKeyPath, { maximum: 16 * 1024, protectedOwner: true, label: "runner attestation public key" });
  const verified = verifyDetached(attestation.bytes, signature, publicKey, fingerprint, "runner attestation");
  return { path: attestation.path, bytes: attestation.size, sha256: attestation.sha256, signature_path: signature.path, signature_sha256: verified.signature_sha256, public_key_path: publicKey.path, public_key_fingerprint: verified.fingerprint, signed: true, owner_uid: attestation.uid, mode: attestation.mode, ...value };
}

function validateReleaseManifest(manifestSnapshot, signatureSnapshot, publicKeySnapshot, fingerprint, artifactPath, sourceCommit, sourceTree, expectedTeamId) {
  const manifest = parseJSON(manifestSnapshot, "release manifest");
  if (releaseManifestJSON(manifest) !== manifestSnapshot.bytes.toString("utf8")) fail("release manifest is not canonical JSON");
  const verified = verifyDetached(manifestSnapshot.bytes, signatureSnapshot, publicKeySnapshot, fingerprint, "release manifest");
  exact(manifest, ["schema_version", "product", "version", "source", "generated_at", "candidate_id", "artifacts", "external_qualification_controller", "evidence"], "release manifest");
  if (manifest.schema_version !== RELEASE_MANIFEST_SCHEMA_VERSION || manifest.product !== "AgentPass" || typeof manifest.version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(manifest.version)) fail("unsupported release manifest identity");
  exact(manifest.source, ["commit", "tree", "tag"], "release manifest source");
  if (!COMMIT.test(manifest.source.commit) || !COMMIT.test(manifest.source.tree) || manifest.source.commit !== sourceCommit || manifest.source.tree !== sourceTree) fail("release manifest source commit/tree mismatch");
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) fail("release manifest has no artifacts");
  const artifacts = manifest.artifacts.map((artifact) => {
    exact(artifact, ["name", "role", "media_type", "bytes", "sha256"], "release artifact");
    if (!SAFE_NAME.test(artifact.name) || !Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0 || !DIGEST.test(artifact.sha256)) fail("release artifact metadata is invalid");
    return artifact;
  });
  const products = artifacts.filter((item) => item.role === "product" && item.media_type === "application/vnd.apple.installer+xml");
  if (products.length !== 1 || products[0].name !== `AgentPass-v${manifest.version}-macos-universal.pkg`) fail("release manifest must contain exactly one canonical macOS product artifact");
  const product = products[0];
  if (path.basename(artifactPath) !== product.name || path.resolve(path.dirname(manifestSnapshot.path), product.name) !== path.resolve(artifactPath)) fail("artifact path is not the signed manifest product");
  const artifactSnapshot = snapshotFile(artifactPath, { maximum: MAX_INPUT, label: "product artifact" });
  if (artifactSnapshot.size !== product.bytes || artifactSnapshot.sha256 !== product.sha256) fail("product artifact does not match signed release manifest");
  if (manifest.candidate_id !== `release-pkg-sha256-v1-${product.sha256}`) fail("release manifest candidate is not bound to the product digest");
  const attestationArtifacts = artifacts.filter((item) => item.name === "release-attestation.json" && item.role === "auxiliary" && item.media_type === "application/json");
  if (attestationArtifacts.length !== 1) fail("signed release manifest is missing release-attestation.json");
  const releaseAttestation = snapshotFile(path.resolve(path.dirname(manifestSnapshot.path), "release-attestation.json"), { maximum: 2 * 1024 * 1024, label: "release attestation" });
  if (releaseAttestation.size !== attestationArtifacts[0].bytes || releaseAttestation.sha256 !== attestationArtifacts[0].sha256) fail("release attestation digest does not match signed manifest");
  const releaseAttestationValue = parseJSON(releaseAttestation, "release attestation");
  if (releaseManifestJSON(releaseAttestationValue) !== releaseAttestation.bytes.toString("utf8") || releaseAttestationValue.schema_version !== 1 || releaseAttestationValue.team_id !== expectedTeamId) fail("release attestation does not bind the expected Developer ID Team ID");
  return { path: manifestSnapshot.path, bytes: manifestSnapshot.size, sha256: manifestSnapshot.sha256, signature_path: signatureSnapshot.path, signature_sha256: verified.signature_sha256, public_key_path: publicKeySnapshot.path, public_key_fingerprint: verified.fingerprint, signed: true, source_commit: manifest.source.commit, source_tree: manifest.source.tree, artifact_name: product.name, artifact_bytes: product.bytes, artifact_sha256: product.sha256, release_attestation_sha256: releaseAttestation.sha256 };
}

function validateProbeExpectations(expectedSha256, expectedSigningIdentity, label) {
  const digest = expectedSha256 ?? null;
  const identity = expectedSigningIdentity ?? null;
  if (digest !== null && !DIGEST.test(digest)) fail(`${label} expected SHA-256 is invalid`);
  if (identity !== null && !DEVELOPER_ID_APPLICATION.test(identity)) fail(`${label} expected signing identity is invalid`);
  if (digest === null && identity === null) fail(`${label} has no protected digest or signing identity binding`);
  return { expected_sha256: digest, expected_signing_identity: identity };
}

function probeSnapshot(command, label) {
  const snapshot = snapshotFile(command, { maximum: 256 * 1024 * 1024, protectedOwner: true, label });
  if ((snapshot.mode & 0o222) !== 0) fail(`${label} is writable`);
  if ((snapshot.mode & 0o111) === 0) fail(`${label} is not executable`);
  return snapshot;
}

function signedProbeIdentity(command, expectedSigningIdentity, label) {
  const verification = spawnSync("/usr/bin/codesign", ["--verify", "--strict", "--verbose=2", command], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C" }, shell: false, timeout: 60_000, maxBuffer: MAX_OUTPUT });
  if (verification.error || verification.status !== 0 || verification.signal) fail(`${label} code signature verification failed`);
  const details = spawnSync("/usr/bin/codesign", ["-dv", "--verbose=4", command], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C" }, shell: false, timeout: 60_000, maxBuffer: MAX_OUTPUT });
  const text = `${details.stdout ?? ""}\n${details.stderr ?? ""}`;
  const match = text.match(/^Authority=(Developer ID Application: [^\r\n]+)$/mu);
  if (details.error || details.status !== 0 || details.signal || !match || !DEVELOPER_ID_APPLICATION.test(match[1]) || match[1] !== expectedSigningIdentity) fail(`${label} Developer ID signing identity mismatch`);
  return match[1];
}

function validateProbeSnapshot(snapshot, expected, label) {
  if (expected.expected_sha256 !== null && snapshot.sha256 !== expected.expected_sha256) fail(`${label} SHA-256 does not match the protected expectation`);
  return snapshot;
}

function commandResult(command, label, expectedSha256, expectedSigningIdentity) {
  const expected = validateProbeExpectations(expectedSha256, expectedSigningIdentity, label);
  const before = validateProbeSnapshot(probeSnapshot(command, label), expected, label);
  const beforeSigningIdentity = expected.expected_signing_identity === null ? null : signedProbeIdentity(command, expected.expected_signing_identity, label);
  const executionBinding = probeSnapshot(command, label);
  if (executionBinding.identity !== before.identity || executionBinding.sha256 !== before.sha256) fail(`${label} changed before execution`);
  const result = spawnSync(command, [], { cwd: "/", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C" }, encoding: "buffer", timeout: 60_000, maxBuffer: MAX_OUTPUT, shell: false });
  const after = validateProbeSnapshot(probeSnapshot(command, label), expected, label);
  if (after.identity !== before.identity || after.sha256 !== before.sha256) fail(`${label} changed after execution`);
  const afterSigningIdentity = expected.expected_signing_identity === null ? null : signedProbeIdentity(command, expected.expected_signing_identity, label);
  if (afterSigningIdentity !== beforeSigningIdentity) fail(`${label} signing identity changed after execution`);
  const stdout = Buffer.from(result.stdout ?? ""); const stderr = Buffer.from(result.stderr ?? "");
  if (result.error || result.status !== 0 || result.signal || stdout.length === 0) fail(`${label} did not pass`);
  let observed; try { observed = JSON.parse(stdout.toString("utf8")); } catch { fail(`${label} did not emit JSON`); }
  if (!observed || observed.status !== "passed" || typeof observed.observed !== "object" || Array.isArray(observed.observed)) fail(`${label} emitted a non-passing result`);
  return { status: "passed", exit_code: 0, executable_sha256: after.sha256, stdout_sha256: sha256(stdout), stderr_sha256: sha256(stderr), probe: { path: after.path, owner_uid: after.uid, mode: after.mode, sha256: after.sha256, expected_sha256: expected.expected_sha256, signing_identity: afterSigningIdentity, expected_signing_identity: expected.expected_signing_identity, verified_before_execution: true, verified_after_execution: true }, observed: observed.observed };
}

export function validateProbeTrustEvidence(value, label = "probe trust") {
  exact(value, ["path", "owner_uid", "mode", "sha256", "expected_sha256", "signing_identity", "expected_signing_identity", "verified_before_execution", "verified_after_execution"], label);
  if (!path.isAbsolute(value.path) || value.owner_uid !== 0 || !Number.isSafeInteger(value.mode) || (value.mode & 0o222) !== 0 || (value.mode & 0o111) === 0 || !DIGEST.test(value.sha256)) fail(`${label} protection is invalid`);
  const expected = validateProbeExpectations(value.expected_sha256, value.expected_signing_identity, label);
  if (expected.expected_sha256 !== null && value.sha256 !== expected.expected_sha256) fail(`${label} digest is not bound to the protected expectation`);
  if (value.signing_identity !== null && (typeof value.signing_identity !== "string" || !DEVELOPER_ID_APPLICATION.test(value.signing_identity))) fail(`${label} signing identity is invalid`);
  if (expected.expected_signing_identity !== null && value.signing_identity !== expected.expected_signing_identity) fail(`${label} signing identity is not bound to the protected expectation`);
  if (value.verified_before_execution !== true || value.verified_after_execution !== true) fail(`${label} was not verified before and after execution`);
  return value;
}

function validateObserved(name, observed) {
  const required = {
    launchd_host_child_identity: ["service_label", "host_pid", "child_pid", "host_identity", "child_identity", "identity_match"],
    nsxpc: ["mach_service", "connection_accepted", "authorized_client", "wrong_identity_denied"],
    crash_restart: ["initial_pid", "crash_signal", "restarted_pid", "restart_count", "state_recovered"]
  }[name];
  exact(observed, required, `${name} observed evidence`);
  if (name === "launchd_host_child_identity" && (typeof observed.service_label !== "string" || !Number.isSafeInteger(observed.host_pid) || !Number.isSafeInteger(observed.child_pid) || !observed.host_identity || !observed.child_identity || observed.identity_match !== true)) fail(`${name} observed evidence is incomplete`);
  if (name === "nsxpc" && (typeof observed.mach_service !== "string" || observed.connection_accepted !== true || observed.authorized_client !== true || observed.wrong_identity_denied !== true)) fail(`${name} observed evidence is incomplete`);
  if (name === "crash_restart" && (!Number.isSafeInteger(observed.initial_pid) || typeof observed.crash_signal !== "string" || !Number.isSafeInteger(observed.restarted_pid) || !Number.isSafeInteger(observed.restart_count) || observed.restart_count < 1 || observed.state_recovered !== true)) fail(`${name} observed evidence is incomplete`);
}

function sysctl(name, required = true) {
  const result = spawnSync("/usr/sbin/sysctl", ["-n", name], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C" }, shell: false });
  const value = result.status === 0 ? result.stdout.trim() : "";
  if (required && (!value || result.signal || result.error)) fail(`sysctl ${name} failed`);
  return value;
}

function machine() {
  if (process.platform !== "darwin") fail("hardware qualification requires macOS");
  const architecture = os.arch() === "arm64" ? "arm64" : os.arch() === "x64" ? "x86_64" : null;
  if (!architecture) fail("unsupported macOS architecture");
  const translated = sysctl("sysctl.proc_translated", false);
  if (translated && !["0", "1"].includes(translated)) fail("Rosetta detection returned an invalid value");
  if ((architecture === "arm64" && translated !== "0") || (architecture === "x86_64" && translated === "1")) fail("Rosetta or non-native execution detected");
  if (architecture === "x86_64" && !translated && sysctl("hw.optional.arm64") !== "0") fail("native x86_64 execution could not be established");
  const vm = sysctl("kern.hv_vmm_present");
  if (vm !== "0") fail("virtual machine or hypervisor execution detected");
  const model = sysctl("hw.model"); const version = sysctl("kern.osproductversion"); const build = sysctl("kern.osversion");
  return { architecture, hardware_class: architecture === "arm64" ? "apple_silicon" : "intel", model_identifier: model, os_version: version, os_build: build, native_execution: true, vm_detected: false, rosetta_detected: false };
}

function signedArtifact(artifactPath, expectedTeamId) {
  const snapshot = snapshotFile(artifactPath, { maximum: MAX_INPUT, label: "product artifact" });
  if (!artifactPath.endsWith(".pkg")) fail("qualified artifact must be a PKG");
  const result = spawnSync("/usr/sbin/pkgutil", ["--check-signature", artifactPath], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C" }, shell: false, timeout: 60_000, maxBuffer: MAX_OUTPUT });
  const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (result.error || result.status !== 0 || !/^Status: signed by a certificate trusted by Mac OS X$/mu.test(text)) fail("product package signature verification failed");
  const identity = text.match(/Developer ID Installer:\s*[^\r\n]+\(([A-Z0-9]{10})\)/u);
  if (!identity || identity[1] !== expectedTeamId) fail("product package Developer ID Team ID mismatch");
  return { path: snapshot.path, name: path.basename(snapshot.path), bytes: snapshot.size, sha256: snapshot.sha256, signed: true, signing_identity: identity[0].trim(), team_id: identity[1] };
}

function validateMachine(value) {
  exact(value, ["architecture", "hardware_class", "model_identifier", "os_version", "os_build", "native_execution", "vm_detected", "rosetta_detected"], "machine");
  if (!["arm64", "x86_64"].includes(value.architecture) || (value.architecture === "arm64" ? value.hardware_class !== "apple_silicon" : value.hardware_class !== "intel") || typeof value.model_identifier !== "string" || !/^[A-Za-z0-9,._-]{3,80}$/u.test(value.model_identifier) || typeof value.os_version !== "string" || !/^\d+\.\d+(?:\.\d+)?$/u.test(value.os_version) || typeof value.os_build !== "string" || !/^[A-Za-z0-9]{3,32}$/u.test(value.os_build) || value.native_execution !== true || value.vm_detected !== false || value.rosetta_detected !== false) fail("machine identity or native-execution evidence is invalid");
}

function validateReportArtifact(value) {
  exact(value, ["path", "name", "bytes", "sha256", "signed", "signing_identity", "team_id"], "artifact");
  if (!path.isAbsolute(value.path) || !SAFE_NAME.test(value.name) || !Number.isSafeInteger(value.bytes) || value.bytes <= 0 || !DIGEST.test(value.sha256) || value.signed !== true || typeof value.signing_identity !== "string" || !value.signing_identity.startsWith("Developer ID Installer:") || !TEAM_ID.test(value.team_id) || !value.signing_identity.endsWith(`(${value.team_id})`)) fail("artifact evidence is invalid");
}

export function validate(report) {
  exact(report, ["schema_version", "kind", "source_commit", "source_tree", "release_manifest", "artifact", "machine", "runner_attestation", "checks", "qualified"], "report");
  if (report.schema_version !== REPORT_SCHEMA_VERSION || report.kind !== "agentpass.macos.hardware-qualification" || !COMMIT.test(report.source_commit) || !COMMIT.test(report.source_tree) || report.qualified !== true) fail("report is not a qualified v2 report");
  exact(report.release_manifest, ["path", "bytes", "sha256", "signature_path", "signature_sha256", "public_key_path", "public_key_fingerprint", "signed", "source_commit", "source_tree", "artifact_name", "artifact_bytes", "artifact_sha256", "release_attestation_sha256"], "release manifest evidence");
  if (!path.isAbsolute(report.release_manifest.path) || !Number.isSafeInteger(report.release_manifest.bytes) || report.release_manifest.bytes <= 0 || !DIGEST.test(report.release_manifest.sha256) || !path.isAbsolute(report.release_manifest.signature_path) || !DIGEST.test(report.release_manifest.signature_sha256) || !path.isAbsolute(report.release_manifest.public_key_path) || !FINGERPRINT.test(report.release_manifest.public_key_fingerprint) || report.release_manifest.signed !== true || report.release_manifest.source_commit !== report.source_commit || report.release_manifest.source_tree !== report.source_tree || !SAFE_NAME.test(report.release_manifest.artifact_name) || !Number.isSafeInteger(report.release_manifest.artifact_bytes) || report.release_manifest.artifact_bytes <= 0 || report.release_manifest.artifact_sha256 !== report.artifact.sha256 || !DIGEST.test(report.release_manifest.release_attestation_sha256)) fail("release manifest evidence is invalid");
  validateReportArtifact(report.artifact);
  if (report.artifact.name !== report.release_manifest.artifact_name || report.artifact.bytes !== report.release_manifest.artifact_bytes || report.artifact.sha256 !== report.release_manifest.artifact_sha256) fail("artifact evidence is not bound to the signed release manifest");
  exact(report.runner_attestation, ["path", "bytes", "sha256", "signature_path", "signature_sha256", "public_key_path", "public_key_fingerprint", "signed", "owner_uid", "mode", "schema_version", "kind", "runner_id", "architecture", "hardware_class", "model_identifier", "native_execution", "vm_detected", "rosetta_detected", "attested_at"], "runner attestation evidence");
  if (!path.isAbsolute(report.runner_attestation.path) || !Number.isSafeInteger(report.runner_attestation.bytes) || report.runner_attestation.bytes <= 0 || !DIGEST.test(report.runner_attestation.sha256) || !path.isAbsolute(report.runner_attestation.signature_path) || !DIGEST.test(report.runner_attestation.signature_sha256) || !path.isAbsolute(report.runner_attestation.public_key_path) || !FINGERPRINT.test(report.runner_attestation.public_key_fingerprint) || report.runner_attestation.signed !== true || report.runner_attestation.owner_uid !== 0 || !Number.isSafeInteger(report.runner_attestation.mode) || (report.runner_attestation.mode & 0o022) !== 0) fail("runner attestation protection is invalid");
  validateRunnerAttestation(runnerAttestationPayload(report.runner_attestation));
  validateMachine(report.machine);
  if (report.runner_attestation.architecture !== report.machine.architecture || report.runner_attestation.hardware_class !== report.machine.hardware_class || report.runner_attestation.model_identifier !== report.machine.model_identifier || report.runner_attestation.native_execution !== report.machine.native_execution || report.runner_attestation.vm_detected !== report.machine.vm_detected || report.runner_attestation.rosetta_detected !== report.machine.rosetta_detected) fail("runner attestation does not bind machine evidence");
  exact(report.checks, CHECKS, "checks");
  for (const name of CHECKS) { const check = report.checks[name]; exact(check, ["status", "exit_code", "executable_sha256", "stdout_sha256", "stderr_sha256", "probe", "observed"], `${name} check`); if (check.status !== "passed" || check.exit_code !== 0 || !DIGEST.test(check.executable_sha256) || !DIGEST.test(check.stdout_sha256) || !DIGEST.test(check.stderr_sha256) || !check.observed || typeof check.observed !== "object" || Array.isArray(check.observed)) fail(`${name} check is not passing evidence`); validateProbeTrustEvidence(check.probe, `${name} probe`); if (check.executable_sha256 !== check.probe.sha256) fail(`${name} executable digest is not bound to probe trust evidence`); validateObserved(name, check.observed); }
  return report;
}

function compareEvidence(report, actual, label) {
  for (const key of Object.keys(actual)) if (report[key] !== actual[key]) fail(`${label} changed after qualification`);
}

function verifyProbeEvidence(value, label) {
  validateProbeTrustEvidence(value, label);
  const current = validateProbeSnapshot(probeSnapshot(value.path, label), { expected_sha256: value.expected_sha256, expected_signing_identity: value.expected_signing_identity }, label);
  if (current.uid !== value.owner_uid || current.mode !== value.mode || current.sha256 !== value.sha256) fail(`${label} changed after qualification`);
  const identity = value.expected_signing_identity === null ? null : signedProbeIdentity(value.path, value.expected_signing_identity, label);
  if (identity !== value.signing_identity) fail(`${label} signing identity changed after qualification`);
}

function verifyEvidence(report) {
  const manifest = snapshotFile(report.release_manifest.path, { maximum: 16 * 1024 * 1024, label: "release manifest" });
  if (manifest.size !== report.release_manifest.bytes || manifest.sha256 !== report.release_manifest.sha256) fail("release manifest digest does not match evidence");
  const signature = snapshotFile(report.release_manifest.signature_path, { maximum: 1024, label: "release manifest signature" });
  const publicKey = snapshotFile(report.release_manifest.public_key_path, { maximum: 16 * 1024, label: "release manifest public key" });
  const binding = validateReleaseManifest(manifest, signature, publicKey, report.release_manifest.public_key_fingerprint, report.artifact.path, report.source_commit, report.source_tree, report.artifact.team_id);
  compareEvidence(report.release_manifest, binding, "release manifest evidence");
  const artifact = signedArtifact(report.artifact.path, report.artifact.team_id);
  compareEvidence(report.artifact, artifact, "artifact evidence");
  const runner = readRunnerAttestation(report.runner_attestation.path, report.runner_attestation.signature_path, report.runner_attestation.public_key_path, report.runner_attestation.public_key_fingerprint);
  compareEvidence(report.runner_attestation, runner, "runner attestation evidence");
  for (const name of CHECKS) verifyProbeEvidence(report.checks[name].probe, `${name} probe`);
  return report;
}

export function qualify({ artifact, releaseManifest, releaseManifestSignature, releaseManifestPublicKey, releaseManifestFingerprint, sourceCommit, sourceTree, expectedTeamId, runnerAttestation, runnerAttestationSignature, runnerAttestationPublicKey, runnerAttestationFingerprint, expectedArchitecture, launchdProbe, launchdProbeSha256, launchdProbeSigningIdentity, nsxpcProbe, nsxpcProbeSha256, nsxpcProbeSigningIdentity, crashRestartProbe, crashRestartProbeSha256, crashRestartProbeSigningIdentity } = {}) {
  if (!COMMIT.test(sourceCommit ?? "") || !COMMIT.test(sourceTree ?? "")) fail("source commit and source tree must be full lowercase SHA-1 identities");
  if (!TEAM_ID.test(expectedTeamId ?? "")) fail("expected Developer ID Team ID is invalid");
  const manifest = snapshotFile(releaseManifest, { maximum: 16 * 1024 * 1024, label: "release manifest" });
  const signature = snapshotFile(releaseManifestSignature, { maximum: 1024, label: "release manifest signature" });
  const publicKey = snapshotFile(releaseManifestPublicKey, { maximum: 16 * 1024, label: "release manifest public key" });
  const manifestEvidence = validateReleaseManifest(manifest, signature, publicKey, releaseManifestFingerprint, artifact, sourceCommit, sourceTree, expectedTeamId);
  const artifactEvidence = signedArtifact(artifact, expectedTeamId);
  if (artifactEvidence.name !== manifestEvidence.artifact_name || artifactEvidence.bytes !== manifestEvidence.artifact_bytes || artifactEvidence.sha256 !== manifestEvidence.artifact_sha256) fail("signed product package changed after manifest verification");
  const runnerEvidence = readRunnerAttestation(runnerAttestation, runnerAttestationSignature, runnerAttestationPublicKey, runnerAttestationFingerprint);
  const machineEvidence = machine();
  if (expectedArchitecture !== null && machineEvidence.architecture !== expectedArchitecture) fail("runner architecture does not match the requested qualification lane");
  if (runnerEvidence.architecture !== machineEvidence.architecture || runnerEvidence.hardware_class !== machineEvidence.hardware_class || runnerEvidence.model_identifier !== machineEvidence.model_identifier || runnerEvidence.native_execution !== machineEvidence.native_execution || runnerEvidence.vm_detected !== machineEvidence.vm_detected || runnerEvidence.rosetta_detected !== machineEvidence.rosetta_detected) fail("protected runner attestation does not match live native machine evidence");
  const checks = { launchd_host_child_identity: commandResult(launchdProbe, "launchd host-child probe", launchdProbeSha256, launchdProbeSigningIdentity), nsxpc: commandResult(nsxpcProbe, "NSXPC probe", nsxpcProbeSha256, nsxpcProbeSigningIdentity), crash_restart: commandResult(crashRestartProbe, "crash/restart probe", crashRestartProbeSha256, crashRestartProbeSigningIdentity) };
  const report = { schema_version: REPORT_SCHEMA_VERSION, kind: "agentpass.macos.hardware-qualification", source_commit: sourceCommit, source_tree: sourceTree, release_manifest: manifestEvidence, artifact: artifactEvidence, machine: machineEvidence, runner_attestation: runnerEvidence, checks, qualified: true };
  validate(report);
  return report;
}

export function verifyFile(reportPath) {
  const snapshot = snapshotFile(reportPath, { maximum: 4 * 1024 * 1024, label: "qualification report" });
  const report = parseJSON(snapshot, "qualification report");
  if (canonicalJSON(report) !== snapshot.bytes.toString("utf8")) fail("report is not canonical JSON");
  validate(report);
  verifyEvidence(report);
  return report;
}

function args(values) {
  const out = {};
  for (let i = 0; i < values.length; i += 2) { if (!values[i]?.startsWith("--") || !values[i + 1] || out[values[i].slice(2)]) fail("invalid arguments"); out[values[i].slice(2)] = values[i + 1]; }
  return out;
}
const required = (value, name) => { if (!value) fail(`${name} is required`); return value; };

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const value = args(process.argv.slice(2));
    if (value.verify) {
      if (Object.keys(value).length !== 1) fail("--verify cannot be combined with qualification arguments");
      verifyFile(path.resolve(value.verify));
      process.stdout.write('{"ok":true,"status":"verified"}\n');
    } else {
      const output = absolute(required(value.output, "--output"), "output");
      const report = qualify({ artifact: absolute(required(value.artifact, "--artifact"), "artifact"), releaseManifest: absolute(required(value["release-manifest"], "--release-manifest"), "release manifest"), releaseManifestSignature: absolute(required(value["release-manifest-signature"], "--release-manifest-signature"), "release manifest signature"), releaseManifestPublicKey: absolute(required(value["release-manifest-public-key"], "--release-manifest-public-key"), "release manifest public key"), releaseManifestFingerprint: required(value["release-manifest-fingerprint"], "--release-manifest-fingerprint"), sourceCommit: required(value["source-commit"], "--source-commit"), sourceTree: required(value["source-tree"], "--source-tree"), expectedTeamId: required(value["expected-team-id"], "--expected-team-id"), runnerAttestation: absolute(required(value["runner-attestation"], "--runner-attestation"), "runner attestation"), runnerAttestationSignature: absolute(required(value["runner-attestation-signature"], "--runner-attestation-signature"), "runner attestation signature"), runnerAttestationPublicKey: absolute(required(value["runner-attestation-public-key"], "--runner-attestation-public-key"), "runner attestation public key"), runnerAttestationFingerprint: required(value["runner-attestation-fingerprint"], "--runner-attestation-fingerprint"), expectedArchitecture: required(value["expected-architecture"], "--expected-architecture"), launchdProbe: absolute(required(value["launchd-probe"], "--launchd-probe"), "launchd probe"), launchdProbeSha256: value["launchd-probe-sha256"] ?? null, launchdProbeSigningIdentity: value["launchd-probe-signing-identity"] ?? null, nsxpcProbe: absolute(required(value["nsxpc-probe"], "--nsxpc-probe"), "NSXPC probe"), nsxpcProbeSha256: value["nsxpc-probe-sha256"] ?? null, nsxpcProbeSigningIdentity: value["nsxpc-probe-signing-identity"] ?? null, crashRestartProbe: absolute(required(value["crash-restart-probe"], "--crash-restart-probe"), "crash/restart probe"), crashRestartProbeSha256: value["crash-restart-probe-sha256"] ?? null, crashRestartProbeSigningIdentity: value["crash-restart-probe-signing-identity"] ?? null });
      fs.writeFileSync(output, canonicalJSON(report), { mode: 0o600, flag: "wx" });
      process.stdout.write('{"ok":true,"qualified":true}\n');
    }
  } catch (error) { process.stderr.write(`macOS hardware qualification refused: ${error.message}\n`); process.exitCode = 1; }
}

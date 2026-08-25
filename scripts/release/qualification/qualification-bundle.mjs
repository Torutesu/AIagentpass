import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const QUALIFICATION_BUNDLE_SCHEMA_VERSION = 1;
export const COMMIT_SHA = /^[0-9a-f]{40}$/u;
export const RUN_ID = /^[1-9][0-9]{0,18}$/u;
export const SHA256 = /^[0-9a-f]{64}$/u;
export const DIGEST = /^sha256:[0-9a-f]{64}$/u;
export const ARTIFACT_ID = /^[1-9][0-9]{0,18}$/u;
export const RELEASE_TAG = /^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$/u;
export const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;

const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 1 * 1024 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 16 * 1024 * 1024 * 1024;
const API_ORIGIN = "https://api.github.com";
const RETAINED_LANES = Object.freeze([
  Object.freeze({ directory: "cloud-production-qualification", name: "cloud" }),
  Object.freeze({ directory: "macos-hardware-qualification-arm64", name: "macos-arm64" }),
  Object.freeze({ directory: "macos-hardware-qualification-x86_64", name: "macos-x86_64" })
]);

const fail = (message) => { throw new Error(message); };
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail(`${label} schema is not exact`);
};
const requireString = (value, pattern, label) => {
  if (typeof value !== "string" || !pattern.test(value)) fail(`${label} is invalid`);
  return value;
};
const requireRunId = (value, label) => requireString(String(value), RUN_ID, label);
const safeName = (value) => typeof value === "string" && SAFE_NAME.test(value) && value === path.basename(value);

function readRegular(file, maximum, { capture = true, privateKey = false } = {}) {
  const resolved = path.resolve(file);
  let descriptor;
  try { descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch { fail(`cannot open qualification bundle input: ${file}`); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum)) fail(`unsafe qualification bundle input: ${file}`);
    if (privateKey && ((before.mode & 0o077n) !== 0n || before.uid !== BigInt(process.getuid()))) fail(`qualification bundle private key is not owner-only: ${file}`);
    if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) fail(`qualification bundle input is too large: ${file}`);
    const size = Number(before.size);
    const hash = createHash("sha256");
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const wanted = Math.min(buffer.length, size - offset);
      const count = fs.readSync(descriptor, buffer, 0, wanted, offset);
      if (count !== wanted) fail(`qualification bundle input changed while reading: ${file}`);
      const chunk = Buffer.from(buffer.subarray(0, count));
      hash.update(chunk);
      if (chunks) chunks.push(chunk);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
    if (identity(before) !== identity(after)) fail(`qualification bundle input changed while reading: ${file}`);
    return Object.freeze({ path: resolved, name: path.basename(resolved), bytes: size, sha256: hash.digest("hex"), content: chunks ? Buffer.concat(chunks, size) : undefined });
  } finally {
    fs.closeSync(descriptor);
  }
}

function readCanonicalJson(file, label) {
  const snapshot = readRegular(file, MAX_JSON_BYTES, { capture: true });
  let value;
  try { value = JSON.parse(snapshot.content.toString("utf8")); }
  catch { fail(`${label} is not valid JSON`); }
  if (!Buffer.from(canonical(value), "utf8").equals(snapshot.content)) fail(`${label} is not canonical JSON`);
  return Object.freeze({ value, snapshot });
}

function sha256Digest(snapshot) {
  return `sha256:${snapshot.sha256}`;
}

function validateExpectedRunIds(options) {
  const names = ["release_run_id", "qualification_run_id", "cloud_qualification_run_id", "macos_qualification_run_id", "ci_run_id"];
  const values = Object.fromEntries(names.map((name) => [name, requireRunId(options[name], name)]));
  if (new Set(Object.values(values)).size !== names.length) fail("qualification bundle run IDs must be distinct");
  return values;
}

function validateManifestAndPackage({ manifestPath, packagePath, sourceSha, releaseTag }) {
  const manifestFile = readCanonicalJson(manifestPath, "release manifest");
  const manifest = manifestFile.value;
  if (manifest.schema_version !== 4 || manifest.product !== "AgentPass") fail("qualification bundle requires release manifest v4");
  if (!manifest.source || manifest.source.commit !== sourceSha || manifest.source.tag !== releaseTag || !COMMIT_SHA.test(manifest.source.tree || "")) fail("qualification bundle source is not bound through the release manifest and tag");
  const products = Array.isArray(manifest.artifacts) ? manifest.artifacts.filter((item) => item?.role === "product") : [];
  if (products.length !== 1 || !safeName(products[0].name) || !SHA256.test(products[0].sha256) || !Number.isSafeInteger(products[0].bytes) || products[0].bytes <= 0) fail("qualification bundle product manifest binding is invalid");
  const product = products[0];
  const packageFile = readRegular(packagePath, MAX_PACKAGE_BYTES, { capture: false });
  if (path.resolve(packagePath) !== path.resolve(path.dirname(manifestPath), product.name) || path.basename(packagePath) !== product.name) fail("qualification bundle package is not the signed manifest product");
  if (packageFile.bytes !== product.bytes || packageFile.sha256 !== product.sha256) fail("qualification bundle package digest differs from the signed manifest");
  return Object.freeze({
    manifest,
    manifestFile,
    packageFile,
    packageName: product.name,
    packageSha256: product.sha256
  });
}

function validateSummaryBinding({ summaryPath, dispatchBindingPath, runIds, candidateArtifactName }) {
  const summaryFile = readCanonicalJson(summaryPath, "qualification summary");
  const bindingFile = readCanonicalJson(dispatchBindingPath, "qualification dispatch binding");
  const binding = bindingFile.value;
  exactKeys(binding, ["candidate_artifact_name", "qualification_run_id", "qualification_summary_sha256", "release_run_id", "schema_version"], "qualification dispatch binding");
  if (binding.schema_version !== 1 || binding.release_run_id !== runIds.release_run_id || binding.qualification_run_id !== runIds.qualification_run_id || binding.candidate_artifact_name !== candidateArtifactName) fail("qualification dispatch binding does not select the requested release and qualification runs");
  if (!SHA256.test(binding.qualification_summary_sha256) || binding.qualification_summary_sha256 !== summaryFile.snapshot.sha256) fail("qualification dispatch binding summary digest mismatch");
  return Object.freeze({ summaryFile, bindingFile });
}

function validateRetainedLane({ root, lane, sourceSha, repository, expectedRunId }) {
  const directory = path.resolve(root, lane.directory);
  const metadataPath = path.join(directory, "artifact-metadata.json");
  const runPath = path.join(directory, "workflow-run.json");
  const jobsPath = path.join(directory, "workflow-jobs.json");
  const archivePath = path.join(directory, "artifact.zip");
  const metadataFile = readCanonicalJson(metadataPath, `${lane.name} artifact metadata`);
  const runFile = readCanonicalJson(runPath, `${lane.name} workflow run`);
  const jobsFile = readCanonicalJson(jobsPath, `${lane.name} workflow jobs`);
  const metadata = metadataFile.value;
  const run = runFile.value;
  const jobs = jobsFile.value;
  const archive = readRegular(archivePath, MAX_ARCHIVE_BYTES, { capture: false });
  requireString(metadata.name, SAFE_NAME, `${lane.name} artifact name`);
  requireString(metadata.digest, DIGEST, `${lane.name} artifact digest`);
  const expectedArtifactName = lane.directory === "cloud-production-qualification"
    ? `cloud-production-qualification-${sourceSha}`
    : `${lane.directory}-${sourceSha}`;
  if (metadata.name !== expectedArtifactName) fail(`${lane.name} retained artifact name is not source-bound`);
  if (!ARTIFACT_ID.test(String(metadata.id)) || metadata.outputName !== lane.directory || metadata.archive_download_url !== `${API_ORIGIN}/repos/${repository}/actions/artifacts/${metadata.id}/zip`) fail(`${lane.name} retained metadata is not canonical`);
  if (archive.sha256 !== metadata.digest.slice("sha256:".length)) fail(`${lane.name} retained archive digest mismatch`);
  if (String(run.id) !== String(expectedRunId) || run.repository?.full_name !== repository || run.head_repository?.full_name !== repository || run.head_sha !== sourceSha || run.status !== "completed" || run.conclusion !== "success") fail(`${lane.name} retained workflow run is not source-bound`);
  if (!jobs || !Array.isArray(jobs.jobs)) fail(`${lane.name} retained jobs are invalid`);
  return Object.freeze({
    name: metadata.name,
    digest: metadata.digest,
    run_id: String(run.id),
    archive_sha256: archive.sha256,
    metadata_sha256: metadataFile.snapshot.sha256,
    workflow_run_sha256: runFile.snapshot.sha256,
    workflow_jobs_sha256: jobsFile.snapshot.sha256
  });
}

function validateRetainedQualification({ root, sourceSha, repository, runIds }) {
  const rootPath = path.resolve(root);
  const verificationPath = path.join(rootPath, "qualification-verification.json");
  const verificationFile = readCanonicalJson(verificationPath, "qualification verification");
  const verification = verificationFile.value;
  exactKeys(verification, ["cloud", "macos", "repository", "schema_version", "source_sha"], "qualification verification");
  if (verification.schema_version !== 1 || verification.repository !== repository || verification.source_sha !== sourceSha) fail("retained qualification verification is not source-bound");
  const lanes = RETAINED_LANES.map((lane) => validateRetainedLane({ root: rootPath, lane, sourceSha, repository, expectedRunId: lane.name === "cloud" ? runIds.cloud_qualification_run_id : runIds.macos_qualification_run_id }));
  const cloud = verification.cloud;
  const macos = verification.macos;
  const matchesRetained = (record, lane) => record?.run_id === lane.run_id && record?.source_sha === sourceSha && record?.name === lane.name
    && record?.digest === lane.digest && record?.archive === "artifact.zip" && record?.metadata_sha256 === lane.metadata_sha256
    && record?.workflow_run_sha256 === lane.workflow_run_sha256 && record?.workflow_jobs_sha256 === lane.workflow_jobs_sha256;
  if (!matchesRetained(cloud, lanes[0]) || cloud.run_id !== runIds.cloud_qualification_run_id) fail("retained Cloud qualification record is not bound");
  if (macos.run_id !== runIds.macos_qualification_run_id || macos.source_sha !== sourceSha || !Array.isArray(macos.artifacts) || macos.artifacts.length !== 2) fail("retained macOS qualification record is not bound");
  for (const lane of lanes.slice(1)) {
    const record = macos.artifacts.find((item) => item?.name === lane.name);
    if (!matchesRetained(record, lane)) fail("retained macOS qualification artifact record is not bound");
  }
  return Object.freeze({ verificationFile, artifacts: Object.freeze(lanes) });
}

function validateBundleShape(bundle, expected) {
  const keys = [
    "candidate_artifact_digest", "candidate_artifact_name", "ci_run_id", "cloud_qualification_run_id", "qualification_dispatch_binding_sha256",
    "manifest_name", "manifest_sha256", "macos_qualification_run_id", "package_name", "package_sha256", "qualification_run_id",
    "qualification_summary_sha256", "qualification_verification_sha256", "release_run_id", "release_tag", "repository", "schema_version",
    "source_sha", "retained_artifacts"
  ];
  exactKeys(bundle, keys, "qualification bundle");
  if (bundle.schema_version !== QUALIFICATION_BUNDLE_SCHEMA_VERSION || bundle.repository !== expected.repository || bundle.source_sha !== expected.sourceSha || bundle.release_tag !== expected.releaseTag) fail("qualification bundle source identity is invalid");
  for (const name of ["candidate_artifact_digest"]) requireString(bundle[name], DIGEST, name);
  for (const name of ["manifest_sha256", "package_sha256", "qualification_summary_sha256", "qualification_dispatch_binding_sha256", "qualification_verification_sha256"]) requireString(bundle[name], SHA256, name);
  requireString(bundle.candidate_artifact_name, SAFE_NAME, "candidate artifact name");
  for (const name of ["manifest_name", "package_name"]) requireString(bundle[name], SAFE_NAME, name);
  const runIds = validateExpectedRunIds(bundle);
  if (JSON.stringify(runIds) !== JSON.stringify(validateExpectedRunIds(expected))) fail("qualification bundle run IDs do not match the selected runs");
  if (!Array.isArray(bundle.retained_artifacts) || bundle.retained_artifacts.length !== RETAINED_LANES.length) fail("qualification bundle retained artifact list is incomplete");
  const names = new Set();
  for (const artifact of bundle.retained_artifacts) {
    exactKeys(artifact, ["archive_sha256", "digest", "metadata_sha256", "name", "run_id", "workflow_jobs_sha256", "workflow_run_sha256"], "qualification bundle retained artifact");
    requireString(artifact.name, SAFE_NAME, "retained artifact name");
    requireString(artifact.digest, DIGEST, "retained artifact digest");
    requireRunId(artifact.run_id, "retained artifact run ID");
    for (const name of ["archive_sha256", "metadata_sha256", "workflow_run_sha256", "workflow_jobs_sha256"]) requireString(artifact[name], SHA256, `retained artifact ${name}`);
    if (names.has(artifact.name)) fail("qualification bundle retained artifacts contain duplicates");
    names.add(artifact.name);
  }
  return Object.freeze({ runIds });
}

function publicKeyFingerprint(publicKey) {
  return `SHA256:${createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function readEd25519PublicKey(publicKeyPath) {
  const bytes = readRegular(publicKeyPath, 16 * 1024).content;
  let key;
  try { key = createPublicKey(bytes); } catch { fail("qualification bundle public key is invalid"); }
  if (key.asymmetricKeyType !== "ed25519") fail("qualification bundle public key must be Ed25519");
  return key;
}

function readDetachedSignature(signaturePath) {
  const snapshot = readRegular(signaturePath, 1024);
  const encoded = snapshot.content.toString("utf8");
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) fail("qualification bundle signature encoding is invalid");
  const bytes = Buffer.from(encoded.trim(), "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== encoded.trim()) fail("qualification bundle signature bytes are invalid");
  return bytes;
}

function makeBundle({ repository, sourceSha, releaseTag, candidateArtifactName, candidateArtifactDigest, manifestPath, packagePath, summaryPath, dispatchBindingPath, qualificationRoot, ...runOptions }) {
  requireString(repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u, "repository");
  requireString(sourceSha, COMMIT_SHA, "source SHA");
  requireString(releaseTag, RELEASE_TAG, "release tag");
  requireString(candidateArtifactName, SAFE_NAME, "candidate artifact name");
  requireString(candidateArtifactDigest, DIGEST, "candidate artifact digest");
  const runIds = validateExpectedRunIds(runOptions);
  const candidate = validateManifestAndPackage({ manifestPath, packagePath, sourceSha, releaseTag });
  const summary = validateSummaryBinding({ summaryPath, dispatchBindingPath, runIds, candidateArtifactName });
  const retained = validateRetainedQualification({ root: qualificationRoot, sourceSha, repository, runIds });
  const bundle = {
    schema_version: QUALIFICATION_BUNDLE_SCHEMA_VERSION,
    repository,
    source_sha: sourceSha,
    release_tag: releaseTag,
    release_run_id: runIds.release_run_id,
    qualification_run_id: runIds.qualification_run_id,
    cloud_qualification_run_id: runIds.cloud_qualification_run_id,
    macos_qualification_run_id: runIds.macos_qualification_run_id,
    ci_run_id: runIds.ci_run_id,
    candidate_artifact_name: candidateArtifactName,
    candidate_artifact_digest: candidateArtifactDigest,
    package_name: candidate.packageName,
    package_sha256: candidate.packageFile.sha256,
    manifest_name: candidate.manifestFile.snapshot.name,
    manifest_sha256: candidate.manifestFile.snapshot.sha256,
    qualification_summary_sha256: summary.summaryFile.snapshot.sha256,
    qualification_dispatch_binding_sha256: summary.bindingFile.snapshot.sha256,
    qualification_verification_sha256: retained.verificationFile.snapshot.sha256,
    retained_artifacts: retained.artifacts
  };
  validateBundleShape(bundle, { repository, sourceSha, releaseTag, ...runIds });
  return Object.freeze({ bundle: Object.freeze(bundle), bytes: Buffer.from(canonical(bundle), "utf8") });
}

export function createSignedQualificationBundle(options) {
  const { outputPath, signaturePath, privateKeyPath } = options;
  if (!outputPath || !signaturePath || !privateKeyPath) fail("qualification bundle output, signature, and private key are required");
  const result = makeBundle(options);
  const privateBytes = readRegular(privateKeyPath, 16 * 1024, { privateKey: true }).content;
  let privateKey;
  try { privateKey = createPrivateKey(privateBytes); } catch { fail("qualification bundle private key is invalid"); }
  finally { privateBytes.fill(0); }
  if (privateKey.asymmetricKeyType !== "ed25519") fail("qualification bundle private key must be Ed25519");
  const signature = sign(null, result.bytes, privateKey);
  fs.writeFileSync(path.resolve(outputPath), result.bytes, { flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.resolve(signaturePath), `${signature.toString("base64")}\n`, { flag: "wx", mode: 0o600 });
  return Object.freeze({ ...result.bundle, signature_bytes: signature.length });
}

export function verifySignedQualificationBundle(options) {
  const { bundlePath, signaturePath, publicKeyPath, expectedFingerprint } = options;
  if (!bundlePath || !signaturePath || !publicKeyPath || !expectedFingerprint) fail("qualification bundle, signature, public key, and fingerprint are required");
  const bundleFile = readCanonicalJson(bundlePath, "qualification bundle");
  const expected = {
    repository: options.repository,
    sourceSha: options.sourceSha,
    releaseTag: options.releaseTag,
    candidateArtifactName: options.candidateArtifactName,
    candidateArtifactDigest: options.candidateArtifactDigest,
    release_run_id: options.release_run_id,
    qualification_run_id: options.qualification_run_id,
    cloud_qualification_run_id: options.cloud_qualification_run_id,
    macos_qualification_run_id: options.macos_qualification_run_id,
    ci_run_id: options.ci_run_id
  };
  validateBundleShape(bundleFile.value, expected);
  if (bundleFile.value.candidate_artifact_name !== expected.candidateArtifactName || bundleFile.value.candidate_artifact_digest !== expected.candidateArtifactDigest) fail("qualification bundle candidate artifact binding changed");
  const publicKey = readEd25519PublicKey(publicKeyPath);
  if (!/^SHA256:[A-Za-z0-9_-]{43}$/u.test(expectedFingerprint) || publicKeyFingerprint(publicKey) !== expectedFingerprint) fail("qualification bundle public key fingerprint mismatch");
  const signature = readDetachedSignature(signaturePath);
  if (!verify(null, bundleFile.snapshot.content, publicKey, signature)) fail("qualification bundle detached signature is invalid");
  const candidate = validateManifestAndPackage({ manifestPath: options.manifestPath, packagePath: options.packagePath, sourceSha: options.sourceSha, releaseTag: options.releaseTag });
  if (candidate.manifestFile.snapshot.sha256 !== bundleFile.value.manifest_sha256 || candidate.packageFile.sha256 !== bundleFile.value.package_sha256 || candidate.manifestFile.snapshot.name !== bundleFile.value.manifest_name || candidate.packageName !== bundleFile.value.package_name) fail("qualification bundle candidate/package/manifest digest binding mismatch");
  const summary = validateSummaryBinding({ summaryPath: options.summaryPath, dispatchBindingPath: options.dispatchBindingPath, runIds: validateExpectedRunIds(options), candidateArtifactName: options.candidateArtifactName });
  if (summary.summaryFile.snapshot.sha256 !== bundleFile.value.qualification_summary_sha256 || summary.bindingFile.snapshot.sha256 !== bundleFile.value.qualification_dispatch_binding_sha256) fail("qualification bundle summary digest binding mismatch");
  const retained = validateRetainedQualification({ root: options.qualificationRoot, sourceSha: options.sourceSha, repository: options.repository, runIds: validateExpectedRunIds(options) });
  if (retained.verificationFile.snapshot.sha256 !== bundleFile.value.qualification_verification_sha256) fail("qualification bundle retained verification digest mismatch");
  if (JSON.stringify(retained.artifacts) !== JSON.stringify(bundleFile.value.retained_artifacts)) fail("qualification bundle retained artifact binding mismatch");
  return Object.freeze({ ok: true, bundle_sha256: bundleFile.snapshot.sha256, signature_verified: true });
}

export const BUNDLE_OPTION_NAMES = Object.freeze([
  "repository", "source-sha", "release-tag", "candidate-artifact-name", "candidate-artifact-digest", "release-run-id", "qualification-run-id",
  "cloud-qualification-run-id", "macos-qualification-run-id", "ci-run-id", "manifest", "package", "summary", "dispatch-binding", "qualification-root",
  "output", "signature", "private-key", "public-key", "fingerprint", "bundle"
]);

export function parseBundleArguments(args) {
  const values = {};
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    if (!name.startsWith("--") || !BUNDLE_OPTION_NAMES.includes(name.slice(2)) || index + 1 >= args.length || args[index + 1].startsWith("--")) fail("invalid qualification bundle arguments");
    if (values[name.slice(2)] !== undefined) fail("duplicate qualification bundle argument");
    values[name.slice(2)] = args[++index];
  }
  return Object.fromEntries(Object.entries(values).map(([key, value]) => [key.replace(/-([a-z])/gu, (_, character) => character.toUpperCase()), value]));
}

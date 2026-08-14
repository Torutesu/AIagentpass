#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { basename, resolve } from 'node:path';
import { deriveReleaseCandidateId, RELEASE_MANIFEST_SCHEMA_VERSION } from '../../lib/release-candidate-identity.mjs';
import { parseCanonicalExternalQualificationControllerIdentity } from './n3e/controller-identity-contract.mjs';

const [output, sumsOutput, ...remaining] = process.argv.slice(2);
if (!output || !sumsOutput) throw new Error('Usage: generate-manifest.mjs MANIFEST SHA256SUMS --controller-identity=FILE --controller-notarization-status=accepted_stapled --controller-notary-submission=UUID --controller-notarytool-evidence=FILE --controller-stapler-evidence=FILE [--notarization-status=STATUS] [--notary-submission=UUID] [--notarytool-evidence=FILE] [--stapler-evidence=FILE] ARTIFACT...');

const takeOptions = (prefix) => remaining.filter((value) => value.startsWith(prefix)).map((value) => value.slice(prefix.length));
const statusOptions = takeOptions('--notarization-status=');
const submissionIDs = takeOptions('--notary-submission=');
const notarytoolInputs = takeOptions('--notarytool-evidence=');
const staplerInputs = takeOptions('--stapler-evidence=');
const controllerIdentityInputs = takeOptions('--controller-identity=');
const controllerStatusOptions = takeOptions('--controller-notarization-status=');
const controllerSubmissionIDs = takeOptions('--controller-notary-submission=');
const controllerNotarytoolInputs = takeOptions('--controller-notarytool-evidence=');
const controllerStaplerInputs = takeOptions('--controller-stapler-evidence=');
const knownOption = (value) => [
  '--notarization-status=', '--notary-submission=', '--notarytool-evidence=', '--stapler-evidence=',
  '--controller-identity=', '--controller-notarization-status=', '--controller-notary-submission=',
  '--controller-notarytool-evidence=', '--controller-stapler-evidence='
].some((prefix) => value.startsWith(prefix));
const inputs = remaining.filter((value) => !knownOption(value));
const unknownOptions = inputs.filter((value) => value.startsWith('--'));
if (unknownOptions.length) throw new Error(`unknown release manifest option: ${unknownOptions[0]}`);
if (inputs.length === 0) throw new Error('at least one release artifact is required');
if (statusOptions.length > 1 || statusOptions.some((value) => !value)) throw new Error('notarization status must be specified at most once');
if (controllerIdentityInputs.length !== 1 || !controllerIdentityInputs[0]) throw new Error('exactly one controller identity document is required');
if (controllerStatusOptions.length !== 1 || controllerStatusOptions[0] !== 'accepted_stapled') throw new Error('controller notarization status must be accepted_stapled');
if (controllerSubmissionIDs.length === 0 || controllerSubmissionIDs.some((id) => !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) || new Set(controllerSubmissionIDs.map((id) => id.toLowerCase())).size !== controllerSubmissionIDs.length) throw new Error('invalid or duplicate controller notary submission ID');
if (controllerNotarytoolInputs.length !== 1 || controllerStaplerInputs.length !== 1) throw new Error('accepted_stapled controller requires one notarytool result and one stapler result');

const notarizationStatus = statusOptions[0] || 'not_verified';
if (!['not_verified', 'accepted_stapled'].includes(notarizationStatus)) throw new Error('invalid notarization status');
if (submissionIDs.some((id) => !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) || new Set(submissionIDs.map((id) => id.toLowerCase())).size !== submissionIDs.length) throw new Error('invalid or duplicate notary submission ID');
if (notarizationStatus === 'not_verified' && (submissionIDs.length || notarytoolInputs.length || staplerInputs.length)) throw new Error('not_verified releases cannot carry notarization claims or evidence');
if (notarizationStatus === 'accepted_stapled' && (submissionIDs.length === 0 || notarytoolInputs.length !== 1 || staplerInputs.length !== 1)) throw new Error('accepted_stapled requires submission ID(s), one notarytool result, and one stapler result');

if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');
const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const snapshotFile = (input, { maximum = 16 * 1024 * 1024 * 1024, capture = false } = {}) => {
  const path = resolve(input);
  const descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`release input must be a nonempty single-link regular file: ${input}`);
    const size = Number(before.size);
    const hash = createHash('sha256');
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const wanted = Math.min(buffer.length, size - offset);
      const count = fs.readSync(descriptor, buffer, 0, wanted, offset);
      if (count === 0) throw new Error(`release input changed while reading: ${input}`);
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`release input changed while reading: ${input}`);
    return { path, name: basename(path), bytes: size, sha256: hash.digest('hex'), content: chunks ? Buffer.concat(chunks, size) : undefined };
  } finally {
    fs.closeSync(descriptor);
  }
};

const safeName = (name) => typeof name === 'string' && /^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(name) && name === basename(name);
const lexicalCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const controllerArchiveName = /^AgentPassQualificationController-(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?-macos-universal\.tar$/u;
const mediaType = (name) => {
  if (name.endsWith('.spdx.json')) return 'application/spdx+json';
  if (name.endsWith('.zip')) return 'application/zip';
  if (name.endsWith('.pkg')) return 'application/vnd.apple.installer+xml';
  if (name.endsWith('.tgz') || name.endsWith('.tar.gz')) return 'application/gzip';
  if (name.endsWith('.pem')) return 'application/x-pem-file';
  if (name.endsWith('.json')) return 'application/json';
  if (name.endsWith('.txt')) return 'text/plain';
  return 'application/octet-stream';
};
const artifactRole = (name) => {
  if (controllerArchiveName.test(name)) return 'external_qualification_controller';
  if (name.endsWith('.spdx.json')) return 'sbom';
  if (name.endsWith('.pkg') || name.endsWith('.zip') || name.endsWith('.tgz') || name.endsWith('.tar.gz')) return 'product';
  if (name === 'NOT_NOTARIZED.txt') return 'release_notice';
  if (name.endsWith('.public.pem')) return 'trust_root';
  return 'auxiliary';
};

const seen = new Set();
const artifacts = inputs.map((input) => {
  const candidateName = basename(resolve(input));
  const capture = candidateName.endsWith('.spdx.json');
  const value = snapshotFile(input, { maximum: capture ? 32 * 1024 * 1024 : 16 * 1024 * 1024 * 1024, capture });
  if (!safeName(value.name)) throw new Error(`unsafe artifact basename: ${value.name}`);
  if (seen.has(value.name)) throw new Error(`duplicate release input basename: ${value.name}`);
  seen.add(value.name);
  return { name: value.name, role: artifactRole(value.name), media_type: mediaType(value.name), bytes: value.bytes, sha256: value.sha256, content: value.content };
}).sort((a, b) => lexicalCompare(a.name, b.name));

const controllerArtifacts = artifacts.filter((item) => item.role === 'external_qualification_controller');
if (controllerArtifacts.length !== 1) throw new Error('release manifest requires exactly one external qualification controller archive');
const productArtifacts = artifacts.filter((item) => item.role === 'product');
if (productArtifacts.length !== 1 || !productArtifacts[0].name.endsWith('.pkg')) throw new Error('release manifest requires exactly one product PKG artifact');
const productArtifact = productArtifacts[0];

const controllerIdentitySnapshot = snapshotFile(controllerIdentityInputs[0], { maximum: 1024 * 1024, capture: true });
if (!safeName(controllerIdentitySnapshot.name) || seen.has(controllerIdentitySnapshot.name)) throw new Error('unsafe or duplicate controller identity basename');
seen.add(controllerIdentitySnapshot.name);
let controllerIdentity;
try { controllerIdentity = parseCanonicalExternalQualificationControllerIdentity(controllerIdentitySnapshot.content); }
catch (error) { throw new Error(`controller identity document is invalid: ${error.message}`); }
const controllerArtifact = controllerArtifacts[0];
if (controllerIdentity.archive_name !== controllerArtifact.name || controllerIdentity.archive_sha256 !== controllerArtifact.sha256 || controllerIdentity.archive_bytes !== controllerArtifact.bytes) throw new Error('controller identity does not bind the exact external archive');

const notaryEvidence = [
  ...notarytoolInputs.map((path) => ({ kind: 'notarytool_result', ...snapshotFile(path, { maximum: 4 * 1024 * 1024, capture: true }) })),
  ...staplerInputs.map((path) => ({ kind: 'stapler_result', ...snapshotFile(path, { maximum: 1024 * 1024, capture: true }) }))
].map((value) => {
  if (!safeName(value.name) || seen.has(value.name)) throw new Error(`unsafe or duplicate notarization evidence basename: ${value.name}`);
  seen.add(value.name);
  return value;
});

const controllerNotaryEvidence = [
  ...controllerNotarytoolInputs.map((path) => ({ kind: 'notarytool_result', ...snapshotFile(path, { maximum: 4 * 1024 * 1024, capture: true }) })),
  ...controllerStaplerInputs.map((path) => ({ kind: 'stapler_result', ...snapshotFile(path, { maximum: 1024 * 1024, capture: true }) }))
].map((value) => {
  if (!safeName(value.name) || seen.has(value.name)) throw new Error(`unsafe or duplicate controller notarization evidence basename: ${value.name}`);
  seen.add(value.name);
  return value;
});

if (notarizationStatus === 'accepted_stapled') {
  const notarytool = notaryEvidence.find((item) => item.kind === 'notarytool_result');
  let result;
  try { result = JSON.parse(notarytool.content.toString('utf8')); } catch { throw new Error('notarytool evidence must be valid JSON'); }
  if (typeof result !== 'object' || result === null || result.status !== 'Accepted' || typeof result.id !== 'string' || !submissionIDs.some((id) => id.toLowerCase() === result.id.toLowerCase())) throw new Error('notarytool evidence does not prove an accepted declared submission');
  const stapler = notaryEvidence.find((item) => item.kind === 'stapler_result').content.toString('utf8');
  if (!/The validate action worked!/i.test(stapler)) throw new Error('stapler evidence does not record successful validation');
}

{
  const notarytool = controllerNotaryEvidence.find((item) => item.kind === 'notarytool_result');
  let result;
  try { result = JSON.parse(notarytool.content.toString('utf8')); } catch { throw new Error('controller notarytool evidence must be valid JSON'); }
  if (typeof result !== 'object' || result === null || result.status !== 'Accepted' || typeof result.id !== 'string' || !controllerSubmissionIDs.some((id) => id.toLowerCase() === result.id.toLowerCase())) throw new Error('controller notarytool evidence does not prove an accepted declared submission');
  const stapler = controllerNotaryEvidence.find((item) => item.kind === 'stapler_result').content.toString('utf8');
  if (!/The validate action worked!/i.test(stapler)) throw new Error('controller stapler evidence does not record successful validation');
}

const root = resolve(process.env.AGENTPASS_REPOSITORY_ROOT || process.cwd());
const git = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }).trim();
const commit = git(['rev-parse', 'HEAD']);
const tree = git(['rev-parse', 'HEAD^{tree}']);
if (!/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree)) throw new Error('invalid Git source identity');
const pkg = JSON.parse(execFileSync('git', ['show', `${commit}:package.json`], { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }));
if (typeof pkg.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(pkg.version)) throw new Error('invalid committed release version');
if (controllerArtifact.name !== `AgentPassQualificationController-${pkg.version}-macos-universal.tar`) throw new Error('controller archive version does not match the release');
const sourceTag = process.env.AGENTPASS_RELEASE_TAG || null;
if (sourceTag !== null && sourceTag !== `v${pkg.version}`) throw new Error('release tag and committed package version disagree');

const sbomArtifacts = artifacts.filter((item) => item.role === 'sbom');
if (sbomArtifacts.length !== 1) throw new Error('release manifest requires exactly one SPDX SBOM artifact');
const sbomArtifact = sbomArtifacts[0];
let sbom;
try { sbom = JSON.parse(sbomArtifact.content.toString('utf8')); } catch { throw new Error('SBOM artifact is not valid JSON'); }
if (sbom.spdxVersion !== 'SPDX-2.3' || sbom.SPDXID !== 'SPDXRef-DOCUMENT' || typeof sbom.documentNamespace !== 'string' || !/^https:\/\/github\.com\/Torutesu\/Agentpass\/sbom\//.test(sbom.documentNamespace)) throw new Error('invalid SPDX document identity');
if (!Array.isArray(sbom.documentDescribes) || sbom.documentDescribes.length !== 1 || sbom.documentDescribes[0] !== 'SPDXRef-AgentPass') throw new Error('SPDX document must describe AgentPass');
const describedPackage = Array.isArray(sbom.packages) ? sbom.packages.find((item) => item?.SPDXID === 'SPDXRef-AgentPass') : undefined;
if (!describedPackage || describedPackage.versionInfo !== pkg.version || typeof describedPackage.sourceInfo !== 'string' || !describedPackage.sourceInfo.includes(commit) || !describedPackage.sourceInfo.includes(tree)) throw new Error('SPDX source identity does not match the release');
let sbomCreation;
try { sbomCreation = JSON.parse(sbom.creationInfo?.comment); } catch { throw new Error('SPDX creation metadata is missing'); }
if (sbomCreation.source_commit !== commit || sbomCreation.source_tree !== tree || !Number.isSafeInteger(sbomCreation.swift_input_count) || sbomCreation.swift_input_count < 1 || typeof sbomCreation.swift !== 'string' || typeof sbomCreation.macos_sdk !== 'string') throw new Error('SPDX build/source metadata does not match the release');

const publicArtifacts = artifacts.map(({ content, ...item }) => item);
const publicNotaryEvidence = notaryEvidence.map(({ content, path, ...item }) => ({ kind: item.kind, name: item.name, bytes: item.bytes, sha256: item.sha256 })).sort((a, b) => lexicalCompare(a.name, b.name));
const publicControllerNotaryEvidence = controllerNotaryEvidence.map(({ content, path, ...item }) => ({ kind: item.kind, name: item.name, bytes: item.bytes, sha256: item.sha256 })).sort((a, b) => lexicalCompare(a.name, b.name));
const controllerIdentityDocument = { name: controllerIdentitySnapshot.name, bytes: controllerIdentitySnapshot.bytes, sha256: controllerIdentitySnapshot.sha256 };
const checksumEntries = [...publicArtifacts, ...publicNotaryEvidence, controllerIdentityDocument, ...publicControllerNotaryEvidence].sort((a, b) => lexicalCompare(a.name, b.name));
const checksumBytes = Buffer.from(`${checksumEntries.map((item) => `${item.sha256}  ${item.name}`).join('\n')}\n`, 'utf8');
const checksumsName = basename(resolve(sumsOutput));
if (!safeName(checksumsName) || seen.has(checksumsName)) throw new Error('unsafe or colliding SHA256SUMS basename');
const manifestName = basename(resolve(output));
if (!safeName(manifestName) || seen.has(manifestName) || manifestName === checksumsName || resolve(output) === resolve(sumsOutput)) throw new Error('unsafe or colliding release manifest basename');

const manifest = {
  schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
  product: 'AgentPass',
  version: pkg.version,
  source: { commit, tree, tag: sourceTag },
  generated_at: new Date().toISOString(),
  candidate_id: deriveReleaseCandidateId(productArtifact.sha256),
  artifacts: publicArtifacts,
  external_qualification_controller: {
    identity_document: controllerIdentityDocument,
    identity: controllerIdentity,
    notarization: {
      status: 'accepted_stapled',
      submission_ids: controllerSubmissionIDs.map((id) => id.toLowerCase()).sort(),
      evidence: publicControllerNotaryEvidence
    }
  },
  evidence: {
    checksums: { name: checksumsName, bytes: checksumBytes.length, sha256: createHash('sha256').update(checksumBytes).digest('hex'), entry_count: checksumEntries.length },
    sbom: {
      artifact_name: sbomArtifact.name,
      sha256: sbomArtifact.sha256,
      spdx_version: sbom.spdxVersion,
      document_namespace: sbom.documentNamespace,
      document_spdx_id: sbom.SPDXID,
      document_describes: [...sbom.documentDescribes],
      source_commit: commit,
      source_tree: tree
    },
    notarization: { status: notarizationStatus, submission_ids: submissionIDs.map((id) => id.toLowerCase()).sort(), evidence: publicNotaryEvidence }
  }
};

fs.writeFileSync(resolve(sumsOutput), checksumBytes, { flag: 'wx', mode: 0o644 });
fs.writeFileSync(resolve(output), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o644 });

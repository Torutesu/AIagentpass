#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';

const [output] = process.argv.slice(2);
if (!output || process.argv.slice(2).length !== 1) throw new Error('Usage: generate-sbom.mjs OUTPUT');

const root = resolve(process.env.AGENTPASS_REPOSITORY_ROOT || process.cwd());
const gitText = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }).trim();
const gitBytes = (args) => execFileSync('git', args, { cwd: root, encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
const commandText = (command, args) => execFileSync(command, args, { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const spdxID = (prefix, identity) => `SPDXRef-${prefix}-${sha256(identity).slice(0, 20)}`;

const commit = gitText(['rev-parse', 'HEAD']);
const tree = gitText(['rev-parse', 'HEAD^{tree}']);
if (!/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree)) throw new Error('unsupported Git object identity');

// Read source metadata from the exact Git object named above, not from a mutable
// worktree path. This keeps the SBOM's source inventory bound to source.commit/tree.
const pkgBytes = gitBytes(['show', `${commit}:package.json`]);
const lockBytes = gitBytes(['show', `${commit}:package-lock.json`]);
const pkg = JSON.parse(pkgBytes.toString('utf8'));
const lock = JSON.parse(lockBytes.toString('utf8'));
if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string' || typeof lock !== 'object' || lock === null) throw new Error('invalid committed package metadata');

const tracked = gitBytes(['ls-tree', '-r', '-z', '--name-only', commit]).toString('utf8').split('\0').filter(Boolean);
const swiftInputs = tracked.filter((path) =>
  path === 'native/macos/Package.swift' ||
  path === 'native/macos/Package.resolved' ||
  (path.startsWith('native/macos/') && path.endsWith('.swift'))
);
if (!swiftInputs.includes('native/macos/Package.swift') || !swiftInputs.some((path) => path.endsWith('.swift'))) throw new Error('committed Swift build inputs are missing');

const sourcePaths = ['package.json', 'package-lock.json', ...swiftInputs].sort();
const files = sourcePaths.map((path) => {
  const bytes = path === 'package.json' ? pkgBytes : path === 'package-lock.json' ? lockBytes : gitBytes(['show', `${commit}:${path}`]);
  return {
    fileName: path,
    SPDXID: spdxID('File', path),
    checksums: [
      { algorithm: 'SHA1', checksumValue: createHash('sha1').update(bytes).digest('hex') },
      { algorithm: 'SHA256', checksumValue: sha256(bytes) }
    ],
    licenseConcluded: 'NOASSERTION',
    copyrightText: 'NOASSERTION'
  };
});

const rootPackage = {
  name: 'AgentPass',
  SPDXID: 'SPDXRef-AgentPass',
  versionInfo: pkg.version,
  downloadLocation: 'https://github.com/Torutesu/Agentpass',
  filesAnalyzed: true,
  packageVerificationCode: {
    packageVerificationCodeValue: createHash('sha1').update(files.map((file) => file.checksums.find((item) => item.algorithm === 'SHA1').checksumValue).sort().join('')).digest('hex')
  },
  licenseConcluded: 'NOASSERTION',
  licenseDeclared: typeof pkg.license === 'string' ? pkg.license : 'NOASSERTION',
  primaryPackagePurpose: 'APPLICATION',
  sourceInfo: `Git commit ${commit}; tree ${tree}`,
  externalRefs: [{
    referenceCategory: 'OTHER',
    referenceType: 'vcs',
    referenceLocator: `git+https://github.com/Torutesu/Agentpass.git@${commit}`
  }]
};

const dependencies = Object.entries(lock.packages || {})
  .filter(([path]) => path !== '')
  .map(([path, value]) => ({
    SPDXID: spdxID('NpmPackage', path),
    name: value.name || basename(path),
    versionInfo: value.version || 'NOASSERTION',
    downloadLocation: value.resolved || 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: value.license || 'NOASSERTION',
    primaryPackagePurpose: 'LIBRARY',
    externalRefs: value.name && value.version ? [{
      referenceCategory: 'PACKAGE-MANAGER',
      referenceType: 'purl',
      referenceLocator: `pkg:npm/${encodeURIComponent(value.name)}@${encodeURIComponent(value.version)}`
    }] : undefined
  }))
  .map((value) => Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)))
  .sort((a, b) => a.SPDXID.localeCompare(b.SPDXID));

const nodeVersion = process.version.replace(/^v/, '');
const swiftCompiler = commandText('swiftc', ['--version']);
const swiftVersion = swiftCompiler.match(/Swift version ([^\s]+)/)?.[1];
if (!swiftVersion) throw new Error('unable to determine Swift compiler version');
const sdkVersion = commandText('xcrun', ['--sdk', 'macosx', '--show-sdk-version']);
const sdkBuild = commandText('xcrun', ['--sdk', 'macosx', '--show-sdk-build-version']);
const xcodeVersion = commandText('xcodebuild', ['-version']).replace(/\s+/g, ' ');
const buildTools = [
  {
    name: 'Node.js', SPDXID: 'SPDXRef-BuildTool-Node', versionInfo: nodeVersion,
    downloadLocation: 'https://nodejs.org/', filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', primaryPackagePurpose: 'APPLICATION'
  },
  {
    name: 'Apple Swift compiler', SPDXID: 'SPDXRef-BuildTool-Swift', versionInfo: swiftVersion,
    downloadLocation: 'NOASSERTION', filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', primaryPackagePurpose: 'APPLICATION',
    comment: swiftCompiler.replace(/\s+/g, ' ')
  },
  {
    name: 'macOS SDK', SPDXID: 'SPDXRef-BuildTool-macOSSDK', versionInfo: sdkVersion,
    downloadLocation: 'NOASSERTION', filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', primaryPackagePurpose: 'APPLICATION',
    comment: `SDK build ${sdkBuild}; ${xcodeVersion}`
  }
];

const relationships = [
  ...files.map((file) => ({ spdxElementId: rootPackage.SPDXID, relationshipType: 'CONTAINS', relatedSpdxElement: file.SPDXID })),
  ...dependencies.map((dependency) => ({ spdxElementId: rootPackage.SPDXID, relationshipType: 'DEPENDS_ON', relatedSpdxElement: dependency.SPDXID })),
  ...buildTools.map((tool) => ({ spdxElementId: tool.SPDXID, relationshipType: 'BUILD_TOOL_OF', relatedSpdxElement: rootPackage.SPDXID }))
];

const createdAt = new Date().toISOString();
const document = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: `AgentPass-${pkg.version}`,
  documentNamespace: `https://github.com/Torutesu/Agentpass/sbom/${pkg.version}/${tree}/${randomUUID()}`,
  creationInfo: {
    created: createdAt,
    creators: ['Tool: AgentPass-generate-sbom'],
    comment: JSON.stringify({ source_commit: commit, source_tree: tree, swift_input_count: swiftInputs.length, node: nodeVersion, swift: swiftVersion, macos_sdk: sdkVersion, macos_sdk_build: sdkBuild })
  },
  documentDescribes: [rootPackage.SPDXID],
  packages: [rootPackage, ...dependencies, ...buildTools],
  files,
  relationships
};

writeFileSync(resolve(output), `${JSON.stringify(document, null, 2)}\n`, { flag: 'wx', mode: 0o644 });

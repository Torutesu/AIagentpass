#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const NATIVE_XPC_CONTRACT_RELATIVE_PATH = "native/macos/Qualification/native-xpc-contract-v1.json";
export const NATIVE_XPC_SWIFT_CONTRACT_RELATIVE_PATH = "native/macos/Sources/AgentPassNativeCore/NativeXPCContract.swift";
export const NATIVE_XPC_CONTRACT_MAX_BYTES = 128 * 1024;
export const NATIVE_XPC_SOURCE_MAX_BYTES = 8 * 1024 * 1024;

const SHA = /^[0-9a-f]{40}$/u;
const FINGERPRINT = /^SHA256:[0-9a-f]{64}$/u;
const SAFE_RELATIVE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u;

export class NativeXpcContractGateError extends Error {
  constructor(message) {
    super(message);
    this.name = "NativeXpcContractGateError";
  }
}

const fail = (message) => {
  throw new NativeXpcContractGateError(message);
};

const plainObject = (value) => value !== null
  && typeof value === "object"
  && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

const exactKeys = (value, keys, label) => {
  if (!plainObject(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown fields`);
  }
};

const nonZeroSha = (value, label) => {
  if (typeof value !== "string" || !SHA.test(value) || value === "0".repeat(40)) fail(`${label} is invalid`);
  return value;
};

const git = (repoRoot, args, label) => {
  try {
    return execFileSync("git", ["-C", repoRoot, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 4 * 1024 * 1024
    }).trim();
  } catch (error) {
    const detail = error?.stderr?.toString?.("utf8")?.trim();
    fail(`${label} failed${detail ? `: ${detail}` : ""}`);
  }
};

const gitBytes = (repoRoot, args, label) => {
  try {
    return execFileSync("git", ["-C", repoRoot, ...args], {
      encoding: null,
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: NATIVE_XPC_SOURCE_MAX_BYTES * 2
    });
  } catch (error) {
    const detail = error?.stderr?.toString?.("utf8")?.trim();
    fail(`${label} failed${detail ? `: ${detail}` : ""}`);
  }
};

const readStableFile = (file, label, maximumBytes = NATIVE_XPC_CONTRACT_MAX_BYTES) => {
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximumBytes)) {
      fail(`${label} is not a safe regular file`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) fail(`${label} changed while being read`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
    if (identity(before) !== identity(after)) fail(`${label} changed while being read`);
    return bytes;
  } catch (error) {
    if (error instanceof NativeXpcContractGateError) throw error;
    fail(`${label} is not readable: ${error.message}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
};

const sourceTreeBlob = (repoRoot, tree, relativePath) => {
  const listing = git(repoRoot, ["ls-tree", "-r", "--full-tree", tree, "--", relativePath], `source tree lookup for ${relativePath}`);
  const lines = listing.length === 0 ? [] : listing.split("\n");
  if (lines.length !== 1) fail(`source tree does not contain exactly one entry for ${relativePath}`);
  const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u.exec(lines[0]);
  if (!match || match[3] !== relativePath) fail(`source tree entry for ${relativePath} is not a regular file`);
  return { mode: match[1], oid: match[2] };
};

const sourceTreeFile = (repoRoot, tree, relativePath, label, maximumBytes = NATIVE_XPC_SOURCE_MAX_BYTES) => {
  const entry = sourceTreeBlob(repoRoot, tree, relativePath);
  const bytes = gitBytes(repoRoot, ["cat-file", "blob", entry.oid], `source tree blob for ${relativePath}`);
  if (bytes.length > maximumBytes) fail(`${label} exceeds the release source size limit`);
  return { ...entry, bytes };
};

const escapedRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

const validateShape = (contract) => {
  exactKeys(contract, ["$id", "$schema", "contract_identifier", "contract_version", "host_control", "mach_services", "source_refs", "swift_contract_version", "swift_fingerprint"], "native XPC contract");
  if (contract.$schema !== "https://agentpass.dev/schemas/native-xpc-contract-v1.json"
    || contract.$id !== "https://agentpass.dev/contracts/native-xpc-v1.json"
    || contract.contract_identifier !== "dev.agentpass.native-xpc"
    || contract.contract_version !== 1
    || !Number.isSafeInteger(contract.swift_contract_version)
    || contract.swift_contract_version < 1
    || typeof contract.swift_fingerprint !== "string"
    || !FINGERPRINT.test(contract.swift_fingerprint)) {
    fail("native XPC contract identity or fingerprint is invalid");
  }

  exactKeys(contract.mach_services, ["management", "agent_session", "host", "host_control", "child_git"], "native XPC Mach services");
  const expectedServices = {
    management: "dev.agentpass.native-service",
    agent_session: "dev.agentpass.agent-session",
    host: "dev.agentpass.agent-host",
    host_control: "dev.agentpass.agent-host-control",
    child_git: "dev.agentpass.child-git"
  };
  for (const [name, expected] of Object.entries(expectedServices)) if (contract.mach_services[name] !== expected) fail(`native XPC Mach service ${name} is not canonical`);

  exactKeys(contract.host_control, ["protocol", "selectors", "request_classes", "response_classes", "authorized_bundle_identifier", "cli_command"], "native XPC host-control contract");
  if (contract.host_control.protocol !== "AgentPassHostControlXPCProtocol"
    || contract.host_control.authorized_bundle_identifier !== "dev.agentpass.native-client"
    || contract.host_control.cli_command !== "agentpass close"
    || JSON.stringify(contract.host_control.selectors) !== JSON.stringify(["closeHostSessionFromControl:withReply:"])
    || JSON.stringify(contract.host_control.request_classes) !== JSON.stringify(["AgentPassHostControlCloseRequest"])
    || JSON.stringify(contract.host_control.response_classes) !== JSON.stringify(["AgentPassHostControlCloseResponse"])) {
    fail("native XPC host-control contract is not canonical");
  }

  if (!Array.isArray(contract.source_refs) || contract.source_refs.length < 1 || new Set(contract.source_refs).size !== contract.source_refs.length
    || contract.source_refs.some((value) => typeof value !== "string" || !SAFE_RELATIVE_PATH.test(value))) {
    fail("native XPC source reference inventory is invalid");
  }
};

const validateImplementationFingerprint = (contract, swiftBytes) => {
  const swift = swiftBytes.toString("utf8");
  const version = new RegExp(`contractVersion\\s*=\\s*${contract.swift_contract_version}\\b`, "u");
  const fingerprint = new RegExp(`frozenFingerprint\\s*=\\s*"${escapedRegExp(contract.swift_fingerprint)}"`, "u");
  if (!version.test(swift)) fail("native XPC contract version is not bound to NativeXPCContract.swift");
  if (!fingerprint.test(swift)) fail("native XPC fingerprint is not bound to NativeXPCContract.swift");
  if ((swift.match(/frozenFingerprint\s*=\s*"/gu) ?? []).length !== 1) fail("NativeXPCContract.swift has an ambiguous frozen fingerprint binding");
};

export function validateNativeXpcContract({ repoRoot, expectedSourceCommit, expectedSourceTree, sourceRef = "HEAD" } = {}) {
  if (typeof repoRoot !== "string" || !path.isAbsolute(repoRoot)) fail("native XPC release gate requires an absolute repository root");
  const repositoryRoot = path.resolve(repoRoot);
  const sourceCommit = nonZeroSha(expectedSourceCommit, "expected source commit");
  const sourceTree = nonZeroSha(expectedSourceTree, "expected source tree");
  if (typeof sourceRef !== "string" || sourceRef.length === 0 || sourceRef.startsWith("-")) fail("source ref is invalid");

  const resolvedContract = path.join(repositoryRoot, NATIVE_XPC_CONTRACT_RELATIVE_PATH);
  const sourceHead = git(repositoryRoot, ["rev-parse", "--verify", `${sourceRef}^{commit}`], "source commit lookup");
  const checkoutTree = git(repositoryRoot, ["rev-parse", "--verify", `${sourceRef}^{tree}`], "source tree lookup");
  if (sourceHead !== sourceCommit) fail("native XPC contract source commit is not bound to the release");
  if (checkoutTree !== sourceTree) fail("native XPC contract source tree is not bound to the release");

  const contractBytes = readStableFile(resolvedContract, "native XPC contract");
  let contract;
  try { contract = JSON.parse(contractBytes.toString("utf8")); } catch { fail("native XPC contract is not valid UTF-8 JSON"); }
  validateShape(contract);
  if (!contractBytes.equals(Buffer.from(`${canonicalJson(contract)}\n`, "utf8"))) fail("native XPC contract is not canonical JSON");

  const treeContract = sourceTreeFile(repositoryRoot, sourceTree, NATIVE_XPC_CONTRACT_RELATIVE_PATH, "native XPC contract", NATIVE_XPC_CONTRACT_MAX_BYTES);
  if (!contractBytes.equals(treeContract.bytes)) fail("native XPC contract bytes are not source-tree bound");

  const sourceFiles = new Map();
  for (const sourceRef of contract.source_refs) {
    const source = sourceTreeFile(repositoryRoot, sourceTree, sourceRef, `native XPC source reference ${sourceRef}`);
    const localPath = path.join(repositoryRoot, sourceRef);
    if (!localPath.startsWith(`${repositoryRoot}${path.sep}`)) fail(`native XPC source reference escapes repository: ${sourceRef}`);
    const localBytes = readStableFile(localPath, `native XPC source reference ${sourceRef}`, NATIVE_XPC_SOURCE_MAX_BYTES);
    if (!localBytes.equals(source.bytes)) fail(`native XPC source reference is not source-tree bound: ${sourceRef}`);
    sourceFiles.set(sourceRef, localBytes);
  }

  const swiftBytes = sourceFiles.get(NATIVE_XPC_SWIFT_CONTRACT_RELATIVE_PATH);
  if (!swiftBytes) fail("native XPC source references omit NativeXPCContract.swift");
  validateImplementationFingerprint(contract, swiftBytes);

  const swiftText = swiftBytes.toString("utf8");
  const protocolText = (sourceFiles.get("native/macos/Sources/AgentPassNativeCore/AgentHostXPCProtocol.swift") ?? Buffer.alloc(0)).toString("utf8");
  const serviceText = (sourceFiles.get("native/macos/Sources/AgentPassNativeService/main.swift") ?? Buffer.alloc(0)).toString("utf8");
  const clientText = (sourceFiles.get("native/macos/Sources/AgentPassNativeClient/main.swift") ?? Buffer.alloc(0)).toString("utf8");
  const brokerText = (sourceFiles.get("lib/broker-client.mjs") ?? Buffer.alloc(0)).toString("utf8");
  const cliText = (sourceFiles.get("bin/agentpass.mjs") ?? Buffer.alloc(0)).toString("utf8");
  for (const serviceName of Object.values(contract.mach_services)) {
    if (![protocolText, serviceText, clientText].some((value) => value.includes(`"${serviceName}"`))) fail(`native XPC Mach service is not bound to source: ${serviceName}`);
  }
  for (const selector of contract.host_control.selectors) if (!swiftText.includes(selector)) fail(`native XPC selector is not bound to source: ${selector}`);
  for (const typeName of [...contract.host_control.request_classes, ...contract.host_control.response_classes]) if (!protocolText.includes(typeName)) fail(`native XPC DTO is not bound to source: ${typeName}`);
  if (!serviceText.includes("authorizedControlBundleIdentifier: NativeClientCodeRequirement.clientBundleID")
    || !clientText.includes("host-control-close")
    || !brokerText.includes("native.host.close")
    || !brokerText.includes("host-control-close")
    || !/agentpass close|close --session-id/u.test(cliText)) {
    fail("native XPC host-control route is not source-bound");
  }

  return Object.freeze({
    status: "passed",
    contract_path: NATIVE_XPC_CONTRACT_RELATIVE_PATH,
    contract_sha256: createHash("sha256").update(contractBytes).digest("hex"),
    source_commit: sourceCommit,
    source_tree: sourceTree,
    source_tree_blob: treeContract.oid,
    swift_contract_version: contract.swift_contract_version,
    swift_fingerprint: contract.swift_fingerprint,
    source_ref_count: contract.source_refs.length
  });
}

const usage = "Usage: native-xpc-contract-gate.mjs REPOSITORY-ROOT EXPECTED-SOURCE-COMMIT EXPECTED-SOURCE-TREE [SOURCE-REF]";
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  if (args.length < 3 || args.length > 4) {
    process.stderr.write(`${usage}\n`);
    process.exitCode = 2;
  } else {
    try {
      process.stdout.write(`${canonicalJson(validateNativeXpcContract({ repoRoot: path.resolve(args[0]), expectedSourceCommit: args[1], expectedSourceTree: args[2], sourceRef: args[3] ?? "HEAD" }))}\n`);
    } catch (error) {
      process.stderr.write(`native XPC contract gate failed: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    }
  }
}

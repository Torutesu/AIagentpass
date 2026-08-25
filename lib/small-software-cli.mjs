import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalDigest, normalizeAppManifest, parseStrictJson, redact } from "../packages/small-software-contracts/src/index.mjs";

const MAX_FILES = 10_000;
const IGNORED = new Set([".git", "node_modules", ".wrangler", ".next", "dist"]);
const SECRET_FILE = /^(?:\.env(?:\..*)?|credentials(?:\..*)?|secrets(?:\..*)?|id_(?:rsa|ed25519)|.*\.(?:pem|key|p12|pfx|secret))$/iu;

function parseFlags(argv) {
  const flags = { path: ".", planOnly: false, manifest: undefined };
  const seen = new Set();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--plan-only") {
      if (seen.has(arg)) throw new Error("--plan-only may only be supplied once");
      seen.add(arg);
      flags.planOnly = true;
      continue;
    }
    if (arg === "--path" || arg === "--manifest") {
      if (seen.has(arg)) throw new Error(`${arg} may only be supplied once`);
      seen.add(arg);
      const value = argv[++i];
      if (!value || value.startsWith("--")) throw new Error(`${arg} requires a value`);
      flags[arg.slice(2)] = value;
      continue;
    }
    throw new Error(`unknown small-software option: ${arg}`);
  }
  return flags;
}

function projectRoot(flags) {
  const root = path.resolve(flags.path);
  const stat = fs.lstatSync(root, { throwIfNoEntry: false });
  if (stat?.isSymbolicLink()) throw new Error("project path must not be a symlink");
  if (!stat?.isDirectory()) throw new Error("project path must be a directory");
  if (root === path.parse(root).root || root === path.resolve(os.homedir())) throw new Error("project path must be a project directory");
  return root;
}

function readManifest(root, flags) {
  const manifestPath = path.resolve(root, flags.manifest ?? "agentpass.app.json");
  if (manifestPath !== root && !manifestPath.startsWith(`${root}${path.sep}`)) throw new Error("manifest must stay inside project path");
  const raw = fs.readFileSync(manifestPath, "utf8");
  const value = normalizeAppManifest(parseStrictJson(raw));
  return { path: path.relative(root, manifestPath) || "agentpass.app.json", value, digest: canonicalDigest(value) };
}

function inventory(root) {
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (IGNORED.has(entry.name)) continue;
      if (SECRET_FILE.test(entry.name)) throw new Error("credential-like files are not allowed in source inventory");
      const full = path.join(dir, entry.name);
      const relative = path.relative(root, full).split(path.sep).join("/");
      if (entry.isSymbolicLink()) throw new Error("symlinks are not allowed in source inventory");
      if (entry.isDirectory()) { walk(full); continue; }
      if (!entry.isFile()) throw new Error("non-regular files are not allowed in source inventory");
      if (files.length >= MAX_FILES) throw new Error("source inventory exceeds file limit");
      const bytes = fs.readFileSync(full);
      files.push({ path: relative, bytes: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex") });
    }
  }
  walk(root);
  return files;
}

function inspect(root, flags) {
  const manifest = readManifest(root, flags);
  const files = inventory(root);
  const inventoryDigest = canonicalDigest(files);
  return { status: "plan_only", project: root, manifest: { path: manifest.path, digest: manifest.digest, value: redact(manifest.value) }, file_count: files.length, total_bytes: files.reduce((sum, file) => sum + file.bytes, 0), file_inventory_digest: inventoryDigest, next: ["bundle", "prepare", "publish --plan-only"] };
}

export function runSmallSoftwareCli(action, argv = []) {
  const flags = parseFlags(argv);
  const root = projectRoot(flags);
  const inspected = inspect(root, flags);
  if (action === "inspect") return inspected;
  const bundle = { status: "plan_only", kind: "agentpass.source-bundle-plan", project: root, manifest_digest: inspected.manifest.digest, file_inventory_digest: inspected.file_inventory_digest, file_count: inspected.file_count, total_bytes: inspected.total_bytes, mutation: "none", qualification_status: "not_proven", reason: "external_identity_and_storage_not_configured" };
  if (action === "bundle") return bundle;
  const prepare = { status: "plan_only", kind: "agentpass.publish-plan", source_bundle_digest: canonicalDigest(bundle), manifest_digest: inspected.manifest.digest, runtime: inspected.manifest.value.runtime, entrypoint: inspected.manifest.value.entrypoint, approval_required: true, risk_classification: "medium", mutation: "none", qualification_status: "not_proven", reason: "external_build_and_runtime_not_configured" };
  if (action === "prepare") return prepare;
  if (action === "publish") {
    if (!flags.planOnly) throw new Error("publish requires --plan-only until protected provider qualification is configured");
    return { ...prepare, action: "publish", deployment: "not_started", qualification_status: "not_proven", reason: "plan_only_does_not_contact_provider" };
  }
  throw new Error(`unknown small-software action: ${action}`);
}

export function smallSoftwareCommand(action, argv = []) {
  return runSmallSoftwareCli(action, argv);
}

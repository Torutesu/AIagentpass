#!/usr/bin/env node

import { createHash } from "node:crypto";

import { canonicalJson } from "./report.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const SAFE_BROWSER_VERSION = /^[0-9][0-9A-Za-z._+-]{0,63}$/u;
const SAFE_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u;
const ABSOLUTE_PATH = /(?:^|[\s=])(?:\/(?:[^\s/]+\/)*[^\s/]+|[A-Za-z]:\\[^\s]+|file:\/\/)/u;
const USERINFO_URL = /\b[a-z][a-z0-9+.-]{1,31}:\/\/[^\s/@]+(?::[^\s/@]*)?@/iu;
const PEM = /-----BEGIN [^-\n]+ KEY-----/u;
const SECRET_ASSIGNMENT = /(?:credential|cookie|csrf|nonce|private[-_ ]?key|public[-_ ]?key|secret|password|bearer|authorization|token)\s*[:=]/iu;
const UNSAFE_KEY = /(?:^|[_.-])(credential|cookie|csrf|nonce|api[-_ ]?key|access[-_ ]?key|client[-_ ]?secret|refresh[-_ ]?token|session[-_ ]?token|private[-_ ]?key|public[-_ ]?key|key[-_ ]?material|secret|password|bearer|authorization|token|path|pathname|cwd|argv|environment|env)(?:$|[_.-])/iu;
const RAW_OUTPUT_KEYS = new Set(["stdout", "stderr", "output", "raw_output", "command_output"]);
const SAFE_DIGEST_KEY = /(?:^|_)(?:sha256|digest)$/u;
const MAX_DEPTH = 8;
const MAX_NODES = 512;
const MAX_STRING_LENGTH = 4096;

export class RuntimeEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = "RuntimeEvidenceError";
    this.code = code;
  }
}

function fail(code) {
  throw new RuntimeEvidenceError(code);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateBrowserVersion(value) {
  if (typeof value !== "string" || !SAFE_BROWSER_VERSION.test(value)) fail("invalid_browser_version");
  return value;
}

function validateSafeString(value) {
  if (typeof value !== "string" || value.length > MAX_STRING_LENGTH || value.includes("\u0000")) {
    fail("unsafe_metadata");
  }
  if (/\p{Cc}/u.test(value) || ABSOLUTE_PATH.test(value) || USERINFO_URL.test(value) || PEM.test(value) || SECRET_ASSIGNMENT.test(value)) {
    fail("unsafe_metadata");
  }
}

function validateSafeMetadata(value, depth, state) {
  if (depth > MAX_DEPTH || state.nodes++ >= MAX_NODES) fail("metadata_too_large");

  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    validateSafeString(value);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("unsafe_metadata");
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) validateSafeMetadata(item, depth + 1, state);
    return;
  }
  if (!isPlainObject(value)) fail("unsafe_metadata");

  for (const [key, child] of Object.entries(value)) {
    if (!SAFE_KEY.test(key) || key === "__proto__" || key === "constructor" || key === "prototype") fail("unsafe_metadata");
    const normalizedKey = key.toLowerCase();
    if (RAW_OUTPUT_KEYS.has(normalizedKey) || (UNSAFE_KEY.test(key) && !SAFE_DIGEST_KEY.test(normalizedKey))) {
      fail("unsafe_metadata");
    }
    if (SAFE_DIGEST_KEY.test(normalizedKey) && child !== null && (typeof child !== "string" || !/^(?:sha256:)?[0-9a-f]{64}$/u.test(child))) {
      fail("unsafe_metadata");
    }
    validateSafeMetadata(child, depth + 1, state);
  }
}

/**
 * Collects metadata from the same Playwright Chromium used by the E2E lane.
 *
 * `chromium` is injected so this module has no Playwright dependency of its
 * own. `browser` is an optional already-launched browser for deterministic
 * tests; when omitted, chromium.launch({ headless: true }) is used.
 */
export async function collectBrowserMetadata({ chromium, browser } = {}) {
  if (browser !== undefined && (chromium !== undefined || browser === null || typeof browser !== "object")) {
    fail("invalid_browser_injection");
  }
  if (browser === undefined && (chromium === null || typeof chromium !== "object" || typeof chromium.launch !== "function")) {
    fail("browser_unavailable");
  }

  let activeBrowser = browser;
  let result;
  let failure;

  try {
    if (activeBrowser === undefined) activeBrowser = await chromium.launch({ headless: true });
    if (activeBrowser === null || typeof activeBrowser !== "object" || typeof activeBrowser.version !== "function" || typeof activeBrowser.close !== "function") {
      fail("invalid_browser");
    }
    result = {
      name: "Chromium",
      version: validateBrowserVersion(await activeBrowser.version()),
      engine: "Playwright"
    };
  } catch (error) {
    failure = error instanceof RuntimeEvidenceError ? error : new RuntimeEvidenceError("browser_metadata_failed");
  } finally {
    if (activeBrowser !== undefined && activeBrowser !== null && typeof activeBrowser.close === "function") {
      try {
        await activeBrowser.close();
      } catch {
        if (!failure) failure = new RuntimeEvidenceError("browser_close_failed");
      }
    }
  }

  if (failure) throw failure;
  return result;
}

/**
 * Hashes only bounded, JSON-safe qualification metadata.
 *
 * The digest is deliberately the bare lowercase SHA-256 hex string used by
 * the P0-B report's evidence_sha256 field. Raw output, paths, URLs with
 * credentials, and secret-bearing fields are rejected before serialization.
 */
export function evidenceDigest(metadata) {
  if (!isPlainObject(metadata)) fail("unsafe_metadata");
  validateSafeMetadata(metadata, 0, { nodes: 0 });
  try {
    return createHash("sha256").update(Buffer.from(canonicalJson(metadata), "utf8")).digest("hex");
  } catch {
    fail("unsafe_metadata");
  }
}

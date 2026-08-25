#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";

const SHA_ACTION = /^[^\s@]+@[0-9a-f]{40}$/u;
const REQUIRED_STEP_LOCAL_ENV = Object.freeze([
  "MANIFEST",
  "MANIFEST_SIGNATURE",
  "MANIFEST_PUBLIC_KEY",
  "DEPLOYMENT_TRUST_ROOT_PUBLIC_KEY",
  "ROUNDTRIP_EVIDENCE"
]);
const REQUIRED_STAGING_ENV = Object.freeze([
  "STAGING_READINESS_JSON",
  "STAGING_ROLLBACK_JSON",
  "STAGING_BINDING_JSON",
  "STAGING_READINESS_RESULT",
  "STAGING_ROLLBACK_RESULT"
]);

export class WorkflowYamlError extends Error {
  constructor(message, line) {
    super(`${message}${line ? ` (line ${line})` : ""}`);
    this.name = "WorkflowYamlError";
    this.line = line;
  }
}

/**
 * Parse the small, deliberately conservative YAML subset used by GitHub
 * Actions workflows. Keeping this parser here avoids an undeclared runtime
 * dependency while still giving us the important property for a security
 * validator: duplicate mapping keys are rejected instead of silently
 * overwritten. Block scalars are preserved as strings, including shell code.
 */
export function parseYaml(source) {
  if (typeof source !== "string") throw new TypeError("workflow YAML must be a string");
  const lines = source.replace(/^\uFEFF/u, "").split(/\r?\n/u);
  const state = { lines, index: 0 };
  const first = nextSignificant(state);
  if (!first) return null;
  const value = parseBlock(state, first.indent);
  const trailing = nextSignificant(state);
  if (trailing) throw new WorkflowYamlError("unexpected YAML content", trailing.line);
  return value;
}

function parseBlock(state, indent) {
  const current = nextSignificant(state);
  if (!current || current.indent < indent) return null;
  if (current.indent !== indent) {
    throw new WorkflowYamlError(`expected indentation ${indent}, found ${current.indent}`, current.line);
  }
  return current.content === "-" || current.content.startsWith("- ")
    ? parseSequence(state, indent)
    : parseMapping(state, indent);
}

function parseMapping(state, indent) {
  const object = {};
  const keyLines = new Map();
  while (true) {
    const current = nextSignificant(state);
    if (!current || current.indent < indent) break;
    if (current.indent !== indent || current.content === "-" || current.content.startsWith("- ")) {
      throw new WorkflowYamlError("invalid YAML mapping indentation", current.line);
    }
    state.index = current.index + 1;
    const pair = splitMappingEntry(current.content, current.line);
    const key = parseKey(pair.key, current.line);
    if (keyLines.has(key)) {
      throw new WorkflowYamlError(`duplicate YAML key ${JSON.stringify(key)}; previous definition is on line ${keyLines.get(key)}`, current.line);
    }
    keyLines.set(key, current.line);
    const parsed = parseValue(state, pair.value, indent, current.line);
    object[key] = parsed.value;
    state.index = parsed.index;
  }
  return object;
}

function parseSequence(state, indent) {
  const array = [];
  while (true) {
    const current = nextSignificant(state);
    if (!current || current.indent < indent) break;
    if (current.indent !== indent || !(current.content === "-" || current.content.startsWith("- "))) {
      throw new WorkflowYamlError("invalid YAML sequence indentation", current.line);
    }
    state.index = current.index + 1;
    const rest = current.content === "-" ? "" : current.content.slice(2).trim();
    if (!rest) {
      const child = nextSignificant(state);
      if (!child || child.indent <= indent) {
        array.push(null);
      } else {
        array.push(parseBlock(state, child.indent));
      }
      continue;
    }
    if (hasMappingColon(rest)) {
      const firstPair = splitMappingEntry(rest, current.line);
      const object = {};
      const keyLines = new Map();
      addMappingEntry(state, object, keyLines, firstPair, indent + 2, current.line);
      while (true) {
        const continuation = nextSignificant(state);
        if (!continuation || continuation.indent <= indent) break;
        if (continuation.indent !== indent + 2 || continuation.content === "-" || continuation.content.startsWith("- ")) {
          throw new WorkflowYamlError("invalid YAML sequence-item mapping indentation", continuation.line);
        }
        state.index = continuation.index + 1;
        addMappingEntry(state, object, keyLines, splitMappingEntry(continuation.content, continuation.line), indent + 2, continuation.line);
      }
      array.push(object);
      continue;
    }
    const parsed = parseValue(state, rest, indent, current.line);
    array.push(parsed.value);
    state.index = parsed.index;
  }
  return array;
}

function addMappingEntry(state, object, keyLines, pair, indent, line) {
  const key = parseKey(pair.key, line);
  if (keyLines.has(key)) {
    throw new WorkflowYamlError(`duplicate YAML key ${JSON.stringify(key)}; previous definition is on line ${keyLines.get(key)}`, line);
  }
  keyLines.set(key, line);
  const parsed = parseValue(state, pair.value, indent, line);
  object[key] = parsed.value;
  state.index = parsed.index;
}

function parseValue(state, rawValue, parentIndent, line) {
  const value = stripComment(rawValue.trim());
  if (value === "" || value === "~") {
    const child = nextSignificant(state);
    if (!child || child.indent <= parentIndent) return { value: null, index: state.index };
    return { value: parseBlock(state, child.indent), index: state.index };
  }
  if (/^[|>][+-]?\d*$/u.test(value)) {
    return parseBlockScalar(state, parentIndent, value[0] === ">", value.includes("-"));
  }
  return { value: parseScalar(value, line), index: state.index };
}

function parseBlockScalar(state, parentIndent, folded, stripFinalNewline) {
  const content = [];
  let minimumIndent;
  while (state.index < state.lines.length) {
    const raw = state.lines[state.index];
    const indent = indentation(raw);
    if (raw.trim() !== "" && indent <= parentIndent) break;
    state.index += 1;
    if (raw.trim() === "") {
      content.push("");
      continue;
    }
    minimumIndent ??= indent;
    content.push(raw.slice(minimumIndent));
  }
  let text;
  if (folded) {
    text = content.join(" ").replace(/\s*\n\s*/gu, " ");
  } else {
    text = content.join("\n");
  }
  if (!stripFinalNewline) text += "\n";
  return { value: text, index: state.index };
}

function parseScalar(value, line) {
  if (value.startsWith("*") || value.startsWith("&")) throw new WorkflowYamlError("YAML aliases and anchors are not allowed", line);
  if (value.startsWith("[") && value.endsWith("]")) {
    return splitTopLevel(value.slice(1, -1), ",").filter((item) => item.trim() !== "").map((item) => parseScalar(item.trim(), line));
  }
  if (value.startsWith("{") && value.endsWith("}")) {
    const object = {};
    const keyLines = new Map();
    for (const item of splitTopLevel(value.slice(1, -1), ",")) {
      const pair = splitMappingEntry(item.trim(), line);
      const key = parseKey(pair.key, line);
      if (keyLines.has(key)) throw new WorkflowYamlError(`duplicate YAML key ${JSON.stringify(key)} in inline mapping`, line);
      keyLines.set(key, line);
      object[key] = parseScalar(stripComment(pair.value.trim()), line);
    }
    return object;
  }
  if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
    if (value[0] === "'") return value.slice(1, -1).replace(/''/gu, "'");
    try { return JSON.parse(value); } catch { return value.slice(1, -1); }
  }
  if (/^(?:true|false)$/iu.test(value)) return value.toLowerCase() === "true";
  if (/^(?:null|~)$/iu.test(value)) return null;
  if (/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(value)) return Number(value);
  return value;
}

function parseKey(value, line) {
  const key = stripComment(value.trim());
  if (!key) throw new WorkflowYamlError("empty YAML mapping key", line);
  return parseScalar(key, line);
}

function splitMappingEntry(content, line) {
  const index = findTopLevelColon(content);
  if (index < 0) throw new WorkflowYamlError("expected a YAML mapping entry", line);
  return { key: content.slice(0, index), value: content.slice(index + 1) };
}

function hasMappingColon(content) {
  return findTopLevelColon(content) >= 0;
}

function findTopLevelColon(content) {
  let quote = null;
  let depth = 0;
  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    if (quote === "'" && char === "'" && content[index + 1] === "'") { index += 1; continue; }
    if (quote && char === quote) { quote = null; continue; }
    if (!quote && (char === "'" || char === '"')) { quote = char; continue; }
    if (!quote && "[{".includes(char)) depth += 1;
    if (!quote && "]}".includes(char)) depth -= 1;
    if (!quote && depth === 0 && char === ":" && (index + 1 === content.length || /\s/u.test(content[index + 1]))) return index;
  }
  return -1;
}

function splitTopLevel(content, separator) {
  const items = [];
  let start = 0;
  let quote = null;
  let depth = 0;
  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    if (quote === "'" && char === "'" && content[index + 1] === "'") { index += 1; continue; }
    if (quote && char === quote) { quote = null; continue; }
    if (!quote && (char === "'" || char === '"')) { quote = char; continue; }
    if (!quote && "[{".includes(char)) depth += 1;
    if (!quote && "]}".includes(char)) depth -= 1;
    if (!quote && depth === 0 && char === separator) { items.push(content.slice(start, index)); start = index + 1; }
  }
  items.push(content.slice(start));
  return items;
}

function stripComment(value) {
  let quote = null;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (quote === "'" && char === "'" && value[index + 1] === "'") { index += 1; continue; }
    if (quote && char === quote) { quote = null; continue; }
    if (!quote && (char === "'" || char === '"')) { quote = char; continue; }
    if (!quote && char === "#" && (index === 0 || /\s/u.test(value[index - 1]))) return value.slice(0, index).trimEnd();
  }
  return value;
}

function indentation(raw) {
  const match = raw.match(/^ */u);
  if (/^\t/u.test(raw)) throw new WorkflowYamlError("tabs are not allowed for YAML indentation");
  return match[0].length;
}

function nextSignificant(state) {
  let index = state.index;
  while (index < state.lines.length) {
    const raw = state.lines[index];
    const content = raw.trim();
    if (content !== "" && !content.startsWith("#") && content !== "---" && content !== "...") {
      return { index, line: index + 1, indent: indentation(raw), content: raw.slice(indentation(raw)) };
    }
    index += 1;
    state.index = index;
  }
  state.index = index;
  return null;
}

export function validatePromotionWorkflowText(source, { workflowPath = "<workflow>", repoRoot = process.cwd() } = {}) {
  const issues = [];
  let workflow;
  try {
    workflow = parseYaml(source);
  } catch (error) {
    issues.push(`YAML parse error: ${error.message}`);
    return report(workflowPath, issues);
  }
  if (!isRecord(workflow)) return report(workflowPath, ["workflow root must be a mapping"]);
  const jobs = workflow.jobs;
  if (!isRecord(jobs)) return report(workflowPath, ["workflow must define a jobs mapping"]);
  const promotion = jobs.promote;
  if (!isRecord(promotion)) return report(workflowPath, ["jobs.promote is required for the promotion workflow"]);
  const steps = promotion.steps;
  if (!Array.isArray(steps) || steps.length === 0) return report(workflowPath, ["jobs.promote.steps must be a non-empty sequence"]);

  validateImmutableActions(workflow, issues);
  const jobEnv = isRecord(promotion.env) ? promotion.env : {};
  const runTexts = [];
  const names = new Set();
  for (const [index, step] of steps.entries()) {
    if (!isRecord(step)) {
      issues.push(`jobs.promote.steps[${index + 1}] must be a mapping`);
      continue;
    }
    const label = String(step.name ?? step.id ?? `step ${index + 1}`);
    if (step.id !== undefined) {
      if (names.has(step.id)) issues.push(`duplicate promotion step id ${JSON.stringify(step.id)}`);
      names.add(step.id);
    }
    if (step.env !== undefined && !isRecord(step.env)) issues.push(`${label}: env must be a mapping`);
    const run = typeof step.run === "string" ? step.run : "";
    runTexts.push({ index, label, run, step });
    if (run.includes("scripts/ci-preflight.mjs")) {
      issues.push(`${label}: references nonexistent scripts/ci-preflight.mjs; use scripts/release/ci-preflight.mjs`);
    }
    if (run.includes("ci-preflight.mjs") && !run.includes("scripts/release/ci-preflight.mjs")) {
      issues.push(`${label}: ci-preflight must be invoked as scripts/release/ci-preflight.mjs`);
    }
    for (const variable of REQUIRED_STEP_LOCAL_ENV) {
      if (new RegExp(`\\b${variable}\\b`, "u").test(run) && !Object.prototype.hasOwnProperty.call(step.env ?? {}, variable)) {
        issues.push(`${label}: ${variable} is referenced by run but missing from step-local env`);
      }
    }
    if (run.includes("scripts/release/ci-preflight.mjs") && !fs.existsSync(path.join(repoRoot, "scripts/release/ci-preflight.mjs"))) {
      issues.push(`${label}: scripts/release/ci-preflight.mjs does not exist under ${repoRoot}`);
    }
  }

  const publishIndex = runTexts.findIndex(({ run }) => /gh\s+release\s+edit[\s\S]*--draft=false/u.test(run));
  if (publishIndex < 0) {
    issues.push("promotion job must publish with gh release edit ... --draft=false");
  } else {
    const verifiedRoundtripIndex = runTexts.findIndex(({ run, index }) => index < publishIndex && /release-asset-roundtrip/u.test(run) && /verifyReleaseAssetRoundTrip|writeFileSync/u.test(run));
    if (verifiedRoundtripIndex < 0) issues.push("release-asset roundtrip verification must run before publish");
    const retainedRoundtripIndex = runTexts.findIndex(({ run, index }) => index < publishIndex && /ROUNDTRIP_EVIDENCE/u.test(run) && /gh\s+release\s+upload/u.test(run));
    if (retainedRoundtripIndex < 0) issues.push("roundtrip evidence must be uploaded before publish");
    if (verifiedRoundtripIndex >= 0 && retainedRoundtripIndex >= 0 && verifiedRoundtripIndex > retainedRoundtripIndex) {
      issues.push("roundtrip evidence must be verified before it is uploaded");
    }
    const retainedEvidenceCheckIndex = runTexts.findIndex(({ run, index }) => index < publishIndex
      && /release-asset-roundtrip\.json/u.test(run)
      && /gh\s+release\s+download/u.test(run)
      && /cmp\s+-s/u.test(run)
      && /canonicalJson/u.test(run));
    if (retainedEvidenceCheckIndex < 0) issues.push("uploaded roundtrip evidence must be re-downloaded, byte-compared, and canonical-JSON checked before publish");
    if (retainedEvidenceCheckIndex >= 0 && retainedRoundtripIndex >= 0 && retainedEvidenceCheckIndex < retainedRoundtripIndex) {
      issues.push("uploaded roundtrip evidence must be checked after it is uploaded");
    }
  }

  const trustRootIndex = runTexts.findIndex(({ run }) => /DEPLOYMENT_TRUST_ROOT_PUBLIC_KEY/u.test(run));
  if (trustRootIndex < 0) {
    issues.push("promotion job must consume DEPLOYMENT_TRUST_ROOT_PUBLIC_KEY");
  } else if (!Object.prototype.hasOwnProperty.call(runTexts[trustRootIndex].step.env ?? {}, "DEPLOYMENT_TRUST_ROOT_PUBLIC_KEY")) {
    issues.push(`${runTexts[trustRootIndex].label}: DEPLOYMENT_TRUST_ROOT_PUBLIC_KEY must be step-local env`);
  }

  const stagingReadinessIndex = runTexts.findIndex(({ run }) => /scripts\/release\/staging-readiness\.mjs\s+verify/u.test(run));
  const stagingRollbackIndex = runTexts.findIndex(({ run }) => /scripts\/release\/staging-rollback\.mjs\s+verify/u.test(run));
  if (stagingReadinessIndex < 0) issues.push("promotion job must verify staging readiness with scripts/release/staging-readiness.mjs");
  if (stagingRollbackIndex < 0) issues.push("promotion job must verify staging rollback with scripts/release/staging-rollback.mjs");
  if (stagingReadinessIndex >= 0 && stagingRollbackIndex >= 0 && stagingRollbackIndex < stagingReadinessIndex) {
    issues.push("staging readiness must be verified before staging rollback");
  }
  for (const [label, required] of [["staging readiness", stagingReadinessIndex], ["staging rollback", stagingRollbackIndex]]) {
    if (required < 0) continue;
    const { run, step } = runTexts[required];
    for (const variable of REQUIRED_STAGING_ENV) {
      if (new RegExp(`\\b${variable}\\b`, "u").test(run) && !Object.prototype.hasOwnProperty.call(step.env ?? {}, variable)) {
        issues.push(`${label}: ${variable} must be step-local env`);
      }
    }
    if (!/--now=/u.test(run)) issues.push(`${label}: verification must use an explicit current UTC timestamp for expiry enforcement`);
    if (!/status|qualified/u.test(run)) issues.push(`${label}: verification result must be consumed as a qualified pass`);
  }
  const stagingBindingIndex = runTexts.findIndex(({ run }) => /STAGING_BINDING_JSON/u.test(run) && /candidate|deployment|digest/u.test(run));
  if (stagingBindingIndex < 0) issues.push("promotion job must bind staging evidence to candidate, deployment, and artifact digests");
  if (stagingReadinessIndex >= 0 && publishIndex >= 0 && stagingReadinessIndex > publishIndex) issues.push("staging readiness must be verified before publish");
  if (stagingRollbackIndex >= 0 && publishIndex >= 0 && stagingRollbackIndex > publishIndex) issues.push("staging rollback must be verified before publish");

  const cleanupIndex = runTexts.findIndex(({ step, run, index }) => index > publishIndex && /always\(\)/u.test(String(step.if ?? "")) && /rm\s+-rf/u.test(run));
  if (cleanupIndex < 0) issues.push("promotion job must have an after-publish cleanup step with if: ${{ always() }}");

  // Job-level env is intentionally read above: these are only used to make
  // the explicit step-local rules auditable and to reject malformed env maps.
  void jobEnv;
  return report(workflowPath, issues);
}

function validateImmutableActions(workflow, issues) {
  const visit = (value, location) => {
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${location}[${index}]`));
      return;
    }
    if (!isRecord(value)) return;
    for (const [key, child] of Object.entries(value)) {
      if (key === "uses") {
        if (typeof child !== "string" || !SHA_ACTION.test(child)) issues.push(`${location}.uses must pin an action to an immutable 40-character commit SHA; found ${JSON.stringify(child)}`);
      } else {
        visit(child, `${location}.${key}`);
      }
    }
  };
  visit(workflow, "workflow");
}

function report(workflowPath, issues) {
  return Object.freeze({ workflowPath, ok: issues.length === 0, issues: Object.freeze([...issues]) });
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validatePromotionWorkflow(workflowPath, options = {}) {
  if (typeof workflowPath !== "string" || workflowPath.length === 0) throw new TypeError("workflow path is required");
  let source;
  try {
    source = fs.readFileSync(workflowPath, "utf8");
  } catch (error) {
    throw new Error(`cannot read promotion workflow ${workflowPath}: ${error.message}`, { cause: error });
  }
  return validatePromotionWorkflowText(source, { ...options, workflowPath });
}

export function assertPromotionWorkflow(workflowPath, options = {}) {
  const result = validatePromotionWorkflow(workflowPath, options);
  if (!result.ok) throw new Error(formatIssues(result));
  return result;
}

function formatIssues(result) {
  return [`Promotion workflow validation failed for ${result.workflowPath}:`, ...result.issues.map((issue) => `- ${issue}`)].join("\n");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const workflowPath = process.argv[2];
  if (!workflowPath || process.argv.length > 3) {
    process.stderr.write("Usage: node scripts/release/validate-promotion-workflow.mjs <workflow-path>\n");
    process.exitCode = 2;
  } else {
    try {
      const result = validatePromotionWorkflow(workflowPath);
      if (!result.ok) {
        process.stderr.write(`${formatIssues(result)}\n`);
        process.exitCode = 1;
      } else {
        process.stdout.write(`Promotion workflow validation passed: ${workflowPath}\n`);
      }
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    }
  }
}

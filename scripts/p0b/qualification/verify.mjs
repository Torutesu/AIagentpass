#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";

import { readP0BQualificationReport, resolveSourceState } from "./report.mjs";

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

export async function verifyQualificationReport(inputFile, { repositoryRoot = REPOSITORY_ROOT } = {}) {
  const report = await readP0BQualificationReport(inputFile);
  const source = resolveSourceState(repositoryRoot);
  if (report.source_commit !== source.commit) throw stableError("source_commit_mismatch");
  if (report.overall.status !== "passed" || report.overall.failed_commands.length !== 0 || report.overall.failed_gates.length !== 0) {
    throw stableError("qualification_failed");
  }
  return Object.freeze({ report_digest: report.report_digest, source_commit: report.source_commit });
}

function stableError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [inputFile, ...extra] = process.argv.slice(2);
  if (!inputFile || extra.length !== 0 || !path.isAbsolute(inputFile)) {
    process.stderr.write("p0b-qualification-verify: invalid_arguments\n");
    process.exitCode = 2;
  } else {
    try {
      const result = await verifyQualificationReport(inputFile);
      process.stdout.write(`${result.report_digest}\n`);
    } catch (error) {
      const code = typeof error?.code === "string" && /^[a-z][a-z0-9_]*$/u.test(error.code) ? error.code : "verification_failed";
      process.stderr.write(`p0b-qualification-verify: ${code}\n`);
      process.exitCode = 1;
    }
  }
}

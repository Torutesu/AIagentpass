#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildKmsQualificationReport, KmsQualificationEvidenceError, writeKmsQualificationReport } from "./schema.mjs";

export { buildKmsQualificationReport, writeKmsQualificationReport } from "./schema.mjs";

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [inputFile, outputFile, ...extra] = process.argv.slice(2);
  if (!inputFile || !outputFile || extra.length !== 0 || !path.isAbsolute(inputFile) || !path.isAbsolute(outputFile)) {
    process.stderr.write("kms-qualification-report: invalid_arguments\n");
    process.exitCode = 2;
  } else {
    try {
      const input = JSON.parse(await fs.readFile(inputFile, "utf8"));
      const report = buildKmsQualificationReport(input);
      await writeKmsQualificationReport(outputFile, report);
      process.stdout.write(`${report.report_digest}\n`);
    } catch (error) {
      const code = error instanceof KmsQualificationEvidenceError ? error.code : "report_failed";
      process.stderr.write(`kms-qualification-report: ${/^[a-z][a-z0-9_]*$/u.test(code) ? code : "report_failed"}\n`);
      process.exitCode = 1;
    }
  }
}

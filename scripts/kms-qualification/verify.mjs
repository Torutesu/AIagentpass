#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { KmsQualificationEvidenceError, parseKmsQualificationReport, verifyKmsQualificationReport } from "./schema.mjs";

export { parseKmsQualificationReport, verifyKmsQualificationReport } from "./schema.mjs";

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [inputFile, trustedPublicKeyFile, trustedKeyId, ...extra] = process.argv.slice(2);
  if (!inputFile || !trustedPublicKeyFile || !trustedKeyId || extra.length !== 0
    || !path.isAbsolute(inputFile) || !path.isAbsolute(trustedPublicKeyFile)) {
    process.stderr.write("kms-qualification-verify: invalid_arguments\n");
    process.exitCode = 2;
  } else {
    try {
      const report = parseKmsQualificationReport(await fs.readFile(inputFile));
      const trustedPublicKeyDer = await fs.readFile(trustedPublicKeyFile);
      const result = verifyKmsQualificationReport(report, { trustedPublicKeyDer, trustedKeyId });
      process.stdout.write(`${result.report_digest}\n`);
    } catch (error) {
      const code = error instanceof KmsQualificationEvidenceError ? error.code : "verification_failed";
      process.stderr.write(`kms-qualification-verify: ${/^[a-z][a-z0-9_]*$/u.test(code) ? code : "verification_failed"}\n`);
      process.exitCode = 1;
    }
  }
}

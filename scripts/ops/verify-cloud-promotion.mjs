#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { parseKmsQualificationReport, verifyKmsQualificationReport } from "../kms-qualification/schema.mjs";
import { readCloudDeploymentEvidence, verifyCloudDeploymentEvidence } from "./verify-cloud-deployment.mjs";

const USAGE = "cloud-promotion-verify: invalid_arguments";

export async function verifyCloudPromotion({
  deploymentEvidencePath,
  deploymentPublicKeyPath,
  deploymentPublicKeyFingerprint,
  kmsReportPath,
  kmsTrustedPublicKeyPath,
  kmsTrustedKeyId,
  repositoryRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url))),
  kmsVerifier = verifyKmsQualificationReport
} = {}) {
  const { evidence, publicKey } = readCloudDeploymentEvidence(deploymentEvidencePath, deploymentPublicKeyPath);
  const deployment = verifyCloudDeploymentEvidence(evidence, { publicKey, expectedFingerprint: deploymentPublicKeyFingerprint });
  const reportBytes = await fs.readFile(kmsReportPath);
  const report = parseKmsQualificationReport(reportBytes);
  const trustedKey = await fs.readFile(kmsTrustedPublicKeyPath);
  const qualification = kmsVerifier(report, {
    repositoryRoot,
    trustedPublicKeyDer: trustedKey,
    trustedKeyId: kmsTrustedKeyId,
    requireProduction: true
  });
  if (deployment.commit_sha !== qualification.source_commit) throw new Error("promotion source commit mismatch");
  if (deployment.artifact_digest !== report.source.image_digest) throw new Error("promotion image digest mismatch");
  return Object.freeze({
    status: "verified",
    source_commit: qualification.source_commit,
    image_digest: report.source.image_digest,
    deployment_evidence_sha256: qualificationDigest(deployment),
    kms_report_digest: qualification.report_digest,
    provider: qualification.provider,
    service: deployment.service,
    revision: deployment.revision
  });
}

function qualificationDigest(value) {
  return crypto.createHash("sha256").update(`${JSON.stringify(value)}\n`, "utf8").digest("hex");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [deploymentEvidencePath, deploymentPublicKeyPath, deploymentFingerprint, kmsReportPath, kmsTrustedPublicKeyPath, kmsTrustedKeyId, ...extra] = process.argv.slice(2);
  if (!deploymentEvidencePath || !deploymentPublicKeyPath || !deploymentFingerprint || !kmsReportPath || !kmsTrustedPublicKeyPath || !kmsTrustedKeyId || extra.length > 1) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
  } else {
    try {
      const result = await verifyCloudPromotion({
        deploymentEvidencePath,
        deploymentPublicKeyPath,
        deploymentPublicKeyFingerprint: deploymentFingerprint,
        kmsReportPath,
        kmsTrustedPublicKeyPath,
        kmsTrustedKeyId,
        ...(extra.length === 1 ? { repositoryRoot: extra[0] } : {})
      });
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } catch {
      process.stderr.write("cloud-promotion-verify: rejected\n");
      process.exitCode = 1;
    }
  }
}

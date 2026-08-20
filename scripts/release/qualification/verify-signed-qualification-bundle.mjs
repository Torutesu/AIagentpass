#!/usr/bin/env node
import { parseBundleArguments, verifySignedQualificationBundle } from "./qualification-bundle.mjs";

try {
  const options = parseBundleArguments(process.argv.slice(2));
  const required = ["repository", "sourceSha", "releaseTag", "candidateArtifactName", "candidateArtifactDigest", "releaseRunId", "qualificationRunId", "cloudQualificationRunId", "macosQualificationRunId", "ciRunId", "manifest", "package", "summary", "dispatchBinding", "qualificationRoot", "bundle", "signature", "publicKey", "fingerprint"];
  if (required.some((name) => !options[name]) || Object.keys(options).some((name) => !required.includes(name))) throw new Error("invalid qualification bundle arguments");
  process.stdout.write(`${JSON.stringify(verifySignedQualificationBundle({ ...options, bundlePath: options.bundle, signaturePath: options.signature, publicKeyPath: options.publicKey, expectedFingerprint: options.fingerprint, manifestPath: options.manifest, packagePath: options.package, summaryPath: options.summary, dispatchBindingPath: options.dispatchBinding }))}\n`);
} catch (error) {
  process.stderr.write(`qualification-bundle-verify: ${error.message}\n`);
  process.exitCode = 1;
}

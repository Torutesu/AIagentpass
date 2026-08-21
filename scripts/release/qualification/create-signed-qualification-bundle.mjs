#!/usr/bin/env node
import { createSignedQualificationBundle, parseBundleArguments } from "./qualification-bundle.mjs";

try {
  const options = parseBundleArguments(process.argv.slice(2));
  const required = ["repository", "sourceSha", "releaseTag", "candidateArtifactName", "candidateArtifactDigest", "releaseRunId", "qualificationRunId", "cloudQualificationRunId", "macosQualificationRunId", "ciRunId", "manifest", "package", "summary", "dispatchBinding", "qualificationRoot", "output", "signature", "privateKey"];
  if (required.some((name) => !options[name]) || Object.keys(options).some((name) => !required.includes(name))) throw new Error("invalid qualification bundle arguments");
  process.stdout.write(`${JSON.stringify(createSignedQualificationBundle({
    ...options,
    manifestPath: options.manifest,
    packagePath: options.package,
    summaryPath: options.summary,
    dispatchBindingPath: options.dispatchBinding,
    qualificationRoot: options.qualificationRoot,
    outputPath: options.output,
    signaturePath: options.signature,
    privateKeyPath: options.privateKey
  }))}\n`);
} catch (error) {
  process.stderr.write(`qualification-bundle-create: ${error.message}\n`);
  process.exitCode = 1;
}

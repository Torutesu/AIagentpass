#!/usr/bin/env node

import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { basename, isAbsolute, resolve } from "node:path";

const KIND = "agentpass.macos-distribution-provenance-v1";
const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_SHA = /^[0-9a-f]{40}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RUN_ATTEMPT = /^[1-9][0-9]{0,5}$/u;
const REPOSITORY = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})?$/u;
const RELEASE_TAG = /^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$/u;
const RUNNER_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}$/u;
const LOCAL_MARKER = /(?:^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|sandbox|test|macos-latest)(?:$|[._:/ -])/iu;
const OUTPUT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

const USAGE = "Usage: create-macos-distribution-provenance.mjs ARTIFACT_SHA256 SOURCE_COMMIT SOURCE_TREE REPOSITORY RELEASE_TAG CI_RUN_ID CI_RUN_ATTEMPT VERIFICATION_RUN_ID VERIFICATION_JOB_ID RUNNER_ID OUTPUT";

function fail(message) {
  throw new Error(message);
}

function required(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) fail(`${label} has invalid grammar`);
  return value;
}

function outputPath(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")
    || !isAbsolute(value) || resolve(value) !== value || !OUTPUT_NAME.test(basename(value))) {
    fail("output has invalid grammar");
  }
  return value;
}

function canonicalJson(value) {
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${JSON.stringify(value[key])}`).join(",")}}`;
}

async function writeOnce(file, value) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  let handle;
  try {
    handle = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    if (error?.code === "EEXIST") fail("output already exists");
    throw error;
  } finally {
    await handle?.close();
  }
}

async function main(argv) {
  if (argv.length !== 11) fail(USAGE);

  const [artifactSha256, sourceCommit, sourceTree, repository, releaseTag, ciRunId, ciRunAttempt, verificationRunId, verificationJobId, runnerId, output] = argv;
  required(artifactSha256, SHA256, "artifact_sha256");
  required(sourceCommit, SOURCE_SHA, "source_commit");
  required(sourceTree, SOURCE_SHA, "source_tree");
  required(repository, REPOSITORY, "repository");
  required(releaseTag, RELEASE_TAG, "release_tag");
  required(ciRunId, RUN_ID, "ci_run_id");
  required(ciRunAttempt, RUN_ATTEMPT, "ci_run_attempt");
  required(verificationRunId, RUN_ID, "verification_run_id");
  required(verificationJobId, RUN_ID, "verification_job_id");
  required(runnerId, RUNNER_ID, "runner_id");
  if (LOCAL_MARKER.test(runnerId)) fail("runner_id contains a local marker");
  if (ciRunId === verificationRunId) fail("ci_run_id and verification_run_id must be distinct");
  const target = outputPath(output);

  const provenance = {
    artifact_sha256: artifactSha256,
    ci_run_attempt: ciRunAttempt,
    ci_run_id: ciRunId,
    kind: KIND,
    release_tag: releaseTag,
    repository,
    runner_id: runnerId,
    source_commit: sourceCommit,
    source_tree: sourceTree,
    verification_job_id: verificationJobId,
    verification_run_id: verificationRunId
  };
  await writeOnce(target, provenance);
  process.stdout.write(`${JSON.stringify({ status: "written", output: target, kind: KIND })}\n`);
}

try {
  await main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

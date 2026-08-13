#!/usr/bin/env node
import { createCloudRuntime } from "./runtime.mjs";
import { createHostedKmsProviders } from "./kms-provider-runtime.mjs";

let signerProviders;
let runtime;
try {
  signerProviders = process.env.AGENTPASS_CLOUD_PROFILE === "hosted"
    ? await createHostedKmsProviders({ env: process.env })
    : {};
  runtime = await createCloudRuntime({ ...signerProviders });
  await runtime.listen();
} catch (error) {
  await signerProviders?.close?.().catch(() => {});
  throw error;
}
let stopping = false;
async function stop(signal) {
  if (stopping) return;
  stopping = true;
  try {
    await runtime.close();
    process.exitCode = 0;
  } catch (error) {
    console.error(`AgentPass Cloud API shutdown failed after ${signal}: ${error.message}`);
    process.exitCode = 1;
  } finally {
    await signerProviders?.close?.().catch((error) => {
      console.error(`AgentPass Cloud KMS shutdown failed after ${signal}: ${error.message}`);
      process.exitCode = 1;
    });
  }
}
process.once("SIGINT", () => void stop("SIGINT"));
process.once("SIGTERM", () => void stop("SIGTERM"));

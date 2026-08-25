#!/usr/bin/env node
import { createCloudRuntime } from "./runtime.mjs";

let runtime;
try {
  const env = Object.freeze({ ...process.env });
  runtime = await createCloudRuntime({ env });
  await runtime.listen();
} catch (error) {
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
  }
}
process.once("SIGINT", () => void stop("SIGINT"));
process.once("SIGTERM", () => void stop("SIGTERM"));

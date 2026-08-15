import { createInterface } from "node:readline";
import crypto from "node:crypto";

import { Pool } from "pg";

import {
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES as REPOSITORY_ERROR_CODES,
  createPostgresHostedIdentityBootstrapRepository
} from "../../src/postgres/hosted-identity-bootstrap-repository.mjs";

const MODES = new Set(["claim_hold", "takeover_complete", "stale_complete", "complete_hold", "replay"]);
const COMMANDS = new Set(["hold", "complete"]);
const MAX_INPUT_BYTES = 2 * 1024;

const mode = process.argv[2];
const fixture = parseFixture(process.env.AGENTPASS_HOSTED_WEBAUTHN_PROCESS_LOSS_FIXTURE);
const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
const commandWaiters = [];
let inputClosed = false;

input.on("line", (line) => {
  if (Buffer.byteLength(line, "utf8") > MAX_INPUT_BYTES) return fail();
  let value;
  try { value = JSON.parse(line); } catch { return fail(); }
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 1 || !COMMANDS.has(value.type)) return fail();
  const waiter = commandWaiters.shift();
  if (waiter) waiter.resolve(value.type);
});
input.once("close", () => {
  inputClosed = true;
  while (commandWaiters.length > 0) commandWaiters.shift().reject(new Error("child input closed"));
});

if (!MODES.has(mode) || !databaseUrl) fail();

const pool = new Pool({
  connectionString: databaseUrl,
  max: 1,
  connectionTimeoutMillis: 2_000,
  idleTimeoutMillis: 500,
  statement_timeout: 10_000,
  query_timeout: 12_000,
  allowExitOnIdle: false
});
const repository = createPostgresHostedIdentityBootstrapRepository({ client: pool });

try {
  if (mode === "claim_hold") {
    const claimed = await claim("stale");
    await send({ type: "claimed", generation: claimed.claim_generation });
    await command("hold");
  } else if (mode === "takeover_complete") {
    const claimed = await claim("replacement");
    await send({ type: "claimed", generation: claimed.claim_generation });
    await command("complete");
    const completed = await complete("replacement", claimed.claim_generation);
    if (completed.replayed) throw new Error("unexpected replay");
    await send({ type: "completed", replayed: false });
  } else if (mode === "stale_complete") {
    try {
      await complete("stale", 1);
      throw new Error("stale completion was accepted");
    } catch (error) {
      if (error?.code !== REPOSITORY_ERROR_CODES.CONFLICT) throw error;
      await send({ type: "stale_fenced" });
    }
  } else if (mode === "complete_hold") {
    const claimed = await claim("response");
    const completed = await complete("response", claimed.claim_generation);
    if (completed.replayed) throw new Error("unexpected replay");
    await send({ type: "committed", replayed: false });
    await command("hold");
  } else if (mode === "replay") {
    const claimed = await optionalClaim("response");
    if (!claimed) {
      await send({ type: "replay_exhausted" });
    } else {
      const completed = await complete("response", claimed.claim_generation);
      if (!completed.replayed) throw new Error("replay was not marked as replayed");
      await send({ type: "replayed" });
    }
  }
  await pool.end();
  closeInput();
} catch {
  await send({ type: "error", code: "CHILD_FAILURE" }).catch(() => {});
  await pool.end().catch(() => {});
  closeInput();
  process.exitCode = 1;
}

async function claim(label) {
  const result = await repository.claimChallengeV2({
    bootstrap_cookie: raw("cookie"),
    challenge_id: fixture.challengeId,
    challenge: raw("challenge"),
    claim_token: raw(`claim:${label}`)
  });
  if (!result) throw new Error("claim unavailable");
  return result;
}

async function optionalClaim(label) {
  return repository.claimChallengeV2({
    bootstrap_cookie: raw("cookie"),
    challenge_id: fixture.challengeId,
    challenge: raw("challenge"),
    claim_token: raw(`claim:${label}`)
  });
}

async function complete(label, generation) {
  return repository.completeWebAuthnRegistrationV3({
    attempt_id: fixture.attemptId,
    bootstrap_cookie: raw("cookie"),
    challenge_id: fixture.challengeId,
    challenge: raw("challenge"),
    claim_token: raw(`claim:${label}`),
    claim_generation: Number(generation),
    credential: {
      id: raw("credential"),
      public_key: Buffer.alloc(65, 0x33),
      sign_count: 0,
      transports: ["internal"],
      label: "N1 qualification passkey",
      backup_eligible: false,
      backup_state: false
    },
    session: {
      token: raw("session"),
      csrf_token: raw("csrf")
    }
  });
}

function raw(label) {
  return crypto.createHash("sha256").update(`${fixture.seed}:${label}`, "utf8").digest("base64url");
}

function parseFixture(value) {
  if (typeof value !== "string") throw new Error("fixture missing");
  let parsed;
  try { parsed = JSON.parse(value); } catch { throw new Error("fixture invalid"); }
  if (!parsed || typeof parsed !== "object" || typeof parsed.seed !== "string"
    || typeof parsed.attemptId !== "string" || typeof parsed.challengeId !== "string"
    || !parsed.attemptId || !parsed.challengeId) {
    throw new Error("fixture invalid");
  }
  return parsed;
}

function command(expected) {
  if (inputClosed) return Promise.reject(new Error("child input closed"));
  return new Promise((resolve, reject) => commandWaiters.push({ expected, resolve: (value) => value === expected ? resolve(value) : reject(new Error("unexpected child command")), reject }));
}

function send(message) {
  return new Promise((resolve, reject) => {
    process.stdout.write(`${JSON.stringify(message)}\n`, (error) => error ? reject(error) : resolve());
  });
}

function closeInput() {
  input.close();
  process.stdin.destroy();
}

function fail() {
  process.exitCode = 1;
  throw new Error("invalid child protocol");
}

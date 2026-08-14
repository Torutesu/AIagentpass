import { createInterface } from "node:readline";

const BOUNDARIES = new Set([
  "after_claim",
  "before_provider_call",
  "after_provider_acceptance",
  "before_terminal_commit",
  "after_terminal_commit",
  "after_response_encoded"
]);
const STATES = new Set(["pending", "published", "uncertain", "dead_letter", "suppressed"]);
const DELIVERY_BINDING = Object.freeze({ binding_id: "test-owner-recovery", key_version: 1, binding_digest: "e".repeat(64) });
const options = parseOptions(process.argv.slice(2));
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
const commands = [];
const commandWaiters = [];
let inputClosed = false;

input.on("line", (line) => {
  if (Buffer.byteLength(line, "utf8") > 4 * 1024) return fail();
  try {
    const command = JSON.parse(line);
    if (!command || typeof command !== "object" || Array.isArray(command) || Object.keys(command).length !== 1 || !new Set(["run", "continue"]).has(command.type)) return fail();
    const waiter = commandWaiters.shift();
    if (waiter) {
      if (command.type === waiter.expected) waiter.resolve(command);
      else waiter.reject(new Error());
    }
    else commands.push(command);
  } catch {
    fail();
  }
});
input.once("close", () => {
  inputClosed = true;
  while (commandWaiters.length > 0) commandWaiters.shift().reject(new Error());
});

try {
  if (options.mode === "contract_noisy") {
    process.stdout.write("x".repeat(64 * 1024));
    process.exit(0);
  }
  if (options.mode === "contract") await runContract();
  else if (options.mode === "delivery") await runDelivery();
  else if (options.mode === "reclaim") await runReclaim();
  else fail();
} catch {
  await send({ type: "error", code: "CHILD_FAILURE" }).catch(() => {});
  closeInput();
  process.exitCode = 1;
}

async function runContract() {
  await send({ type: "ready" });
  await command("run");
  await gate(options.boundary);
  await send({ type: "completed", outcome: "published" });
  closeInput();
}

async function runDelivery() {
  const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
  if (typeof databaseUrl !== "string" || databaseUrl.length === 0) throw new Error();
  const [{ Pool }, { createPostgresOwnerRecoveryOutboxRepository }, { createOwnerRecoveryOutboxWorker }] = await Promise.all([
    import("pg"),
    import("../../src/postgres/owner-recovery-outbox-repository.mjs"),
    import("../../src/postgres/owner-recovery-outbox-worker.mjs")
  ]);
  const pool = new Pool({
    connectionString: databaseUrl,
    max: 2,
    connectionTimeoutMillis: 1_000,
    idleTimeoutMillis: 500,
    statement_timeout: 3_000,
    query_timeout: 4_000,
    allowExitOnIdle: false
  });
  try {
    const base = createPostgresOwnerRecoveryOutboxRepository({ client: pool, deliveryBinding: DELIVERY_BINDING });
    const repository = {
      binding: DELIVERY_BINDING,
      async claimBatch(value) {
        const result = await base.claimBatch(value);
        await gate("after_claim");
        return result;
      },
      async markPublished(value) {
        await gate("before_terminal_commit");
        const result = await base.markPublished(value);
        await gate("after_terminal_commit");
        return result;
      },
      markFailed: (value) => base.markFailed(value),
      markUncertain: (value) => base.markUncertain(value)
    };
    const worker = createOwnerRecoveryOutboxWorker({
      repository,
      publisher: {
        binding: DELIVERY_BINDING,
        async publish(inputValue) {
          await gate("before_provider_call");
          const response = { accepted: true, duplicate: false, idempotency_key: inputValue.idempotency_key };
          await gate("after_provider_acceptance");
          await gate("after_response_encoded");
          return response;
        }
      },
      leaseMs: options.leaseMs,
      publishTimeoutMs: 100,
      drainTimeoutMs: 100,
      pollIntervalMs: 100
    });
    await send({ type: "ready" });
    await command("run");
    const result = await worker.runOnce();
    await send({ type: "completed", outcome: result.published === 1 ? "published" : result.uncertain === 1 ? "uncertain" : "claim_lost" });
  } finally {
    await pool.end().catch(() => {});
  }
  closeInput();
}

async function runReclaim() {
  const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
  if (typeof databaseUrl !== "string" || databaseUrl.length === 0) throw new Error();
  const [{ Pool }, { createPostgresOwnerRecoveryOutboxRepository }] = await Promise.all([
    import("pg"),
    import("../../src/postgres/owner-recovery-outbox-repository.mjs")
  ]);
  const pool = new Pool({ connectionString: databaseUrl, max: 2, connectionTimeoutMillis: 1_000, idleTimeoutMillis: 500, statement_timeout: 3_000, query_timeout: 4_000, allowExitOnIdle: false });
  try {
    const repository = createPostgresOwnerRecoveryOutboxRepository({ client: pool, deliveryBinding: DELIVERY_BINDING });
    await send({ type: "ready" });
    await command("run");
    const result = await repository.claimBatch({ limit: 1, lease_ms: options.leaseMs });
    const state = await pool.query("SELECT status FROM owner_recovery_outbox WHERE organization_id=$1 AND event_id=$2", [options.organizationId, options.eventId]);
    const value = state.rows[0]?.status;
    if (!STATES.has(value)) throw new Error();
    await send({ type: "reclaimed", state: value, claimed: result.events.length });
  } finally {
    await pool.end().catch(() => {});
  }
  closeInput();
}

async function gate(boundary) {
  if (options.boundary !== boundary) return;
  await send({ type: "boundary_reached", boundary });
  const next = await command("continue");
  if (next.type !== "continue") throw new Error();
}

function command(expected) {
  const index = commands.findIndex((value) => value.type === expected);
  if (index !== -1) return Promise.resolve(commands.splice(index, 1)[0]);
  if (inputClosed) return Promise.reject(new Error());
  return new Promise((resolve, reject) => commandWaiters.push({ expected, resolve, reject }));
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
  throw new Error();
}

function parseOptions(args) {
  const result = {};
  for (const arg of args) {
    const match = /^(--mode|--boundary|--organization-id|--event-id|--lease-ms)=(.*)$/u.exec(arg);
    if (!match || result[match[1]] !== undefined) throw new Error();
    result[match[1]] = match[2];
  }
  const mode = result["--mode"];
  const boundary = result["--boundary"];
  if (!["contract", "contract_noisy", "delivery", "reclaim"].includes(mode)) throw new Error();
  if (boundary !== undefined && !BOUNDARIES.has(boundary)) throw new Error();
  if ((mode === "delivery" || mode === "reclaim") && (!result["--organization-id"] || !result["--event-id"])) throw new Error();
  const leaseMs = Number(result["--lease-ms"] ?? 1_500);
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 300_000) throw new Error();
  return Object.freeze({
    mode,
    boundary,
    organizationId: result["--organization-id"],
    eventId: result["--event-id"],
    leaseMs
  });
}

import { createInterface } from "node:readline";

const options = parseOptions(process.argv.slice(2));
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
const commands = [];
const waiters = [];
let inputClosed = false;

input.on("line", (line) => {
  if (Buffer.byteLength(line, "utf8") > 2 * 1024) return fail();
  try {
    const command = JSON.parse(line);
    if (!command || typeof command !== "object" || Array.isArray(command)
      || Object.keys(command).length !== 1 || command.type !== "run") return fail();
    const waiter = waiters.shift();
    if (waiter) waiter.resolve(command);
    else commands.push(command);
  } catch { fail(); }
});
input.once("close", () => {
  inputClosed = true;
  while (waiters.length > 0) waiters.shift().reject(new Error());
});

try {
  const [{ Pool }, { createMigrationRunner }, { createPostgresOwnerRecoveryOutboxRepository }, { createOwnerRecoveryOutboxWorker }, ledgerModule] = await Promise.all([
    import("pg"),
    import("../../src/postgres/migration-runner.mjs"),
    import("../../src/postgres/owner-recovery-outbox-repository.mjs"),
    import("../../src/postgres/owner-recovery-outbox-worker.mjs"),
    import("./owner-recovery-provider-acceptance-ledger.mjs")
  ]);
  const pool = new Pool({ connectionString: process.env.AGENTPASS_TEST_DATABASE_URL, max: 2, connectionTimeoutMillis: 1_000, idleTimeoutMillis: 500, statement_timeout: 3_000, query_timeout: 4_000, allowExitOnIdle: false });
  try {
    const migrationClient = await pool.connect();
    try { await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-provider-acceptance-child" }).run(); }
    finally { migrationClient.release(); }
    await ledgerModule.ensureOwnerRecoveryProviderAcceptanceLedger(pool);
    const ledger = ledgerModule.createOwnerRecoveryProviderAcceptanceLedger({ client: pool });
    const repository = createPostgresOwnerRecoveryOutboxRepository({ client: pool, deliveryBinding: options.binding });
    const provider = ledgerModule.createOwnerRecoveryFakeProvider({
      ledger,
      binding: options.binding,
      afterAcceptance: async (response) => {
        await send({ type: "accepted", duplicate: response.duplicate });
        await new Promise(() => {});
      }
    });
    const worker = createOwnerRecoveryOutboxWorker({ repository, publisher: provider, leaseMs: options.leaseMs, publishTimeoutMs: 100, drainTimeoutMs: 100, pollIntervalMs: 100 });
    await send({ type: "ready" });
    await command();
    await worker.runOnce();
  } finally {
    await pool.end().catch(() => {});
  }
} catch {
  await send({ type: "error" }).catch(() => {});
  process.exitCode = 1;
}

function parseOptions(args) {
  const values = Object.create(null);
  for (const argument of args) {
    const match = /^--([a-z-]+)=(.*)$/u.exec(argument);
    if (!match) throw new Error();
    values[match[1]] = match[2];
  }
  if (values["lease-ms"] === undefined || !/^\d+$/u.test(values["lease-ms"])) throw new Error();
  const leaseMs = Number(values["lease-ms"]);
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 5 * 60_000) throw new Error();
  const binding = {
    binding_id: values["binding-id"],
    key_version: Number(values["key-version"]),
    binding_digest: values["binding-digest"]
  };
  if (typeof binding.binding_id !== "string" || !/^test-owner-recovery-[a-z0-9-]{8,64}$/u.test(binding.binding_id)
    || !Number.isSafeInteger(binding.key_version) || binding.key_version < 1 || binding.key_version > 2_147_483_647
    || typeof binding.binding_digest !== "string" || !/^[0-9a-f]{64}$/u.test(binding.binding_digest)) throw new Error();
  return Object.freeze({ leaseMs, binding });
}

async function send(message) {
  const line = `${JSON.stringify(message)}\n`;
  if (Buffer.byteLength(line, "utf8") > 2 * 1024 || !process.stdout.write(line)) await onceDrain();
}

function onceDrain() { return new Promise((resolve) => process.stdout.once("drain", resolve)); }

function command() {
  if (commands.length > 0) return Promise.resolve(commands.shift());
  if (inputClosed) return Promise.reject(new Error());
  return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
}

function fail() {
  input.close();
  process.exitCode = 1;
}

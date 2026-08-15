import assert from "node:assert/strict";
import crypto from "node:crypto";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const CHILD_PATH = fileURLToPath(new URL("../support/hosted-webauthn-process-loss-child.mjs", import.meta.url));
const REPOSITORY_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const RP_ID = "console.example.test";
const ORIGIN = "https://console.example.test";
const REDIRECT_URI = `${ORIGIN}/api/auth/bootstrap/github/callback`;
const TEST_TIMEOUT_MS = 45_000;
const CHILD_TIMEOUT_MS = 12_000;
const MAX_CHILD_OUTPUT_BYTES = 32 * 1024;

test("N1 Hosted WebAuthn process loss is fenced and response recovery is exactly once", {
  skip: !databaseUrl,
  timeout: TEST_TIMEOUT_MS
}, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8, statement_timeout: 15_000, query_timeout: 20_000 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "hosted-webauthn-process-loss-qualification" }).run();
  } finally {
    migrationClient.release();
  }

  await t.test("process loss after claim requires takeover and fences stale completion", async (subtest) => {
    const fixture = await seed(pool, "takeover");
    const children = new Set();
    subtest.after(async () => {
      await stopChildren(children);
      await cleanup(pool, fixture);
    });

    const staleProcess = launchChild("claim_hold", fixture, children);
    const staleClaim = await staleProcess.waitForMessage("claimed");
    assert.equal(Number(staleClaim.generation), 1);
    assert.equal((await staleProcess.kill()).signal, "SIGKILL");

    await expireLease(pool, fixture.challengeId);

    const takeoverProcess = launchChild("takeover_complete", fixture, children);
    const replacementClaim = await takeoverProcess.waitForMessage("claimed");
    assert.equal(Number(replacementClaim.generation), 2);

    const staleVerifier = launchChild("stale_complete", fixture, children);
    assert.deepEqual(await staleVerifier.waitForMessage("stale_fenced"), { type: "stale_fenced" });
    assert.deepEqual(await staleVerifier.waitForExit(), { code: 0, signal: null });

    takeoverProcess.send({ type: "complete" });
    assert.deepEqual(await takeoverProcess.waitForMessage("completed"), { type: "completed", replayed: false });
    assert.deepEqual(await takeoverProcess.waitForExit(), { code: 0, signal: null });

    const evidence = await readEvidence(pool, fixture);
    assert.deepEqual(evidence.counts, { credentials: 1, sessions: 1, completions: 1 });
    assert.deepEqual(await readClaimEvents(pool, fixture.challengeId), [
      { event_type: "claimed", generation: 1 },
      { event_type: "takeover", generation: 2 },
      { event_type: "completed", generation: 2 }
    ]);
    assert.equal((await readChallengeState(pool, fixture.challengeId)).status, "consumed");
    assert.equal((await readAttemptState(pool, fixture.attemptId)).state, "completed");
    assertNoSecretOutput([...children], fixture);
  });

  await t.test("response loss after commit recovers the exact session once", async (subtest) => {
    const fixture = await seed(pool, "response");
    const children = new Set();
    subtest.after(async () => {
      await stopChildren(children);
      await cleanup(pool, fixture);
    });

    const committingProcess = launchChild("complete_hold", fixture, children);
    assert.deepEqual(await committingProcess.waitForMessage("committed"), { type: "committed", replayed: false });
    assert.deepEqual(await committingProcess.kill(), { code: null, signal: "SIGKILL" });

    const committedEvidence = await readEvidence(pool, fixture);
    assert.deepEqual(committedEvidence.counts, { credentials: 1, sessions: 1, completions: 1 });
    assert.ok(committedEvidence.sessionFingerprint);

    const recoveryProcess = launchChild("replay", fixture, children);
    assert.deepEqual(await recoveryProcess.waitForMessage("replayed"), { type: "replayed" });
    assert.deepEqual(await recoveryProcess.waitForExit(), { code: 0, signal: null });

    const recoveredEvidence = await readEvidence(pool, fixture);
    assert.deepEqual(recoveredEvidence.counts, { credentials: 1, sessions: 1, completions: 1 });
    assert.equal(recoveredEvidence.sessionFingerprint, committedEvidence.sessionFingerprint, "response recovery must return the committed session");

    const exhaustedProcess = launchChild("replay", fixture, children);
    assert.deepEqual(await exhaustedProcess.waitForMessage("replay_exhausted"), { type: "replay_exhausted" });
    assert.deepEqual(await exhaustedProcess.waitForExit(), { code: 0, signal: null });

    const finalEvidence = await readEvidence(pool, fixture);
    assert.deepEqual(finalEvidence.counts, { credentials: 1, sessions: 1, completions: 1 });
    assert.equal(finalEvidence.sessionFingerprint, committedEvidence.sessionFingerprint, "a replay cannot replace the committed session");
    assert.deepEqual(await readClaimEvents(pool, fixture.challengeId), [
      { event_type: "claimed", generation: 1 },
      { event_type: "completed", generation: 1 },
      { event_type: "replayed", generation: 1 }
    ]);
    assertNoSecretOutput([...children], fixture);
  });
});

async function seed(pool, label) {
  const seedValue = `${label}-${crypto.randomBytes(24).toString("hex")}`;
  const fixture = {
    seed: seedValue,
    memberId: crypto.randomUUID(),
    organizationId: crypto.randomUUID(),
    membershipId: crypto.randomUUID(),
    attemptId: crypto.randomUUID(),
    oauthStateId: crypto.randomUUID(),
    challengeId: crypto.randomUUID()
  };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Explicit fault injection: simulate a database clock crossing the lease
    // boundary without weakening the production trigger or waiting 30 seconds.
    await client.query("SET LOCAL session_replication_role = replica");
    await client.query("SET CONSTRAINTS ALL DEFERRED");
    const clock = (await client.query("SELECT clock_timestamp() AS now")).rows[0].now;
    const createdAt = new Date(clock);
    const oauthExpiry = new Date(createdAt.getTime() + 10 * 60_000);
    const attemptExpiry = new Date(createdAt.getTime() + 15 * 60_000);
    const challengeExpiry = new Date(createdAt.getTime() + 5 * 60_000);
    await client.query("INSERT INTO public.members (id,github_subject,display_name) VALUES ($1,NULL,$2)", [fixture.memberId, `N1 ${label} member`]);
    await client.query("INSERT INTO public.organizations (id,name) VALUES ($1,$2)", [fixture.organizationId, `N1 ${label} ${fixture.organizationId}`]);
    await client.query("INSERT INTO public.memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [fixture.organizationId, fixture.membershipId, fixture.memberId]);
    await client.query(`INSERT INTO public.hosted_identity_bootstrap_attempts
      (id,oauth_state_id,state,bootstrap_cookie_hash,provider,member_id,organization_id,membership_id,identity_subject_digest,created_at,expires_at,identity_verified_at)
      VALUES ($1,$2,'webauthn_required',$3,'github',$4,$5,$6,$7,$8,$9,$8)`,
    [fixture.attemptId, fixture.oauthStateId, hashRaw(fixture, "cookie"), fixture.memberId, fixture.organizationId, fixture.membershipId, hashText(fixture.memberId), createdAt, attemptExpiry]);
    await client.query(`INSERT INTO public.hosted_identity_oauth_states
      (id,attempt_id,state_hash,code_hash,provider,client_id,redirect_uri,pkce_challenge,pkce_method,status,created_at,expires_at,consume_started_at,consumed_at)
      VALUES ($1,$2,$3,$4,'github','agentpass-n1',$5,$6,'S256','consumed',$7,$8,$7,$7)`,
    [fixture.oauthStateId, fixture.attemptId, hashRaw(fixture, "oauth-state"), hashRaw(fixture, "oauth-code"), REDIRECT_URI, "A".repeat(43), createdAt, oauthExpiry]);
    await client.query(`INSERT INTO public.hosted_identity_bootstrap_webauthn_challenges
      (id,attempt_id,member_id,organization_id,challenge_hash,operation,rp_id,origin,user_verification,status,created_at,expires_at)
      VALUES ($1,$2,$3,$4,$5,'bootstrap_registration',$6,$7,'required','pending',$8,$9)`,
    [fixture.challengeId, fixture.attemptId, fixture.memberId, fixture.organizationId, hashRaw(fixture, "challenge"), RP_ID, ORIGIN, createdAt, challengeExpiry]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  return Object.freeze({ ...fixture, values: values(fixture) });
}

async function expireLease(pool, challengeId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Explicit qualification-only fault injection. A normal application or
    // migrator update must continue to be rejected by the immutable guard.
    await client.query("SET LOCAL session_replication_role = replica");
    await client.query("SET LOCAL ROLE agentpass_migrator");
    await client.query(`UPDATE public.hosted_identity_bootstrap_webauthn_challenges
      SET consume_started_at=clock_timestamp()-interval '60 seconds',
          claim_expires_at=clock_timestamp()-interval '1 second'
      WHERE id=$1 AND status='consuming'`, [challengeId]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function readEvidence(pool, fixture) {
  const result = await pool.query(`SELECT
    (SELECT count(*)::int FROM public.hosted_identity_bootstrap_completions WHERE attempt_id=$1) AS completions,
    (SELECT count(*)::int FROM public.webauthn_credentials AS credential
      JOIN public.hosted_identity_bootstrap_completions AS completion ON completion.credential_id=credential.id
      WHERE completion.attempt_id=$1) AS credentials,
    (SELECT count(*)::int FROM public.human_sessions AS session
      JOIN public.hosted_identity_bootstrap_completions AS completion ON completion.session_id=session.id
      WHERE completion.attempt_id=$1) AS sessions,
    (SELECT session.id::text FROM public.human_sessions AS session
      JOIN public.hosted_identity_bootstrap_completions AS completion ON completion.session_id=session.id
      WHERE completion.attempt_id=$1) AS session_id`, [fixture.attemptId]);
  assert.equal(result.rowCount, 1);
  const row = result.rows[0];
  return {
    counts: { credentials: row.credentials, sessions: row.sessions, completions: row.completions },
    sessionFingerprint: row.session_id ? crypto.createHash("sha256").update(row.session_id, "utf8").digest("hex") : null
  };
}

async function readClaimEvents(pool, challengeId) {
  const result = await pool.query("SELECT event_type,generation FROM public.hosted_identity_bootstrap_webauthn_claim_events WHERE challenge_id=$1 ORDER BY observed_at,event_type", [challengeId]);
  return result.rows.map((row) => ({ event_type: row.event_type, generation: Number(row.generation) }));
}

async function readChallengeState(pool, challengeId) {
  const result = await pool.query("SELECT status FROM public.hosted_identity_bootstrap_webauthn_challenges WHERE id=$1", [challengeId]);
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}

async function readAttemptState(pool, attemptId) {
  const result = await pool.query("SELECT state FROM public.hosted_identity_bootstrap_attempts WHERE id=$1", [attemptId]);
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}

async function cleanup(pool, fixture) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = replica");
    await client.query("DELETE FROM public.hosted_identity_bootstrap_webauthn_claim_events WHERE challenge_id=$1", [fixture.challengeId]);
    await client.query("DELETE FROM public.hosted_identity_bootstrap_completions WHERE attempt_id=$1", [fixture.attemptId]);
    await client.query("DELETE FROM public.human_sessions WHERE member_id=$1", [fixture.memberId]);
    await client.query("DELETE FROM public.webauthn_credentials WHERE member_id=$1", [fixture.memberId]);
    await client.query("DELETE FROM public.hosted_identity_bootstrap_webauthn_challenges WHERE id=$1", [fixture.challengeId]);
    await client.query("DELETE FROM public.hosted_identity_oauth_states WHERE id=$1", [fixture.oauthStateId]);
    await client.query("DELETE FROM public.hosted_identity_bootstrap_attempts WHERE id=$1", [fixture.attemptId]);
    await client.query("DELETE FROM public.memberships WHERE organization_id=$1", [fixture.organizationId]);
    await client.query("DELETE FROM public.organizations WHERE id=$1", [fixture.organizationId]);
    await client.query("DELETE FROM public.members WHERE id=$1", [fixture.memberId]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function launchChild(mode, fixture, children) {
  const child = spawn(process.execPath, [CHILD_PATH, mode], {
    cwd: REPOSITORY_ROOT,
    env: {
      NODE_ENV: "test",
      AGENTPASS_TEST_DATABASE_URL: databaseUrl,
      AGENTPASS_TEST_POSTGRES_URL: databaseUrl,
      AGENTPASS_HOSTED_WEBAUTHN_PROCESS_LOSS_FIXTURE: JSON.stringify({
        seed: fixture.seed,
        attemptId: fixture.attemptId,
        challengeId: fixture.challengeId
      })
    },
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  });
  const state = {
    child,
    stdout: "",
    stdoutEvidence: "",
    stderr: "",
    messages: [],
    waiters: [],
    exit: null,
    protocolError: null
  };
  children.add(state);
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => receiveOutput(state, "stdout", chunk));
  child.stderr.on("data", (chunk) => receiveOutput(state, "stderr", chunk));
  child.on("error", () => failProtocol(state));
  child.on("exit", (code, signal) => {
    state.exit = { code, signal };
    if (!state.protocolError && code !== 0 && signal !== "SIGKILL") failProtocol(state);
    while (state.waiters.length > 0) state.waiters.shift().reject(new Error("hosted WebAuthn child exited before protocol message"));
  });
  return {
    send(message) {
      if (!message || typeof message !== "object" || !["hold", "complete"].includes(message.type)) throw new Error("invalid child command");
      child.stdin.write(`${JSON.stringify(message)}\n`);
    },
    waitForMessage(type) {
      const existing = state.messages.findIndex((message) => message.type === type);
      if (existing >= 0) return Promise.resolve(state.messages.splice(existing, 1)[0]);
      if (state.exit) return Promise.reject(new Error("hosted WebAuthn child exited before protocol message"));
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          state.waiters = state.waiters.filter((waiter) => waiter.resolve !== resolve);
          reject(new Error("hosted WebAuthn child protocol deadline exceeded"));
        }, CHILD_TIMEOUT_MS);
        state.waiters.push({ type, resolve: (message) => { clearTimeout(timer); resolve(message); }, reject });
      });
    },
    async kill(signal = "SIGKILL") {
      if (state.exit) return state.exit;
      child.kill(signal);
      return waitForExit(state);
    },
    waitForExit() { return waitForExit(state); },
    transcript() { return `${state.stdoutEvidence}\n${state.stderr}`; }
  };
}

function receiveOutput(state, channel, chunk) {
  state[channel] += chunk;
  if (channel === "stdout") state.stdoutEvidence += chunk;
  if (Buffer.byteLength(state[channel], "utf8") > MAX_CHILD_OUTPUT_BYTES) return failProtocol(state);
  if (channel !== "stdout") return;
  const lines = state.stdout.split("\n");
  state.stdout = lines.pop() ?? "";
  for (const line of lines) {
    if (!line) continue;
    let message;
    try { message = JSON.parse(line); } catch { return failProtocol(state); }
    if (!message || typeof message !== "object" || Array.isArray(message) || typeof message.type !== "string") return failProtocol(state);
    if (message.type === "error") return failProtocol(state);
    const waiter = state.waiters.find((candidate) => candidate.type === message.type);
    if (waiter) {
      state.waiters.splice(state.waiters.indexOf(waiter), 1);
      waiter.resolve(message);
    } else state.messages.push(message);
  }
}

function failProtocol(state) {
  if (state.protocolError) return;
  state.protocolError = new Error("hosted WebAuthn child protocol failure");
  if (state.child.exitCode === null && state.child.signalCode === null) state.child.kill("SIGKILL");
  while (state.waiters.length > 0) state.waiters.shift().reject(state.protocolError);
}

function waitForExit(state) {
  if (state.exit) return Promise.resolve(state.exit);
  return once(state.child, "exit").then(([code, signal]) => ({ code, signal }));
}

async function stopChildren(children) {
  await Promise.allSettled([...children].map(async (state) => {
    if (!state.exit) state.child.kill("SIGKILL");
    await waitForExit(state);
  }));
}

function assertNoSecretOutput(children, fixture) {
  const secretValues = Object.values(fixture.values);
  for (const state of children) {
    const transcript = `${state.stdoutEvidence}\n${state.stderr}`;
    for (const secret of secretValues) assert.equal(transcript.includes(secret), false, "child output retained a raw WebAuthn authority value");
  }
}

function values(fixture) {
  return Object.freeze({
    cookie: raw(fixture, "cookie"),
    challenge: raw(fixture, "challenge"),
    session: raw(fixture, "session"),
    csrf: raw(fixture, "csrf"),
    credential: raw(fixture, "credential"),
    "claim:stale": raw(fixture, "claim:stale"),
    "claim:replacement": raw(fixture, "claim:replacement"),
    "claim:response": raw(fixture, "claim:response")
  });
}

function raw(fixture, label) {
  return crypto.createHash("sha256").update(`${fixture.seed}:${label}`, "utf8").digest("base64url");
}

function hashRaw(fixture, label) {
  return crypto.createHash("sha256").update(raw(fixture, label), "utf8").digest();
}

function hashText(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DEFAULT_TIMEOUT_MILLISECONDS,
  LAUNCHCTL_PATH,
  SERVICE_LABEL,
  SERVICE_TARGET,
  recoverProtectedQualification,
  restartNativeService,
  runProtectedQualification
} from './run-protected-qualification.mjs';
import {
  PROVISION_STATE_PATH,
  SCENARIO_PHASE
} from './provision-qualification-config.mjs';

/**
 * Contract for scripts/release/n3e/run-protected-qualification.mjs.
 *
 * The parent implementation owns the privileged lifecycle. These tests use
 * only its exported API and inject every OS/process boundary:
 *
 *   runProtectedQualification({
 *     provisionOptions, executeQualification, disarmQualification,
 *     proveListenerUnavailable, platform, uid, fileSystem, statePath,
 *     provision, restore, restart, registerSignals, timeoutMilliseconds,
 *     setTimer, clearTimer
 *   })
 *
 * executeQualification is the controller/driver runner. It must resolve to
 * the closed result { ok: true, status, evidence_sha256 } and must receive an
 * AbortSignal plus the provisioned scenario/phase and digest bindings.
 */

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const SECRET = 'qualification-secret-must-never-escape';

const absentError = () => {
  const error = new Error('missing');
  error.code = 'ENOENT';
  return error;
};

const LOCK_PATH = '/Library/Application Support/AgentPass/n3e-qualification-run.lock';
const makeFileSystem = (state) => ({
  mkdirSync(path) {
    if (path === LOCK_PATH) {
      if (state.lockPresent) { const error = new Error('exists'); error.code = 'EEXIST'; throw error; }
      state.lockPresent = true;
      return;
    }
    throw new Error('unexpected mkdir');
  },
  lstatSync(path) {
    if (path === '/Library/Application Support/AgentPass') {
      return {
        isFile: () => false, isSymbolicLink: () => false, isDirectory: () => true,
        dev: 1n, ino: 1n, mode: 0o40700n, nlink: 2n, uid: 0n, gid: 0n
      };
    }
    if (path === LOCK_PATH && state.lockPresent) {
      return {
        isFile: () => false,
        isSymbolicLink: () => false,
        isDirectory: () => true,
        dev: 1n, ino: 2n, mode: 0o40700n, nlink: 1n, uid: 0n, gid: 0n
      };
    }
    if (path === PROVISION_STATE_PATH && state.present) {
      return {
        isFile: () => true,
        isSymbolicLink: () => false,
        isDirectory: () => false
      };
    }
    if (path === LOCK_PATH || path === PROVISION_STATE_PATH) {
      throw absentError();
    }
    throw new Error('unexpected lstat');
  },
  rmdirSync(path) {
    assert.equal(path, LOCK_PATH);
    if (!state.lockPresent) throw new Error('missing lock');
    state.lockPresent = false;
  }
});

const makeLifecycle = ({ scenario = 'pre-cloud-kill', staleState = false, lockPresent = false } = {}) => {
  const state = { present: staleState, lockPresent };
  const events = [];
  let registeredSignalHandler;
  let executeInput;
  let disarmSignal;

  const lifecycle = {
    provisionOptions: { scenario },
    platform: 'darwin',
    uid: 0,
    fileSystem: makeFileSystem(state),
    statePath: PROVISION_STATE_PATH,
    provision(options) {
      events.push(`provision:${options.scenario}`);
      state.present = true;
      return {
        scenario: options.scenario,
        phase: SCENARIO_PHASE[options.scenario],
        candidate_sha256: DIGEST_A,
        run_id_sha256: DIGEST_B
      };
    },
    restore() { events.push('restore'); state.present = false; },
    restart() { events.push('restart'); },
    registerSignals(handler) {
      events.push('register-signals');
      registeredSignalHandler = handler;
      return () => events.push('unregister-signals');
    },
    setTimer() { events.push('set-timer'); return { timer: true }; },
    clearTimer() { events.push('clear-timer'); },
    executeQualification(input) {
      events.push('execute-controller-driver');
      executeInput = input;
      return {
        completion: Promise.resolve({ ok: true, status: 'passed', evidence_sha256: DIGEST_A }),
        terminate: async (reason) => events.push(`terminate:${reason}`)
      };
    },
    async disarmQualification({ signal }) { events.push('disarm'); disarmSignal = signal; },
    proveListenerUnavailable() { events.push('prove-listener-unreachable'); return true; }
  };

  return {
    lifecycle,
    events,
    state,
    get executeInput() { return executeInput; },
    get disarmSignal() { return disarmSignal; },
    triggerSignal(signal) {
      assert.equal(typeof registeredSignalHandler, 'function');
      registeredSignalHandler(signal);
    }
  };
};

const run = (lifecycle, overrides = {}) => runProtectedQualification({
  ...lifecycle,
  ...overrides
});

test('protected qualification exposes fixed root paths and fixed launchd target', () => {
  assert.equal(SERVICE_LABEL, 'dev.agentpass.native-service');
  assert.equal(SERVICE_TARGET, 'system/dev.agentpass.native-service');
  assert.equal(LAUNCHCTL_PATH, '/bin/launchctl');
  assert.equal(PROVISION_STATE_PATH, '/Library/Application Support/AgentPass/n3e-qualification-provision.json');
  assert.equal(DEFAULT_TIMEOUT_MILLISECONDS, 15 * 60 * 1000);
});

test('run and recovery guards reject non-macOS and non-root callers through injected identity', async () => {
  await assert.rejects(
    () => runProtectedQualification({ platform: 'linux', uid: 0 }),
    /root on macOS/
  );
  await assert.rejects(
    () => runProtectedQualification({ platform: 'darwin', uid: 501 }),
    /root on macOS/
  );
  assert.throws(
    () => recoverProtectedQualification({ platform: 'linux', uid: 0 }),
    /root on macOS/
  );
  assert.throws(
    () => recoverProtectedQualification({ platform: 'darwin', uid: 501 }),
    /root on macOS/
  );
});

test('scenario and phase are a closed six-pair contract', async () => {
  assert.deepEqual(SCENARIO_PHASE, {
    'pre-cloud-kill': 'pre-cloud',
    'post-cloud-pre-local-kill': 'post-cloud-pre-local',
    'post-activation-pre-audit-kill': 'post-activation-pre-audit',
    'post-audit-pre-reply-loss': 'post-audit-pre-reply',
    'audit-fsync-failure': 'audit-fsync',
    'transport-reply-loss': 'transport-reply'
  });

  for (const [scenario, phase] of Object.entries(SCENARIO_PHASE)) {
    const value = makeLifecycle({ scenario });
    const result = await run(value.lifecycle);
    assert.equal(result.scenario, scenario);
    assert.equal(result.phase, phase);
    assert.equal(value.executeInput.scenario, scenario);
    assert.equal(value.executeInput.phase, phase);
  }

  const invalid = makeLifecycle();
  invalid.lifecycle.provisionOptions = { scenario: 'post-cloud-kill;touch /tmp/pwned' };
  await assert.rejects(
    () => run(invalid.lifecycle),
    /scenario is invalid/
  );
  assert.deepEqual(invalid.events, []);
});

test('provision completes before the first launchd reload and controller/driver runner receives bound input', async () => {
  const value = makeLifecycle();
  const result = await run(value.lifecycle);

  assert.deepEqual(value.events.slice(0, 6), [
    'register-signals',
    'provision:pre-cloud-kill',
    'restart',
    'execute-controller-driver',
    'set-timer',
    'clear-timer'
  ]);
  assert.ok(value.executeInput.signal instanceof AbortSignal);
  assert.equal(value.executeInput.candidateSHA256, DIGEST_A);
  assert.equal(value.executeInput.runIDSHA256, DIGEST_B);
  assert.deepEqual(result.execution, {
    ok: true,
    status: 'passed',
    evidence_sha256: DIGEST_A
  });
});

test('launchd invocation uses fixed argv and never enables shell interpolation', () => {
  const calls = [];
  const result = { status: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
  const observed = { status: 0, signal: null, stdout: Buffer.from('pid = 4312\n'), stderr: Buffer.alloc(0) };
  const restarted = restartNativeService({
    runCommand(command, args, options) {
      calls.push({ command, args, options });
      return calls.length === 1 ? result : observed;
    }
  });

  assert.deepEqual(restarted, { pid: 4312 });
  assert.deepEqual(calls.map(({ command, args }) => [command, args]), [
    [LAUNCHCTL_PATH, ['kickstart', '-k', SERVICE_TARGET]],
    [LAUNCHCTL_PATH, ['print', SERVICE_TARGET]]
  ]);
  for (const { options } of calls) {
    assert.equal(options.shell, false);
    assert.equal(options.cwd, '/');
    assert.deepEqual(options.env, {
      HOME: '/var/empty',
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin'
    });
    assert.deepEqual(options.stdio, ['ignore', 'pipe', 'pipe']);
  }
});

test('restore, disarm, reload, and listener proof are attempted on execution failure', async () => {
  const value = makeLifecycle();
  value.lifecycle.executeQualification = () => {
    value.events.push('execute-fails');
    return {
      completion: Promise.reject(new Error(SECRET)),
      terminate: async (reason) => value.events.push(`terminate:${reason}`)
    };
  };
  value.lifecycle.disarmQualification = async () => {
    value.events.push('disarm-fails');
    throw new Error('driver teardown failed');
  };

  await assert.rejects(() => run(value.lifecycle), (error) => {
    assert.equal(error.message, 'protected qualification failed');
    assert.doesNotMatch(String(error), new RegExp(SECRET));
    return true;
  });
  assert.deepEqual(value.events.slice(-6), [
    'terminate:failure',
    'clear-timer',
    'disarm-fails',
    'restore',
    'restart',
    'prove-listener-unreachable'
  ]);
  assert.equal(value.state.present, false);
});

test('timeout is modeled through the injected timer and still cleans up the protected run', async () => {
  const value = makeLifecycle();
  let timerCallback;
  let observedSignal;
  value.lifecycle.executeQualification = ({ signal }) => {
    observedSignal = signal;
    return {
      completion: new Promise(() => {}),
      terminate: async (reason) => value.events.push(`terminate:${reason}`)
    };
  };
  value.lifecycle.setTimer = (callback) => {
    timerCallback = callback;
    queueMicrotask(() => timerCallback());
    return { timer: true };
  };

  await assert.rejects(() => run(value.lifecycle, { timeoutMilliseconds: 1000 }), /protected qualification failed/);
  assert.equal(observedSignal.aborted, true);
  assert.ok(value.events.includes('terminate:timeout'));
  assert.deepEqual(value.events.slice(-5), [
    'clear-timer',
    'disarm',
    'restore',
    'restart',
    'prove-listener-unreachable'
  ]);
});

test('signal interruption is modeled through the injected signal registrar and reaches the runner', async () => {
  const value = makeLifecycle();
  let observedSignal;
  value.lifecycle.registerSignals = (handler) => {
    value.events.push('register-signals');
    queueMicrotask(() => handler('SIGTERM'));
    return () => value.events.push('unregister-signals');
  };
  value.lifecycle.executeQualification = ({ signal }) => {
    observedSignal = signal;
    const completion = new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => reject(new Error('runner observed abort')), { once: true });
    });
    return { completion, terminate: async (reason) => value.events.push(`terminate:${reason}`) };
  };

  await assert.rejects(() => run(value.lifecycle), /protected qualification failed/);
  assert.equal(observedSignal.aborted, true);
  assert.equal(value.disarmSignal.aborted, true);
  assert.ok(value.events.includes('terminate:signal'));
  assert.ok(value.events.includes('restore'));
  assert.ok(value.events.includes('restart'));
  assert.ok(value.events.includes('prove-listener-unreachable'));
});

test('stale state requires explicit recovery, which requires no-active proof', async () => {
  const value = makeLifecycle({ staleState: true });
  await assert.rejects(() => run(value.lifecycle), /protected qualification failed/);
  assert.deepEqual(value.events, []);
  assert.throws(() => recoverProtectedQualification({
    platform: 'darwin', uid: 0, fileSystem: value.lifecycle.fileSystem,
    proveListenerUnavailable: () => true, proveNoActiveRun: () => false,
    restore: () => { throw new Error(SECRET); }, restart: () => {}
  }), /recovery failed/);
  const recovery = recoverProtectedQualification({
    platform: 'darwin', uid: 0, fileSystem: value.lifecycle.fileSystem,
    proveListenerUnavailable: () => true, proveNoActiveRun: () => true,
    restore: () => { value.events.push('restore'); value.state.present = false; },
    restart: () => value.events.push('restart')
  });
  assert.deepEqual(recovery, {
    ok: true, action: 'recovered', restored: true, stale_lock_removed: false, listener_unreachable: true
  });
  assert.deepEqual(value.events, ['restore', 'restart']);
});

test('exclusive lock rejects concurrent runs and releases after success', async () => {
  const value = makeLifecycle({ lockPresent: true });
  await assert.rejects(() => run(value.lifecycle), /protected qualification failed/);
  const fresh = makeLifecycle();
  await run(fresh.lifecycle);
  assert.equal(fresh.state.lockPresent, false);
});

test('cleanup failure, listener proof, termination, and closed errors are all enforced', async () => {
  const value = makeLifecycle();
  value.lifecycle.executeQualification = () => ({
    completion: Promise.reject(new Error(SECRET)),
    terminate: async (reason) => value.events.push(`terminate:${reason}`)
  });
  value.lifecycle.disarmQualification = async () => { throw new Error(SECRET); };
  value.lifecycle.restore = () => { throw new Error(SECRET); };
  let restartCount = 0;
  value.lifecycle.restart = () => { restartCount += 1; if (restartCount > 1) throw new Error(SECRET); };
  value.lifecycle.proveListenerUnavailable = () => { throw new Error(SECRET); };
  await assert.rejects(() => run(value.lifecycle), (error) => {
    assert.equal(error.message, 'protected qualification failed');
    assert.deepEqual(error.cleanupFailures, ['cleanup_failed', 'cleanup_failed', 'cleanup_failed', 'cleanup_failed']);
    assert.doesNotMatch(String(error), new RegExp(SECRET));
    return true;
  });
  assert.ok(value.events.includes('terminate:failure'));
});

test('public results reject raw output and launchd output is bounded without leaking secrets', async () => {
  const value = makeLifecycle();
  value.lifecycle.executeQualification = () => ({
    completion: Promise.resolve({
      ok: true,
      status: 'passed',
      evidence_sha256: DIGEST_A,
      stdout: SECRET
    }),
    terminate: async () => {}
  });
  await assert.rejects(() => run(value.lifecycle), (error) => {
    assert.equal(error.message, 'protected qualification failed');
    assert.doesNotMatch(String(error), new RegExp(SECRET));
    return true;
  });

  const oversized = Buffer.from(SECRET.repeat(Math.ceil((64 * 1024 + 1) / SECRET.length)));
  assert.throws(() => restartNativeService({
    runCommand: () => ({ status: 0, signal: null, stdout: oversized, stderr: Buffer.alloc(0) })
  }), (error) => {
    assert.equal(error.message, 'launchd service restart failed');
    assert.doesNotMatch(String(error), new RegExp(SECRET));
    return true;
  });
});

const observations = new WeakMap();

/**
 * Queue a recovery state-latency observation on the transaction that owns the
 * state change. The queue is flushed only after that transaction commits.
 */
export function observeOwnerRecoveryStateTransition({ tx, metrics, previousUpdatedAt, nextUpdatedAt }) {
  if (!tx || (typeof tx !== "object" && typeof tx !== "function")) return false;
  if (typeof metrics?.recordOwnerRecoveryStateLatency !== "function") return false;
  const previous = millis(previousUpdatedAt);
  const next = millis(nextUpdatedAt);
  const latency = next - previous;
  if (!Number.isSafeInteger(latency) || latency < 0) return false;
  const queued = observations.get(tx) ?? [];
  queued.push(Object.freeze({ metrics, latency }));
  observations.set(tx, queued);
  return true;
}

export function flushOwnerRecoveryStateTransitions(tx) {
  const queued = observations.get(tx) ?? [];
  observations.delete(tx);
  for (const { metrics, latency } of queued) {
    try {
      const recorded = metrics.recordOwnerRecoveryStateLatency(latency);
      if (recorded && typeof recorded.then === "function") recorded.catch(() => {});
    } catch {
      // Metrics are non-authoritative and must never change a committed result.
    }
  }
  return queued.length;
}

export function discardOwnerRecoveryStateTransitions(tx) {
  const count = observations.get(tx)?.length ?? 0;
  observations.delete(tx);
  return count;
}

function millis(value) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "string" || typeof value === "number") return new Date(value).getTime();
  return Number.NaN;
}

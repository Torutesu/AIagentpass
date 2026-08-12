# G4.1 propagation latency qualification

`apps/cloud-api/src/postgres/g4-1-propagation-qualification.mjs` is the
aggregate-only evidence component for G4.1. It is intentionally not imported
by the cloud service, PostgreSQL runtime, refresh service, or notifier. A
qualification run can use the same PostgreSQL repositories and protocol
fixtures as the G4.1 integration tests without creating an operational
dependency.

## Evidence contract

The recorder has two fixed phases:

- `commit_to_observation`: committed authority-generation row to the first
  observation of the corresponding refresh hint.
- `commit_to_applied_ack`: the same commit point to the device's applied ACK
  being durably accepted by PostgreSQL.

Each attempt is recorded once. A completed attempt supplies either a bounded
`latency_ms`, or a bounded pair of `committed_at_ms` and the phase-specific
completion timestamp (`observed_at_ms` or `applied_ack_at_ms`). A timed-out
attempt supplies `timed_out: true` and no completion timestamp. Timeouts count
in `count` and the timeout-rate denominator; percentile values use successful
completed attempts only. Percentiles use deterministic nearest-rank selection:
`ceil(count * percentile) - 1` after ascending sort.

Every attempt should also supply this exact resource snapshot:

```js
{
  pool_connections: pool.totalCount,
  pool_waiters: pool.waitingCount,
  in_flight_operations: harnessInFlightRefreshes,
  notification_reconnects: harnessNotificationReconnects
}
```

The report retains only the maximum of each resource field and the number of
snapshots. It does not retain timestamps, samples after report construction,
SQL, error text, tenant identifiers, request identifiers, UUIDs, or arbitrary
labels. Unknown fields are rejected at the recorder boundary and again during
JSON validation.

## Default qualification SLO

The report includes the complete threshold object used for the run. The
defaults are deliberately explicit and can be overridden only with another
fully validated fixed-shape threshold object:

| Phase | p50 | p95 | p99 | maximum completed latency |
| --- | ---: | ---: | ---: | ---: |
| commit to observation | 100 ms | 250 ms | 500 ms | 2,000 ms |
| commit to applied ACK | 250 ms | 1,000 ms | 2,000 ms | 5,000 ms |

Both phases require at least 100 attempts. The timeout rate must be at most
1%. Resource maxima must be at most 16 pool connections, 0 pool waiters, 100
in-flight operations, and 3 notification reconnects. The recorder is bounded
to 100,000 retained latency values per run and 24 hours per latency value.
Exceeding a sample count, latency, timeout, or resource bound produces a
non-qualified report with a fixed failure code.

## Feeding it from a real PostgreSQL harness

The harness should use a controlled test organization/device and the existing
transactional G4.1 operations. It should not pass those identifiers to the
recorder. The following is illustrative pseudocode; the repository and device
setup remains owned by the harness:

```js
const recorder = createG41PropagationLatencyRecorder({
  // Use defaults for release qualification; smaller values are appropriate
  // only for unit tests.
  thresholds: G41_DEFAULT_SLO_THRESHOLDS
});

for (let attempt = 0; attempt < 100; attempt += 1) {
  const committedAt = performance.timeOrigin + performance.now();
  await postgres.query("BEGIN");
  await postgres.query(/* fixed G4.1 mutation that advances generation */);
  await postgres.query("COMMIT");

  const observed = await pollUntilGenerationIsVisible(/* harness-local state */);
  recorder.recordCommitToObservation(observed
    ? {
        committed_at_ms: committedAt,
        observed_at_ms: performance.timeOrigin + performance.now(),
        resource_snapshot: readAggregateResources(pool, harnessState)
      }
    : {
        timed_out: true,
        resource_snapshot: readAggregateResources(pool, harnessState)
      });

  const ack = observed && await waitForAppliedAck(/* harness-local state */);
  recorder.recordCommitToAppliedAck(ack
    ? {
        committed_at_ms: committedAt,
        applied_ack_at_ms: performance.timeOrigin + performance.now(),
        resource_snapshot: readAggregateResources(pool, harnessState)
      }
    : {
        timed_out: true,
        resource_snapshot: readAggregateResources(pool, harnessState)
      });
}

const report = recorder.report();
const json = serializeG41PropagationReport(report);
// Persist json as the qualification evidence artifact and fail the harness
// if report.qualified is false.
```

In production qualification code, take the commit timestamp immediately
after the successful commit returns and use one monotonic clock domain for all
three timestamps. If the PostgreSQL client and device process use different
clocks, have the harness measure the commit/observation and commit/ACK spans
with a single coordinator clock and pass `latency_ms` instead. A timeout must
be recorded separately for each phase; an observation timeout must not be
silently omitted when the ACK also cannot arrive.

Before accepting an evidence artifact, call
`parseAndValidateG41PropagationReport`. It requires canonical pretty-printed
JSON, exact fixed keys, safe integer/finite numeric values, internally
consistent counts, monotonic percentile summaries, and a qualification
decision derived from the supplied thresholds and aggregate maxima. Because
the secret-free report intentionally omits raw samples, artifact provenance
must separately bind it to the qualification process and source commit; the
validator cannot recompute percentiles from samples that are not retained.
`serializeG41PropagationReport` is the canonical writer.

The component is intentionally a qualification input, not an operational
metrics export. If the service later exposes operational counters, keep those
as fixed-key aggregates and do not attach the harness's organization, device,
request, trace, or SQL labels.

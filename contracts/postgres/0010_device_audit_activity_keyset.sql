BEGIN;

-- device_timestamp is normalized to fixed-width UTC ISO-8601 milliseconds before
-- persistence, so its text ordering is chronological and indexable without a
-- locale/time-zone-dependent cast. The device_id component is retained in the
-- keyset even though the query is device-scoped to make the cursor tuple
-- complete and fail closed if a scope is substituted.
CREATE INDEX device_audit_events_activity_keyset
  ON device_audit_events (
    organization_id,
    device_id,
    (redacted_json ->> 'device_timestamp') DESC,
    event_id DESC
  );

COMMIT;

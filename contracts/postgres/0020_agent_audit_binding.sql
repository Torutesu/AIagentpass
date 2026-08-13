BEGIN;

-- The M2 audit extension stores only public correlation identifiers and
-- digests. Raw audit tokens, process metadata, arguments, environment values,
-- repository contents, payloads, and key material are intentionally absent.
ALTER TABLE capabilities
  ADD CONSTRAINT capabilities_audit_identity_unique
    UNIQUE (organization_id, id, sequence);

ALTER TABLE device_audit_events
  ADD COLUMN session_id uuid,
  ADD COLUMN grant_id uuid,
  ADD COLUMN adapter_id uuid,
  ADD COLUMN adapter_kind text,
  ADD COLUMN process_binding_sha256 text,
  ADD COLUMN ancestry_binding_sha256 text,
  ADD COLUMN worktree_binding_sha256 text,
  ADD COLUMN capability_id uuid,
  ADD COLUMN capability_sequence bigint,
  ADD CONSTRAINT device_audit_events_adapter_kind_valid
    CHECK (adapter_kind IS NULL OR (
      adapter_kind IN ('claude-code', 'cursor', 'mcp', 'cli', 'custom')
    )),
  ADD CONSTRAINT device_audit_events_process_binding_hash_valid
    CHECK (process_binding_sha256 IS NULL OR process_binding_sha256 ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT device_audit_events_ancestry_binding_hash_valid
    CHECK (ancestry_binding_sha256 IS NULL OR ancestry_binding_sha256 ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT device_audit_events_worktree_binding_hash_valid
    CHECK (worktree_binding_sha256 IS NULL OR worktree_binding_sha256 ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT device_audit_events_capability_sequence_valid
    CHECK (capability_sequence IS NULL OR capability_sequence > 0),
  ADD CONSTRAINT device_audit_events_m2_binding_complete
    CHECK (
      (session_id IS NULL
       AND grant_id IS NULL
       AND adapter_id IS NULL
       AND adapter_kind IS NULL
       AND process_binding_sha256 IS NULL
       AND ancestry_binding_sha256 IS NULL
       AND worktree_binding_sha256 IS NULL
       AND capability_id IS NULL
       AND capability_sequence IS NULL)
      OR
      (session_id IS NOT NULL
       AND grant_id IS NOT NULL
       AND adapter_id IS NOT NULL
       AND adapter_kind IS NOT NULL
       AND process_binding_sha256 IS NOT NULL
       AND ancestry_binding_sha256 IS NOT NULL
       AND worktree_binding_sha256 IS NOT NULL
       AND ((capability_id IS NULL AND capability_sequence IS NULL)
         OR (capability_id IS NOT NULL AND capability_sequence IS NOT NULL)))
    ),
  ADD CONSTRAINT device_audit_events_grant_fk
    FOREIGN KEY (organization_id, grant_id)
    REFERENCES agent_session_grants(organization_id, grant_id),
  ADD CONSTRAINT device_audit_events_session_fk
    FOREIGN KEY (organization_id, session_id)
    REFERENCES agent_sessions(organization_id, session_id),
  ADD CONSTRAINT device_audit_events_session_identity_fk
    FOREIGN KEY (organization_id, session_id, grant_id, device_id)
    REFERENCES agent_sessions(organization_id, session_id, grant_id, device_id),
  ADD CONSTRAINT device_audit_events_capability_fk
    FOREIGN KEY (organization_id, capability_id, capability_sequence)
    REFERENCES capabilities(organization_id, id, sequence);

CREATE INDEX device_audit_events_agent_session_lookup
  ON device_audit_events (organization_id, device_id, session_id, received_at DESC, event_id)
  WHERE session_id IS NOT NULL;

CREATE INDEX device_audit_events_agent_grant_lookup
  ON device_audit_events (organization_id, device_id, grant_id, received_at DESC, event_id)
  WHERE grant_id IS NOT NULL;

CREATE INDEX device_audit_events_agent_capability_lookup
  ON device_audit_events (organization_id, device_id, capability_id, capability_sequence, received_at DESC, event_id)
  WHERE capability_id IS NOT NULL;

-- Existing audit rows and repositories remain compatible because all M2
-- fields are nullable and every added foreign key is tenant-qualified. Do not
-- enable FORCE RLS on this pre-existing table until every legacy audit read
-- and ingest transaction installs the tenant setting; doing so here would
-- silently deny all current device audit traffic immediately after migration.

COMMIT;

BEGIN;

-- The migration role's default privileges are deny-by-default. The online
-- control-plane writer needs only the replay/event ledger permissions; the
-- referenced device, outbox, membership, and generation rows retain their
-- existing tenant-scoped read/lock boundary.
REVOKE ALL PRIVILEGES ON TABLE public.device_manual_wake_events,
  public.device_manual_wake_requests
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT, INSERT, UPDATE ON TABLE public.device_manual_wake_events,
  public.device_manual_wake_requests TO agentpass_app;

-- Manual wake authenticates the actor inside the same transaction while the
-- device state is locked. Re-assert the reviewed read/lock boundary here so
-- databases upgraded from older role bootstrap scripts cannot lose it.
GRANT SELECT ON TABLE public.memberships TO agentpass_app;

COMMIT;

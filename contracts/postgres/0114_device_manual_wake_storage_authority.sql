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

COMMIT;

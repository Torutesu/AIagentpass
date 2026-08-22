BEGIN;

-- The online application must never receive direct access to the
-- deployment-wide recovery outbox. The dedicated maintenance identity is
-- allowed only the bounded worker transitions and their append-only ledgers.
REVOKE ALL PRIVILEGES ON TABLE
  public.owner_recovery_outbox,
  public.owner_recovery_outbox_transition_heads,
  public.owner_recovery_outbox_transition_ledger,
  public.owner_recovery_outbox_retention_ledger
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

GRANT SELECT, UPDATE, DELETE ON TABLE public.owner_recovery_outbox
  TO agentpass_maintenance;
GRANT SELECT, INSERT, UPDATE ON TABLE public.owner_recovery_outbox_transition_heads
  TO agentpass_maintenance;
GRANT SELECT, INSERT ON TABLE public.owner_recovery_outbox_transition_ledger
  TO agentpass_maintenance;
GRANT SELECT, INSERT ON TABLE public.owner_recovery_outbox_retention_ledger
  TO agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_prune_owner_recovery_outbox_terminal(integer)
  TO agentpass_maintenance;

COMMENT ON TABLE public.owner_recovery_outbox IS
  'Worker transitions are restricted to agentpass_maintenance; the app role uses the reviewed recovery authority boundary.';

COMMIT;

BEGIN;

-- Registration ceremonies need a durable challenge ledger, but the online
-- role must never read session token hashes or other session secrets. Expose
-- only the binding fields required by the ceremony through a migrator-owned,
-- security-barrier view.
CREATE OR REPLACE VIEW public.agentpass_webauthn_registration_sessions
WITH (security_barrier = true) AS
SELECT s.id,
       s.member_id,
       s.organization_id,
       s.membership_id,
       s.role,
       s.revoked_at,
       s.expires_at,
       s.idle_expires_at,
       s.organization_authority_epoch,
       s.membership_session_epoch,
       m.status AS membership_status,
       m.role AS membership_role,
       m.session_epoch,
       o.authority_epoch
FROM public.human_sessions AS s
JOIN public.memberships AS m
  ON m.organization_id = s.organization_id
 AND m.member_id = s.member_id
 AND m.id = s.membership_id
JOIN public.organizations AS o ON o.id = s.organization_id;

REVOKE ALL PRIVILEGES ON TABLE public.agentpass_webauthn_registration_sessions
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT ON TABLE public.agentpass_webauthn_registration_sessions TO agentpass_app;

-- The challenge ledger contains only a digest and public ceremony binding;
-- credential material and session token material are never persisted here.
REVOKE ALL PRIVILEGES ON TABLE public.webauthn_challenges
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT, INSERT, UPDATE ON TABLE public.webauthn_challenges TO agentpass_app;

COMMIT;

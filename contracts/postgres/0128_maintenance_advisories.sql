BEGIN;
CREATE TABLE public.maintenance_advisories (
  advisory_id uuid PRIMARY KEY, provider_id uuid NOT NULL REFERENCES public.maintenance_providers(provider_id),
  advisory_version integer NOT NULL CHECK (advisory_version > 0), api_id text NOT NULL, severity text NOT NULL CHECK (severity IN ('informational','low','medium','high','critical')),
  released_at timestamptz NOT NULL, enforcement_at timestamptz, payload jsonb NOT NULL, payload_digest bytea NOT NULL,
  signature bytea NOT NULL, signing_key_id text NOT NULL, state text NOT NULL DEFAULT 'published' CHECK (state IN ('published','superseded','withdrawn')),
  supersedes_advisory_id uuid REFERENCES public.maintenance_advisories(advisory_id), withdraws_advisory_id uuid REFERENCES public.maintenance_advisories(advisory_id),
  published_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(provider_id, advisory_id, advisory_version)
);
CREATE TABLE public.maintenance_advisory_events (
  event_id bigserial PRIMARY KEY, advisory_id uuid NOT NULL REFERENCES public.maintenance_advisories(advisory_id), event_type text NOT NULL CHECK (event_type IN ('publish','supersede','withdraw')), event_payload jsonb NOT NULL, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION public.agentpass_immutable_maintenance_advisory() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF NEW.advisory_id <> OLD.advisory_id OR NEW.provider_id <> OLD.provider_id OR NEW.advisory_version <> OLD.advisory_version OR NEW.payload IS DISTINCT FROM OLD.payload OR NEW.payload_digest IS DISTINCT FROM OLD.payload_digest OR NEW.signature IS DISTINCT FROM OLD.signature OR NEW.signing_key_id <> OLD.signing_key_id THEN
    RAISE EXCEPTION USING ERRCODE='integrity_constraint_violation', MESSAGE='published advisory bytes are immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER maintenance_advisory_immutable BEFORE UPDATE ON public.maintenance_advisories FOR EACH ROW EXECUTE FUNCTION public.agentpass_immutable_maintenance_advisory();
ALTER TABLE public.maintenance_advisories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.maintenance_advisory_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.maintenance_advisories FORCE ROW LEVEL SECURITY;
ALTER TABLE public.maintenance_advisory_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.maintenance_advisories OWNER TO agentpass_migrator;
ALTER TABLE public.maintenance_advisory_events OWNER TO agentpass_migrator;
REVOKE ALL ON public.maintenance_advisories, public.maintenance_advisory_events FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT ON public.maintenance_advisories, public.maintenance_advisory_events TO agentpass_app, agentpass_maintenance;
COMMIT;

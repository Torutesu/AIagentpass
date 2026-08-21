BEGIN;

-- 0054 captures authenticated_at with clock_timestamp() before inserting the
-- session, while the original created_at default evaluates a later
-- clock_timestamp(). The table deliberately requires created_at <=
-- authenticated_at. Bind created_at to the start of the database statement so
-- every approved insertion preserves that ordering without weakening the
-- invariant or trusting an application clock.
ALTER TABLE public.platform_sessions
  ALTER COLUMN created_at SET DEFAULT statement_timestamp();

COMMENT ON COLUMN public.platform_sessions.created_at IS
  'Database statement start time for durable Platform Session creation; never later than authenticated_at.';

COMMIT;

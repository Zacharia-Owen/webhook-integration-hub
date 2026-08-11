-- The event log is the backbone of this whole project.
-- Every webhook attempt gets a row here, whether it succeeded, failed
-- signature verification, or was a duplicate. This is what the log
-- analyzer (built in a later step) will read from.

CREATE TABLE IF NOT EXISTS events (
  id SERIAL PRIMARY KEY,


  delivery_id TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'github',
  event_type TEXT,                -- e.g. 'push', 'issues', 'star'

  payload JSONB,                  -- the raw event body, for later inspection
  signature_valid BOOLEAN NOT NULL,

  -- status tracks what happened to this event after receipt
  status TEXT NOT NULL,           -- 'received' | 'rejected' | 'duplicate' | 'processed' | 'error'
  error_category TEXT,            -- populated by the log analyzer step: 'auth' | 'duplicate' | 'malformed' | null

  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at TIMESTAMPTZ,

  -- Enforcing idempotency at the database level
  UNIQUE (source, delivery_id)
);

CREATE INDEX IF NOT EXISTS idx_events_status ON events (status);
CREATE INDEX IF NOT EXISTS idx_events_received_at ON events (received_at);
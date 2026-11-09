ALTER TABLE information_query.audit ADD COLUMN IF NOT EXISTS created_at timestamptz;
UPDATE information_query.audit SET created_at=(body->>'created_at')::timestamptz WHERE created_at IS NULL;
ALTER TABLE information_query.audit ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE information_query.audit ALTER COLUMN created_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS audit_retention ON information_query.audit(created_at,id);

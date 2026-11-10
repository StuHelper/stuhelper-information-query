CREATE SCHEMA IF NOT EXISTS information_query;
CREATE TABLE IF NOT EXISTS information_query.audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 school text NOT NULL,
 group_id text NOT NULL,
 module text NOT NULL,
 body jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS audit_scope ON information_query.audit(school,group_id,module,id);
CREATE INDEX IF NOT EXISTS audit_retention ON information_query.audit(created_at,id);
REVOKE ALL ON SCHEMA information_query FROM PUBLIC;
REVOKE ALL ON information_query.audit FROM PUBLIC;

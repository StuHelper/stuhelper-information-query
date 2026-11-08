CREATE SCHEMA IF NOT EXISTS information_query;
CREATE TABLE IF NOT EXISTS information_query.audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 school text NOT NULL,
 group_id text NOT NULL,
 module text NOT NULL,
 body jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_scope ON information_query.audit(school,group_id,module,id);
REVOKE ALL ON SCHEMA information_query FROM PUBLIC;
REVOKE ALL ON information_query.audit FROM PUBLIC;

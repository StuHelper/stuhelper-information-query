ALTER TABLE information_query.audit ADD COLUMN IF NOT EXISTS target_scopes jsonb NOT NULL DEFAULT '{}';

-- The original request scope stays on audit, including rows written by older hosts.
CREATE TABLE IF NOT EXISTS information_query.audit_scopes (
    id bigint NOT NULL REFERENCES information_query.audit(id) ON DELETE CASCADE,
    school text NOT NULL,
    group_id text NOT NULL,
    module text NOT NULL,
    PRIMARY KEY (id, school, group_id, module)
);
CREATE INDEX IF NOT EXISTS audit_school_page ON information_query.audit(school,id DESC);
CREATE INDEX IF NOT EXISTS audit_group_page ON information_query.audit(group_id,id DESC);
CREATE INDEX IF NOT EXISTS audit_module_page ON information_query.audit(module,id DESC);
CREATE INDEX IF NOT EXISTS audit_scopes_school_page ON information_query.audit_scopes(school,id DESC);
CREATE INDEX IF NOT EXISTS audit_scopes_group_page ON information_query.audit_scopes(group_id,id DESC);
CREATE INDEX IF NOT EXISTS audit_scopes_module_page ON information_query.audit_scopes(module,id DESC);

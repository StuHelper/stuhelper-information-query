CREATE INDEX IF NOT EXISTS audit_actor_id_desc ON information_query.audit((body->>'actor'),id DESC);
CREATE INDEX IF NOT EXISTS audit_action_id_desc ON information_query.audit((body->>'action'),id DESC);
CREATE INDEX IF NOT EXISTS audit_result_id_desc ON information_query.audit((body->>'result'),id DESC);
CREATE INDEX IF NOT EXISTS audit_channel_id_desc ON information_query.audit((body->>'channel'),id DESC);
CREATE INDEX IF NOT EXISTS audit_targets_gin ON information_query.audit USING gin ((body->'targets') jsonb_path_ops);

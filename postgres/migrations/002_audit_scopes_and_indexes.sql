ALTER TABLE information_query.audit ADD COLUMN IF NOT EXISTS schools text[] NOT NULL DEFAULT '{}';
ALTER TABLE information_query.audit ADD COLUMN IF NOT EXISTS groups text[] NOT NULL DEFAULT '{}';
ALTER TABLE information_query.audit ADD COLUMN IF NOT EXISTS modules text[] NOT NULL DEFAULT '{}';
ALTER TABLE information_query.audit ADD COLUMN IF NOT EXISTS target_scopes jsonb NOT NULL DEFAULT '{}'::jsonb;
UPDATE information_query.audit
SET schools = CASE WHEN school <> '*' AND school <> '' THEN ARRAY[school] ELSE '{}' END,
    groups = CASE WHEN group_id <> '*' AND group_id <> '' THEN ARRAY[group_id] ELSE '{}' END,
    modules = CASE WHEN module <> '*' AND module <> '' THEN ARRAY[module] ELSE '{}' END
WHERE (school <> '*' AND school <> '' AND NOT (schools @> ARRAY[school]))
   OR (group_id <> '*' AND group_id <> '' AND NOT (groups @> ARRAY[group_id]))
   OR (module <> '*' AND module <> '' AND NOT (modules @> ARRAY[module]));
CREATE INDEX IF NOT EXISTS audit_scope_id_desc ON information_query.audit(school,group_id,module,id DESC);
CREATE INDEX IF NOT EXISTS audit_school_id_desc ON information_query.audit(school,id DESC);
CREATE INDEX IF NOT EXISTS audit_group_id_desc ON information_query.audit(group_id,id DESC);
CREATE INDEX IF NOT EXISTS audit_module_id_desc ON information_query.audit(module,id DESC);
CREATE INDEX IF NOT EXISTS audit_schools_gin ON information_query.audit USING gin (schools);
CREATE INDEX IF NOT EXISTS audit_groups_gin ON information_query.audit USING gin (groups);
CREATE INDEX IF NOT EXISTS audit_modules_gin ON information_query.audit USING gin (modules);

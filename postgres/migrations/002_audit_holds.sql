CREATE TABLE IF NOT EXISTS information_query.audit_holds (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 audit_id bigint,
 request_id text NOT NULL DEFAULT '',
 target_account text NOT NULL DEFAULT '',
 reason text NOT NULL,
 created_by text NOT NULL,
 review_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
 released_at timestamptz,
 released_by text NOT NULL DEFAULT '',
 release_reason text NOT NULL DEFAULT '',
 CONSTRAINT audit_holds_selector_check CHECK (
  audit_id IS NOT NULL OR request_id <> '' OR target_account <> ''
 )
);
CREATE INDEX IF NOT EXISTS audit_holds_active_audit_id
 ON information_query.audit_holds(audit_id)
 WHERE released_at IS NULL AND audit_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS audit_holds_active_request_id
 ON information_query.audit_holds(request_id)
 WHERE released_at IS NULL AND request_id <> '';
CREATE INDEX IF NOT EXISTS audit_holds_active_target_account
 ON information_query.audit_holds(target_account)
 WHERE released_at IS NULL AND target_account <> '';
CREATE INDEX IF NOT EXISTS audit_holds_active_review
 ON information_query.audit_holds(review_at,id)
 WHERE released_at IS NULL;
REVOKE ALL ON information_query.audit_holds FROM PUBLIC;
REVOKE ALL ON SEQUENCE information_query.audit_holds_id_seq FROM PUBLIC;

CREATE OR REPLACE FUNCTION information_query.audit_is_held(
 p_audit_id bigint,
 p_request_id text,
 p_targets jsonb
) RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = information_query, pg_catalog
AS $$
 SELECT EXISTS (
  SELECT 1
  FROM information_query.audit_holds h
  WHERE h.released_at IS NULL
    AND (
     (h.audit_id IS NOT NULL AND h.audit_id = p_audit_id)
     OR (h.request_id <> '' AND h.request_id = p_request_id)
     OR (h.target_account <> '' AND p_targets @> jsonb_build_array(h.target_account))
    )
 );
$$;

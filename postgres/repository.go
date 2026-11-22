// Package postgres owns only information-query audit data.
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/admin"
	"github.com/jackc/pgx/v5/pgxpool"
	"io/fs"
	"slices"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Repository struct{ Pool *pgxpool.Pool }

// Migrate must run with a separate migration identity.
func (r Repository) Migrate(ctx context.Context) error {
	return migrateFromFS(ctx, r.Pool, migrations, "migrations")
}

// MigrateFS applies ordered SQL migrations from dir, recording each version in
// information_query.schema_migrations inside its own database transaction.
func MigrateFS(ctx context.Context, pool *pgxpool.Pool, fsys fs.ReadDirFS, dir string) error {
	return migrateFromFS(ctx, pool, fsys, dir)
}

func migrateFromFS(ctx context.Context, pool *pgxpool.Pool, fsys fs.ReadDirFS, dir string) error {
	if pool == nil {
		return iq.ErrUnavailable
	}
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return err
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	bootTx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	if _, err = bootTx.Exec(ctx, `
SELECT pg_advisory_xact_lock(hashtext('information_query.schema_migrations'));
CREATE SCHEMA IF NOT EXISTS information_query;
REVOKE ALL ON SCHEMA information_query FROM PUBLIC;
CREATE TABLE IF NOT EXISTS information_query.schema_migrations (
 version text PRIMARY KEY,
 applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
REVOKE ALL ON information_query.schema_migrations FROM PUBLIC;
`); err != nil {
		_ = bootTx.Rollback(ctx)
		return err
	}
	if err = bootTx.Commit(ctx); err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version := entry.Name()
		b, readErr := fs.ReadFile(fsys, dir+"/"+version)
		if readErr != nil {
			return readErr
		}
		tx, txErr := pool.Begin(ctx)
		if txErr != nil {
			return txErr
		}
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('information_query.schema_migrations'))`); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		var applied bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_query.schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if applied {
			_ = tx.Rollback(ctx)
			continue
		}
		if _, err = tx.Exec(ctx, string(b)); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO information_query.schema_migrations(version) VALUES($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (r Repository) Append(ctx context.Context, a iq.Audit) error {
	a = iq.SanitizeAuditForContext(ctx, a)
	if r.Pool == nil {
		return iq.ErrUnavailable
	}
	extra := slices.Clone(a.Scopes)
	for _, scopes := range a.TargetScopes {
		extra = append(extra, scopes...)
	}
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	targets, err := json.Marshal(a.TargetScopes)
	if err != nil {
		return err
	}
	scopes, err := json.Marshal(append([]admin.Scope{}, extra...))
	if err != nil {
		return err
	}
	_, err = r.Pool.Exec(ctx, `WITH entry AS (
		INSERT INTO information_query.audit(school,group_id,module,body,created_at,target_scopes)
		VALUES($1,$2,$3,$4,$5,$6) RETURNING id
	)
	INSERT INTO information_query.audit_scopes(id,school,group_id,module)
	SELECT DISTINCT entry.id,s.school,s."group",s.module FROM entry
	CROSS JOIN jsonb_to_recordset($7::jsonb) AS s(school text,"group" text,module text)
	WHERE (s.school,s."group",s.module) <> ($1,$2,$3)`, a.Scope.School, a.Scope.Group, a.Scope.Module, body, a.CreatedAt, targets, scopes)
	return err
}

func (r Repository) Read(ctx context.Context, f iq.AuditFilter) (out iq.AuditPage, err error) {
	if r.Pool == nil {
		return out, iq.ErrUnavailable
	}
	if f.Limit < 1 || f.Limit > 100 {
		return out, iq.ErrInvalid
	}
	conds := make([]string, 0, 4)
	args := make([]any, 0, 5)
	add := func(expr string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(expr, len(args)))
	}
	if f.After != "" {
		after, e := strconv.ParseInt(f.After, 10, 64)
		if e != nil {
			return out, e
		}
		add("id < $%d", after)
	}
	if f.Scope.School != "*" {
		add("school = $%d", f.Scope.School)
	}
	if f.Scope.Group != "*" {
		add("group_id = $%d", f.Scope.Group)
	}
	if f.Scope.Module != "*" {
		add("module = $%d", f.Scope.Module)
	}
	metadata := []string{}
	addMetadata := func(expr string, value any) {
		args = append(args, value)
		metadata = append(metadata, fmt.Sprintf(expr, len(args)))
	}
	if f.Actor != "" {
		addMetadata("body->>'actor' = $%d", f.Actor)
	}
	if f.Target != "" {
		targetJSON, e := json.Marshal([]string{f.Target})
		if e != nil {
			return out, e
		}
		addMetadata("(body->'targets') @> $%d::jsonb", string(targetJSON))
		if f.Scope != admin.Global {
			// A target filter must have the same visibility as the returned target.
			required := map[string]string{}
			if f.Scope.School != "*" {
				required["school"] = f.Scope.School
			}
			if f.Scope.Group != "*" {
				required["group"] = f.Scope.Group
			}
			if f.Scope.Module != "*" {
				required["module"] = f.Scope.Module
			}
			tuple, err := json.Marshal([]map[string]string{required})
			if err != nil {
				return out, err
			}
			args = append(args, f.Target, string(tuple))
			metadata = append(metadata, fmt.Sprintf("COALESCE(NULLIF(a.target_scopes->($%d::text), '[]'::jsonb),jsonb_build_array(a.body->'scope')) @> $%d::jsonb", len(args)-1, len(args)))
		}
	}
	if f.Action != "" {
		addMetadata("body->>'action' = $%d", f.Action)
	}
	if f.Result == "denied" || f.Result == "forbidden" {
		metadata = append(metadata, "body->>'result' IN ('denied','forbidden')")
	} else if f.Result != "" {
		addMetadata("body->>'result' = $%d", f.Result)
	}
	if f.Channel != "" {
		addMetadata("body->>'channel' = $%d", f.Channel)
	}
	if f.CreatedFrom != nil {
		addMetadata("created_at >= $%d", f.CreatedFrom.UTC())
	}
	if f.CreatedUntil != nil {
		addMetadata("created_at <= $%d", f.CreatedUntil.UTC())
	}
	if len(metadata) > 0 {
		conds = append(conds, "id IN (SELECT a.id FROM information_query.audit a WHERE "+strings.Join(metadata, " AND ")+")")
	}
	args = append(args, f.Limit+1)
	limit := fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	query := `SELECT id,body,target_scopes FROM information_query.audit` + where + limit
	if f.Scope != admin.Global {
		// Cap each ordered input before merging. An audit may match multiple observed scopes.
		base := `SELECT id FROM information_query.audit` + where + limit
		extra := `SELECT DISTINCT id FROM information_query.audit_scopes` + where + limit
		query = `WITH page AS ((` + base + `) UNION (` + extra + `)` + limit + `)
			SELECT a.id,a.body,a.target_scopes FROM page JOIN information_query.audit a USING(id) ORDER BY a.id DESC`
	}
	rows, err := r.Pool.Query(ctx, query, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Items = []iq.Audit{}
	for rows.Next() {
		var id int64
		var b, tsBytes []byte
		if err = rows.Scan(&id, &b, &tsBytes); err != nil {
			return out, err
		}
		var a iq.Audit
		if err = json.Unmarshal(b, &a); err != nil {
			return out, err
		}
		if f.Scope != admin.Global && len(a.Targets) > 0 {
			var targets map[string][]admin.Scope
			if err = json.Unmarshal(tsBytes, &targets); err != nil {
				return out, err
			}
			filtered := make([]string, 0, len(a.Targets))
			for _, target := range a.Targets {
				scopes := targets[target]
				// Legacy/provider rows only have the original request scope.
				if (len(scopes) == 0 && f.Scope.Contains(a.Scope)) || slices.ContainsFunc(scopes, f.Scope.Contains) {
					filtered = append(filtered, target)
				}
			}
			a.Targets = filtered
		}
		a = iq.SanitizeAudit(a)
		a.ID = strconv.FormatInt(id, 10)
		out.Items = append(out.Items, a)
	}
	if len(out.Items) > f.Limit {
		out.Items = out.Items[:f.Limit]
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	return out, rows.Err()
}

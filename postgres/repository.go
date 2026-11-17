// Package postgres owns only information-query audit data.
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	iq "github.com/StuHelper/stuhelper-information-query"
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
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	_, e = r.Pool.Exec(ctx, `INSERT INTO information_query.audit(school,group_id,module,body,created_at) VALUES($1,$2,$3,$4,$5)`, a.Scope.School, a.Scope.Group, a.Scope.Module, b, a.CreatedAt)
	return e
}
func (r Repository) Read(ctx context.Context, f iq.AuditFilter) (out iq.AuditPage, err error) {
	after := int64(0)
	if f.After != "" {
		after, err = strconv.ParseInt(f.After, 10, 64)
		if err != nil {
			return out, err
		}
	}
	rows, err := r.Pool.Query(ctx, `SELECT id,body FROM information_query.audit WHERE id>$1 AND ($2='*' OR school=$2) AND ($3='*' OR group_id=$3) AND ($4='*' OR module=$4) ORDER BY id LIMIT $5`, after, f.Scope.School, f.Scope.Group, f.Scope.Module, f.Limit)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Items = []iq.Audit{}
	for rows.Next() {
		var id int64
		var b []byte
		if err = rows.Scan(&id, &b); err != nil {
			return out, err
		}
		var a iq.Audit
		if err = json.Unmarshal(b, &a); err != nil {
			return out, err
		}
		a.ID = strconv.FormatInt(id, 10)
		out.Items = append(out.Items, a)
	}
	if len(out.Items) == f.Limit {
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	return out, rows.Err()
}

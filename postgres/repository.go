// Package postgres owns only information-query audit data.
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/jackc/pgx/v5/pgxpool"
	"strconv"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Repository struct{ Pool *pgxpool.Pool }

// Migrate must run with a separate migration identity.
func (r Repository) Migrate(ctx context.Context) error {
	b, e := migrations.ReadFile("migrations/001_audit.sql")
	if e != nil {
		return e
	}
	_, e = r.Pool.Exec(ctx, string(b))
	return e
}
func (r Repository) Append(ctx context.Context, a iq.Audit) error {
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	_, e = r.Pool.Exec(ctx, `INSERT INTO information_query.audit(school,group_id,module,body) VALUES($1,$2,$3,$4)`, a.Scope.School, a.Scope.Group, a.Scope.Module, b)
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

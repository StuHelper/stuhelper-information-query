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
	"slices"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Repository struct{ Pool *pgxpool.Pool }

// Migrate must run with a separate migration identity.
func (r Repository) Migrate(ctx context.Context) error {
	if r.Pool == nil {
		return iq.ErrUnavailable
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		b, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		if _, err = r.Pool.Exec(ctx, string(b)); err != nil {
			return err
		}
	}
	return nil
}

func addDim(dst *[]string, v string) {
	if v != "" && v != "*" && !slices.Contains(*dst, v) {
		*dst = append(*dst, v)
	}
}

func collectDimensions(a iq.Audit) (schools, groups, modules []string) {
	schools, groups, modules = []string{}, []string{}, []string{}
	recordScope := func(sc admin.Scope) {
		addDim(&schools, sc.School)
		addDim(&groups, sc.Group)
		addDim(&modules, sc.Module)
	}
	recordScope(a.Scope)
	for _, sc := range a.Scopes {
		recordScope(sc)
	}
	for _, list := range a.TargetScopes {
		for _, sc := range list {
			recordScope(sc)
		}
	}
	return schools, groups, modules
}

func targetInScope(filter admin.Scope, fallback admin.Scope, scopes []admin.Scope) bool {
	if len(scopes) == 0 {
		_, ok := filter.Intersection(fallback)
		return ok
	}
	schoolOK := filter.School == "*"
	groupOK := filter.Group == "*"
	moduleOK := filter.Module == "*"
	for _, sc := range scopes {
		if !schoolOK && sc.School == filter.School {
			schoolOK = true
		}
		if !groupOK && sc.Group == filter.Group {
			groupOK = true
		}
		if !moduleOK && (sc.Module == "*" || sc.Module == filter.Module) {
			moduleOK = true
		}
	}
	return schoolOK && groupOK && moduleOK
}

func (r Repository) Append(ctx context.Context, a iq.Audit) error {
	if r.Pool == nil {
		return iq.ErrUnavailable
	}
	schools, groups, modules := collectDimensions(a)
	targetScopes := a.TargetScopes
	if targetScopes == nil {
		targetScopes = map[string][]admin.Scope{}
	}
	tsBytes, e := json.Marshal(targetScopes)
	if e != nil {
		return e
	}
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	_, e = r.Pool.Exec(
		ctx,
		`INSERT INTO information_query.audit(school,group_id,module,schools,groups,modules,target_scopes,body,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		a.Scope.School, a.Scope.Group, a.Scope.Module, schools, groups, modules, tsBytes, b, a.CreatedAt,
	)
	return e
}

func (r Repository) Read(ctx context.Context, f iq.AuditFilter) (out iq.AuditPage, err error) {
	if r.Pool == nil {
		return out, iq.ErrUnavailable
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
		add("schools @> ARRAY[$%d]::text[]", f.Scope.School)
	}
	if f.Scope.Group != "*" {
		add("groups @> ARRAY[$%d]::text[]", f.Scope.Group)
	}
	if f.Scope.Module != "*" {
		add("modules @> ARRAY[$%d]::text[]", f.Scope.Module)
	}
	args = append(args, f.Limit)
	query := `SELECT id,body,target_scopes FROM information_query.audit`
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))
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
		if f.Scope != admin.Global && len(a.Targets) > 0 && len(tsBytes) > 0 {
			var ts map[string][]admin.Scope
			if json.Unmarshal(tsBytes, &ts) == nil && len(ts) > 0 {
				filtered := make([]string, 0, len(a.Targets))
				for _, target := range a.Targets {
					if targetInScope(f.Scope, a.Scope, ts[target]) {
						filtered = append(filtered, target)
					}
				}
				a.Targets = filtered
			}
		}
		a.ID = strconv.FormatInt(id, 10)
		out.Items = append(out.Items, a)
	}
	if len(out.Items) == f.Limit {
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	return out, rows.Err()
}

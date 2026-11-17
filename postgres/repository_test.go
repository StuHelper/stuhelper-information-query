package postgres_test

import (
	"context"
	"encoding/json"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-information-query/postgres"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIsolatedAuditPersistenceAndRuntimePrivileges(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal("migration replay", e)
	}
	_, e = pool.Exec(ctx, `CREATE ROLE iq_runtime NOLOGIN; GRANT USAGE ON SCHEMA information_query TO iq_runtime; GRANT SELECT,INSERT ON information_query.audit TO iq_runtime; GRANT USAGE ON SEQUENCE information_query.audit_id_seq TO iq_runtime; CREATE SCHEMA foreign_module; CREATE TABLE foreign_module.secret(value text);`)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["role"] = "iq_runtime"
	runtime, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	r.Pool = runtime
	a := iq.Audit{Actor: "operator", RequestID: "request", Purpose: "audit-test", Scope: admin.Scope{School: "a", Group: "g", Module: "profiles"}, Channel: "bot_group", TargetGroup: "g", Action: "query", Result: "success", Count: 1, Targets: []string{"subject"}, Fields: []string{"identity"}, Basis: []string{"information-query.identity.read"}, CreatedAt: time.Now().UTC()}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			if e := r.Append(ctx, a); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	page, e := r.Read(ctx, iq.AuditFilter{Scope: a.Scope, Limit: 10})
	if e != nil || len(page.Items) != 10 || page.NextCursor == "" {
		t.Fatal(page, e)
	}
	next, e := r.Read(ctx, iq.AuditFilter{Scope: a.Scope, Limit: 100, After: page.NextCursor})
	if e != nil || len(next.Items) != 10 {
		t.Fatal(next, e)
	}
	b, _ := json.Marshal(next)
	if strings.Contains(string(b), "123456789") {
		t.Fatal("raw identity in audit")
	}
	page, e = r.Read(ctx, iq.AuditFilter{Scope: admin.Scope{School: "b", Group: "*", Module: "*"}, Limit: 100})
	if e != nil || len(page.Items) != 0 {
		t.Fatal("scope leak", e)
	}
	for _, sql := range []string{`SELECT * FROM foreign_module.secret`, `DELETE FROM information_query.audit`, `UPDATE information_query.audit SET school='b'`, `CREATE TABLE information_query.forbidden(id int)`} {
		if _, e = runtime.Exec(ctx, sql); e == nil {
			t.Fatalf("runtime accepted %s", sql)
		}
	}
}

type allow struct{}

func (allow) Evaluate(context.Context, account.Principal, string, admin.Scope) error { return nil }

type records struct{}

func (records) Query(context.Context, account.Principal, iq.Query) ([]iq.Record, error) {
	return []iq.Record{{ID: "profiles:1", Subject: "user-1", Scope: admin.Scope{School: "a", Group: "g", Module: "profiles"}, Source: "test-binding", Current: true, ChangedAt: time.Now(), Fields: []iq.Field{{Name: "qq", Category: "identity", Value: "123456789"}}}}, nil
}
func TestSensitiveResponseRequiresCommittedAudit(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	s := iq.Service{Auth: allow{}, Repo: r, Providers: map[string]iq.Provider{"profiles": records{}}}
	q := iq.Query{Kind: "account", Value: "user-1", Scope: admin.Scope{School: "a", Group: "g", Module: "profiles"}, Domains: []string{"profiles"}, Fields: []string{"identity"}, Purpose: "test disclosure", Limit: 10}
	out, e := s.Query(ctx, account.Principal{Issuer: "test", Subject: "operator"}, "disclosure-request", iq.Delivery{Channel: "bot_group", Group: "g"}, q)
	if e != iq.ErrForbidden || recordCount(out) != 0 {
		t.Fatal("bot default", e)
	}
	s.BotEnabled = true
	out, e = s.Query(ctx, account.Principal{Issuer: "test", Subject: "operator"}, "disclosure-request", iq.Delivery{Channel: "bot_group", Group: "g"}, q)
	if e != nil || recordCount(out) != 1 || out.Groups[0].Items[0].Fields[0].Value != "123456789" {
		t.Fatal(e)
	}
	var count int
	var raw string
	e = pool.QueryRow(ctx, `SELECT count(*),string_agg(body::text,'') FROM information_query.audit WHERE body->>'request_id'='disclosure-request'`).Scan(&count, &raw)
	if e != nil || count != 2 || strings.Contains(raw, "123456789") || !strings.Contains(raw, "user-1") {
		t.Fatal("audit commit/content", count, e)
	}
	// A real database rejection must suppress the already-fetched sensitive result.
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readOnly, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer readOnly.Close()
	s.Repo = postgres.Repository{Pool: readOnly}
	out, e = s.Query(ctx, account.Principal{Issuer: "test", Subject: "operator"}, "blocked", iq.Delivery{Channel: "admin"}, q)
	if e != iq.ErrUnavailable || recordCount(out) != 0 {
		t.Fatal("failed commit leaked", e)
	}
}

func recordCount(out iq.Result) int {
	n := 0
	for _, g := range out.Groups {
		n += len(g.Items)
	}
	return n
}

func TestBoundedPruneAndMaintenancePrivileges(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	cutoff := now.AddDate(-1, 0, 0)
	for _, at := range []time.Time{cutoff.Add(-time.Second), cutoff.Add(-time.Second), cutoff.Add(-time.Second), cutoff, cutoff.Add(time.Second)} {
		if e = r.Append(ctx, iq.Audit{Scope: admin.Global, CreatedAt: at}); e != nil {
			t.Fatal(e)
		}
	}
	_, e = pool.Exec(ctx, `CREATE ROLE iq_maintenance NOLOGIN; GRANT USAGE ON SCHEMA information_query TO iq_maintenance; GRANT SELECT,DELETE ON information_query.audit TO iq_maintenance; CREATE ROLE iq_prune_runtime NOLOGIN; GRANT USAGE ON SCHEMA information_query TO iq_prune_runtime; GRANT SELECT,INSERT ON information_query.audit TO iq_prune_runtime;`)
	if e != nil {
		t.Fatal(e)
	}
	makePool := func(role string) *pgxpool.Pool {
		cfg, e := pgxpool.ParseConfig(dsn)
		if e != nil {
			t.Fatal(e)
		}
		cfg.ConnConfig.RuntimeParams["role"] = role
		p, e := pgxpool.NewWithConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(p.Close)
		return p
	}
	m := postgres.Maintenance{Pool: makePool("iq_maintenance"), Now: func() time.Time { return now }}
	runtime := postgres.Maintenance{Pool: makePool("iq_prune_runtime"), Now: m.Now}
	if n, e := runtime.PruneAudit(ctx, cutoff, 1); e == nil || n != 0 {
		t.Fatal("runtime deletion allowed", n, e)
	}
	if _, e = m.Pool.Exec(ctx, `INSERT INTO information_query.audit(school,group_id,module,body) VALUES ('a','g','m','{}')`); e == nil {
		t.Fatal("maintenance insert allowed")
	}
	if _, e = m.Pool.Exec(ctx, `UPDATE information_query.audit SET school='changed'`); e == nil {
		t.Fatal("maintenance update allowed")
	}
	for _, limit := range []int{0, -1, 1001} {
		if _, e = m.PruneAudit(ctx, cutoff, limit); e != iq.ErrInvalid {
			t.Fatal("invalid limit", e)
		}
	}
	if _, e = m.PruneAudit(ctx, cutoff.Add(time.Second), 1); e != iq.ErrInvalid {
		t.Fatal("retention shortened", e)
	}
	for _, want := range []int{2, 1, 0} {
		n, e := m.PruneAudit(ctx, cutoff, 2)
		if e != nil || n != want {
			t.Fatal("bounded/repeated cleanup", n, e)
		}
	}
	var kept int
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM information_query.audit WHERE created_at=$1 OR created_at=$2`, cutoff, cutoff.Add(time.Second)).Scan(&kept); e != nil || kept != 2 {
		t.Fatal("boundary removed", kept, e)
	}
}

func TestAuditNewestFirstPaginationAndMultidimensionalFilters(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	testScope := admin.Scope{School: "filter-school", Group: "filter-group", Module: "profiles"}
	base := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	entries := []iq.Audit{
		{Actor: "issuer:admin-1", RequestID: "req-1", Purpose: "工单核查-1", Scope: testScope, Channel: "admin", Action: "query", Result: "success", Count: 1, Targets: []string{"issuer:student-a", "issuer:student-b"}, Fields: []string{"identity"}, Basis: []string{"information-query.profiles.read"}, CreatedAt: base},
		{Actor: "issuer:admin-2", RequestID: "req-2", Purpose: "群聊核查-2", Scope: testScope, Channel: "bot_group", TargetGroup: "filter-group", Action: "query", Result: "forbidden", Count: 0, Targets: []string{"issuer:student-c"}, Fields: []string{}, Basis: []string{}, CreatedAt: base.Add(time.Minute)},
		{Actor: "issuer:admin-1", RequestID: "req-3", Purpose: "申诉复查-3", Scope: testScope, Channel: "admin", Action: "query", Result: "success", Count: 2, Targets: []string{"issuer:student-b"}, Fields: []string{"document"}, Basis: []string{"information-query.document.read"}, CreatedAt: base.Add(2 * time.Minute)},
	}
	for _, entry := range entries {
		if e = r.Append(ctx, entry); e != nil {
			t.Fatal(e)
		}
	}
	svc := iq.Service{Auth: allow{}, Repo: r, Now: func() time.Time { return base.Add(5 * time.Minute) }}
	// Verify newest-first order and termination under limit=1 despite synchronous audit.query appends.
	seen := []string{}
	after := ""
	for step := 0; step < 10; step++ {
		page, err := svc.Audit(ctx, account.Principal{Issuer: "issuer", Subject: "auditor"}, "audit-req", iq.AuditFilter{
			Scope:   testScope,
			Purpose: "本次查阅事由不参与过滤",
			After:   after,
			Limit:   1,
			Action:  "query",
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			seen = append(seen, item.RequestID)
		}
		if page.NextCursor == "" {
			break
		}
		after = page.NextCursor
		if step == 9 {
			t.Fatal("newest-first pagination did not terminate")
		}
	}
	if len(seen) != 3 || seen[0] != "req-3" || seen[1] != "req-2" || seen[2] != "req-1" {
		t.Fatalf("expected newest-first [req-3 req-2 req-1], got %v", seen)
	}
	from := base.Add(30 * time.Second)
	until := base.Add(2 * time.Minute)
	filtered, err := svc.Audit(ctx, account.Principal{Issuer: "issuer", Subject: "auditor"}, "audit-filter", iq.AuditFilter{
		Scope:        admin.Scope{School: "filter-school", Group: "*", Module: "*"},
		Purpose:      "核查学生B谁查过",
		Limit:        20,
		Actor:        "issuer:admin-1",
		Target:       "issuer:student-b",
		Action:       "query",
		Result:       "success",
		Channel:      "admin",
		CreatedFrom:  &from,
		CreatedUntil: &until,
	})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].RequestID != "req-3" {
		t.Fatalf("unexpected multidimensional filter result: %+v %v", filtered, err)
	}
	denied, err := svc.Audit(ctx, account.Principal{Issuer: "issuer", Subject: "auditor"}, "audit-denied", iq.AuditFilter{
		Scope:   testScope,
		Purpose: "核查拒绝记录",
		Limit:   20,
		Result:  "forbidden",
		Channel: "bot_group",
	})
	if err != nil || len(denied.Items) != 1 || denied.Items[0].RequestID != "req-2" {
		t.Fatalf("unexpected result/channel filter: %+v %v", denied, err)
	}
}

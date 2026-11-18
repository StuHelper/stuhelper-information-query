package postgres_test

import (
	"context"
	"encoding/json"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-information-query/postgres"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strconv"
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
	_, e = pool.Exec(ctx, `CREATE ROLE iq_runtime NOLOGIN; GRANT USAGE ON SCHEMA information_query TO iq_runtime; GRANT SELECT,INSERT ON information_query.audit, information_query.audit_scopes TO iq_runtime; GRANT USAGE ON SEQUENCE information_query.audit_id_seq TO iq_runtime; CREATE SCHEMA foreign_module; CREATE TABLE foreign_module.secret(value text);`)
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
	for _, sql := range []string{`SELECT * FROM foreign_module.secret`, `DELETE FROM information_query.audit_scopes`, `DELETE FROM information_query.audit`, `UPDATE information_query.audit SET school='b'`, `CREATE TABLE information_query.forbidden(id int)`} {
		if _, e = runtime.Exec(ctx, sql); e == nil {
			t.Fatalf("runtime accepted %s", sql)
		}
	}
	// Scope indexing and the audit body must commit together.
	if _, e = pool.Exec(ctx, `REVOKE INSERT ON information_query.audit_scopes FROM iq_runtime`); e != nil {
		t.Fatal(e)
	}
	a.RequestID = "must-roll-back"
	a.Scopes = []admin.Scope{admin.Global}
	if e = r.Append(ctx, a); e == nil {
		t.Fatal("scope index write should fail")
	}
	var count int
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM information_query.audit WHERE body->>'request_id'='must-roll-back'`).Scan(&count); e != nil || count != 0 {
		t.Fatalf("partial audit: count=%d err=%v", count, e)
	}

}

type allow struct{}

func (allow) Evaluate(context.Context, account.Principal, string, admin.Scope) error { return nil }

type records struct{}

func (records) Query(context.Context, account.Principal, iq.Query) ([]iq.Record, error) {
	return []iq.Record{{ID: "profiles:1", Subject: (account.Principal{Issuer: "test", Subject: "user"}).Key(), Scope: admin.Scope{School: "a", Group: "g", Module: "profiles"}, Source: "test-binding", Current: true, ChangedAt: time.Now(), Fields: []iq.Field{{Name: "qq", Category: "identity", Value: "123456789"}}}}, nil
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
	q := iq.Query{Kind: "account", Value: (account.Principal{Issuer: "test", Subject: "user"}).Key(), Scope: admin.Scope{School: "a", Group: "g", Module: "profiles"}, Domains: []string{"profiles"}, Fields: []string{"identity"}, Purpose: "test disclosure", Limit: 10}
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
	if e != nil || count != 2 || strings.Contains(raw, "123456789") || !strings.Contains(raw, (account.Principal{Issuer: "test", Subject: "user"}).Key()) {
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

func TestNilPoolReturnsUnavailable(t *testing.T) {
	ctx := context.Background()
	var repo postgres.Repository
	if e := repo.Migrate(ctx); e != iq.ErrUnavailable {
		t.Fatalf("Migrate nil pool: got %v, want ErrUnavailable", e)
	}
	if e := repo.Append(ctx, iq.Audit{Scope: admin.Global}); e != iq.ErrUnavailable {
		t.Fatalf("Append nil pool: got %v, want ErrUnavailable", e)
	}
	if _, e := repo.Read(ctx, iq.AuditFilter{Scope: admin.Global, Limit: 10}); e != iq.ErrUnavailable {
		t.Fatalf("Read nil pool: got %v, want ErrUnavailable", e)
	}
	var maint postgres.Maintenance
	if _, e := maint.PruneAudit(ctx, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), 10); e != iq.ErrUnavailable {
		t.Fatalf("PruneAudit nil pool: got %v, want ErrUnavailable", e)
	}
	svc := iq.Service{Auth: allow{}, Repo: postgres.Repository{}}
	actor := account.Principal{Issuer: "test", Subject: "operator"}
	if _, e := svc.Audit(ctx, actor, "nil-audit", iq.AuditFilter{Scope: admin.Global, Purpose: "check", Limit: 1}); e != iq.ErrUnavailable {
		t.Fatalf("Service.Audit nil pool: got %v, want ErrUnavailable", e)
	}
}

func TestAuditDescendingPaginationTerminatesUnderSelfAudit(t *testing.T) {
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
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	sc := admin.Scope{School: "a01-school-" + nonce, Group: "a01-group-" + nonce, Module: "profiles"}
	for _, reqID := range []string{"first-entry", "second-entry"} {
		if e = r.Append(ctx, iq.Audit{
			Actor:     "operator",
			RequestID: reqID,
			Purpose:   reqID,
			Scope:     sc,
			Channel:   "admin",
			Action:    "query",
			Result:    "success",
			Targets:   []string{},
			Fields:    []string{},
			Basis:     []string{},
			CreatedAt: time.Now().UTC(),
		}); e != nil {
			t.Fatal(e)
		}
	}
	svc := iq.Service{Auth: allow{}, Repo: r}
	actor := account.Principal{Issuer: "test", Subject: "auditor"}
	var purposes []string
	after := ""
	for pages := 0; ; pages++ {
		if pages >= 5 {
			t.Fatalf("audit pagination entered self-audit loop after %d pages", pages)
		}
		page, err := svc.Audit(ctx, actor, "audit-page", iq.AuditFilter{
			Scope:   sc,
			Purpose: "audit review",
			After:   after,
			Limit:   1,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			purposes = append(purposes, item.Purpose)
		}
		if page.NextCursor == "" {
			break
		}
		after = page.NextCursor
	}
	var ownAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_query.audit WHERE school=$1 AND body->>'action'='audit.query'`, sc.School).Scan(&ownAudits); err != nil || ownAudits != 2 {
		t.Fatal("self audit count", ownAudits, err)
	}
	if len(purposes) != 2 || purposes[0] != "second-entry" || purposes[1] != "first-entry" {
		t.Fatalf("expected newest-first [second-entry first-entry], got %v", purposes)
	}
}

type multiSchoolResolver struct {
	candidates []iq.Candidate
}

func (m multiSchoolResolver) Resolve(_ context.Context, _ account.Principal, l iq.Lead) ([]iq.Candidate, string, error) {
	idx := 0
	if l.After == "1" {
		idx = 1
	} else if l.After != "" {
		return []iq.Candidate{}, "", nil
	}
	if idx >= len(m.candidates) {
		return []iq.Candidate{}, "", nil
	}
	next := ""
	if idx+1 < len(m.candidates) {
		next = "1"
	}
	return []iq.Candidate{m.candidates[idx]}, next, nil
}

type scopedDomainProvider struct {
	domain string
	byAcct map[string]admin.Scope
}

func (p scopedDomainProvider) Query(_ context.Context, _ account.Principal, q iq.Query) ([]iq.Record, error) {
	sc, ok := p.byAcct[q.Value]
	if !ok {
		return []iq.Record{}, nil
	}
	return []iq.Record{{
		ID:        p.domain + ":1",
		Subject:   q.Value,
		Scope:     sc,
		Source:    p.domain,
		Current:   true,
		ChangedAt: time.Unix(200, 0).UTC(),
		Fields:    []iq.Field{{Name: "status", Category: "business", Value: "ok"}},
	}}, nil
}

func TestMultiDomainAndCrossSchoolAuditVisibilityAndTargetRedaction(t *testing.T) {
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
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	schoolA, groupA := "a04-school-a-"+nonce, "a04-group-a-"+nonce
	schoolB, groupB := "a04-school-b-"+nonce, "a04-group-b-"+nonce
	schoolC := "a04-school-c-" + nonce
	acctA := account.Principal{Issuer: "https://sso.example", Subject: "student-a"}.Key()
	acctB := account.Principal{Issuer: "https://sso.example", Subject: "student-b"}.Key()
	svc := iq.Service{
		Auth: allow{},
		Repo: r,
		Resolvers: map[string]iq.Resolver{
			"name": multiSchoolResolver{candidates: []iq.Candidate{
				{
					Account:   acctA,
					Source:    "verification",
					Current:   true,
					ChangedAt: time.Unix(100, 0).UTC(),
					Scope:     admin.Scope{School: schoolA, Group: groupA, Module: "*"},
					Label:     []iq.Field{{Name: "name", Category: "identity", Value: "***", Masked: true}},
				},
				{
					Account:   acctB,
					Source:    "verification",
					Current:   true,
					ChangedAt: time.Unix(100, 0).UTC(),
					Scope:     admin.Scope{School: schoolB, Group: groupB, Module: "*"},
					Label:     []iq.Field{{Name: "name", Category: "identity", Value: "***", Masked: true}},
				},
			}},
		},
		Providers: map[string]iq.Provider{
			"verification": scopedDomainProvider{
				domain: "verification",
				byAcct: map[string]admin.Scope{
					acctA: {School: schoolA, Group: groupA, Module: "verification"},
					acctB: {School: schoolB, Group: groupB, Module: "verification"},
				},
			},
			"billing": scopedDomainProvider{
				domain: "billing",
				byAcct: map[string]admin.Scope{
					acctA: {School: "*", Group: "*", Module: "billing"},
				},
			},
		},
	}
	actor := account.Principal{Issuer: "https://sso.example", Subject: "platform-admin"}
	_, err := svc.Query(ctx, actor, "global-multi-domain", iq.Delivery{Channel: "admin"}, iq.Query{
		Kind:    "name",
		Value:   "Same Name",
		Scope:   admin.Global,
		Domains: []string{"verification", "billing"},
		Purpose: "cross-school investigation",
		Limit:   20,
	})
	if err != nil {
		t.Fatal(err)
	}

	// School-A auditor must see the global query and only see acctA (not acctB from school-B).
	schoolAPage, err := r.Read(ctx, iq.AuditFilter{
		Scope: admin.Scope{School: schoolA, Group: "*", Module: "*"},
		Limit: 10,
	})
	if err != nil || len(schoolAPage.Items) != 1 {
		t.Fatalf("school-a auditor missed global query: items=%d err=%v", len(schoolAPage.Items), err)
	}
	if len(schoolAPage.Items[0].Targets) != 1 || schoolAPage.Items[0].Targets[0] != acctA {
		t.Fatalf("expected only acctA in school-a audit view, got %v", schoolAPage.Items[0].Targets)
	}

	// Group-A auditor must also see the query with only acctA.
	groupAPage, err := r.Read(ctx, iq.AuditFilter{
		Scope: admin.Scope{School: "*", Group: groupA, Module: "*"},
		Limit: 10,
	})
	if err != nil || len(groupAPage.Items) != 1 || len(groupAPage.Items[0].Targets) != 1 || groupAPage.Items[0].Targets[0] != acctA {
		t.Fatalf("group-a auditor view mismatch: %+v err=%v", groupAPage, err)
	}

	// Billing module auditor must see the multi-domain query (where request Scope.Module was "*").
	billingPage, err := r.Read(ctx, iq.AuditFilter{
		Scope: admin.Scope{School: schoolA, Group: "*", Module: "billing"},
		Limit: 10,
	})
	if err != nil || len(billingPage.Items) != 1 || len(billingPage.Items[0].Targets) != 1 || billingPage.Items[0].Targets[0] != acctA {
		t.Fatalf("billing module auditor missed multi-domain query: %+v err=%v", billingPage, err)
	}

	// Restrictions have to match one observed scope.
	mixed, err := r.Read(ctx, iq.AuditFilter{Scope: admin.Scope{School: schoolA, Group: groupB, Module: "billing"}, Limit: 10})
	if err != nil || len(mixed.Items) != 0 {
		t.Fatalf("unrelated tuple matched: %d rows, %v", len(mixed.Items), err)
	}

	// Unrelated school-C auditor must see 0 records.
	schoolCPage, err := r.Read(ctx, iq.AuditFilter{
		Scope: admin.Scope{School: schoolC, Group: "*", Module: "*"},
		Limit: 10,
	})
	if err != nil || len(schoolCPage.Items) != 0 {
		t.Fatalf("unrelated school-c saw records: %+v err=%v", schoolCPage, err)
	}
}

func TestAuditSelectiveScopeUsesIndexWithoutWildcardOrPredicate(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx := context.Background()
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.MaxConns = 1
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	noiseSchool := "a12-noise-school-" + nonce
	targetSchool := "a12-target-school-" + nonce
	for i := 0; i < 400; i++ {
		sc := admin.Scope{School: noiseSchool + strconv.Itoa(i), Group: "*", Module: "profiles"}
		if i == 250 {
			sc.School = targetSchool
		}
		if e = r.Append(ctx, iq.Audit{
			Actor:     "op",
			RequestID: "r",
			Purpose:   "p",
			Scope:     sc,
			Scopes:    []admin.Scope{{School: "extra-" + sc.School, Group: "*", Module: "profiles"}},
			Channel:   "admin",
			Action:    "query",
			Result:    "success",
			Targets:   []string{},
			Fields:    []string{},
			Basis:     []string{},
			CreatedAt: time.Now().UTC(),
		}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = pool.Exec(ctx, `ANALYZE information_query.audit; ANALYZE information_query.audit_scopes`); e != nil {
		t.Fatal(e)
	}
	page, e := r.Read(ctx, iq.AuditFilter{
		Scope: admin.Scope{School: targetSchool, Group: "*", Module: "*"},
		Limit: 10,
	})
	if e != nil || len(page.Items) != 1 {
		t.Fatalf("selective read failed: %+v %v", page, e)
	}
	conn, e := pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Release()
	if _, e = conn.Exec(ctx, `SET plan_cache_mode = force_generic_plan`); e != nil {
		t.Fatal(e)
	}
	var statement string
	if e = conn.QueryRow(ctx, `SELECT name FROM pg_prepared_statements WHERE statement LIKE 'WITH page AS (%' LIMIT 1`).Scan(&statement); e != nil {
		t.Fatal(e)
	}
	rows, e := conn.Query(ctx, "EXPLAIN EXECUTE "+pgx.Identifier{statement}.Sanitize()+"('school', 10)")
	if e != nil {
		t.Fatal("explaining repository scope query:", e)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if e = rows.Scan(&line); e != nil {
			t.Fatal(e)
		}
		plan.WriteString(line + "\n")
	}
	rows.Close()
	if !strings.Contains(plan.String(), "audit_school_page") || !strings.Contains(plan.String(), "audit_scopes_school_page") {
		t.Fatalf("expected ordered school indexes for request and observed scopes, got:\n%s", plan.String())
	}
}

func TestMalformedInputAuditSanitizationAndNonNullSlices(t *testing.T) {
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
	svc := iq.Service{Auth: allow{}, Repo: r}
	actor := account.Principal{Issuer: "test", Subject: "student"}
	reqID := "malformed-" + time.Now().UTC().Format("150405.000000000")

	// The malformed request must keep its rejection code and commit a readable denial.
	_, err := svc.Query(ctx, actor, reqID+"\x00", iq.Delivery{Channel: "bad\x00", Group: "g\x00"}, iq.Query{
		Kind:    "name",
		Value:   "x",
		Scope:   admin.Scope{School: "", Group: "a02-group", Module: "*"},
		Domains: []string{"profiles"},
		Purpose: "bad\x00purpose",
		Limit:   1,
	})
	if err != iq.ErrInvalid {
		t.Fatalf("expected ErrInvalid for NUL/invalid scope, got %v", err)
	}

	var stored iq.Audit
	var body []byte
	var indexed admin.Scope
	if e = pool.QueryRow(ctx, `SELECT school,group_id,module,body FROM information_query.audit WHERE body->>'request_id'=$1`, reqID).Scan(&indexed.School, &indexed.Group, &indexed.Module, &body); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(body, &stored); e != nil || indexed != admin.Global || stored.Scope != indexed || stored.Purpose != "badpurpose" || stored.Channel != "unknown" || stored.Result != "invalid_request" || stored.Fields == nil || stored.Targets == nil || stored.Basis == nil {
		t.Fatal("stored denial", stored, e)
	}
	// Direct Repository.Append with nil slices must also round-trip as [] not null.
	nilSliceScope := admin.Scope{School: "a02-nil-school", Group: "a02-group", Module: "profiles"}
	if err = r.Append(ctx, iq.Audit{
		Actor:     actor.Key(),
		RequestID: reqID + "-nil",
		Purpose:   "provider denial",
		Scope:     nilSliceScope,
		Channel:   "admin",
		Action:    "provider.query",
		Result:    "denied",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Append nil slices failed: %v", err)
	}

	// Simulate an immutable row written by an older host and inspect its read projection.
	if _, err = pool.Exec(ctx, `INSERT INTO information_query.audit(school,group_id,module,body)
		VALUES('legacy','a02-group','profiles','{"scope":{"school":"","group":"a02-group","module":"profiles"},"channel":"legacy","action":"legacy","result":"forbidden","fields":["business"],"targets":null,"basis":null}')`); err != nil {
		t.Fatal(err)
	}
	page, err := r.Read(ctx, iq.AuditFilter{Scope: admin.Scope{School: "*", Group: "a02-group", Module: "*"}, Limit: 100})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("Read sanitized audits failed: items=%d err=%v", len(page.Items), err)
	}
	for _, item := range page.Items {
		if !item.Scope.Valid() {
			t.Fatalf("persisted invalid Scope in audit: %+v", item.Scope)
		}
		if strings.ContainsRune(item.Purpose, '\x00') || strings.ContainsRune(item.RequestID, '\x00') {
			t.Fatalf("persisted NUL byte in audit: %+v", item)
		}
		if item.Action == "unknown" && (item.Channel != "unknown" || item.Result != "denied" || len(item.Fields) != 0) {
			t.Fatal("legacy projection", item)
		}
		raw, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"targets":null`) || strings.Contains(string(raw), `"fields":null`) || strings.Contains(string(raw), `"basis":null`) {
			t.Fatalf("serialized null array in audit JSON: %s", string(raw))
		}
	}
}

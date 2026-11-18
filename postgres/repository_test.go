package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
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
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

var roleSeq atomic.Uint64

func uniqueSuffix() string {
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), roleSeq.Add(1))
}

func createScopedRole(t *testing.T, pool *pgxpool.Pool, prefix, grants string) string {
	t.Helper()
	role := fmt.Sprintf("%s_%s", prefix, uniqueSuffix())
	ctx := context.Background()
	if _, err := pool.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s; CREATE ROLE %s NOLOGIN; %s", role, role, strings.ReplaceAll(grants, "$ROLE", role))); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, fmt.Sprintf("REVOKE ALL ON ALL TABLES IN SCHEMA information_query FROM %s; REVOKE ALL ON ALL SEQUENCES IN SCHEMA information_query FROM %s; REVOKE ALL ON SCHEMA information_query FROM %s; DROP ROLE IF EXISTS %s;", role, role, role, role)); err != nil {
			t.Errorf("cleanup database fixture: %v", err)
		}
	})
	return role
}

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
	t.Cleanup(pool.Close)
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal("migration replay", e)
	}
	if _, e = pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS foreign_module; CREATE TABLE IF NOT EXISTS foreign_module.secret(value text);`); e != nil {
		t.Fatal(e)
	}
	role := createScopedRole(t, pool, "iq_runtime", `GRANT USAGE ON SCHEMA information_query TO $ROLE; GRANT SELECT,INSERT ON information_query.audit,information_query.audit_scopes TO $ROLE; GRANT USAGE ON SEQUENCE information_query.audit_id_seq TO $ROLE;`)
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["role"] = role
	runtime, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	r.Pool = runtime
	testScope := admin.Scope{School: "school-" + uniqueSuffix(), Group: "g", Module: "profiles"}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM information_query.audit WHERE school=$1`, testScope.School); err != nil {
			t.Errorf("cleanup database fixture: %v", err)
		}
	})
	a := iq.Audit{Actor: "operator", RequestID: "request", Purpose: "audit-test", Scope: testScope, Channel: "bot_group", TargetGroup: "g", Action: "query", Result: "success", Count: 1, Targets: []string{"subject"}, Fields: []string{"identity"}, Basis: []string{"information-query.identity.read"}, CreatedAt: time.Now().UTC()}
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
	page, e = r.Read(ctx, iq.AuditFilter{Scope: admin.Scope{School: "unmatched-" + uniqueSuffix(), Group: "*", Module: "*"}, Limit: 100})
	if e != nil || len(page.Items) != 0 {
		t.Fatal("scope leak", e)
	}
	for _, sql := range []string{`SELECT * FROM foreign_module.secret`, `DELETE FROM information_query.audit_scopes`, `DELETE FROM information_query.audit`, `UPDATE information_query.audit SET school='b'`, `CREATE TABLE information_query.forbidden(id int)`} {
		if _, e = runtime.Exec(ctx, sql); e == nil {
			t.Fatalf("runtime accepted %s", sql)
		}
	}
	// Scope indexing and the audit body must commit together.
	if _, e = pool.Exec(ctx, `REVOKE INSERT ON information_query.audit_scopes FROM `+role); e != nil {
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

type records struct {
	scope admin.Scope
}

func (rec records) Query(context.Context, account.Principal, iq.Query) ([]iq.Record, error) {
	return []iq.Record{{ID: "profiles:1", Subject: (account.Principal{Issuer: "test", Subject: "user"}).Key(), Scope: rec.scope, Source: "test-binding", Current: true, ChangedAt: time.Now(), Fields: []iq.Field{{Name: "qq", Category: "identity", Value: "123456789"}}}}, nil
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
	t.Cleanup(pool.Close)
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	testScope := admin.Scope{School: "commit-" + uniqueSuffix(), Group: "g", Module: "profiles"}
	reqID := "disclosure-" + uniqueSuffix()
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM information_query.audit WHERE school=$1`, testScope.School); err != nil {
			t.Errorf("cleanup database fixture: %v", err)
		}
	})
	s := iq.Service{Auth: allow{}, Repo: r, Providers: map[string]iq.Provider{"profiles": records{scope: testScope}}}
	q := iq.Query{Kind: "account", Value: (account.Principal{Issuer: "test", Subject: "user"}).Key(), Scope: testScope, Domains: []string{"profiles"}, Fields: []string{"identity"}, Purpose: "test disclosure", Limit: 10}
	out, e := s.Query(ctx, account.Principal{Issuer: "test", Subject: "operator"}, reqID, iq.Delivery{Channel: "bot_group", Group: "g"}, q)
	if e != iq.ErrForbidden || recordCount(out) != 0 {
		t.Fatal("bot default", e)
	}
	s.BotEnabled = true
	out, e = s.Query(ctx, account.Principal{Issuer: "test", Subject: "operator"}, reqID, iq.Delivery{Channel: "bot_group", Group: "g"}, q)
	if e != nil || recordCount(out) != 1 || out.Groups[0].Items[0].Fields[0].Value != "123456789" {
		t.Fatal(e)
	}
	var count int
	var raw string
	e = pool.QueryRow(ctx, `SELECT count(*),string_agg(body::text,'') FROM information_query.audit WHERE body->>'request_id'=$1`, reqID).Scan(&count, &raw)
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
	out, e = s.Query(ctx, account.Principal{Issuer: "test", Subject: "operator"}, "blocked-"+uniqueSuffix(), iq.Delivery{Channel: "admin"}, q)
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
	t.Cleanup(pool.Close)
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	pruneScope := admin.Scope{School: "prune-" + uniqueSuffix(), Group: "*", Module: "*"}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM information_query.audit WHERE school=$1`, pruneScope.School); err != nil {
			t.Errorf("cleanup database fixture: %v", err)
		}
	})
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	cutoff := now.AddDate(-1, 0, 0)
	for _, at := range []time.Time{cutoff.Add(-time.Second), cutoff.Add(-time.Second), cutoff.Add(-time.Second), cutoff, cutoff.Add(time.Second)} {
		if e = r.Append(ctx, iq.Audit{Scope: pruneScope, Targets: []string{}, Fields: []string{}, Basis: []string{}, CreatedAt: at}); e != nil {
			t.Fatal(e)
		}
	}
	maintRole := createScopedRole(t, pool, "iq_maintenance", `GRANT USAGE ON SCHEMA information_query TO $ROLE; GRANT SELECT,DELETE ON information_query.audit TO $ROLE;`)
	runtimeRole := createScopedRole(t, pool, "iq_prune_runtime", `GRANT USAGE ON SCHEMA information_query TO $ROLE; GRANT SELECT,INSERT ON information_query.audit,information_query.audit_scopes TO $ROLE;`)
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
	m := postgres.Maintenance{Pool: makePool(maintRole), Now: func() time.Time { return now }}
	runtime := postgres.Maintenance{Pool: makePool(runtimeRole), Now: m.Now}
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
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM information_query.audit WHERE school=$3 AND (created_at=$1 OR created_at=$2)`, cutoff, cutoff.Add(time.Second), pruneScope.School).Scan(&kept); e != nil || kept != 2 {
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

func TestTransactionalVersionedMigrationsAndRollback(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)

	if err := (postgres.Repository{}).Migrate(ctx); err != iq.ErrUnavailable {
		t.Fatalf("expected ErrUnavailable on nil pool, got %v", err)
	}

	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	var firstApplied time.Time
	if e = pool.QueryRow(ctx, `SELECT applied_at FROM information_query.schema_migrations WHERE version='001_audit.sql'`).Scan(&firstApplied); e != nil {
		t.Fatalf("001_audit.sql not recorded in schema_migrations: %v", e)
	}

	// Non-idempotent migration runs once and is skipped on subsequent MigrateFS calls.
	customFS := fstest.MapFS{
		"migrations/090_once_only.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE information_query.migration_probe (id int PRIMARY KEY); REVOKE ALL ON information_query.migration_probe FROM PUBLIC;`),
		},
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS information_query.migration_probe; DELETE FROM information_query.schema_migrations WHERE version IN ('090_once_only.sql', '091_broken.sql');`); err != nil {
			t.Errorf("cleanup migration fixtures: %v", err)
		}
	})
	if e = postgres.MigrateFS(ctx, pool, customFS, "migrations"); e != nil {
		t.Fatal(e)
	}
	// Second run would fail if 090_once_only.sql (without IF NOT EXISTS) were re-executed.
	if e = postgres.MigrateFS(ctx, pool, customFS, "migrations"); e != nil {
		t.Fatalf("expected recorded migration to be skipped on replay, got %v", e)
	}

	// Failing multi-statement script rolls back earlier DDL in the same script and records nothing.
	brokenFS := fstest.MapFS{
		"migrations/090_once_only.sql": customFS["migrations/090_once_only.sql"],
		"migrations/091_broken.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE information_query.partial_should_rollback (id int); SELECT * FROM information_query.nonexistent_syntax_fail;`),
		},
	}
	if e = postgres.MigrateFS(ctx, pool, brokenFS, "migrations"); e == nil {
		t.Fatal("expected broken migration to fail")
	}
	var exists bool
	if e = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='information_query' AND table_name='partial_should_rollback')`).Scan(&exists); e != nil || exists {
		t.Fatalf("partial DDL from failed migration was not rolled back: exists=%v err=%v", exists, e)
	}
	if e = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_query.schema_migrations WHERE version='091_broken.sql')`).Scan(&exists); e != nil || exists {
		t.Fatalf("failed migration version must not be recorded: exists=%v err=%v", exists, e)
	}
}

func TestAuditLegalHoldExclusionReleaseAndRoleIsolation(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	r := postgres.Repository{Pool: pool}
	if e = r.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	cutoff := now.AddDate(-1, 0, 0)
	expiredAt := cutoff.Add(-time.Hour)
	holdSchool := "hold-school"

	// Insert 4 expired audit rows: one matched by audit_id, one by request_id, one by target_account, one unheld.
	var heldAuditID string
	var rawID int64
	body1, _ := json.Marshal(iq.Audit{Actor: "issuer:op", RequestID: "req-by-id", Purpose: "p1", Scope: admin.Scope{School: holdSchool, Group: "*", Module: "profiles"}, Targets: []string{"issuer:u1"}, Fields: []string{}, Basis: []string{}, CreatedAt: expiredAt})
	if e = pool.QueryRow(ctx, `INSERT INTO information_query.audit(school,group_id,module,body,created_at) VALUES($1,'*','profiles',$2,$3) RETURNING id`, holdSchool, body1, expiredAt).Scan(&rawID); e != nil {
		t.Fatal(e)
	}
	heldAuditID = jsonNumberString(rawID)
	for _, a := range []iq.Audit{
		{Actor: "issuer:op", RequestID: "req-held-2", Purpose: "p2", Scope: admin.Scope{School: holdSchool, Group: "*", Module: "profiles"}, Targets: []string{"issuer:u2"}, Fields: []string{}, Basis: []string{}, CreatedAt: expiredAt},
		{Actor: "issuer:op", RequestID: "req-3", Purpose: "p3", Scope: admin.Scope{School: holdSchool, Group: "*", Module: "profiles"}, Targets: []string{"issuer:held-target"}, Fields: []string{}, Basis: []string{}, CreatedAt: expiredAt},
		{Actor: "issuer:op", RequestID: "req-unheld", Purpose: "p4", Scope: admin.Scope{School: holdSchool, Group: "*", Module: "profiles"}, Targets: []string{"issuer:normal"}, Fields: []string{}, Basis: []string{}, CreatedAt: expiredAt},
	} {
		if e = r.Append(ctx, a); e != nil {
			t.Fatal(e)
		}
	}

	governanceRole := createScopedRole(t, pool, "iq_hold_governance", `GRANT USAGE ON SCHEMA information_query TO $ROLE; GRANT SELECT,INSERT,UPDATE ON information_query.audit_holds TO $ROLE; GRANT USAGE ON SEQUENCE information_query.audit_holds_id_seq TO $ROLE;`)
	maintenanceRole := createScopedRole(t, pool, "iq_hold_maint", `GRANT USAGE ON SCHEMA information_query TO $ROLE; GRANT SELECT,DELETE ON information_query.audit TO $ROLE;`)
	makePool := func(role string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.RuntimeParams["role"] = role
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	govPool := makePool(governanceRole)
	maintPool := makePool(maintenanceRole)

	// Role isolation checks: maintenance cannot read/modify audit_holds; governance cannot delete holds or touch audit.
	if _, e = maintPool.Exec(ctx, `SELECT * FROM information_query.audit_holds`); e == nil {
		t.Fatal("maintenance role should not read audit_holds directly")
	}
	if _, e = govPool.Exec(ctx, `DELETE FROM information_query.audit_holds`); e == nil {
		t.Fatal("governance role must not delete audit_holds")
	}
	if _, e = govPool.Exec(ctx, `SELECT * FROM information_query.audit`); e == nil {
		t.Fatal("governance role must not read audit table")
	}

	currentTime := now
	holds := postgres.HoldStore{Pool: govPool, Now: func() time.Time { return currentTime }}
	if _, e = holds.CreateHold(ctx, iq.AuditHoldInput{Reason: "missing selector", CreatedBy: "issuer:gov", ReviewAt: now.Add(24 * time.Hour)}); e != iq.ErrInvalid {
		t.Fatalf("expected ErrInvalid for empty selector, got %v", e)
	}

	h1, e := holds.CreateHold(ctx, iq.AuditHoldInput{AuditID: heldAuditID, Reason: "退费争议调查", CreatedBy: "issuer:gov", ReviewAt: now.Add(24 * time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	h2, e := holds.CreateHold(ctx, iq.AuditHoldInput{RequestID: "req-held-2", Reason: "申诉核查", CreatedBy: "issuer:gov", ReviewAt: now.Add(24 * time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	h3, e := holds.CreateHold(ctx, iq.AuditHoldInput{TargetAccount: "issuer:held-target", Reason: "涉诉账号保全", CreatedBy: "issuer:gov", ReviewAt: now.Add(24 * time.Hour)})
	if e != nil {
		t.Fatal(e)
	}

	active, next, e := holds.ListActiveHolds(ctx, "", 2)
	if e != nil || len(active) != 2 || next == "" {
		t.Fatalf("unexpected active holds page 1: %+v next=%q err=%v", active, next, e)
	}
	active2, next2, e := holds.ListActiveHolds(ctx, next, 10)
	if e != nil || len(active2) != 1 || next2 != "" {
		t.Fatalf("unexpected active holds page 2: %+v next=%q err=%v", active2, next2, e)
	}

	// Advance time past review_at without releasing: holds must still protect records from automatic deletion.
	currentTime = now.Add(48 * time.Hour)
	maint := postgres.Maintenance{Pool: maintPool, Now: func() time.Time { return currentTime }}
	deleted, e := maint.PruneAudit(ctx, cutoff, 100)
	if e != nil || deleted != 1 {
		t.Fatalf("expected only 1 unheld expired audit row deleted, got deleted=%d err=%v", deleted, e)
	}
	var remaining int
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM information_query.audit WHERE school=$1`, holdSchool).Scan(&remaining); e != nil || remaining != 3 {
		t.Fatalf("expected 3 held rows preserved, got %d err=%v", remaining, e)
	}

	// Release holds (including idempotent replay check) and verify subsequent PruneAudit cleans them up.
	released1, e := holds.ReleaseHold(ctx, iq.AuditHoldRelease{ID: h1.ID, Actor: "issuer:gov-1", Reason: "结案解除"})
	if e != nil || released1.ReleasedAt == nil || released1.ReleasedBy != "issuer:gov-1" {
		t.Fatalf("release failed: %+v %v", released1, e)
	}
	currentTime = currentTime.Add(time.Hour)
	replay1, e := holds.ReleaseHold(ctx, iq.AuditHoldRelease{ID: h1.ID, Actor: "issuer:gov-2", Reason: "重复请求"})
	if e != nil || replay1.ReleasedBy != "issuer:gov-1" || !replay1.ReleasedAt.Equal(*released1.ReleasedAt) {
		t.Fatalf("release replay overwrote original release metadata: %+v %v", replay1, e)
	}
	for _, id := range []string{h2.ID, h3.ID} {
		if _, e = holds.ReleaseHold(ctx, iq.AuditHoldRelease{ID: id, Actor: "issuer:gov-1", Reason: "全部结案"}); e != nil {
			t.Fatal(e)
		}
	}
	deleted, e = maint.PruneAudit(ctx, cutoff, 100)
	if e != nil || deleted != 3 {
		t.Fatalf("expected 3 released rows pruned, got %d err=%v", deleted, e)
	}
}

func jsonNumberString(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestPruneSeesHoldCommittedWhileWaiting(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	repo := postgres.Repository{Pool: pool}
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	request := "concurrent-hold-" + uniqueSuffix()
	now := time.Date(1982, 1, 1, 0, 0, 0, 0, time.UTC)
	if err = repo.Append(ctx, iq.Audit{Scope: admin.Global, RequestID: request, CreatedAt: now.AddDate(-2, 0, 0)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM information_query.audit_holds WHERE request_id=$1`, `DELETE FROM information_query.audit WHERE body->>'request_id'=$1`} {
			if _, err := pool.Exec(context.Background(), q, request); err != nil {
				t.Error(err)
			}
		}
	})
	// Pause the real CreateHold at INSERT, after it has entered the retention transaction.
	barrier, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Rollback(context.Background())
	if _, err = barrier.Exec(ctx, `LOCK TABLE information_query.audit_holds IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	waitForBlocked := func(blocker uint32) uint32 {
		t.Helper()
		for ctx.Err() == nil {
			var pid uint32
			if err := pool.QueryRow(ctx, `SELECT COALESCE((SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) LIMIT 1),0)`, int32(blocker)).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if pid != 0 {
				return pid
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("expected a database session waiting for the preceding transaction")
		return 0
	}
	holdDone := make(chan error, 1)
	go func() {
		h := postgres.HoldStore{Pool: pool, Now: func() time.Time { return now }}
		_, e := h.CreateHold(ctx, iq.AuditHoldInput{RequestID: request, Reason: "preserve evidence", CreatedBy: "fixture", ReviewAt: now.Add(time.Hour)})
		holdDone <- e
	}()
	creator := waitForBlocked(barrier.Conn().PgConn().PID())
	pruneDone := make(chan error, 1)
	go func() {
		m := postgres.Maintenance{Pool: pool, Now: func() time.Time { return now }}
		_, e := m.PruneAudit(ctx, now.AddDate(-1, 0, 0), 100)
		pruneDone <- e
	}()
	waitForBlocked(creator)
	if err = barrier.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-holdDone; err != nil {
		t.Fatal(err)
	}
	if err = <-pruneDone; err != nil {
		t.Fatal(err)
	}
	var kept int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM information_query.audit WHERE body->>'request_id'=$1`, request).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("protected audit rows = %d, err = %v", kept, err)
	}
}

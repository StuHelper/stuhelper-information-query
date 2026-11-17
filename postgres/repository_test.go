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
	defer pool.Close()
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

	_, e = pool.Exec(ctx, `
CREATE ROLE iq_hold_governance NOLOGIN;
GRANT USAGE ON SCHEMA information_query TO iq_hold_governance;
GRANT SELECT,INSERT,UPDATE ON information_query.audit_holds TO iq_hold_governance;
GRANT USAGE ON SEQUENCE information_query.audit_holds_id_seq TO iq_hold_governance;
CREATE ROLE iq_hold_maint NOLOGIN;
GRANT USAGE ON SCHEMA information_query TO iq_hold_maint;
GRANT SELECT,DELETE ON information_query.audit TO iq_hold_maint;
`)
	if e != nil {
		t.Fatal(e)
	}
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
	govPool := makePool("iq_hold_governance")
	maintPool := makePool("iq_hold_maint")

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

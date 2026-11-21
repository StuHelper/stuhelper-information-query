package postgres_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-information-query/postgres"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type previewAuditProvider struct {
	repo postgres.Repository
}

func (p previewAuditProvider) Query(ctx context.Context, actor account.Principal, q iq.Query) ([]iq.Record, error) {
	if len(q.Fields) != 0 {
		return nil, iq.ErrForbidden
	}
	// Host providers may audit their own authorization even for count-only reads.
	return nil, p.repo.Append(context.WithoutCancel(ctx), iq.Audit{
		Actor: actor.Key(), RequestID: "provider-read", Purpose: q.Value,
		Action: "provider.query", Result: "success", Channel: "admin", CreatedAt: time.Now().UTC(),
		Scope: q.Scope, Targets: []string{q.Value}, TargetScopes: map[string][]admin.Scope{q.Value: {q.Scope}},
	})
}

func TestBatchPreviewSanitizesStoredAggregateAndProviderAudit(t *testing.T) {
	dsn := os.Getenv("STUHELPER_INFORMATION_QUERY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	repo := postgres.Repository{Pool: pool}
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	scope := admin.Scope{School: "preview-" + uniqueSuffix(), Group: "*", Module: "*"}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, "DELETE FROM information_query.audit WHERE school=$1", scope.School); err != nil {
			t.Errorf("cleanup preview fixture: %v", err)
		}
	})
	runtimeRole := createScopedRole(t, pool, "iq_preview", `
		GRANT USAGE ON SCHEMA information_query TO $ROLE;
		GRANT SELECT,INSERT ON information_query.audit,information_query.audit_scopes TO $ROLE;
		GRANT USAGE ON SEQUENCE information_query.audit_id_seq TO $ROLE;
	`)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["role"] = runtimeRole
	repo.Pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Pool.Close)

	actor := account.Principal{Issuer: "fixture", Subject: "operator"}
	lead := (account.Principal{Issuer: "fixture", Subject: "preview-target"}).Key()
	query := iq.BatchQuery{
		Kind: "account", Values: []string{lead}, Scope: scope, Domains: []string{"profiles"},
		Purpose: "operator reason " + lead,
	}
	service := iq.Service{Auth: allow{}, Repo: repo, Providers: map[string]iq.Provider{"profiles": previewAuditProvider{repo}}}
	delivery := iq.Delivery{Channel: "admin"}
	result, err := service.Preview(ctx, actor, "preview-success", delivery, query)
	if err != nil || len(result.Entries) != 1 || result.Entries[0].Value != lead {
		t.Fatalf("preview did not return its own row: %v", err)
	}
	query.Values = []string{lead, lead}
	result, err = service.Preview(ctx, actor, "preview-invalid", delivery, query)
	if !errors.Is(err, iq.ErrInvalid) || len(result.Entries) != 0 {
		t.Fatalf("rejected request disclosed preview rows: %v", err)
	}
	var auditCount, contaminated int
	if err = pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (
			WHERE strpos(body::text,$2) > 0 OR strpos(target_scopes::text,$2) > 0
		)
		FROM information_query.audit WHERE school=$1
	`, scope.School, lead).Scan(&auditCount, &contaminated); err != nil || auditCount != 3 || contaminated != 0 {
		t.Fatalf("stored audit count=%d, entries containing the lead=%d, err=%v", auditCount, contaminated, err)
	}
	page, err := repo.Read(ctx, iq.AuditFilter{Scope: scope, Limit: 10})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("missing scoped audit: %v", err)
	}
	summarized := false
	for _, entry := range page.Items {
		if len(entry.Targets) != 0 || strings.Contains(entry.Purpose, lead) {
			t.Error("scoped audit returned a preview target")
		}
		if entry.RequestID == "preview-success" {
			digest, err := hex.DecodeString(entry.LeadDigest)
			summarized = entry.LeadKind == "account" && err == nil && len(digest) == 32
		}
	}
	if !summarized {
		t.Fatal("successful preview audit has no lead kind and digest")
	}
}

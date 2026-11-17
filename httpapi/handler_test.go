package httpapi_test

import (
	"context"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-information-query/httpapi"
	"github.com/StuHelper/stuhelper-information-query/sdk"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictHTTPAndTrustedIdentity(t *testing.T) {
	h := httpapi.Handler{Service: &iq.Service{Repo: auditRepo{}}, Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
		return account.Principal{}, iq.Delivery{Channel: "admin"}, "req"
	}}
	for _, body := range []string{`{"actor":"admin"}`, `{} {}`, strings.Repeat("x", 17000)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/information-query/query", strings.NewReader(body)))
		if w.Code != 400 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestCapabilitiesEndpointSDKIntegration(t *testing.T) {
	actor := account.Principal{Issuer: "issuer", Subject: "moderator"}
	svc := &iq.Service{
		Auth:       capAuth{"information-query.reviews.read": true, "information-query.audit.read": true},
		Repo:       auditRepo{},
		Providers:  map[string]iq.Provider{"reviews": emptyProvider{}, "profiles": emptyProvider{}},
		BotEnabled: true,
	}
	srv := httptest.NewServer(httpapi.Handler{
		Service: svc,
		Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
			return actor, iq.Delivery{Channel: "admin"}, "req-cap"
		},
	})
	defer srv.Close()

	client, err := sdk.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.QueryInformationCapabilitiesWithResponse(context.Background(), sdk.CapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != 200 || resp.JSON200 == nil {
		t.Fatalf("status=%d body=%s", resp.StatusCode(), string(resp.Body))
	}
	got := resp.JSON200
	if got.Scope.School != "*" || len(got.AllowedDomains) != 1 || got.AllowedDomains[0] != sdk.CapabilitiesAllowedDomainsReviews || !got.AuditReadable || got.BotEnabled {
		t.Fatalf("unexpected capabilities payload: %+v", got)
	}
	if len(got.AvailableDomains) != 2 || len(got.AvailableKinds) != 1 || got.AvailableKinds[0] != sdk.CapabilitiesAvailableKindsAccount {
		t.Fatalf("unexpected available domains/kinds: %+v", got)
	}
}

type capAuth map[string]bool

func (m capAuth) Evaluate(_ context.Context, p account.Principal, cap string, _ admin.Scope) error {
	if !p.Valid() {
		return iq.ErrUnauthenticated
	}
	if m[cap] {
		return nil
	}
	return iq.ErrForbidden
}

type emptyProvider struct{}

func (emptyProvider) Query(context.Context, account.Principal, iq.Query) ([]iq.Record, error) {
	return []iq.Record{}, nil
}

type auditRepo struct{}

func (auditRepo) Append(context.Context, iq.Audit) error { return nil }
func (auditRepo) Read(context.Context, iq.AuditFilter) (iq.AuditPage, error) {
	return iq.AuditPage{}, nil
}

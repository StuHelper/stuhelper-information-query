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

func TestBatchPreviewHTTPRejectsSensitiveFieldsAndSupportsSDK(t *testing.T) {
	actor := account.Principal{Issuer: "issuer", Subject: "admin"}
	svc := &iq.Service{
		Auth:      allowAll{},
		Repo:      auditRepo{},
		Providers: map[string]iq.Provider{"profiles": emptyProvider{}},
	}
	h := httpapi.Handler{
		Service: svc,
		Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
			return actor, iq.Delivery{Channel: "admin"}, "req-preview"
		},
	}
	// Passing fields in /preview must be rejected with 400.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/information-query/preview", strings.NewReader(`{"kind":"account","values":["issuer:u1"],"scope":{"school":"buaa","group":"*","module":"*"},"domains":["profiles"],"fields":["identity"],"purpose":"batch"}`)))
	if w.Code != 400 {
		t.Fatalf("expected 400 when fields supplied to /preview, got %d %s", w.Code, w.Body.String())
	}

	srv := httptest.NewServer(h)
	defer srv.Close()
	client, err := sdk.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.PreviewInformationBatchWithResponse(context.Background(), sdk.BatchPreviewRequest{
		Kind:    sdk.BatchPreviewRequestKindAccount,
		Values:  []string{"issuer:u1", "issuer:u2"},
		Scope:   sdk.Scope{School: "buaa", Group: "*", Module: "*"},
		Domains: []sdk.BatchPreviewRequestDomains{sdk.BatchPreviewRequestDomainsProfiles},
		Purpose: "批量核对",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != 200 || resp.JSON200 == nil || len(resp.JSON200.Entries) != 2 {
		t.Fatalf("unexpected SDK preview response: status=%d body=%s", resp.StatusCode(), string(resp.Body))
	}
}

type allowAll struct{}

func (allowAll) Evaluate(context.Context, account.Principal, string, admin.Scope) error { return nil }

type emptyProvider struct{}

func (emptyProvider) Query(context.Context, account.Principal, iq.Query) ([]iq.Record, error) {
	return []iq.Record{}, nil
}

type auditRepo struct{}

func (auditRepo) Append(context.Context, iq.Audit) error { return nil }
func (auditRepo) Read(context.Context, iq.AuditFilter) (iq.AuditPage, error) {
	return iq.AuditPage{}, nil
}

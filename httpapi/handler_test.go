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

func TestAuditFilterOptionalAfterInSDK(t *testing.T) {
	actor := account.Principal{Issuer: "issuer", Subject: "auditor"}
	srv := httptest.NewServer(httpapi.Handler{
		Service: &iq.Service{Auth: allowAll{}, Repo: auditRepo{}},
		Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
			return actor, iq.Delivery{Channel: "admin"}, "req-audit"
		},
	})
	defer srv.Close()

	client, err := sdk.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// After is omitted (nil) on first-page SDK calls.
	resp, err := client.QueryInformationAuditWithResponse(context.Background(), sdk.AuditFilter{
		Scope:   sdk.Scope{School: "buaa", Group: "*", Module: "*"},
		Purpose: "first-page without explicit after",
		Limit:   20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != 200 || resp.JSON200 == nil {
		t.Fatalf("status=%d body=%s", resp.StatusCode(), string(resp.Body))
	}
}

type allowAll struct{}

func (allowAll) Evaluate(context.Context, account.Principal, string, admin.Scope) error { return nil }

type auditRepo struct{}

func (auditRepo) Append(context.Context, iq.Audit) error { return nil }
func (auditRepo) Read(context.Context, iq.AuditFilter) (iq.AuditPage, error) {
	return iq.AuditPage{Items: []iq.Audit{}}, nil
}

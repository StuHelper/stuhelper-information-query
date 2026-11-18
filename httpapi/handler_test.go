package httpapi_test

import (
	"context"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-information-query/httpapi"
	"github.com/StuHelper/stuhelper-platform/account"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictHTTPAndTrustedIdentity(t *testing.T) {
	h := httpapi.Handler{Service: &iq.Service{Repo: auditRepo{}}, Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
		return account.Principal{Issuer: "test", Subject: "operator"}, iq.Delivery{Channel: "admin"}, "req"
	}}
	for _, body := range []string{`{"actor":"admin"}`, `{} {}`, strings.Repeat("x", 17000)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/information-query/query", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
		if w.Code != 400 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

type auditRepo struct{}

func (auditRepo) Append(context.Context, iq.Audit) error { return nil }
func (auditRepo) Read(context.Context, iq.AuditFilter) (iq.AuditPage, error) {
	return iq.AuditPage{}, nil
}

package httpapi_test

import (
	"context"
	"encoding/json"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-information-query/httpapi"
	"github.com/StuHelper/stuhelper-platform/account"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type observedRepo struct {
	auditRepo
	entries []iq.Audit
}

func (s *observedRepo) Append(_ context.Context, a iq.Audit) error {
	s.entries = append(s.entries, a)
	return nil
}

type observedBody struct {
	strings.Reader
	read bool
}

func (b *observedBody) Read(p []byte) (int, error) { b.read = true; return b.Reader.Read(p) }
func TestRequestBoundariesAndRejectionAudit(t *testing.T) {
	const query = "/api/v1/information-query/query"
	const audit = "/api/v1/information-query/audit/query"
	for _, tc := range []struct {
		method, path, media, channel string
		anon                         bool
		status                       int
		action                       string
		read                         bool
	}{
		{"POST", query, "application/json", "admin", true, 401, "", false},
		{"POST", audit, "application/json", "admin", true, 401, "", false},
		{"GET", query, "", "admin", false, 405, "", false},
		{"POST", "/unknown", "", "admin", false, 404, "", false},
		{"POST", query, "text/plain", "admin", false, 415, "query.rejected", false},
		{"POST", audit, "", "admin", false, 415, "audit.rejected", false},
		{"POST", query, "application/json; charset=utf-8", "admin", false, 400, "query.rejected", true},
		{"POST", audit, "application/json", "admin", false, 400, "audit.rejected", true},
		{"POST", audit, "application/json", "bot_private", false, 403, "audit.rejected", false},
	} {
		t.Run(tc.method+tc.path+tc.media+tc.channel, func(t *testing.T) {
			repo := &observedRepo{}
			h := httpapi.Handler{Service: &iq.Service{Repo: repo}, Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
				p := account.Principal{Issuer: "test", Subject: "operator"}
				if tc.anon {
					p = account.Principal{}
				}
				return p, iq.Delivery{Channel: tc.channel}, "request"
			}}
			body := &observedBody{Reader: *strings.NewReader("{")}
			r := httptest.NewRequest(tc.method, tc.path, body)
			r.Header.Set("Content-Type", tc.media)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var msg struct{ Code string }
			if w.Code != tc.status || json.Unmarshal(w.Body.Bytes(), &msg) != nil || msg.Code == "" || body.read != tc.read || (w.Code == 405 && w.Header().Get("Allow") != "POST") {
				t.Fatalf("status=%d body=%s read=%v", w.Code, w.Body, body.read)
			}
			if tc.action == "" {
				if len(repo.entries) != 0 {
					t.Fatal(repo.entries)
				}
			} else if len(repo.entries) != 1 || repo.entries[0].Action != tc.action || (tc.status == 403 && repo.entries[0].Purpose != "channel forbidden") || repo.entries[0].Actor == "" || len(repo.entries[0].Targets) != 0 {
				t.Fatal(repo.entries)
			}
		})
	}
}

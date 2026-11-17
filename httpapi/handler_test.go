package httpapi_test

import (
	"context"
	"encoding/json"
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
		var errBody sdk.Error
		if e := json.Unmarshal(w.Body.Bytes(), &errBody); e != nil || errBody.Code != "invalid_request" || errBody.Reason == nil || *errBody.Reason != sdk.InvalidParameter {
			t.Fatalf("unexpected decode error body: %s %v", w.Body.String(), e)
		}
	}
}

func TestStructuredErrorReasonsAndNoSecretEcho(t *testing.T) {
	actor := account.Principal{Issuer: "issuer", Subject: "operator"}
	scope := admin.Scope{School: "school-a", Group: "*", Module: "*"}
	auth := mapAuth{"information-query.profiles.read": true}
	svc := &iq.Service{Auth: auth, Repo: auditRepo{}}
	channel := iq.Delivery{Channel: "admin"}
	h := httpapi.Handler{Service: svc, Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
		return actor, channel, "req-reason"
	}}

	cases := []struct {
		name       string
		path       string
		delivery   iq.Delivery
		body       string
		wantStatus int
		wantCode   string
		wantReason sdk.ErrorReason
		wantDomain string
		wantField  string
	}{
		{
			name:       "school required for student_id",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "admin"},
			body:       `{"kind":"student_id","value":"SECRET-ID-2237","scope":{"school":"*","group":"*","module":"*"},"domains":["profiles"],"purpose":"check","limit":10}`,
			wantStatus: 400,
			wantCode:   "invalid_request",
			wantReason: sdk.SchoolRequired,
		},
		{
			name:       "domain forbidden reports blocked domain",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "admin"},
			body:       `{"kind":"account","value":"SECRET-ACCOUNT","scope":{"school":"school-a","group":"*","module":"*"},"domains":["profiles","billing"],"purpose":"check","limit":10}`,
			wantStatus: 403,
			wantCode:   "forbidden",
			wantReason: sdk.DomainForbidden,
			wantDomain: "billing",
		},
		{
			name:       "field forbidden reports domain and field",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "admin"},
			body:       `{"kind":"account","value":"SECRET-ACCOUNT","scope":{"school":"school-a","group":"*","module":"*"},"domains":["profiles"],"fields":["document"],"purpose":"check","limit":10}`,
			wantStatus: 403,
			wantCode:   "forbidden",
			wantReason: sdk.FieldForbidden,
			wantDomain: "profiles",
			wantField:  "document",
		},
		{
			name:       "bot disabled reason",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "bot_group", Group: "chat-1"},
			body:       `{"kind":"account","value":"SECRET-ACCOUNT","scope":{"school":"school-a","group":"*","module":"*"},"domains":["profiles"],"purpose":"check","limit":10}`,
			wantStatus: 403,
			wantCode:   "forbidden",
			wantReason: sdk.BotDisabled,
		},
		{
			name:       "audit channel forbidden for bot",
			path:       "/api/v1/information-query/audit/query",
			delivery:   iq.Delivery{Channel: "bot_group", Group: "chat-1"},
			body:       `{"scope":{"school":"school-a","group":"*","module":"*"},"purpose":"audit","after":"","limit":10}`,
			wantStatus: 403,
			wantCode:   "forbidden",
			wantReason: sdk.ChannelForbidden,
		},
		{
			name:       "missing resolver reports resolver_unavailable",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "admin"},
			body:       `{"kind":"name","value":"SECRET-NAME","scope":{"school":"school-a","group":"*","module":"*"},"domains":["profiles"],"purpose":"check","limit":10}`,
			wantStatus: 503,
			wantCode:   "unavailable",
			wantReason: sdk.ResolverUnavailable,
		},
	}
	_ = scope
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			channel = tc.delivery
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body)))
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			raw := w.Body.String()
			if strings.Contains(raw, "SECRET-") {
				t.Fatalf("error response leaked secret input: %s", raw)
			}
			var got sdk.Error
			if e := json.Unmarshal(w.Body.Bytes(), &got); e != nil {
				t.Fatal(e)
			}
			if got.Code != tc.wantCode || got.Reason == nil || *got.Reason != tc.wantReason {
				t.Fatalf("got=%+v want code=%s reason=%s", got, tc.wantCode, tc.wantReason)
			}
			gotDomain := ""
			if got.Domain != nil {
				gotDomain = string(*got.Domain)
			}
			gotField := ""
			if got.Field != nil {
				gotField = string(*got.Field)
			}
			if gotDomain != tc.wantDomain || gotField != tc.wantField {
				t.Fatalf("got domain=%q field=%q, want domain=%q field=%q", gotDomain, gotField, tc.wantDomain, tc.wantField)
			}
		})
	}
}

type mapAuth map[string]bool

func (m mapAuth) Evaluate(_ context.Context, p account.Principal, cap string, _ admin.Scope) error {
	if !p.Valid() {
		return iq.ErrUnauthenticated
	}
	if m[cap] {
		return nil
	}
	return iq.ErrForbidden
}

type auditRepo struct{}

func (auditRepo) Append(context.Context, iq.Audit) error { return nil }
func (auditRepo) Read(context.Context, iq.AuditFilter) (iq.AuditPage, error) {
	return iq.AuditPage{}, nil
}

package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-information-query/httpapi"
	"github.com/StuHelper/stuhelper-information-query/sdk"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestStrictHTTPAndTrustedIdentity(t *testing.T) {
	spec := loadOpenAPI(t)
	h := httpapi.Handler{Service: &iq.Service{Repo: &auditRepo{}}, Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
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
		assertOpenAPISchema(t, spec, "Error", w.Body.Bytes())
	}
}

func TestHTTPEndpointsStatusCodesAndOpenAPIContract(t *testing.T) {
	spec := loadOpenAPI(t)
	// Verify contract validator catches null slices and invalid empty Scope fields.
	if err := validateOpenAPIBytes(spec, "AuditPage", []byte(`{"items":[{"id":"1","actor":"a","request_id":"r","purpose":"p","scope":{"school":"s","group":"g","module":"m"},"channel":"admin","target_group":"","action":"query","result":"success","count":0,"targets":null,"fields":[],"basis":[],"created_at":"2026-11-18T00:00:00Z"}],"next_cursor":""}`)); err == nil {
		t.Fatal("contract validator accepted null targets slice")
	}
	if err := validateOpenAPIBytes(spec, "Scope", []byte(`{"school":"","group":"*","module":"*"}`)); err == nil {
		t.Fatal("contract validator accepted empty school in Scope")
	}

	// 405 and 404 handling, plus 503 when Service or Identity is nil.
	emptyHandler := httpapi.Handler{}
	w := httptest.NewRecorder()
	emptyHandler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/information-query/query", nil))
	if w.Code != 405 {
		t.Fatalf("expected 405 for GET, got %d", w.Code)
	}
	w = httptest.NewRecorder()
	emptyHandler.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/information-query/query", strings.NewReader(`{}`)))
	if w.Code != 503 {
		t.Fatalf("expected 503 for nil Service/Identity, got %d", w.Code)
	}
	assertOpenAPISchema(t, spec, "Error", w.Body.Bytes())

	repo := &auditRepo{}
	auth := mapAuth{
		"information-query.profiles.read":     true,
		"information-query.verification.read": true,
		"information-query.audit.read":        true,
	}
	prov := fixedProvider{items: []iq.Record{{
		ID:        "profiles:1",
		Subject:   (account.Principal{Issuer: "issuer", Subject: "alice"}).Key(),
		Scope:     admin.Scope{School: "buaa", Group: "*", Module: "profiles"},
		Source:    "profiles",
		Current:   true,
		ChangedAt: time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC),
		Fields: []iq.Field{
			{Name: "nickname", Category: "business", Value: "alice", Masked: false},
			{Name: "real_name", Category: "identity", Value: "Alice", Masked: false},
		},
	}}}
	svc := &iq.Service{
		Auth:      auth,
		Repo:      repo,
		Providers: map[string]iq.Provider{"profiles": prov},
		Now:       func() time.Time { return time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC) },
	}

	currentPrincipal := account.Principal{Issuer: "issuer", Subject: "operator"}
	currentDelivery := iq.Delivery{Channel: "admin"}
	h := httpapi.Handler{
		Service: svc,
		Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
			return currentPrincipal, currentDelivery, "req-http-1"
		},
	}

	// Unknown route -> 404.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/information-query/unknown", strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()
	client, err := sdk.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	// 1. 200 OK on /query via generated SDK + strict OpenAPI validation.
	qResp, err := client.QueryInformationWithResponse(context.Background(), sdk.Query{
		Kind:    sdk.Account,
		Value:   (account.Principal{Issuer: "issuer", Subject: "alice"}).Key(),
		Scope:   sdk.Scope{School: "buaa", Group: "*", Module: "*"},
		Domains: []sdk.QueryDomains{sdk.Profiles, sdk.Verification},
		Purpose: "核查账号资料",
		Limit:   20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if qResp.StatusCode() != 200 || qResp.JSON200 == nil || len(qResp.JSON200.Groups) != 1 || len(qResp.JSON200.UnavailableDomains) != 1 {
		t.Fatalf("unexpected 200 query response: status=%d body=%s", qResp.StatusCode(), string(qResp.Body))
	}
	assertOpenAPISchema(t, spec, "Result", qResp.Body)

	// 2. 200 OK on /audit/query via generated SDK + strict OpenAPI validation.
	aResp, err := client.QueryInformationAuditWithResponse(context.Background(), sdk.AuditFilter{
		Scope:   sdk.Scope{School: "buaa", Group: "*", Module: "*"},
		Purpose: "查阅审计记录",
		Limit:   20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if aResp.StatusCode() != 200 || aResp.JSON200 == nil || len(aResp.JSON200.Items) != 1 {
		t.Fatalf("unexpected 200 audit response: status=%d body=%s", aResp.StatusCode(), string(aResp.Body))
	}
	assertOpenAPISchema(t, spec, "AuditPage", aResp.Body)

	// 3. Bot channel calling /audit/query is intercepted with 403 and recorded in audit.
	beforeRejectCount := len(repo.items)
	currentDelivery = iq.Delivery{Channel: "bot_group", Group: "group-1"}
	botAuditResp, err := client.QueryInformationAuditWithResponse(context.Background(), sdk.AuditFilter{
		Scope:   sdk.Scope{School: "buaa", Group: "*", Module: "*"},
		Purpose: "机器人越权查审计",
		Limit:   10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if botAuditResp.StatusCode() != 403 || len(repo.items) != beforeRejectCount+1 || repo.items[len(repo.items)-1].Result != "denied" || repo.items[len(repo.items)-1].Action != "audit.rejected" {
		t.Fatalf("expected 403 and recorded rejection for bot audit access, got status=%d audits=%d", botAuditResp.StatusCode(), len(repo.items))
	}
	assertOpenAPISchema(t, spec, "Error", botAuditResp.Body)

	// 4. 403 Forbidden for unauthorized domain on admin channel.
	currentDelivery = iq.Delivery{Channel: "admin"}
	forbResp, err := client.QueryInformationWithResponse(context.Background(), sdk.Query{
		Kind:    sdk.Account,
		Value:   (account.Principal{Issuer: "issuer", Subject: "alice"}).Key(),
		Scope:   sdk.Scope{School: "buaa", Group: "*", Module: "*"},
		Domains: []sdk.QueryDomains{sdk.Billing},
		Purpose: "无权查账务",
		Limit:   10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if forbResp.StatusCode() != 403 {
		t.Fatalf("expected 403, got %d", forbResp.StatusCode())
	}
	assertOpenAPISchema(t, spec, "Error", forbResp.Body)

	// 5. 401 Unauthenticated when principal is empty.
	currentPrincipal = account.Principal{}
	unauthResp, err := client.QueryInformationWithResponse(context.Background(), sdk.Query{
		Kind:    sdk.Account,
		Value:   (account.Principal{Issuer: "issuer", Subject: "alice"}).Key(),
		Scope:   sdk.Scope{School: "buaa", Group: "*", Module: "*"},
		Domains: []sdk.QueryDomains{sdk.Profiles},
		Purpose: "匿名请求",
		Limit:   10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if unauthResp.StatusCode() != 401 {
		t.Fatalf("expected 401, got %d", unauthResp.StatusCode())
	}
	assertOpenAPISchema(t, spec, "Error", unauthResp.Body)

	// 6. 503 Unavailable when audit repository fails.
	currentPrincipal = account.Principal{Issuer: "issuer", Subject: "operator"}
	repo.fail = true
	unavailResp, err := client.QueryInformationWithResponse(context.Background(), sdk.Query{
		Kind:    sdk.Account,
		Value:   (account.Principal{Issuer: "issuer", Subject: "alice"}).Key(),
		Scope:   sdk.Scope{School: "buaa", Group: "*", Module: "*"},
		Domains: []sdk.QueryDomains{sdk.Profiles},
		Purpose: "审计离线",
		Limit:   10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if unavailResp.StatusCode() != 503 {
		t.Fatalf("expected 503, got %d", unavailResp.StatusCode())
	}
	assertOpenAPISchema(t, spec, "Error", unavailResp.Body)
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

type fixedProvider struct {
	items []iq.Record
}

func (p fixedProvider) Query(context.Context, account.Principal, iq.Query) ([]iq.Record, error) {
	return p.items, nil
}

type auditRepo struct {
	items []iq.Audit
	fail  bool
}

func (r *auditRepo) Append(_ context.Context, a iq.Audit) error {
	if r.fail {
		return errors.New("audit down")
	}
	a.ID = fmt.Sprintf("%d", len(r.items)+1)
	r.items = append(r.items, a)
	return nil
}

func (r *auditRepo) Read(_ context.Context, _ iq.AuditFilter) (iq.AuditPage, error) {
	if r.fail {
		return iq.AuditPage{}, errors.New("audit down")
	}
	out := make([]iq.Audit, len(r.items))
	copy(out, r.items)
	return iq.AuditPage{Items: out}, nil
}

type openAPIDoc struct {
	Components struct {
		Schemas map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

func loadOpenAPI(t *testing.T) openAPIDoc {
	t.Helper()
	var doc openAPIDoc
	if err := json.Unmarshal(iq.OpenAPI(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func assertOpenAPISchema(t *testing.T, doc openAPIDoc, schemaName string, raw []byte) {
	t.Helper()
	if err := validateOpenAPIBytes(doc, schemaName, raw); err != nil {
		t.Fatalf("OpenAPI %s contract violation: %v\npayload: %s", schemaName, err, string(raw))
	}
}

func validateOpenAPIBytes(doc openAPIDoc, schemaName string, raw []byte) error {
	var val any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&val); err != nil {
		return err
	}
	schema, ok := doc.Components.Schemas[schemaName]
	if !ok {
		return fmt.Errorf("unknown schema %q", schemaName)
	}
	return validateValue(doc, schema, val, schemaName)
}

func validateValue(doc openAPIDoc, schema map[string]any, val any, path string) error {
	if ref, ok := schema["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/components/schemas/")
		target, exists := doc.Components.Schemas[name]
		if !exists {
			return fmt.Errorf("%s: unresolved ref %s", path, ref)
		}
		return validateValue(doc, target, val, path)
	}
	if val == nil {
		return fmt.Errorf("%s: unexpected null value", path)
	}
	switch schema["type"] {
	case "object":
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected object, got %T", path, val)
		}
		props, _ := schema["properties"].(map[string]any)
		if reqList, ok := schema["required"].([]any); ok {
			for _, r := range reqList {
				key := r.(string)
				if _, exists := obj[key]; !exists {
					return fmt.Errorf("%s: missing required field %q", path, key)
				}
			}
		}
		if addl, ok := schema["additionalProperties"].(bool); ok && !addl {
			for k := range obj {
				if _, allowed := props[k]; !allowed {
					return fmt.Errorf("%s: unexpected additional property %q", path, k)
				}
			}
		}
		for k, v := range obj {
			if propSchema, exists := props[k].(map[string]any); exists {
				if err := validateValue(doc, propSchema, v, path+"."+k); err != nil {
					return err
				}
			}
		}
	case "array":
		arr, ok := val.([]any)
		if !ok {
			return fmt.Errorf("%s: expected array, got %T", path, val)
		}
		if maxItems, ok := schema["maxItems"].(float64); ok && len(arr) > int(maxItems) {
			return fmt.Errorf("%s: array length %d > maxItems %d", path, len(arr), int(maxItems))
		}
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for i, elem := range arr {
				if err := validateValue(doc, itemSchema, elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	case "string":
		s, ok := val.(string)
		if !ok {
			return fmt.Errorf("%s: expected string, got %T", path, val)
		}
		runes := utf8.RuneCountInString(s)
		if minLen, ok := schema["minLength"].(float64); ok && runes < int(minLen) {
			return fmt.Errorf("%s: length %d < minLength %d", path, runes, int(minLen))
		}
		if maxLen, ok := schema["maxLength"].(float64); ok && runes > int(maxLen) {
			return fmt.Errorf("%s: length %d > maxLength %d", path, runes, int(maxLen))
		}
		if enums, ok := schema["enum"].([]any); ok {
			allowed := make([]string, len(enums))
			for i, e := range enums {
				allowed[i] = e.(string)
			}
			if !slices.Contains(allowed, s) {
				return fmt.Errorf("%s: value %q not in enum %v", path, s, allowed)
			}
		}
		if pat, ok := schema["pattern"].(string); ok {
			re, err := regexp.Compile(pat)
			if err != nil || !re.MatchString(s) {
				return fmt.Errorf("%s: value %q does not match pattern %q", path, s, pat)
			}
		}
		if schema["format"] == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
				return fmt.Errorf("%s: invalid date-time %q: %v", path, s, err)
			}
		}
	case "boolean":
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("%s: expected boolean, got %T", path, val)
		}
	case "integer":
		num, ok := val.(json.Number)
		if !ok {
			return fmt.Errorf("%s: expected integer, got %T", path, val)
		}
		n, err := num.Int64()
		if err != nil {
			return fmt.Errorf("%s: invalid integer %q: %v", path, num.String(), err)
		}
		if minVal, ok := schema["minimum"].(float64); ok && n < int64(minVal) {
			return fmt.Errorf("%s: %d < minimum %d", path, n, int64(minVal))
		}
		if maxVal, ok := schema["maximum"].(float64); ok && n > int64(maxVal) {
			return fmt.Errorf("%s: %d > maximum %d", path, n, int64(maxVal))
		}
	}
	return nil
}

func TestStructuredErrorReasonsAndNoSecretEcho(t *testing.T) {
	actor := account.Principal{Issuer: "issuer", Subject: "operator"}
	scope := admin.Scope{School: "school-a", Group: "*", Module: "*"}
	auth := mapAuth{"information-query.profiles.read": true}
	svc := &iq.Service{Auth: auth, Repo: &auditRepo{}}
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
			wantReason: sdk.ErrorReasonSchoolRequired,
		},
		{
			name:       "domain forbidden reports blocked domain",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "admin"},
			body:       `{"kind":"account","value":"` + (account.Principal{Issuer: "test", Subject: "SECRET-ACCOUNT"}).Key() + `","scope":{"school":"school-a","group":"*","module":"*"},"domains":["profiles","billing"],"purpose":"check","limit":10}`,
			wantStatus: 403,
			wantCode:   "forbidden",
			wantReason: sdk.ErrorReasonDomainForbidden,
			wantDomain: "billing",
		},
		{
			name:       "field forbidden reports domain and field",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "admin"},
			body:       `{"kind":"account","value":"` + (account.Principal{Issuer: "test", Subject: "SECRET-ACCOUNT"}).Key() + `","scope":{"school":"school-a","group":"*","module":"*"},"domains":["profiles"],"fields":["document"],"purpose":"check","limit":10}`,
			wantStatus: 403,
			wantCode:   "forbidden",
			wantReason: sdk.ErrorReasonFieldForbidden,
			wantDomain: "profiles",
			wantField:  "document",
		},
		{
			name:       "bot disabled reason",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "bot_group", Group: "chat-1"},
			body:       `{"kind":"account","value":"` + (account.Principal{Issuer: "test", Subject: "SECRET-ACCOUNT"}).Key() + `","scope":{"school":"school-a","group":"*","module":"*"},"domains":["profiles"],"purpose":"check","limit":10}`,
			wantStatus: 403,
			wantCode:   "forbidden",
			wantReason: sdk.ErrorReasonBotDisabled,
		},
		{
			name:       "audit channel forbidden for bot",
			path:       "/api/v1/information-query/audit/query",
			delivery:   iq.Delivery{Channel: "bot_group", Group: "chat-1"},
			body:       `{"scope":{"school":"school-a","group":"*","module":"*"},"purpose":"audit","after":"","limit":10}`,
			wantStatus: 403,
			wantCode:   "forbidden",
			wantReason: sdk.ErrorReasonChannelForbidden,
		},
		{
			name:       "missing resolver reports resolver_unavailable",
			path:       "/api/v1/information-query/query",
			delivery:   iq.Delivery{Channel: "admin"},
			body:       `{"kind":"name","value":"SECRET-NAME","scope":{"school":"school-a","group":"*","module":"*"},"domains":["profiles"],"purpose":"check","limit":10}`,
			wantStatus: 503,
			wantCode:   "unavailable",
			wantReason: sdk.ErrorReasonResolverUnavailable,
		},
	}
	_ = scope
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			channel = tc.delivery
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(w, req)
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

func TestCapabilitiesEndpointSDKIntegration(t *testing.T) {
	actor := account.Principal{Issuer: "issuer", Subject: "moderator"}
	svc := &iq.Service{
		Auth:       capAuth{"information-query.reviews.read": true, "information-query.audit.read": true},
		Repo:       nil,
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

func TestMalformedCapabilitiesBypassAudit(t *testing.T) {
	store := &auditRepo{fail: true}
	h := httpapi.Handler{Service: &iq.Service{Repo: store}, Identity: func(*http.Request) (account.Principal, iq.Delivery, string) {
		return account.Principal{Issuer: "test", Subject: "operator"}, iq.Delivery{Channel: "admin"}, "request"
	}}
	for _, tc := range []struct {
		media, body string
		status      int
	}{{"application/json", `{"unknown":true}`, 400}, {"text/plain", "{}", 415}} {
		req := httptest.NewRequest("POST", "/api/v1/information-query/capabilities", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.media)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.status || len(store.items) != 0 {
			t.Fatalf("status=%d audits=%d", w.Code, len(store.items))
		}
	}
}

func TestAuditFilterOptionalAfterInSDK(t *testing.T) {
	actor := account.Principal{Issuer: "issuer", Subject: "auditor"}
	srv := httptest.NewServer(httpapi.Handler{
		Service: &iq.Service{Auth: allowAll{}, Repo: &auditRepo{}},
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

func TestBatchPreviewHTTPRejectsSensitiveFieldsAndSupportsSDK(t *testing.T) {
	actor := account.Principal{Issuer: "issuer", Subject: "admin"}
	svc := &iq.Service{
		Auth:      allowAll{},
		Repo:      &auditRepo{},
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
	req := httptest.NewRequest("POST", "/api/v1/information-query/preview", strings.NewReader(`{"kind":"account","values":["issuer:u1"],"scope":{"school":"buaa","group":"*","module":"*"},"domains":["profiles"],"fields":["identity"],"purpose":"batch"}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, req)
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
		Values:  []string{(account.Principal{Issuer: "issuer", Subject: "u1"}).Key(), (account.Principal{Issuer: "issuer", Subject: "u2"}).Key()},
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

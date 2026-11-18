package informationquery_test

import (
	"context"
	"encoding/json"
	"errors"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"slices"
	"strings"
	"testing"
	"time"
)

var actor = account.Principal{Issuer: "test", Subject: "operator"}
var scope = admin.Scope{School: "school-a", Group: "group-a", Module: "profiles"}

type auth struct {
	caps     map[string]bool
	scope    admin.Scope
	platform bool
}

func (a *auth) Evaluate(_ context.Context, p account.Principal, c string, s admin.Scope) error {
	if !p.Valid() {
		return iq.ErrUnauthenticated
	}
	if a.platform || a.caps[c] && a.scope.Contains(s) {
		return nil
	}
	return iq.ErrForbidden
}

type repo struct {
	records []iq.Audit
	fail    bool
}

func (r *repo) Append(_ context.Context, a iq.Audit) error {
	if r.fail {
		return errors.New("offline")
	}
	r.records = append(r.records, a)
	return nil
}
func (r *repo) Read(context.Context, iq.AuditFilter) (iq.AuditPage, error) {
	return iq.AuditPage{Items: r.records}, nil
}

type provider struct {
	items []iq.Record
	calls int
}

func (p *provider) Query(_ context.Context, _ account.Principal, _ iq.Query) ([]iq.Record, error) {
	p.calls++
	return p.items, nil
}
func fixture() (*iq.Service, *repo, *auth, *provider, iq.Query) {
	r := &repo{}
	a := &auth{caps: map[string]bool{"information-query.profiles.read": true}, scope: scope}
	p := &provider{items: []iq.Record{{ID: "profiles:1", Subject: (account.Principal{Issuer: "test", Subject: "user"}).Key(), Scope: scope, Source: "qq-binding", Current: true, ChangedAt: time.Now(), Fields: []iq.Field{{Name: "name", Category: "identity", Value: "同名"}, {Name: "qq", Category: "identity", Value: "123456789"}, {Name: "document", Category: "document", Value: "private-document"}, {Name: "material", Category: "material", Value: "private-material"}, {Name: "refund_payee", Category: "refund_payee", Value: "private-refund"}}}}}
	s := &iq.Service{Auth: a, Repo: r, Providers: map[string]iq.Provider{"profiles": p}}
	q := iq.Query{Kind: "account", Value: (account.Principal{Issuer: "test", Subject: "user"}).Key(), Scope: scope, Domains: []string{"profiles"}, Fields: []string{}, Purpose: "业务核查", Limit: 20}
	return s, r, a, p, q
}
func run(s *iq.Service, q iq.Query) (iq.Result, error) {
	return s.Query(context.Background(), actor, "request-1", iq.Delivery{Channel: "admin"}, q)
}
func TestPlatformSensitiveFields(t *testing.T) {
	s, r, a, _, q := fixture()
	a.platform = true
	q.Fields = []string{"identity", "document", "material", "refund_payee"}
	out, e := run(s, q)
	if e != nil || recordCount(out) != 1 || len(out.Groups[0].Items[0].Fields) != 5 || len(r.records) != 1 {
		t.Fatalf("%+v %v", out, e)
	}

}
func TestScopeAndDomainIsolation(t *testing.T) {
	s, r, _, p, q := fixture()
	q.Scope.School = "school-b"
	if _, e := run(s, q); !errors.Is(e, iq.ErrForbidden) || p.calls != 0 || r.records[0].Result != "denied" {
		t.Fatal(e)
	}
	q.Scope = scope
	p.items[0].Scope.School = "school-b"
	out, e := run(s, q)
	if !errors.Is(e, iq.ErrUnavailable) || recordCount(out) != 0 {
		t.Fatal("provider scope leaked", e)
	}
	s, _, _, p, q = fixture()
	q.Scope.Module = "*"
	q.Domains = []string{"profiles", "billing"}
	out, e = run(s, q)
	if !errors.Is(e, iq.ErrForbidden) || recordCount(out) > 0 {
		t.Fatal("wallet permission bypass", e)
	}
}
func TestSensitiveMaskAuditAndFailure(t *testing.T) {
	s, r, a, _, q := fixture()
	out, e := run(s, q)
	if e != nil || len(out.Groups[0].Items[0].Fields) != 2 || out.Groups[0].Items[0].Fields[0].Value != "***" || !out.Groups[0].Items[0].Fields[1].Masked {
		t.Fatal("mask", e)
	}
	q.Fields = []string{"identity"}
	if _, e = run(s, q); !errors.Is(e, iq.ErrForbidden) {
		t.Fatal(e)
	}
	a.caps["information-query.identity.read"] = true
	out, e = run(s, q)
	if e != nil || out.Groups[0].Items[0].Fields[0].Value != "同名" || r.records[len(r.records)-1].Count != 1 {
		t.Fatal("disclosure", e)
	}
	for _, category := range []string{"document", "material", "refund_payee"} {
		q.Fields = []string{category}
		if _, e = run(s, q); !errors.Is(e, iq.ErrForbidden) {
			t.Fatal("independent capability", category, e)
		}
	}
	q.Fields = []string{"identity"}
	r.fail = true
	out, e = run(s, q)
	if !errors.Is(e, iq.ErrUnavailable) || recordCount(out) != 0 {
		t.Fatal("audit failure disclosed", e)
	}
}
func TestBotDefaultAndGroupDelivery(t *testing.T) {
	s, r, a, _, q := fixture()
	d := iq.Delivery{Channel: "bot_group", Group: "chat-1"}
	if _, e := s.Query(context.Background(), actor, "r", d, q); !errors.Is(e, iq.ErrForbidden) {
		t.Fatal(e)
	}
	s.BotEnabled = true
	if _, e := s.Query(context.Background(), actor, "r", d, q); !errors.Is(e, iq.ErrForbidden) {
		t.Fatal(e)
	}
	a.caps["information-query.bot"] = true
	out, e := s.Query(context.Background(), actor, "r", d, q)
	last := r.records[len(r.records)-1]
	if e != nil || recordCount(out) != 1 || last.Channel != "bot_group" || last.TargetGroup != "chat-1" {
		t.Fatal(e)
	}
	a.caps["information-query.bot"] = false
	if _, e = s.Query(context.Background(), actor, "r", d, q); !errors.Is(e, iq.ErrForbidden) {
		t.Fatal("revocation", e)
	}
}
func TestAuditIndependentAndUnavailableProvider(t *testing.T) {
	s, r, a, _, q := fixture()
	f := iq.AuditFilter{Scope: scope, Purpose: "审计核查", Limit: 10}
	if _, e := s.Audit(context.Background(), actor, "r", f); !errors.Is(e, iq.ErrForbidden) {
		t.Fatal(e)
	}
	a.caps["information-query.audit.read"] = true
	if _, e := s.Audit(context.Background(), actor, "r", f); e != nil {
		t.Fatal(e)
	}
	from := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	until := from.Add(-time.Second)
	if _, e := s.Audit(context.Background(), actor, "r", iq.AuditFilter{Scope: scope, Purpose: "审计核查", Limit: 10, CreatedFrom: &from, CreatedUntil: &until}); !errors.Is(e, iq.ErrInvalid) {
		t.Fatal("inverted time range accepted", e)
	}
	if _, e := s.Audit(context.Background(), actor, "r", iq.AuditFilter{Scope: scope, Purpose: "审计核查", Limit: 10, Target: "bad\nvalue"}); !errors.Is(e, iq.ErrInvalid) {
		t.Fatal("control character in filter accepted", e)
	}
	s.Providers = nil
	out, e := run(s, q)
	if e != nil || len(out.UnavailableDomains) != 1 || len(r.records) != 5 {
		t.Fatal(e)
	}
}
func TestInvalidAndAnonymous(t *testing.T) {
	s, r, _, p, q := fixture()
	if _, e := s.Query(context.Background(), account.Principal{}, "r", iq.Delivery{Channel: "admin"}, q); !errors.Is(e, iq.ErrUnauthenticated) {
		t.Fatal(e)
	}
	q.Kind = "student_id"
	q.Scope.School = "*"
	if _, e := run(s, q); !errors.Is(e, iq.ErrInvalid) || p.calls != 0 || len(r.records) != 2 {
		t.Fatal(e)
	}
}

type platformIdentity struct{}

func (platformIdentity) PlatformAdmin(context.Context, account.Principal) (bool, error) {
	return true, nil
}

type platformRepo struct{}

func (platformRepo) View(context.Context, func(admin.Store) error) error {
	panic("platform administrator must not need grants")
}
func (platformRepo) Write(context.Context, func(admin.Store) error) error { panic("unexpected write") }
func TestPlatformEvaluateIntegration(t *testing.T) {
	s, _, _, _, q := fixture()
	s.Auth = admin.Service{Identity: platformIdentity{}, Repo: platformRepo{}}
	q.Fields = []string{"identity", "document", "material", "refund_payee"}
	out, e := run(s, q)
	if e != nil || len(out.Groups[0].Items[0].Fields) != 5 {
		t.Fatal("platform full capabilities", e)
	}
}

func recordCount(out iq.Result) int {
	n := 0
	for _, g := range out.Groups {
		n += len(g.Items)
	}
	return n
}

func TestUnicodeMultilinePurposeAndControlChars(t *testing.T) {
	s, _, a, _, q := fixture()
	a.caps["information-query.audit.read"] = true
	q.Purpose = strings.Repeat("核", 300) + "\n工单说明\t第二行"
	if _, e := run(s, q); e != nil {
		t.Fatalf("expected 309-rune multiline CJK purpose to succeed, got %v", e)
	}
	f := iq.AuditFilter{Scope: scope, Purpose: q.Purpose, Limit: 10}
	if _, e := s.Audit(context.Background(), actor, "audit-req", f); e != nil {
		t.Fatalf("expected multiline CJK audit purpose to succeed, got %v", e)
	}
	q.Purpose = strings.Repeat("核", 513)
	if _, e := run(s, q); !errors.Is(e, iq.ErrInvalid) {
		t.Fatalf("expected 513-rune purpose to return ErrInvalid, got %v", e)
	}
	q.Purpose = "工单\x00注入"
	if _, e := run(s, q); !errors.Is(e, iq.ErrInvalid) {
		t.Fatalf("expected NUL byte in purpose to return ErrInvalid, got %v", e)
	}
}

func TestAuditFieldsExcludeMaskedAndBusinessAndDeniedResult(t *testing.T) {
	s, r, a, p, q := fixture()
	p.items[0].Fields = append([]iq.Field{{Name: "title", Category: "business", Value: "course"}}, p.items[0].Fields...)
	q.Fields = []string{}
	out, e := run(s, q)
	if e != nil || recordCount(out) != 1 {
		t.Fatalf("default masked query failed: %v", e)
	}
	if len(r.records[0].Fields) != 0 {
		t.Fatalf("masked/business fields leaked into Audit.Fields: %v", r.records[0].Fields)
	}

	q.Fields = []string{"identity"}
	if _, e = run(s, q); !errors.Is(e, iq.ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", e)
	}
	deniedAudit := r.records[len(r.records)-1]
	if deniedAudit.Result != "denied" || !slices.Equal(deniedAudit.Fields, []string{"identity"}) {
		t.Fatalf("unexpected denied audit: result=%q fields=%v", deniedAudit.Result, deniedAudit.Fields)
	}

	a.caps["information-query.identity.read"] = true
	if _, e = run(s, q); e != nil {
		t.Fatalf("authorized identity query failed: %v", e)
	}
	disclosedAudit := r.records[len(r.records)-1]
	if disclosedAudit.Result != "success" || !slices.Equal(disclosedAudit.Fields, []string{"identity"}) {
		t.Fatalf("expected Audit.Fields=[identity], got result=%q fields=%v", disclosedAudit.Result, disclosedAudit.Fields)
	}

	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum  []string `json:"enum"`
					Items struct {
						Enum []string `json:"enum"`
					} `json:"items"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if e := json.Unmarshal(iq.OpenAPI(), &spec); e != nil {
		t.Fatal(e)
	}
	auditProps := spec.Components.Schemas["Audit"].Properties
	for _, field := range []string{"channel", "action", "result"} {
		if len(auditProps[field].Enum) == 0 {
			t.Fatalf("OpenAPI Audit.%s missing enum constraint", field)
		}
	}
	if len(auditProps["fields"].Items.Enum) == 0 {
		t.Fatal("OpenAPI Audit.fields.items missing enum constraint")
	}
}

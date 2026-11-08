package informationquery_test

import (
	"context"
	"errors"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
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
	p := &provider{items: []iq.Record{{ID: "profiles:1", Subject: "user:1", Scope: scope, Source: "qq-binding", Current: true, ChangedAt: time.Now(), Fields: []iq.Field{{Name: "name", Category: "identity", Value: "同名"}, {Name: "qq", Category: "identity", Value: "123456789"}, {Name: "document", Category: "document", Value: "private-document"}, {Name: "material", Category: "material", Value: "private-material"}, {Name: "refund", Category: "refund", Value: "private-refund"}}}}}
	s := &iq.Service{Auth: a, Repo: r, Providers: map[string]iq.Provider{"profiles": p}}
	q := iq.Query{Kind: "qq", Value: "123456789", Scope: scope, Domains: []string{"profiles"}, Fields: []string{}, Purpose: "业务核查", Limit: 20}
	return s, r, a, p, q
}
func run(s *iq.Service, q iq.Query) (iq.Result, error) {
	return s.Query(context.Background(), actor, "request-1", iq.Delivery{Channel: "admin"}, q)
}
func TestPlatformQQAndSeparateCandidates(t *testing.T) {
	s, r, a, p, q := fixture()
	a.platform = true
	q.Fields = []string{"identity", "document", "material", "refund"}
	out, e := run(s, q)
	if e != nil || len(out.Items) != 1 || len(out.Items[0].Fields) != 5 || len(r.records) != 1 {
		t.Fatalf("%+v %v", out, e)
	}
	p.items = append(p.items, p.items[0])
	p.items[1].ID = "profiles:2"
	p.items[1].Subject = "user:2"
	p.items[1].Current = false
	q.Kind = "name"
	q.Value = "同名"
	out, e = run(s, q)
	if e != nil || len(out.Items) != 2 || out.Items[0].Subject == out.Items[1].Subject || out.Items[1].Current {
		t.Fatal("names merged or history lost", e)
	}
}
func TestScopeAndDomainIsolation(t *testing.T) {
	s, r, _, p, q := fixture()
	q.Scope.School = "school-b"
	if _, e := run(s, q); !errors.Is(e, iq.ErrForbidden) || p.calls != 0 || r.records[0].Result != "forbidden" {
		t.Fatal(e)
	}
	q.Scope = scope
	p.items[0].Scope.School = "school-b"
	out, e := run(s, q)
	if !errors.Is(e, iq.ErrUnavailable) || len(out.Items) != 0 {
		t.Fatal("provider scope leaked", e)
	}
	s, _, _, p, q = fixture()
	q.Scope.Module = "*"
	q.Domains = []string{"profiles", "billing"}
	out, e = run(s, q)
	if !errors.Is(e, iq.ErrForbidden) || len(out.Items) > 0 {
		t.Fatal("wallet permission bypass", e)
	}
}
func TestSensitiveMaskAuditAndFailure(t *testing.T) {
	s, r, a, _, q := fixture()
	out, e := run(s, q)
	if e != nil || len(out.Items[0].Fields) != 2 || out.Items[0].Fields[0].Value != "***" || !out.Items[0].Fields[1].Masked {
		t.Fatal("mask", e)
	}
	q.Fields = []string{"identity"}
	if _, e = run(s, q); !errors.Is(e, iq.ErrForbidden) {
		t.Fatal(e)
	}
	a.caps["information-query.identity.read"] = true
	out, e = run(s, q)
	if e != nil || out.Items[0].Fields[0].Value != "同名" || r.records[len(r.records)-1].Count != 1 {
		t.Fatal("disclosure", e)
	}
	for _, category := range []string{"document", "material", "refund"} {
		q.Fields = []string{category}
		if _, e = run(s, q); !errors.Is(e, iq.ErrForbidden) {
			t.Fatal("independent capability", category, e)
		}
	}
	q.Fields = []string{"identity"}
	r.fail = true
	out, e = run(s, q)
	if !errors.Is(e, iq.ErrUnavailable) || len(out.Items) != 0 {
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
	if e != nil || len(out.Items) != 1 || last.Channel != "bot_group" || last.TargetGroup != "chat-1" {
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
	s.Providers = nil
	out, e := run(s, q)
	if e != nil || len(out.UnavailableDomains) != 1 || len(r.records) != 3 {
		t.Fatal(e)
	}
}
func TestInvalidAndAnonymous(t *testing.T) {
	s, r, _, p, q := fixture()
	if _, e := s.Query(context.Background(), account.Principal{}, "r", iq.Delivery{Channel: "admin"}, q); !errors.Is(e, iq.ErrUnauthenticated) {
		t.Fatal(e)
	}
	q.Kind = "student_number"
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
	q.Fields = []string{"identity", "document", "material", "refund"}
	out, e := run(s, q)
	if e != nil || len(out.Items[0].Fields) != 5 {
		t.Fatal("platform full capabilities", e)
	}
}

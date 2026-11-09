package informationquery_test

import (
	"context"
	"errors"
	"fmt"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"strconv"
	"testing"
	"time"
)

type resolver struct {
	candidates []iq.Candidate
	calls      int
	fail       error
}

func (r *resolver) Resolve(_ context.Context, _ account.Principal, l iq.Lead) ([]iq.Candidate, string, error) {
	r.calls++
	if r.fail != nil {
		return nil, "", r.fail
	}
	offset := 0
	if l.After != "" {
		offset, _ = strconv.Atoi(l.After)
	}
	if offset >= len(r.candidates) {
		return []iq.Candidate{}, "", nil
	}
	end := min(offset+l.Limit, len(r.candidates))
	next := ""
	if end < len(r.candidates) {
		next = strconv.Itoa(end)
	}
	return r.candidates[offset:end], next, nil
}

type accountProvider struct {
	domain           string
	calls, requested int
	wrong            bool
}

func (p *accountProvider) Query(_ context.Context, _ account.Principal, q iq.Query) ([]iq.Record, error) {
	p.calls++
	p.requested += q.Limit
	if q.Kind != "account" || (q.Value != "issuer:alice" && q.Value != "issuer:bob") {
		return nil, errors.New("raw clue reached provider")
	}
	result := []iq.Record{}
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("%s:%d", p.domain, i)
		if id <= q.After {
			continue
		}
		subject := q.Value
		if p.wrong {
			subject = "other"
		}
		result = append(result, iq.Record{ID: id, Subject: subject, Scope: admin.Scope{School: scope.School, Group: scope.Group, Module: p.domain}, Source: p.domain, Current: true, ChangedAt: time.Unix(100, 0), Fields: []iq.Field{}})
		if len(result) == q.Limit {
			break
		}
	}
	return result, nil
}
func resolvedFixture() (*iq.Service, *resolver, *accountProvider, iq.Query) {
	s, _, a, _, q := fixture()
	a.platform = true
	q.Scope.Module = "*"
	q.Kind = "name"
	q.Value = "same name"
	r := &resolver{candidates: []iq.Candidate{}}
	for i, account := range []string{"issuer:alice", "issuer:bob"} {
		r.candidates = append(r.candidates, iq.Candidate{Account: account, Source: "verification", Current: i == 0, ChangedAt: time.Unix(100, 0), Scope: q.Scope, Label: []iq.Field{{Name: "name", Category: "identity", Value: "***", Masked: true}}})
	}
	p := &accountProvider{domain: "profiles"}
	s.Providers = map[string]iq.Provider{"profiles": p}
	s.Resolvers = map[string]iq.Resolver{"name": r, "student_id": r, "qq": r}
	return s, r, p, q
}
func TestResolveKindsGroupsAndHistory(t *testing.T) {
	for _, kind := range []string{"name", "student_id", "qq"} {
		t.Run(kind, func(t *testing.T) {
			s, r, p, q := resolvedFixture()
			q.Kind = kind
			out, e := run(s, q)
			if e != nil || len(out.Groups) != 2 || recordCount(out) != 6 || r.calls != 2 || p.calls != 2 {
				t.Fatalf("groups: %+v %v", out, e)
			}
			if out.Groups[0].Candidate.Account == out.Groups[1].Candidate.Account || out.Groups[1].Candidate.Current || out.Groups[1].Candidate.ChangedAt.IsZero() {
				t.Fatal("merged candidates or lost history")
			}
			for _, g := range out.Groups {
				for _, record := range g.Items {
					if record.Subject != g.Candidate.Account {
						t.Fatal("cross candidate leak")
					}
				}
			}
		})
	}
}
func TestResolverFailureAndIsolation(t *testing.T) {
	for _, failure := range []error{iq.ErrUnavailable, errors.New("sensitive clue"), iq.ErrForbidden} {
		s, r, p, q := resolvedFixture()
		r.fail = failure
		out, e := run(s, q)
		expected := iq.ErrUnavailable
		if failure == iq.ErrForbidden {
			expected = failure
		}
		if e != expected || len(out.Groups) != 0 || p.calls != 0 {
			t.Fatal("resolver failure", e)
		}
	}
	s, _, p, q := resolvedFixture()
	s.Resolvers = nil
	if _, e := run(s, q); e != iq.ErrUnavailable || p.calls != 0 {
		t.Fatal("missing resolver", e)
	}
	s, r, p, q := resolvedFixture()
	s.Auth = &auth{caps: map[string]bool{"information-query.profiles.read": true}, scope: q.Scope}
	q.Domains = []string{"profiles", "billing"}
	if _, e := run(s, q); e != iq.ErrForbidden || r.calls != 0 || p.calls != 0 {
		t.Fatal("IQ-04", e)
	}
	s, r, p, q = resolvedFixture()
	r.candidates[0].Scope.School = "other-school"
	if _, e := run(s, q); e != iq.ErrUnavailable || p.calls != 0 {
		t.Fatal("candidate scope leak", e)
	}
	s, _, p, q = resolvedFixture()
	p.wrong = true
	if _, e := run(s, q); e != iq.ErrUnavailable {
		t.Fatal("wrong account", e)
	}
}
func TestCompositePagination(t *testing.T) {
	s, _, p, q := resolvedFixture()
	b := &accountProvider{domain: "billing"}
	s.Providers["billing"] = b
	q.Domains = []string{"profiles", "billing"}
	q.Limit = 2
	seen := map[string]bool{}
	for page := 0; page < 20; page++ {
		out, e := run(s, q)
		if e != nil {
			t.Fatal(e)
		}
		for _, g := range out.Groups {
			for _, r := range g.Items {
				key := g.Candidate.Account + "/" + r.ID
				if seen[key] {
					t.Fatal("duplicate", key)
				}
				seen[key] = true
			}
		}
		if out.NextCursor == "" {
			break
		}
		q.After = out.NextCursor
		if page == 19 {
			t.Fatal("pagination did not finish")
		}
	}
	if len(seen) != 12 {
		t.Fatal("lost records", len(seen))
	}
	if p.calls == 0 || b.calls == 0 {
		t.Fatal("missing domain")
	}
	q.Value = "different"
	if _, e := run(s, q); e != iq.ErrInvalid {
		t.Fatal("cursor query binding", e)
	}
}
func TestCandidateChangeAndWorkBound(t *testing.T) {
	s, r, _, q := resolvedFixture()
	q.Limit = 1
	out, e := run(s, q)
	if e != nil {
		t.Fatal(e)
	}
	q.After = out.NextCursor
	r.candidates[0].Account = "issuer:bob"
	if _, e = run(s, q); e != iq.ErrUnavailable {
		t.Fatal("stale candidate accepted", e)
	}
	s, r, p, q := resolvedFixture()
	q.Limit = 100
	r.candidates = append(r.candidates, r.candidates...)
	r.candidates = append(r.candidates, r.candidates...)
	r.candidates = append(r.candidates, r.candidates...)
	out, e = run(s, q)
	if e != nil || p.requested > 700 || r.calls > 50 || out.NextCursor == "" {
		t.Fatal("work bound", e, p.requested, r.calls)
	}
}

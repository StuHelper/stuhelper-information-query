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
	size             int
	domain           string
	calls, requested int
	wrong            bool
}

func (p *accountProvider) Query(_ context.Context, _ account.Principal, q iq.Query) ([]iq.Record, error) {
	p.calls++
	p.requested += q.Limit
	if q.Kind != "account" || (q.Value != (account.Principal{Issuer: "test", Subject: "alice"}).Key() && q.Value != (account.Principal{Issuer: "test", Subject: "bob"}).Key()) {
		return nil, errors.New("raw clue reached provider")
	}
	result := []iq.Record{}
	size := p.size
	if size == 0 {
		size = 3
	}
	for i := 1; i <= size; i++ {
		id := fmt.Sprintf("%s:%d", p.domain, i)
		if size >= 100 {
			id = fmt.Sprintf("%s:%03d", p.domain, i)
		}
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
	for i, account := range []string{(account.Principal{Issuer: "test", Subject: "alice"}).Key(), (account.Principal{Issuer: "test", Subject: "bob"}).Key()} {
		role := "student"
		if i == 1 {
			role = "teacher"
		}
		r.candidates = append(r.candidates, iq.Candidate{Account: account, Source: "verification", Current: i == 0, ChangedAt: time.Unix(100, 0), Scope: q.Scope, Label: []iq.Field{{Name: "name", Category: "identity", Value: "***", Masked: true}, {Name: "department", Category: "business", Value: "计算机学院", Masked: true}, {Name: "role", Category: "business", Value: role, Masked: true}}})
	}
	p := &accountProvider{domain: "profiles"}
	s.Providers = map[string]iq.Provider{"profiles": p}
	s.Resolvers = map[string]iq.Resolver{"name": r, "student_id": r, "staff_id": r, "qq": r}
	return s, r, p, q
}
func TestResolveKindsGroupsAndHistory(t *testing.T) {
	for _, kind := range []string{"name", "student_id", "staff_id", "qq"} {
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
		if !errors.Is(e, expected) || len(out.Groups) != 0 || p.calls != 0 {
			t.Fatal("resolver failure", e)
		}
	}
	s, _, p, q := resolvedFixture()
	s.Resolvers = nil
	if _, e := run(s, q); !errors.Is(e, iq.ErrUnavailable) || p.calls != 0 {
		t.Fatal("missing resolver", e)
	}
	s, r, p, q := resolvedFixture()
	s.Auth = &auth{caps: map[string]bool{"information-query.profiles.read": true}, scope: q.Scope}
	q.Domains = []string{"profiles", "billing"}
	_, e := run(s, q)
	var detail *iq.ErrorDetail
	if !errors.Is(e, iq.ErrForbidden) || !errors.As(e, &detail) || detail.Reason != "domain_forbidden" || detail.Domain != "billing" || r.calls != 0 || p.calls != 0 {
		t.Fatal("IQ-04", e, detail)
	}
	s, r, p, q = resolvedFixture()
	r.candidates[0].Scope.School = "other-school"
	if _, e := run(s, q); !errors.Is(e, iq.ErrUnavailable) || p.calls != 0 {
		t.Fatal("candidate scope leak", e)
	}
	s, _, p, q = resolvedFixture()
	p.wrong = true
	_, e = run(s, q)
	if !errors.Is(e, iq.ErrUnavailable) || !errors.As(e, &detail) || detail.Reason != "provider_unavailable" || detail.Domain != "profiles" {
		t.Fatal("wrong account", e, detail)
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
	var detail *iq.ErrorDetail
	if _, e := run(s, q); !errors.Is(e, iq.ErrInvalid) || !errors.As(e, &detail) || detail.Reason != "cursor_mismatch" {
		t.Fatal("cursor query binding", e, detail)
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
	r.candidates[0].Account = (account.Principal{Issuer: "test", Subject: "bob"}).Key()
	var detail *iq.ErrorDetail
	if _, e = run(s, q); !errors.Is(e, iq.ErrUnavailable) || !errors.As(e, &detail) || detail.Reason != "candidate_changed" {
		t.Fatal("stale candidate accepted", e, detail)
	}
	s, r, p, q := resolvedFixture()
	q.Limit = 100
	r.candidates = append(r.candidates, r.candidates...)
	r.candidates = append(r.candidates, r.candidates...)
	r.candidates = append(r.candidates, r.candidates...)
	out, e = run(s, q)
	if e != nil || len(out.Groups) != 16 || recordCount(out) != 48 || p.calls != 16 || r.calls != 16 || out.NextCursor != "" {
		t.Fatal("work bound", e, p.requested, r.calls)
	}
}

func TestCandidateGroupHasMoreFlag(t *testing.T) {
	t.Run("provider ceiling", func(t *testing.T) {
		for _, size := range []int{100, 101} {
			svc, resolver, p, q := resolvedFixture()
			p.size = size
			q.Kind, q.Value, q.Limit = "account", resolver.candidates[0].Account, 100
			first, err := run(svc, q)
			if err != nil || len(first.Groups) != 1 || len(first.Groups[0].Items) != 100 || first.Groups[0].HasMore != (size > 100) || (first.NextCursor != "") != (size > 100) || p.calls != 2 || p.requested != 101 {
				t.Fatalf("size=%d has continuation=%t calls=%d requested=%d err=%v", size, first.NextCursor != "", p.calls, p.requested, err)
			}
		}
	})

	t.Run("exactly full", func(t *testing.T) {
		svc, _, _, q := resolvedFixture()
		q.Limit = 3
		first, e := run(svc, q)
		if e != nil || len(first.Groups) != 1 || first.Groups[0].HasMore || first.NextCursor == "" {
			t.Fatalf("exactly full first candidate: %+v %v", first, e)
		}
		q.After = first.NextCursor
		last, e := run(svc, q)
		if e != nil || len(last.Groups) != 1 || last.Groups[0].Candidate.Account == first.Groups[0].Candidate.Account || last.Groups[0].HasMore || last.NextCursor != "" {
			t.Fatalf("final candidate: %+v %v", last, e)
		}
	})

	s, _, _, q := resolvedFixture()
	// Each candidate has 3 records in profiles. Limit=2 truncates alice on page 1 (HasMore=true),
	// then page 2 finishes alice (1 item, HasMore=false) and starts bob (1 item, HasMore=true).
	q.Limit = 2
	page1, err := run(s, q)
	if err != nil || len(page1.Groups) != 1 || len(page1.Groups[0].Items) != 2 || !page1.Groups[0].HasMore {
		t.Fatalf("page 1 expected single candidate with HasMore=true, got %+v err=%v", page1, err)
	}
	q.After = page1.NextCursor
	page2, err := run(s, q)
	if err != nil || len(page2.Groups) != 2 {
		t.Fatalf("page 2 expected 2 groups, got %+v err=%v", page2, err)
	}
	if page2.Groups[0].HasMore || !page2.Groups[1].HasMore {
		t.Fatalf("page 2 expected [HasMore=false, HasMore=true], got [%v, %v]", page2.Groups[0].HasMore, page2.Groups[1].HasMore)
	}
}

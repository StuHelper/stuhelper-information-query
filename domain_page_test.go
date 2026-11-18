package informationquery_test

import (
	"context"
	"errors"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"strings"
	"testing"
)

type domainTrace struct {
	accountProvider
	callsSeen []iq.Query
}

func (p *domainTrace) Query(ctx context.Context, actor account.Principal, q iq.Query) ([]iq.Record, error) {
	p.callsSeen = append(p.callsSeen, q)
	return p.accountProvider.Query(ctx, actor, q)
}
func TestOrderedDomainBudgetAndLocalCursor(t *testing.T) {
	s, _, _, q := resolvedFixture()
	b := &domainTrace{accountProvider: accountProvider{domain: "billing"}}
	p := &domainTrace{accountProvider: accountProvider{domain: "profiles"}}
	s.Providers = map[string]iq.Provider{"billing": b, "profiles": p}
	q.Domains = []string{"profiles", "billing"}
	q.Limit = 2
	out, err := run(s, q)
	if err != nil || len(b.callsSeen) != 1 || len(p.callsSeen) != 0 || recordCount(out) != 2 {
		t.Fatalf("first page: calls %d/%d %v", len(b.callsSeen), len(p.callsSeen), err)
	}
	q.After = out.NextCursor
	out, err = run(s, q)
	if err != nil || len(p.callsSeen) != 1 || p.callsSeen[0].After != "" || p.callsSeen[0].Limit != 1 || out.Groups[0].Items[1].ID != "profiles:1" {
		t.Fatal("domain transition", err, p.callsSeen)
	}
	q.After = out.NextCursor
	out, err = run(s, q)
	if err != nil || len(b.callsSeen) != 2 || p.callsSeen[1].After != "profiles:1" || recordCount(out) != 2 {
		t.Fatal("exhausted domain", err)
	}
}
func TestPageBudgetCountsDisclosedFieldText(t *testing.T) {
	s, audits, _, p, q := fixture()
	f := iq.Field{Name: "file", Category: "material", Value: strings.Repeat("x", 60000)}
	for i := 0; i < 18; i++ {
		p.items[0].Fields = append(p.items[0].Fields, f)
	}
	out, err := run(s, q)
	if err != nil || recordCount(out) != 1 || len(out.Groups[0].Items[0].Fields) != 2 || audits.records[0].Count != 1 {
		t.Fatal("omitted material charged", err)
	}
	for i := range p.items[0].Fields {
		p.items[0].Fields[i].Category = "business"
	}
	out, err = run(s, q)
	if !errors.Is(err, iq.ErrUnavailable) || recordCount(out) != 0 || len(audits.records[1].Targets) != 0 {
		t.Fatal("oversized page", err)
	}
}

func TestSparseDomainPagesUseActualRecords(t *testing.T) {
	s, r, _, q := resolvedFixture()
	q.Limit = 100
	q.Domains = []string{"profiles", "verification", "catalog", "reviews", "resources", "billing", "groups"}
	s.Providers = nil
	for len(r.candidates) < 64 {
		r.candidates = append(r.candidates, r.candidates...)
	}
	out, err := run(s, q)
	if err != nil || len(out.Groups) != 50 || r.calls != 50 || recordCount(out) != 0 || len(out.UnavailableDomains) != 7 || out.NextCursor == "" {
		t.Fatal("sparse first page", len(out.Groups), err)
	}
	q.After = out.NextCursor
	out, err = run(s, q)
	if err != nil || len(out.Groups) != 14 || r.calls != 64 || out.NextCursor != "" {
		t.Fatal("sparse last page", len(out.Groups), err)
	}
}

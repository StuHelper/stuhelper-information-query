package informationquery_test

import (
	"context"
	"errors"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"strings"
	"testing"
)

func TestCursorAuthenticityAndEquivalentSelections(t *testing.T) {
	s, r, p, q := resolvedFixture()
	q.Fields = nil
	q.Domains = []string{"profiles", "billing"}
	q.Limit = 1
	first, err := run(s, q)
	if err != nil || first.NextCursor == "" {
		t.Fatal(err)
	}
	q.Fields = []string{}
	q.Domains = []string{"billing", "profiles"}
	q.After = first.NextCursor
	next, err := run(s, q)
	if err != nil || len(next.Groups) != 1 || next.Groups[0].Items[0].ID != "profiles:2" {
		t.Fatal("equivalent query", err)
	}
	calls, resolves := p.calls, r.calls
	for _, bad := range []string{q.After + "x", strings.Repeat("A", len(q.After)), q.After[:len(q.After)/2] + "!" + q.After[len(q.After)/2+1:]} {
		q.After = bad
		out, err := run(s, q)
		if !errors.Is(err, iq.ErrInvalid) || len(out.Groups) != 0 || p.calls != calls || r.calls != resolves {
			t.Fatal("invalid cursor reached source", err)
		}
	}
}

func TestConfiguredCursorKeyAcrossReplicas(t *testing.T) {
	s, _, _, q := resolvedFixture()
	r, _, p, _ := resolvedFixture()
	s.CursorKey = &[32]byte{1}
	r.CursorKey = &[32]byte{2}
	q.Limit = 1
	first, err := run(s, q)
	if err != nil || first.NextCursor == "" {
		t.Fatal("first page", err)
	}
	q.After = first.NextCursor
	if _, err = run(r, q); !errors.Is(err, iq.ErrInvalid) || p.calls != 0 {
		t.Fatal("key mismatch", err)
	}
	r.CursorKey = s.CursorKey
	out, err := run(r, q)
	if err != nil || recordCount(out) != 1 || p.calls != 1 {
		t.Fatal("shared key", err)
	}
}

type invalidLeadPosition struct{ *resolver }

func (r invalidLeadPosition) Resolve(ctx context.Context, p account.Principal, l iq.Lead) ([]iq.Candidate, string, error) {
	items, _, err := r.resolver.Resolve(ctx, p, l)
	return items, "invalid\x00position", err
}
func TestResolverPositionValidatedBeforeContinuation(t *testing.T) {
	s, r, p, q := resolvedFixture()
	s.Resolvers["name"] = invalidLeadPosition{r}
	out, err := run(s, q)
	if !errors.Is(err, iq.ErrUnavailable) || out.NextCursor != "" || len(out.Groups) != 0 || p.calls != 0 {
		t.Fatal("invalid resolver cursor", err)
	}
}

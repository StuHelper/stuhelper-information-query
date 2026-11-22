package informationquery_test

import (
	"errors"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"strings"
	"testing"
)

func TestQueryRequiresCanonicalAccount(t *testing.T) {
	s, audits, _, provider, q := fixture()
	q.Value = "unresolved-clue"
	out, err := run(s, q)
	if !errors.Is(err, iq.ErrInvalid) || len(out.Groups) != 0 || provider.calls != 0 || len(audits.records) != 1 || len(audits.records[0].Targets) != 0 {
		t.Fatalf("invalid account: err=%v calls=%d audits=%+v", err, provider.calls, audits.records)
	}
	key := account.Principal{Issuer: strings.Repeat("i", 768), Subject: strings.Repeat("s", 767)}.Key()
	if len(key) != 2048 {
		t.Fatal("fixture length", len(key))
	}
	q.Value, provider.items[0].Subject = key, key
	out, err = run(s, q)
	if err != nil || recordCount(out) != 1 || audits.records[1].Targets[0] != key {
		t.Fatal("valid key", err)
	}
	s, resolver, targetProvider, q := resolvedFixture()
	resolver.candidates[0].Account = "unresolved-clue"
	if out, err = run(s, q); !errors.Is(err, iq.ErrUnavailable) || len(out.Groups) != 0 || targetProvider.calls != 0 {
		t.Fatal("invalid resolved account", err)
	}
	resolver.candidates = resolver.candidates[:1]
	resolver.candidates[0].Account = key
	s.Providers = nil
	if out, err = run(s, q); err != nil || len(out.Groups) != 1 || out.Groups[0].Candidate.Account != key {
		t.Fatal("long resolved account", err)
	}
}

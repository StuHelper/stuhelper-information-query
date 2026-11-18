package informationquery_test

import (
	"context"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"testing"
)

type checkKey struct {
	cap   string
	scope admin.Scope
}
type countingAuth struct {
	calls map[checkKey]int
	deny  *checkKey
}

func (a countingAuth) Evaluate(_ context.Context, _ account.Principal, cap string, scope admin.Scope) error {
	key := checkKey{cap, scope}
	a.calls[key]++
	if a.deny != nil && *a.deny == key {
		return iq.ErrForbidden
	}
	return nil
}
func TestAuthorizationReuseEndsAtRequestBoundary(t *testing.T) {
	s, audits, _, p, q := fixture()
	q.Scope.School = "*"
	q.Fields = []string{"identity"}
	auth := countingAuth{calls: map[checkKey]int{}}
	s.Auth = &auth
	out, err := run(s, q)
	if err != nil || recordCount(out) != 1 || len(auth.calls) != 4 || len(audits.records[0].Basis) != 2 {
		t.Fatal(err, auth.calls, audits.records)
	}
	for key, n := range auth.calls {
		if n != 1 {
			t.Fatalf("%v evaluated %d times", key, n)
		}
	}
	denied := checkKey{"information-query.identity.read", p.items[0].Scope}
	auth.deny = &denied
	out, err = run(s, q)
	if err != iq.ErrForbidden || len(out.Groups) != 0 || auth.calls[denied] != 2 || len(audits.records) != 2 || len(audits.records[1].Targets) != 0 {
		t.Fatal("revocation", err, auth.calls)
	}
}

package informationquery_test

import (
	iq "github.com/StuHelper/stuhelper-information-query"
	"testing"
	"time"
)

func TestContinuationKeepsGroupIdentityAndSkipsExhaustedTarget(t *testing.T) {
	s, audits, _, _, q := fixture()
	s.Providers = map[string]iq.Provider{"profiles": &accountProvider{domain: "profiles"}}
	_, resolved, _, _ := resolvedFixture()
	q.Kind, q.Value, q.Limit = "account", resolved.candidates[0].Account, 1
	now := time.Unix(120, 0)
	s.Now = func() time.Time { return now }
	first := now
	var finalPageCursor string
	for i := 0; i < 3; i++ {
		finalPageCursor = q.After
		out, err := run(s, q)
		if err != nil || len(out.Groups) != 1 || len(out.Groups[0].Items) != 1 || !out.Groups[0].Candidate.ChangedAt.Equal(first) || (out.NextCursor != "") != (i < 2) || out.Groups[0].HasMore != (i < 2) {
			t.Fatalf("page %d: %+v %v", i, out, err)
		}
		q.After = out.NextCursor
		now = now.Add(time.Minute)
	}
	// A previously issued cursor must skip the group if the provider now has no remaining facts.
	q.After = finalPageCursor
	s.Providers["profiles"] = &provider{}
	out, err := run(s, q)
	last := audits.records[len(audits.records)-1]
	if err != nil || len(out.Groups) != 0 || out.NextCursor != "" || last.Count != 0 || len(last.Targets) != 0 || !last.CreatedAt.Equal(now) {
		t.Fatalf("exhausted group: %+v %+v %v", out, last, err)
	}
}
func TestExhaustedGroupAdvancesToNextCandidate(t *testing.T) {
	s, r, _, q := resolvedFixture()
	q.Limit = 3
	first, err := run(s, q)
	if err != nil || first.NextCursor == "" {
		t.Fatal(err)
	}
	q.After = first.NextCursor
	next, err := run(s, q)
	if err != nil || len(next.Groups) != 1 || next.Groups[0].Candidate.Account != r.candidates[1].Account || len(next.Groups[0].Items) != 3 {
		t.Fatalf("%+v %v", next, err)
	}
}

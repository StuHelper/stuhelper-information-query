package informationquery_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"strings"
	"testing"
	"time"
)

type batchResolver struct {
	byValue map[string][]iq.Candidate
}

func (r batchResolver) Resolve(_ context.Context, _ account.Principal, l iq.Lead) ([]iq.Candidate, string, error) {
	list := r.byValue[l.Value]
	if len(list) == 0 {
		return []iq.Candidate{}, "", nil
	}
	end := min(l.Limit, len(list))
	next := ""
	if end < len(list) {
		next = "more"
	}
	return list[:end], next, nil
}

type countProvider struct {
	domain        string
	countByTarget map[string]int
	sawFields     bool
}

func (p *countProvider) Query(_ context.Context, _ account.Principal, q iq.Query) ([]iq.Record, error) {
	if len(q.Fields) > 0 {
		p.sawFields = true
	}
	n := p.countByTarget[q.Value]
	limit := min(n, q.Limit)
	out := make([]iq.Record, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, iq.Record{
			ID:        fmt.Sprintf("%s:%03d", p.domain, i),
			Subject:   q.Value,
			Scope:     admin.Scope{School: scope.School, Group: scope.Group, Module: p.domain},
			Source:    p.domain,
			Current:   i%2 == 1,
			ChangedAt: time.Unix(200, 0),
			Fields: []iq.Field{
				{Name: "secret_doc", Category: "document", Value: "SENSITIVE-DOC-9999", Masked: false},
			},
		})
	}
	return out, nil
}

func TestBoundedBatchPreviewAuthorizationMaskingAndAudit(t *testing.T) {
	r := &repo{}
	a := &auth{
		caps: map[string]bool{
			"information-query.profiles.read": true,
			"information-query.groups.read":   true,
		},
		scope: admin.Scope{School: scope.School, Group: scope.Group, Module: "*"},
	}
	manyHomonyms := make([]iq.Candidate, 0, 7)
	for i := 1; i <= 7; i++ {
		manyHomonyms = append(manyHomonyms, iq.Candidate{
			Account:   fmt.Sprintf("issuer:homonym-%d", i),
			Source:    "qq-binding",
			Current:   i == 1,
			ChangedAt: time.Unix(100, 0),
			Scope:     a.scope,
			Label:     []iq.Field{{Name: "qq", Category: "identity", Value: "***", Masked: true}},
		})
	}
	res := batchResolver{byValue: map[string][]iq.Candidate{
		"RAW-QQ-10001": manyHomonyms,
		"RAW-QQ-10002": {},
	}}
	profProv := &countProvider{domain: "profiles", countByTarget: map[string]int{"issuer:homonym-1": 25, "issuer:homonym-2": 2}}
	svc := &iq.Service{
		Auth:      a,
		Repo:      r,
		Resolvers: map[string]iq.Resolver{"qq": res},
		Providers: map[string]iq.Provider{"profiles": profProv},
	}
	bq := iq.BatchQuery{
		Kind:    "qq",
		Values:  []string{"RAW-QQ-10001", "RAW-QQ-10002"},
		Scope:   a.scope,
		Domains: []string{"profiles", "groups"},
		Purpose: "迎新群批量入群核验",
	}
	if fmt.Sprint(bq) != "informationquery.BatchQuery{redacted}" {
		t.Fatalf("BatchQuery String() leaked: %s", fmt.Sprint(bq))
	}

	// Missing independent information-query.batch.read capability -> 403.
	if _, err := svc.Preview(context.Background(), actor, "batch-1", iq.Delivery{Channel: "admin"}, bq); !errors.Is(err, iq.ErrForbidden) {
		t.Fatalf("expected 403 without batch.read capability, got %v", err)
	}

	a.caps["information-query.batch.read"] = true
	// Bot channel is always forbidden for batch preview even when BotEnabled=true.
	svc.BotEnabled = true
	a.caps["information-query.bot"] = true
	if _, err := svc.Preview(context.Background(), actor, "batch-bot", iq.Delivery{Channel: "bot_group", Group: scope.Group}, bq); !errors.Is(err, iq.ErrForbidden) {
		t.Fatalf("expected 403 on bot channel, got %v", err)
	}

	// Over-limit (>20 leads) and duplicate leads -> 400.
	tooMany := bq
	tooMany.Values = make([]string, 21)
	for i := range tooMany.Values {
		tooMany.Values[i] = fmt.Sprintf("qq-%d", i)
	}
	if _, err := svc.Preview(context.Background(), actor, "batch-over", iq.Delivery{Channel: "admin"}, tooMany); !errors.Is(err, iq.ErrInvalid) {
		t.Fatalf("expected 400 for >20 leads, got %v", err)
	}
	dup := bq
	dup.Values = []string{"RAW-QQ-10001", "RAW-QQ-10001"}
	if _, err := svc.Preview(context.Background(), actor, "batch-dup", iq.Delivery{Channel: "admin"}, dup); !errors.Is(err, iq.ErrInvalid) {
		t.Fatalf("expected 400 for duplicate leads, got %v", err)
	}

	// Authorized admin batch preview succeeds with capped candidates (5) and capped counts (20, HasMore=true).
	out, err := svc.Preview(context.Background(), actor, "batch-ok", iq.Delivery{Channel: "admin"}, bq)
	if err != nil {
		t.Fatal(err)
	}
	if profProv.sawFields {
		t.Fatal("batch preview passed sensitive fields to provider")
	}
	if len(out.Entries) != 2 || len(out.UnavailableDomains) != 1 || out.UnavailableDomains[0] != "groups" {
		t.Fatalf("unexpected entries or unavailable domains: %+v", out)
	}
	if !out.Entries[0].HasMoreCandidates || len(out.Entries[0].Candidates) != 5 {
		t.Fatalf("expected 5 candidates with HasMoreCandidates=true, got %+v", out.Entries[0])
	}
	firstSummary := out.Entries[0].Candidates[0].DomainCounts[0]
	if firstSummary.Domain != "profiles" || firstSummary.Count != 20 || firstSummary.CurrentCount != 10 || !firstSummary.HasMore {
		t.Fatalf("unexpected capped summary for homonym-1: %+v", firstSummary)
	}
	secondSummary := out.Entries[0].Candidates[1].DomainCounts[0]
	if secondSummary.Count != 2 || secondSummary.CurrentCount != 1 || secondSummary.HasMore {
		t.Fatalf("unexpected exact summary for homonym-2: %+v", secondSummary)
	}
	if len(out.Entries[1].Candidates) != 0 || out.Entries[1].HasMoreCandidates {
		t.Fatalf("expected empty candidates for second lead, got %+v", out.Entries[1])
	}

	// Verify neither response nor audit contains raw clues or sensitive record values.
	respJSON, _ := json.Marshal(out)
	auditJSON, _ := json.Marshal(r.records)
	for _, secret := range []string{"RAW-QQ-10001", "RAW-QQ-10002", "SENSITIVE-DOC-9999"} {
		if strings.Contains(string(respJSON), secret) || strings.Contains(string(auditJSON), secret) {
			t.Fatalf("secret %q leaked in response or audit", secret)
		}
	}
	lastAudit := r.records[len(r.records)-1]
	if lastAudit.Action != "batch.preview" || lastAudit.Result != "success" || len(lastAudit.Fields) != 0 || len(lastAudit.Targets) != 5 {
		t.Fatalf("unexpected batch audit record: %+v", lastAudit)
	}

	// Audit commit failure suppresses the entire batch preview response.
	r.fail = true
	failedOut, err := svc.Preview(context.Background(), actor, "batch-audit-fail", iq.Delivery{Channel: "admin"}, bq)
	if !errors.Is(err, iq.ErrUnavailable) || len(failedOut.Entries) != 0 {
		t.Fatalf("audit failure leaked batch preview: %+v %v", failedOut, err)
	}
}

package informationquery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/StuHelper/stuhelper-platform/account"
)

type continuation struct {
	Binding   string `json:"b"`
	Lead      string `json:"l"`
	Record    string `json:"r"`
	Candidate string `json:"c"`
}

func fingerprint(v any) string {
	b, _ := json.Marshal(v)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func (s Service) resolveQuery(ctx context.Context, p account.Principal, q Query, a *Audit) (out Result, err error) {
	out = Result{Groups: []CandidateGroup{}, UnavailableDomains: []string{}}
	// Check every requested domain before resolving or disclosing even candidate labels.
	for _, domain := range q.Domains {
		scope := q.Scope
		scope.Module = domain
		if !q.Scope.Contains(scope) {
			return out, ErrInvalid
		}
		for _, capability := range append([]string{domain}, q.Fields...) {
			if err = s.evaluate(ctx, p, "information-query."+fieldCapability(capability)+".read", scope, a); err != nil {
				return out, err
			}
		}
		if s.Providers[domain] == nil {
			out.UnavailableDomains = append(out.UnavailableDomains, domain)
		}
	}
	originalAfter := q.After
	q.After = ""
	binding := fingerprint(struct {
		Query Query
		Actor string
	}{q, p.Key()})
	cursor := continuation{Binding: binding}
	if originalAfter != "" {
		b, e := base64.RawURLEncoding.DecodeString(originalAfter)
		if e != nil || json.Unmarshal(b, &cursor) != nil || cursor.Binding != binding || len(cursor.Lead) > 1024 || len(cursor.Record) > 256 {
			return out, ErrInvalid
		}
	}
	budget, remaining, payload := 700, q.Limit, 0
	for len(out.Groups) < 50 && remaining > 0 && budget >= len(q.Domains) {
		if ctx.Err() != nil {
			s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "timeout"})
			return out, ErrUnavailable
		}
		var candidate Candidate
		next := ""
		if q.Kind == "account" {
			candidate = Candidate{Account: q.Value, Source: "account", Current: true, ChangedAt: a.CreatedAt, Scope: q.Scope, Label: []Field{}}
		} else {
			resolver := s.Resolvers[q.Kind]
			if resolver == nil {
				s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "resolver_missing"})
				return out, ErrUnavailable
			}
			resolveStart := time.Now()
			candidates, n, e := resolver.Resolve(ctx, p, Lead{Kind: q.Kind, Value: q.Value, Scope: q.Scope, Purpose: q.Purpose, Limit: 1, After: cursor.Lead})
			resolveDuration := time.Since(resolveStart)
			if e != nil {
				if errors.Is(e, ErrForbidden) {
					s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "forbidden", Duration: resolveDuration})
					return out, e
				}
				if errors.Is(e, ErrUnauthenticated) {
					s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "unauthenticated", Duration: resolveDuration})
					return out, e
				}
				s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "resolver_error", Duration: resolveDuration})
				return out, ErrUnavailable
			}
			if len(candidates) > 1 || len(n) > 1024 || (n != "" && (n == cursor.Lead || len(candidates) == 0)) {
				s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "invalid_resolver_page", Duration: resolveDuration})
				return out, ErrUnavailable
			}
			if len(candidates) == 0 {
				if cursor.Record != "" {
					s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "candidate_changed", Duration: resolveDuration})
					return out, ErrUnavailable
				}
				s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "ok", Duration: resolveDuration})
				return out, nil
			}
			candidate, next = candidates[0], n
			if !clean(candidate.Account, 256) || !clean(candidate.Source, 128) || candidate.ChangedAt.IsZero() || !candidate.Scope.Valid() || !q.Scope.Contains(candidate.Scope) || len(candidate.Label) > 10 {
				s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "invalid_candidate", Duration: resolveDuration})
				return out, ErrUnavailable
			}
			for _, f := range candidate.Label {
				if !f.Masked || !clean(f.Name, 128) || len(f.Value) > 256 || !slices.Contains([]string{"business", "identity"}, f.Category) {
					s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "invalid_candidate_label", Duration: resolveDuration})
					return out, ErrUnavailable
				}
				payload += len(f.Name) + len(f.Value)
			}
			s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "ok", Duration: resolveDuration})
			// Recheck the actual candidate scope independently in each requested domain.
			for _, domain := range q.Domains {
				scope := candidate.Scope
				scope.Module = domain
				if err = s.evaluate(ctx, p, "information-query."+domain+".read", scope, a); err != nil {
					return out, err
				}
			}
		}
		if candidate.Label == nil {
			candidate.Label = []Field{}
		}
		candidateKey := fingerprint(struct {
			Account, Source string
			Current         bool
		}{candidate.Account, candidate.Source, candidate.Current})
		if q.Kind != "account" {
			candidateKey = fingerprint(candidate)
		}
		if payload > 1048576 {
			s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "payload_limit"})
			return out, ErrUnavailable
		}

		if cursor.Candidate != "" && cursor.Candidate != candidateKey {
			s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "candidate_changed"})
			return out, ErrUnavailable
		}
		// Domain-prefixed IDs form one total order. Its exclusive lower bound
		// resumes every domain without retaining discarded fan-out records.
		pq := q
		pq.Kind = "account"
		pq.Value = candidate.Account
		pq.After = cursor.Record
		pq.Limit = min(remaining, budget/len(q.Domains))
		budget -= pq.Limit * len(q.Domains)
		page, e := s.queryRecords(ctx, p, pq, a, &payload)
		if e != nil {
			return out, e
		}
		out.Groups = append(out.Groups, CandidateGroup{Candidate: candidate, Items: page.Items})
		remaining -= len(page.Items)
		if page.NextCursor != "" {
			cursor.Record = page.NextCursor
			cursor.Candidate = candidateKey
		} else {
			if next == "" {
				return out, nil
			}
			cursor.Lead = next
			cursor.Record = ""
			cursor.Candidate = ""
		}
		// A candidate spans pages; never emit it twice within the same response.
		if page.NextCursor != "" {
			break
		}
	}
	b, _ := json.Marshal(cursor)
	out.NextCursor = base64.RawURLEncoding.EncodeToString(b)
	return out, nil
}

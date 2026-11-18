package informationquery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/StuHelper/stuhelper-platform/account"
)

type continuation struct {
	StartedAt *time.Time `json:"t,omitempty"`
	Binding   string     `json:"b"`
	Lead      string     `json:"l"`
	Record    string     `json:"r"`
	Candidate string     `json:"c"`
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
			return out, detailErr(ErrInvalid, "invalid_scope", domain, "")
		}
		if err = s.evaluate(ctx, p, "information-query."+domain+".read", scope, a, "domain_forbidden", domain, ""); err != nil {
			return out, err
		}
		for _, category := range q.Fields {
			if err = s.evaluate(ctx, p, "information-query."+fieldCapability(category)+".read", scope, a, "field_forbidden", domain, category); err != nil {
				return out, err
			}
		}
		if s.Providers[domain] == nil {
			out.UnavailableDomains = append(out.UnavailableDomains, domain)
		}
	}
	originalAfter := q.After
	q.After = ""
	q.Domains = slices.Sorted(slices.Values(q.Domains))
	q.Fields = slices.Sorted(slices.Values(q.Fields))
	binding := fingerprint(struct {
		Query Query
		Actor string
	}{q, p.Key()})
	cursor := continuation{Binding: binding}
	if originalAfter != "" {
		var ok bool
		cursor, ok = s.parseContinuation(originalAfter)
		if !ok || cursor.Binding != binding || !cursor.valid(q) {
			return out, detailErr(ErrInvalid, "cursor_mismatch", "", "")
		}
	}
	if q.Kind == "account" {
		if originalAfter == "" {
			cursor.StartedAt = &a.CreatedAt
		}
		if cursor.StartedAt == nil || cursor.StartedAt.IsZero() {
			return out, ErrInvalid
		}
	}
	remaining, payload := q.Limit, 0
	for examined := 0; examined < 50 && remaining > 0; examined++ {
		if ctx.Err() != nil {
			s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "timeout"})
			return out, detailErr(ErrUnavailable, "resolver_unavailable", "", "")
		}
		var candidate Candidate
		next := ""
		if q.Kind == "account" {
			candidate = Candidate{Account: q.Value, Source: "account", Current: true, ChangedAt: *cursor.StartedAt, Scope: q.Scope, Label: []Field{}}
		} else {
			resolver := s.Resolvers[q.Kind]
			if resolver == nil {
				s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "resolver_missing"})
				return out, detailErr(ErrUnavailable, "resolver_unavailable", "", "")
			}
			resolveStart := time.Now()
			candidates, n, e := resolver.Resolve(ctx, p, Lead{Kind: q.Kind, Value: q.Value, Scope: q.Scope, Purpose: q.Purpose, Limit: 1, After: cursor.Lead})
			resolveDuration := time.Since(resolveStart)
			if e != nil {
				if errors.Is(e, ErrForbidden) {
					s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "forbidden", Duration: resolveDuration})
					resolverDomain := ""
					if q.Kind == "name" || q.Kind == "student_id" || q.Kind == "staff_id" {
						resolverDomain = "verification"
					}
					return out, detailErr(ErrForbidden, "domain_forbidden", resolverDomain, "")
				}
				if errors.Is(e, ErrUnauthenticated) {
					s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "unauthenticated", Duration: resolveDuration})
					return out, detailErr(ErrUnauthenticated, "unauthenticated", "", "")
				}
				s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "resolver_error", Duration: resolveDuration})
				return out, detailErr(ErrUnavailable, "resolver_unavailable", "", "")
			}
			if len(candidates) > 1 || (n != "" && !clean(n, 1024)) || (n != "" && (n == cursor.Lead || len(candidates) == 0)) {
				s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "invalid_resolver_page", Duration: resolveDuration})
				return out, detailErr(ErrUnavailable, "resolver_unavailable", "", "")
			}
			if len(candidates) == 0 {
				if cursor.Record != "" {
					s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "candidate_changed", Duration: resolveDuration})
					return out, detailErr(ErrUnavailable, "candidate_changed", "", "")
				}
				s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "ok", Duration: resolveDuration})
				return out, nil
			}
			candidate, next = candidates[0], n
			if !validQueryValue("account", candidate.Account) || !clean(candidate.Source, 128) || candidate.ChangedAt.IsZero() || !candidate.Scope.Valid() || !q.Scope.Contains(candidate.Scope) || len(candidate.Label) > 10 {
				s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "invalid_candidate", Duration: resolveDuration})
				return out, detailErr(ErrUnavailable, "resolver_unavailable", "", "")
			}
			for _, f := range candidate.Label {
				if !f.Masked || !clean(f.Name, 128) || len(f.Value) > 256 || !slices.Contains([]string{"business", "identity"}, f.Category) {
					s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "invalid_candidate_label", Duration: resolveDuration})
					return out, detailErr(ErrUnavailable, "resolver_unavailable", "", "")
				}
				payload += len(f.Name) + len(f.Value)
			}
			s.observe(Event{RequestID: a.RequestID, Stage: StageResolve, Kind: q.Kind, Code: "ok", Duration: resolveDuration})
			// Recheck the actual candidate scope independently in each requested domain.
			for _, domain := range q.Domains {
				scope := candidate.Scope
				scope.Module = domain
				if err = s.evaluate(ctx, p, "information-query."+domain+".read", scope, a, "domain_forbidden", domain, ""); err != nil {
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
			return out, detailErr(ErrUnavailable, "payload_too_large", "", "")
		}

		if cursor.Candidate != "" && cursor.Candidate != candidateKey {
			s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Kind: q.Kind, Code: "candidate_changed"})
			return out, detailErr(ErrUnavailable, "candidate_changed", "", "")
		}
		// Domain-prefixed IDs form one total order. Its exclusive lower bound
		// resumes every domain without retaining discarded fan-out records.
		pq := q
		pq.Kind = "account"
		pq.Value = candidate.Account
		pq.After = cursor.Record
		pq.Limit = min(remaining+1, 100)
		page, e := s.queryRecords(ctx, p, pq, a, &payload, remaining)
		if e != nil {
			return out, e
		}
		// Confirm truncation with one authorized record beyond this candidate's displayed page.
		// At the provider's 100-row ceiling the lookahead uses a separate exclusive cursor.
		hasMore := len(page.Items) > remaining
		if hasMore {
			page.Items = page.Items[:remaining]
		} else if len(page.Items) == 100 {
			probe := pq
			probe.After = page.Items[99].ID
			probe.Limit = 1
			extra, err := s.queryRecords(ctx, p, probe, a, &payload, 0)
			if err != nil {
				return out, err
			}
			hasMore = len(extra.Items) > 0
		}
		page.NextCursor = ""
		if hasMore {
			page.NextCursor = page.Items[len(page.Items)-1].ID
		}
		if cursor.Record == "" || len(page.Items) > 0 {
			out.Groups = append(out.Groups, CandidateGroup{Candidate: candidate, Items: page.Items, HasMore: page.NextCursor != ""})
		}
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
	out.NextCursor = s.encodeContinuation(cursor)
	if len(out.NextCursor) > 4096 {
		return out, ErrUnavailable
	}
	return out, nil
}

func (c continuation) valid(q Query) bool {
	if c.Lead != "" && (q.Kind == "account" || !clean(c.Lead, 1024)) {
		return false
	}
	if c.Record == "" {
		return c.Candidate == "" && c.Lead != ""
	}
	digest, err := hex.DecodeString(c.Candidate)
	domain, _, ok := strings.Cut(c.Record, ":")
	return err == nil && len(digest) == sha256.Size && clean(c.Record, 256) && ok && slices.Contains(q.Domains, domain)
}

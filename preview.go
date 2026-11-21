package informationquery

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/StuHelper/stuhelper-platform/account"
)

const (
	maxBatchLeads              = 20
	maxBatchCandidatesPerLead  = 5
	maxBatchTotalCandidates    = 50
	maxBatchDomainPreviewCount = 20
	maxBatchRecordBudget       = 700
	maxBatchPayloadBytes       = 1048576
)

// Preview returns the initiating admin's submitted leads with masked candidate
// metadata and bounded per-domain counts after the batch audit commits.
func (s Service) Preview(ctx context.Context, p account.Principal, id string, d Delivery, q BatchQuery) (out BatchPreviewResult, err error) {
	a := s.start(p, id, batchPreviewPurpose, "batch.preview", q.Scope, d)
	a.LeadKind = q.Kind
	defer func() {
		if err != nil {
			a.Scopes = nil
			a.Count = 0
		}
		err = s.finish(ctx, a, err)
		if err != nil {
			out = BatchPreviewResult{}
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !p.Valid() {
		return out, ErrUnauthenticated
	}
	if !clean(id, 128) || !cleanText(q.Purpose, 512) || !scopeOK(q.Scope) || !validDelivery(d) || !selection(q.Domains, domains, 1) || !slices.Contains(kinds, q.Kind) {
		return out, ErrInvalid
	}
	if (q.Kind == "student_id" || q.Kind == "staff_id") && q.Scope.School == "*" {
		return out, ErrInvalid
	}
	if len(q.Values) < 1 || len(q.Values) > maxBatchLeads {
		return out, ErrInvalid
	}
	seenValues := make(map[string]bool, len(q.Values))
	for _, v := range q.Values {
		if !validLeadText(v) || (q.Kind == "account" && !validQueryValue(q.Kind, v)) || seenValues[v] {
			return out, ErrInvalid
		}
		seenValues[v] = true
	}
	// Forward a fixed purpose so free text cannot persist in provider audit.
	q.Purpose = batchPreviewPurpose
	values, _ := json.Marshal(q.Values)
	// The domain prefix separates audit digests from continuation signatures.
	digestInput := append([]byte("information-query/batch-preview/v1\x00"+id+"\x00"+q.Kind+"\x00"), values...)
	a.LeadDigest = hex.EncodeToString(s.keyedDigest(digestInput))
	ctx = context.WithValue(ctx, batchPreviewAuditKey{}, true)
	// Batch preview is restricted to the admin channel and requires independent batch capability.
	if d.Channel != "admin" {
		return out, ErrForbidden
	}
	if s.Auth != nil {
		s.Auth = queryAuthorizer{source: s.Auth, allowed: make(map[permission]bool)}
	}
	if err = s.evaluate(ctx, p, "information-query.batch.read", q.Scope, &a, "domain_forbidden", "", ""); err != nil {
		return out, err
	}
	out = BatchPreviewResult{
		Entries:            make([]BatchPreviewEntry, len(q.Values)),
		UnavailableDomains: []string{},
	}
	for i := range out.Entries {
		out.Entries[i] = BatchPreviewEntry{Index: i, Value: q.Values[i], Candidates: []CandidatePreview{}}
	}
	for _, domain := range q.Domains {
		domainScope := q.Scope
		domainScope.Module = domain
		if !q.Scope.Contains(domainScope) {
			return BatchPreviewResult{}, ErrInvalid
		}
		if err = s.evaluate(ctx, p, "information-query."+domain+".read", domainScope, &a, "domain_forbidden", domain, ""); err != nil {
			return BatchPreviewResult{}, err
		}
		if s.Providers[domain] == nil {
			out.UnavailableDomains = append(out.UnavailableDomains, domain)
		}
	}
	if q.Kind != "account" && s.Resolvers[q.Kind] == nil {
		return BatchPreviewResult{}, ErrUnavailable
	}

	totalCandidates := 0
	recordBudget := maxBatchRecordBudget
	payloadBytes := 0

	for idx, val := range q.Values {
		if ctx.Err() != nil {
			return BatchPreviewResult{}, ErrUnavailable
		}
		if totalCandidates >= maxBatchTotalCandidates || recordBudget <= 0 {
			out.Truncated = true
			for rest := idx; rest < len(out.Entries); rest++ {
				out.Entries[rest].HasMoreCandidates = true
			}
			break
		}
		var candidates []Candidate
		hasMoreLead := false
		if q.Kind == "account" {
			candidates = []Candidate{{
				Account:   val,
				Source:    "account",
				Current:   true,
				ChangedAt: a.CreatedAt,
				Scope:     q.Scope,
				Label:     []Field{},
			}}
		} else {
			resolver := s.Resolvers[q.Kind]
			limit := min(maxBatchCandidatesPerLead+1, maxBatchTotalCandidates-totalCandidates+1)
			if limit > 50 {
				limit = 50
			}
			resolved, next, e := resolver.Resolve(ctx, p, Lead{
				Kind:    q.Kind,
				Value:   val,
				Scope:   q.Scope,
				Purpose: q.Purpose,
				Limit:   limit,
			})
			if e != nil {
				if errors.Is(e, ErrForbidden) || errors.Is(e, ErrUnauthenticated) {
					return BatchPreviewResult{}, e
				}
				return BatchPreviewResult{}, ErrUnavailable
			}
			if len(resolved) > limit || (next != "" && !clean(next, 1024)) || (next != "" && len(resolved) == 0) {
				return BatchPreviewResult{}, ErrUnavailable
			}
			maxKeep := min(maxBatchCandidatesPerLead, maxBatchTotalCandidates-totalCandidates)
			if len(resolved) > maxKeep {
				hasMoreLead = true
				if maxBatchTotalCandidates-totalCandidates < maxBatchCandidatesPerLead {
					out.Truncated = true
				}
				resolved = resolved[:maxKeep]
			} else if next != "" {
				hasMoreLead = true
			}
			for _, candidate := range resolved {
				if !validQueryValue("account", candidate.Account) || !clean(candidate.Source, 128) || candidate.ChangedAt.IsZero() || !candidate.Scope.Valid() || !q.Scope.Contains(candidate.Scope) || len(candidate.Label) > 10 {
					return BatchPreviewResult{}, ErrUnavailable
				}
				for _, f := range candidate.Label {
					if !f.Masked || !clean(f.Name, 128) || len(f.Value) > 256 || !slices.Contains([]string{"business", "identity"}, f.Category) {
						return BatchPreviewResult{}, ErrUnavailable
					}
					payloadBytes += len(f.Name) + len(f.Value)
					if payloadBytes > maxBatchPayloadBytes {
						return BatchPreviewResult{}, ErrUnavailable
					}
				}
				if candidate.Label == nil {
					candidate.Label = []Field{}
				}
				for _, domain := range q.Domains {
					scope := candidate.Scope
					scope.Module = domain
					if err = s.evaluate(ctx, p, "information-query."+domain+".read", scope, &a, "domain_forbidden", domain, ""); err != nil {
						return BatchPreviewResult{}, err
					}
				}
				candidates = append(candidates, candidate)
			}
		}

		out.Entries[idx].HasMoreCandidates = hasMoreLead
		for _, candidate := range candidates {
			totalCandidates++
			addScope(&a.Scopes, candidate.Scope)
			summaries, usedBudget, truncatedByBudget, e := s.summarizeCandidateDomains(ctx, p, candidate.Account, q, &a, recordBudget, &payloadBytes)
			if e != nil {
				return BatchPreviewResult{}, e
			}
			recordBudget -= usedBudget
			if truncatedByBudget {
				out.Truncated = true
			}
			for _, s := range summaries {
				a.Count += s.Count
			}
			out.Entries[idx].Candidates = append(out.Entries[idx].Candidates, CandidatePreview{
				Candidate:    candidate,
				DomainCounts: summaries,
			})
		}
	}
	return out, nil
}

func (s Service) summarizeCandidateDomains(ctx context.Context, p account.Principal, accountKey string, q BatchQuery, a *Audit, budget int, payloadBytes *int) ([]DomainSummary, int, bool, error) {
	summaries := make([]DomainSummary, 0, len(q.Domains))
	used := 0
	truncated := false
	for _, domain := range q.Domains {
		provider := s.Providers[domain]
		if provider == nil {
			continue
		}
		remaining := budget - used
		if remaining <= 0 {
			truncated = true
			summaries = append(summaries, DomainSummary{Domain: domain, HasMore: true})
			continue
		}
		probeLimit := min(maxBatchDomainPreviewCount+1, remaining)
		domainScope := q.Scope
		domainScope.Module = domain
		pq := Query{
			Kind:    "account",
			Value:   accountKey,
			Scope:   domainScope,
			Domains: []string{domain},
			Fields:  []string{},
			Purpose: q.Purpose,
			Limit:   probeLimit,
		}
		records, e := provider.Query(ctx, p, pq)
		if e != nil {
			if errors.Is(e, ErrForbidden) || errors.Is(e, ErrUnauthenticated) {
				return nil, used, false, e
			}
			return nil, used, false, ErrUnavailable
		}
		if len(records) > probeLimit {
			return nil, used, false, ErrUnavailable
		}
		used += max(len(records), 1)
		previous := ""
		for _, r := range records {
			if !strings.HasPrefix(r.ID, domain+":") || !clean(r.ID, 256) || r.ID <= previous || !clean(r.Subject, 2048) || r.Subject != accountKey || !clean(r.Source, 128) || r.ChangedAt.IsZero() || !r.Scope.Valid() || r.Scope.Module != domain || !domainScope.Contains(r.Scope) || len(r.Fields) > 100 {
				return nil, used, false, ErrUnavailable
			}
			previous = r.ID
			addScope(&a.Scopes, r.Scope)
			if e = s.evaluate(ctx, p, "information-query."+domain+".read", r.Scope, a, "domain_forbidden", domain, ""); e != nil {
				return nil, used, false, e
			}
			for _, f := range r.Fields {
				if !clean(f.Name, 128) || len(f.Value) > 65536 || (f.Category != "business" && !slices.Contains(categories, f.Category)) {
					return nil, used, false, ErrUnavailable
				}
				*payloadBytes += len(f.Name) + len(f.Value)
				if *payloadBytes > maxBatchPayloadBytes {
					return nil, used, false, ErrUnavailable
				}
			}
		}
		hasMore := false
		counted := records
		if len(records) > maxBatchDomainPreviewCount {
			hasMore = true
			counted = records[:maxBatchDomainPreviewCount]
		} else if probeLimit <= maxBatchDomainPreviewCount && len(records) == probeLimit {
			hasMore = true
			truncated = true
		}
		currentCount := 0
		for _, r := range counted {
			if r.Current {
				currentCount++
			}
		}
		summaries = append(summaries, DomainSummary{
			Domain:       domain,
			Count:        len(counted),
			CurrentCount: currentCount,
			HasMore:      hasMore,
		})
	}
	return summaries, used, truncated, nil
}

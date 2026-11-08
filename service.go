package informationquery

import (
	"context"
	"errors"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var domains = []string{"profiles", "verification", "catalog", "reviews", "resources", "billing", "groups"}
var categories = []string{"identity", "document", "material", "refund"}

type Service struct {
	Auth       Authorizer
	Repo       Repository
	Providers  map[string]Provider // immutable after host assembly
	BotEnabled bool                // disabled by default, including platform administrators
	Now        func() time.Time
}

func clean(v string, max int) bool {
	return v != "" && len(v) <= max && utf8.ValidString(v) && !strings.ContainsFunc(v, unicode.IsControl)
}
func scopeOK(s admin.Scope) bool { return s.Valid() }
func selection(v, allowed []string, min int) bool {
	if len(v) < min || len(v) > len(allowed) {
		return false
	}
	seen := map[string]bool{}
	for _, x := range v {
		if seen[x] || !slices.Contains(allowed, x) {
			return false
		}
		seen[x] = true
	}
	return true
}
func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func (s Service) evaluate(ctx context.Context, p account.Principal, cap string, scope admin.Scope, a *Audit) error {
	if s.Auth == nil {
		return ErrUnavailable
	}
	if e := s.Auth.Evaluate(ctx, p, cap, scope); e != nil {
		if errors.Is(e, ErrForbidden) || errors.Is(e, ErrUnauthenticated) {
			return e
		}
		return ErrUnavailable
	}
	if !slices.Contains(a.Basis, cap) {
		a.Basis = append(a.Basis, cap)
	}
	return nil
}
func (s Service) start(p account.Principal, requestID, purpose, action string, scope admin.Scope, d Delivery) Audit {
	return Audit{Actor: p.Key(), RequestID: requestID, Purpose: purpose, Action: action, Scope: scope, Channel: d.Channel, TargetGroup: d.Group, Targets: []string{}, Fields: []string{}, Basis: []string{}, CreatedAt: s.now()}
}
func (s Service) finish(ctx context.Context, a Audit, err error) error {
	a.Result = "success"
	if err != nil {
		a.Result = "unavailable"
		for _, e := range []error{ErrInvalid, ErrForbidden, ErrUnauthenticated} {
			if errors.Is(err, e) {
				a.Result = e.Error()
			}
		}
	}
	// A cancelled caller must not prevent recording a denial or a completed disclosure.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if s.Repo == nil || s.Repo.Append(auditCtx, a) != nil {
		return ErrUnavailable
	}
	return err
}
func validDelivery(d Delivery) bool {
	return (d.Channel == "admin" || d.Channel == "bot_private") && d.Group == "" || d.Channel == "bot_group" && clean(d.Group, 128)
}
func (s Service) Query(ctx context.Context, p account.Principal, id string, d Delivery, q Query) (out Result, err error) {
	a := s.start(p, id, q.Purpose, "query", q.Scope, d)
	defer func() {
		err = s.finish(ctx, a, err)
		if err != nil {
			out = Result{}
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !p.Valid() {
		return out, ErrUnauthenticated
	}
	if !clean(id, 128) || !clean(q.Purpose, 512) || !clean(q.Value, 256) || !scopeOK(q.Scope) || !validDelivery(d) || !selection(q.Domains, domains, 1) || !selection(q.Fields, categories, 0) || q.Limit < 1 || q.Limit > 100 || len(q.After) > 256 || !slices.Contains([]string{"name", "student_number", "qq", "subject"}, q.Kind) {
		return out, ErrInvalid
	}
	if q.Kind == "student_number" && q.Scope.School == "*" {
		return out, ErrInvalid
	}
	if d.Channel != "admin" {
		if !s.BotEnabled {
			return out, ErrForbidden
		}
		if err = s.evaluate(ctx, p, "information-query.bot", q.Scope, &a); err != nil {
			return out, err
		}
	}
	a.Fields = append([]string{}, q.Fields...)
	payloadBytes := 0
	out = Result{Items: []Record{}, UnavailableDomains: []string{}}
	for _, domain := range q.Domains {
		scope := q.Scope
		scope.Module = domain
		if !q.Scope.Contains(scope) {
			return out, ErrInvalid
		}
		if err = s.evaluate(ctx, p, "information-query."+domain+".read", scope, &a); err != nil {
			return out, err
		}
		for _, category := range q.Fields {
			if err = s.evaluate(ctx, p, "information-query."+category+".read", scope, &a); err != nil {
				return out, err
			}
		}
		provider := s.Providers[domain]
		if provider == nil {
			out.UnavailableDomains = append(out.UnavailableDomains, domain)
			continue
		}
		pq := q
		pq.Scope = scope
		pq.Domains = []string{domain}
		records, e := provider.Query(ctx, p, pq)
		if e != nil {
			return out, ErrUnavailable
		}
		if len(records) > q.Limit {
			return out, ErrUnavailable
		}
		previous := q.After
		for _, r := range records {
			if !strings.HasPrefix(r.ID, domain+":") || !clean(r.ID, 256) || r.ID <= previous || !clean(r.Subject, 2048) || !clean(r.Source, 128) || r.ChangedAt.IsZero() || !r.Scope.Valid() || r.Scope.Module != domain || !scope.Contains(r.Scope) || len(r.Fields) > 100 {
				return out, ErrUnavailable
			}
			previous = r.ID
			if e = s.evaluate(ctx, p, "information-query."+domain+".read", r.Scope, &a); e != nil {
				return out, e
			}
			filtered := make([]Field, 0, len(r.Fields))
			for _, f := range r.Fields {
				payloadBytes += len(f.Name) + len(f.Value)
				if !clean(f.Name, 128) || len(f.Value) > 65536 || payloadBytes > 1048576 {
					return out, ErrUnavailable
				}
				if f.Category != "business" && !slices.Contains(categories, f.Category) {
					return out, ErrUnavailable
				}
				if f.Category != "business" {
					if slices.Contains(q.Fields, f.Category) {
						if e = s.evaluate(ctx, p, "information-query."+f.Category+".read", r.Scope, &a); e != nil {
							return out, e
						}
					} else if f.Category == "identity" {
						f.Value = "***"
						f.Masked = true
					} else {
						continue
					}
				}
				filtered = append(filtered, f)
			}
			r.Fields = filtered
			out.Items = append(out.Items, r)
		}
	}
	sort.SliceStable(out.Items, func(i, j int) bool { return out.Items[i].ID < out.Items[j].ID })
	// IDs must be globally unique (owning-module prefix) for stable fan-out pagination.
	for i := 1; i < len(out.Items); i++ {
		if out.Items[i-1].ID == out.Items[i].ID {
			return out, ErrUnavailable
		}
	}
	if len(out.Items) >= q.Limit {
		out.Items = out.Items[:q.Limit]
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	a.Count = len(out.Items)
	for _, r := range out.Items {
		a.Targets = append(a.Targets, r.Subject)
		for _, f := range r.Fields {
			if !slices.Contains(a.Fields, f.Category) {
				a.Fields = append(a.Fields, f.Category)
			}
		}
	}
	return out, nil
}
func (s Service) Audit(ctx context.Context, p account.Principal, id string, f AuditFilter) (out AuditPage, err error) {
	a := s.start(p, id, f.Purpose, "audit.query", f.Scope, Delivery{Channel: "admin"})
	defer func() {
		err = s.finish(ctx, a, err)
		if err != nil {
			out = AuditPage{}
		}
	}()
	if !p.Valid() {
		return out, ErrUnauthenticated
	}
	if !clean(id, 128) || !clean(f.Purpose, 512) || !f.Scope.Valid() || f.Limit < 1 || f.Limit > 100 {
		return out, ErrInvalid
	}
	if f.After != "" {
		n, e := strconv.ParseInt(f.After, 10, 64)
		if e != nil || n < 0 {
			return out, ErrInvalid
		}
	}
	if err = s.evaluate(ctx, p, "information-query.audit.read", f.Scope, &a); err != nil {
		return out, err
	}
	if s.Repo == nil {
		return out, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err = s.Repo.Read(ctx, f)
	if err != nil {
		return out, ErrUnavailable
	}
	a.Count = len(out.Items)
	return out, nil
}

// Reject records malformed HTTP queries without retaining their raw bodies.
func (s Service) Reject(ctx context.Context, p account.Principal, id string, d Delivery, cause error) error {
	a := s.start(p, id, "invalid request", "query.rejected", admin.Global, d)
	return s.finish(ctx, a, cause)
}

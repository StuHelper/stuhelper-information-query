package informationquery

import (
	"context"
	"errors"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var domains = []string{"profiles", "verification", "catalog", "reviews", "resources", "billing", "groups"}
var categories = []string{"identity", "document", "material", "refund_payee"}
var kinds = []string{"name", "student_id", "qq", "account"}
var auditChannels = []string{"admin", "bot_private", "bot_group", "unknown"}
var auditActions = []string{"query", "query.rejected", "audit.query", "audit.rejected", "provider.query"}
var auditResults = []string{"success", "denied", "invalid_request", "unauthenticated", "unavailable"}

func detailErr(base error, reason, domain, field string) error {
	code := "unavailable"
	for _, known := range []error{ErrInvalid, ErrForbidden, ErrUnauthenticated} {
		if errors.Is(base, known) {
			code = known.Error()
		}
	}
	if !slices.Contains(domains, domain) {
		domain = ""
	}
	if !slices.Contains(categories, field) {
		field = ""
	}
	return &ErrorDetail{Base: base, Code: code, Reason: reason, Domain: domain, Field: field}
}

type Service struct {
	// CursorKey may be shared by replicas. A nil key uses this process's ephemeral key.
	CursorKey  *[32]byte
	Auth       Authorizer
	Repo       Repository
	Resolvers  map[string]Resolver // name/student_id: verification; qq: qq-binding
	Providers  map[string]Provider // immutable after host assembly
	BotEnabled bool                // disabled by default, including platform administrators
	Now        func() time.Time
	Observe    func(Event) // optional sanitized diagnostic hook
}

func isDisallowedTextControl(r rune) bool {
	return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t'
}
func clean(v string, max int) bool {
	return v != "" && len(v) <= max && utf8.ValidString(v) && !strings.ContainsFunc(v, unicode.IsControl)
}
func validQueryValue(kind, value string) bool {
	if kind == "account" {
		_, err := account.Parse(value)
		return err == nil
	}
	return utf8.ValidString(value) && value != "" && utf8.RuneCountInString(value) <= 256 && !strings.ContainsFunc(value, unicode.IsControl)
}
func cleanText(v string, max int) bool {
	return v != "" && len(v) <= max*4 && utf8.ValidString(v) && utf8.RuneCountInString(v) <= max && !strings.ContainsFunc(v, isDisallowedTextControl)
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
func (s Service) observe(ev Event) {
	if s.Observe == nil {
		return
	}
	if !clean(ev.RequestID, 128) {
		ev.RequestID = ""
	}
	if !slices.Contains(domains, ev.Domain) {
		ev.Domain = ""
	}
	if !slices.Contains(kinds, ev.Kind) {
		ev.Kind = ""
	}
	s.Observe(ev)
}
func (s Service) evaluate(ctx context.Context, p account.Principal, cap string, scope admin.Scope, a *Audit, forbiddenReason, domain, field string) error {
	start := time.Now()
	if s.Auth == nil {
		s.observe(Event{RequestID: a.RequestID, Stage: StageAuth, Domain: scope.Module, Code: "auth_missing"})
		return detailErr(ErrUnavailable, "auth_unavailable", domain, field)
	}
	if e := s.Auth.Evaluate(ctx, p, cap, scope); e != nil {
		if errors.Is(e, ErrForbidden) {
			s.observe(Event{RequestID: a.RequestID, Stage: StageAuth, Domain: scope.Module, Code: "forbidden", Duration: time.Since(start)})
			return detailErr(ErrForbidden, forbiddenReason, domain, field)
		}
		if errors.Is(e, ErrUnauthenticated) {
			s.observe(Event{RequestID: a.RequestID, Stage: StageAuth, Domain: scope.Module, Code: "unauthenticated", Duration: time.Since(start)})
			return detailErr(ErrUnauthenticated, "unauthenticated", "", "")
		}
		s.observe(Event{RequestID: a.RequestID, Stage: StageAuth, Domain: scope.Module, Code: "auth_error", Duration: time.Since(start)})
		return detailErr(ErrUnavailable, "auth_unavailable", domain, field)
	}
	if !slices.Contains(a.Basis, cap) {
		a.Basis = append(a.Basis, cap)
	}
	return nil
}
func addScope(list *[]admin.Scope, sc admin.Scope) {
	if !slices.Contains(*list, sc) {
		*list = append(*list, sc)
	}
}
func addTargetScope(m map[string][]admin.Scope, target string, sc admin.Scope) {
	list := m[target]
	if !slices.Contains(list, sc) {
		m[target] = append(list, sc)
	}
}
func (s Service) start(p account.Principal, requestID, purpose, action string, scope admin.Scope, d Delivery) Audit {
	return Audit{Actor: p.Key(), RequestID: requestID, Purpose: purpose, Action: action, Scope: scope, Channel: d.Channel, TargetGroup: d.Group, Targets: []string{}, Fields: []string{}, Basis: []string{}, CreatedAt: s.now(), Scopes: []admin.Scope{}, TargetScopes: map[string][]admin.Scope{}}
}
func (s Service) finish(ctx context.Context, a Audit, err error) error {
	a.Result = "success"
	if err != nil {
		switch {
		case errors.Is(err, ErrForbidden):
			a.Result = "denied"
		case errors.Is(err, ErrInvalid):
			a.Result = ErrInvalid.Error()
		case errors.Is(err, ErrUnauthenticated):
			a.Result = ErrUnauthenticated.Error()
		default:
			a.Result = "unavailable"
		}
	}
	a = SanitizeAudit(a)
	start := time.Now()
	// A cancelled caller must not prevent recording a denial or a completed disclosure.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if s.Repo == nil {
		s.observe(Event{RequestID: a.RequestID, Stage: StageAudit, Code: "audit_missing"})
		return detailErr(ErrUnavailable, "audit_unavailable", "", "")
	}
	if s.Repo.Append(auditCtx, a) != nil {
		s.observe(Event{RequestID: a.RequestID, Stage: StageAudit, Code: "audit_append_error", Duration: time.Since(start)})
		return detailErr(ErrUnavailable, "audit_unavailable", "", "")
	}
	s.observe(Event{RequestID: a.RequestID, Stage: StageAudit, Code: a.Result, Duration: time.Since(start)})
	return err
}
func validDelivery(d Delivery) bool {
	return (d.Channel == "admin" || d.Channel == "bot_private") && d.Group == "" || d.Channel == "bot_group" && clean(d.Group, 128)
}

// queryAuthorizer reuses successful checks only within one Query for one principal.
type queryAuthorizer struct {
	source  Authorizer
	allowed map[permission]bool
}
type permission struct {
	capability string
	scope      admin.Scope
}

func (a queryAuthorizer) Evaluate(ctx context.Context, p account.Principal, capability string, scope admin.Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := permission{capability, scope}
	if a.allowed[key] {
		return nil
	}
	if err := a.source.Evaluate(ctx, p, capability, scope); err != nil {
		return err
	}
	a.allowed[key] = true
	return nil
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
		return out, detailErr(ErrUnauthenticated, "unauthenticated", "", "")
	}
	if !scopeOK(q.Scope) {
		return out, detailErr(ErrInvalid, "invalid_scope", "", "")
	}
	if q.Kind == "account" && !validQueryValue(q.Kind, q.Value) {
		return out, detailErr(ErrInvalid, "invalid_account_key", "", "")
	}
	if !clean(id, 128) || !cleanText(q.Purpose, 512) || (q.Kind != "account" && !validQueryValue(q.Kind, q.Value)) || !validDelivery(d) || !selection(q.Domains, domains, 1) || !selection(q.Fields, categories, 0) || q.Limit < 1 || q.Limit > 100 || len(q.After) > 4096 || !slices.Contains(kinds, q.Kind) {
		return out, detailErr(ErrInvalid, "invalid_parameter", "", "")
	}
	if q.Kind == "student_id" && q.Scope.School == "*" {
		return out, detailErr(ErrInvalid, "school_required", "", "")
	}
	if s.Auth != nil {
		s.Auth = queryAuthorizer{source: s.Auth, allowed: make(map[permission]bool)}
	}
	a.Fields = append([]string{}, q.Fields...)
	for _, domain := range q.Domains {
		addScope(&a.Scopes, admin.Scope{School: q.Scope.School, Group: q.Scope.Group, Module: domain})
	}
	if d.Channel != "admin" {
		if !s.BotEnabled {
			return out, detailErr(ErrForbidden, "bot_disabled", "", "")
		}
		if err = s.evaluate(ctx, p, "information-query.bot", q.Scope, &a, "bot_forbidden", "", ""); err != nil {
			return out, err
		}
	}
	out, err = s.resolveQuery(ctx, p, q, &a)
	if err != nil {
		return out, err
	}
	for _, group := range out.Groups {
		acct := group.Candidate.Account
		if !slices.Contains(a.Targets, acct) {
			a.Targets = append(a.Targets, acct)
		}
		addScope(&a.Scopes, group.Candidate.Scope)
		addTargetScope(a.TargetScopes, acct, group.Candidate.Scope)
		for _, domain := range q.Domains {
			sc := admin.Scope{School: group.Candidate.Scope.School, Group: group.Candidate.Scope.Group, Module: domain}
			addScope(&a.Scopes, sc)
			addTargetScope(a.TargetScopes, acct, sc)
		}
		a.Count += len(group.Items)
		for _, r := range group.Items {
			addScope(&a.Scopes, r.Scope)
			addTargetScope(a.TargetScopes, acct, r.Scope)
			for _, f := range r.Fields {
				if f.Category != "business" && !f.Masked && !slices.Contains(a.Fields, f.Category) {
					a.Fields = append(a.Fields, f.Category)
				}
			}
		}
	}
	return out, nil
}

type recordPage struct {
	Items      []Record
	NextCursor string
}

func (s Service) queryRecords(ctx context.Context, p account.Principal, q Query, a *Audit, payloadBytes *int) (out recordPage, err error) {
	out = recordPage{Items: []Record{}}
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
		prefix := domain + ":"
		if q.After != "" && prefix < q.After && !strings.HasPrefix(q.After, prefix) {
			continue
		}
		provider := s.Providers[domain]
		if provider == nil {
			continue
		}
		pq := q
		pq.Scope = scope
		pq.Domains = []string{domain}
		pq.Limit = q.Limit - len(out.Items)
		if !strings.HasPrefix(q.After, prefix) {
			pq.After = ""
		}
		callStart := time.Now()
		records, e := provider.Query(ctx, p, pq)
		callDuration := time.Since(callStart)
		if e != nil {
			if errors.Is(e, ErrForbidden) {
				s.observe(Event{RequestID: a.RequestID, Stage: StageProvider, Domain: domain, Kind: q.Kind, Code: "forbidden", Duration: callDuration})
				return out, detailErr(ErrForbidden, "domain_forbidden", domain, "")
			}
			if errors.Is(e, ErrUnauthenticated) {
				s.observe(Event{RequestID: a.RequestID, Stage: StageProvider, Domain: domain, Kind: q.Kind, Code: "unauthenticated", Duration: callDuration})
				return out, detailErr(ErrUnauthenticated, "unauthenticated", "", "")
			}
			s.observe(Event{RequestID: a.RequestID, Stage: StageProvider, Domain: domain, Kind: q.Kind, Code: "provider_error", Duration: callDuration})
			return out, detailErr(ErrUnavailable, "provider_unavailable", domain, "")
		}
		if len(records) > pq.Limit {
			s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Domain: domain, Kind: q.Kind, Code: "record_limit_exceeded", Duration: callDuration})
			return out, detailErr(ErrUnavailable, "provider_unavailable", domain, "")
		}
		rawBytes := 0
		previous := pq.After
		for _, r := range records {
			if !strings.HasPrefix(r.ID, domain+":") || !clean(r.ID, 256) || r.ID <= previous || (!clean(r.Subject, 2048) || r.Subject != q.Value) || !clean(r.Source, 128) || r.ChangedAt.IsZero() || !r.Scope.Valid() || r.Scope.Module != domain || !scope.Contains(r.Scope) || len(r.Fields) > 100 {
				s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Domain: domain, Kind: q.Kind, Code: "invalid_record", Duration: callDuration})
				return out, detailErr(ErrUnavailable, "provider_unavailable", domain, "")
			}
			previous = r.ID
			if e = s.evaluate(ctx, p, "information-query."+domain+".read", r.Scope, a, "domain_forbidden", domain, ""); e != nil {
				return out, e
			}
			filtered := make([]Field, 0, len(r.Fields))
			for _, f := range r.Fields {
				rawBytes += len(f.Name) + len(f.Value)
				if !clean(f.Name, 128) || len(f.Value) > 65536 || rawBytes > 8<<20 {
					code := "invalid_field"
					reason := "provider_unavailable"
					if len(f.Value) > 65536 || rawBytes > 8<<20 {
						code = "payload_limit"
						reason = "payload_too_large"
					}
					s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Domain: domain, Kind: q.Kind, Code: code, Duration: callDuration})
					return out, detailErr(ErrUnavailable, reason, domain, "")
				}
				if f.Category != "business" && !slices.Contains(categories, f.Category) {
					s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Domain: domain, Kind: q.Kind, Code: "invalid_field_category", Duration: callDuration})
					return out, detailErr(ErrUnavailable, "provider_unavailable", domain, "")
				}
				if f.Category != "business" {
					if slices.Contains(q.Fields, f.Category) {
						if e = s.evaluate(ctx, p, "information-query."+fieldCapability(f.Category)+".read", r.Scope, a, "field_forbidden", domain, f.Category); e != nil {
							return out, e
						}
					} else if f.Category == "identity" {
						f.Value = "***"
						f.Masked = true
					} else {
						continue
					}
				}
				*payloadBytes += len(f.Name) + len(f.Value)
				if *payloadBytes > 1<<20 {
					s.observe(Event{RequestID: a.RequestID, Stage: StageContract, Domain: domain, Kind: q.Kind, Code: "payload_limit", Duration: callDuration})
					return out, detailErr(ErrUnavailable, "payload_too_large", domain, "")
				}
				filtered = append(filtered, f)
			}
			r.Fields = filtered
			out.Items = append(out.Items, r)
		}
		s.observe(Event{RequestID: a.RequestID, Stage: StageProvider, Domain: domain, Kind: q.Kind, Code: "ok", Duration: callDuration})
		if len(out.Items) == q.Limit {
			out.NextCursor = out.Items[len(out.Items)-1].ID
			break
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
		return out, detailErr(ErrUnauthenticated, "unauthenticated", "", "")
	}
	if !f.Scope.Valid() {
		return out, detailErr(ErrInvalid, "invalid_scope", "", "")
	}
	if !clean(id, 128) || !cleanText(f.Purpose, 512) || f.Limit < 1 || f.Limit > 100 {
		return out, detailErr(ErrInvalid, "invalid_parameter", "", "")
	}
	if (f.Actor != "" && !clean(f.Actor, 2048)) || (f.Target != "" && !clean(f.Target, 2048)) || (f.Action != "" && !clean(f.Action, 128)) || (f.Result != "" && !clean(f.Result, 128)) || (f.Channel != "" && !clean(f.Channel, 128)) {
		return out, detailErr(ErrInvalid, "invalid_parameter", "", "")
	}
	if (f.CreatedFrom != nil && f.CreatedFrom.IsZero()) || (f.CreatedUntil != nil && f.CreatedUntil.IsZero()) || (f.CreatedFrom != nil && f.CreatedUntil != nil && f.CreatedFrom.After(*f.CreatedUntil)) {
		return out, detailErr(ErrInvalid, "invalid_parameter", "", "")
	}
	if f.After != "" {
		n, e := strconv.ParseInt(f.After, 10, 64)
		if e != nil || n < 0 {
			return out, detailErr(ErrInvalid, "cursor_mismatch", "", "")
		}
	}
	if err = s.evaluate(ctx, p, "information-query.audit.read", f.Scope, &a, "audit_forbidden", "", ""); err != nil {
		return out, err
	}
	if s.Repo == nil {
		s.observe(Event{RequestID: a.RequestID, Stage: StageAudit, Code: "audit_missing"})
		return out, detailErr(ErrUnavailable, "audit_unavailable", "", "")
	}
	readStart := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err = s.Repo.Read(ctx, f)
	if err != nil {
		s.observe(Event{RequestID: a.RequestID, Stage: StageAudit, Code: "audit_read_error", Duration: time.Since(readStart)})
		return out, detailErr(ErrUnavailable, "audit_unavailable", "", "")
	}
	a.Count = len(out.Items)
	return out, nil
}

// Reject records malformed HTTP queries without retaining their raw bodies.
func (s Service) Reject(ctx context.Context, p account.Principal, id string, d Delivery, cause error) error {
	return s.reject(ctx, p, id, d, "query.rejected", cause)
}

// RejectAudit records a malformed or disallowed audit route request.
func (s Service) RejectAudit(ctx context.Context, p account.Principal, id string, d Delivery, cause error) error {
	return s.reject(ctx, p, id, d, "audit.rejected", cause)
}
func (s Service) reject(ctx context.Context, p account.Principal, id string, d Delivery, action string, cause error) error {
	if !p.Valid() {
		return ErrUnauthenticated
	}
	if !clean(id, 128) {
		id = ""
	}
	if !validDelivery(d) {
		d = Delivery{Channel: "unknown"}
	}
	purpose := "invalid request"
	if errors.Is(cause, ErrForbidden) {
		purpose = "channel forbidden"
	}
	a := s.start(p, id, purpose, action, admin.Global, d)
	return s.finish(ctx, a, cause)
}

func (s Service) checkCapability(ctx context.Context, p account.Principal, cap string, scope admin.Scope) (bool, error) {
	if s.Auth == nil {
		return false, ErrUnavailable
	}
	e := s.Auth.Evaluate(ctx, p, cap, scope)
	if e == nil {
		return true, nil
	}
	if errors.Is(e, ErrForbidden) {
		return false, nil
	}
	if errors.Is(e, ErrUnauthenticated) {
		return false, ErrUnauthenticated
	}
	return false, ErrUnavailable
}

// Capabilities evaluates read-only domain, field, audit, and assembly metadata
// for the current principal without appending query audit entries.
func (s Service) Capabilities(ctx context.Context, p account.Principal, d Delivery, req CapabilitiesRequest) (out Capabilities, err error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if !p.Valid() {
		return out, ErrUnauthenticated
	}
	if !validDelivery(d) {
		return out, ErrInvalid
	}
	scope := admin.Global
	if req.Scope != nil {
		if !scopeOK(*req.Scope) {
			return out, ErrInvalid
		}
		scope = *req.Scope
	}
	if s.Auth == nil {
		return out, ErrUnavailable
	}
	if d.Channel != "admin" {
		if !s.BotEnabled {
			return out, ErrForbidden
		}
		ok, e := s.checkCapability(ctx, p, "information-query.bot", scope)
		if e != nil {
			return out, e
		}
		if !ok {
			return out, ErrForbidden
		}
	}
	out = Capabilities{
		Scope:            scope,
		AllowedDomains:   []string{},
		AllowedFields:    []string{},
		AvailableDomains: []string{},
		AvailableKinds:   []string{},
	}
	for _, domain := range domains {
		if s.Providers[domain] != nil {
			out.AvailableDomains = append(out.AvailableDomains, domain)
		}
		domainScope := scope
		domainScope.Module = domain
		if !scope.Contains(domainScope) {
			continue
		}
		ok, e := s.checkCapability(ctx, p, "information-query."+domain+".read", domainScope)
		if e != nil {
			return Capabilities{}, e
		}
		if ok {
			out.AllowedDomains = append(out.AllowedDomains, domain)
		}
	}
	for _, category := range categories {
		capName := "information-query." + fieldCapability(category) + ".read"
		ok, e := s.checkCapability(ctx, p, capName, scope)
		if e != nil {
			return Capabilities{}, e
		}
		if !ok && scope.Module == "*" && len(out.AllowedDomains) > 0 {
			allAllowed := true
			for _, domain := range out.AllowedDomains {
				domainScope := scope
				domainScope.Module = domain
				domainOK, de := s.checkCapability(ctx, p, capName, domainScope)
				if de != nil {
					return Capabilities{}, de
				}
				if !domainOK {
					allAllowed = false
					break
				}
			}
			ok = allAllowed
		}
		if ok {
			out.AllowedFields = append(out.AllowedFields, category)
		}
	}
	for _, kind := range []string{"name", "student_id", "qq", "account"} {
		if kind == "account" || s.Resolvers[kind] != nil {
			out.AvailableKinds = append(out.AvailableKinds, kind)
		}
	}
	if d.Channel == "admin" {
		ok, e := s.checkCapability(ctx, p, "information-query.audit.read", scope)
		if e != nil {
			return Capabilities{}, e
		}
		out.AuditReadable = ok
	}
	if s.BotEnabled {
		ok, e := s.checkCapability(ctx, p, "information-query.bot", scope)
		if e != nil {
			return Capabilities{}, e
		}
		out.BotEnabled = ok
	}
	return out, nil
}

func fieldCapability(category string) string {
	if category == "refund_payee" {
		return "refund"
	}
	return category
}

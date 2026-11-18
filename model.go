// Package informationquery orchestrates authorized cross-module read interfaces.
package informationquery

import (
	"context"
	"github.com/StuHelper/stuhelper-platform/account"
	"github.com/StuHelper/stuhelper-platform/admin"
	"time"
)

var (
	ErrInvalid         = admin.ErrInvalid
	ErrForbidden       = admin.ErrForbidden
	ErrUnauthenticated = admin.ErrUnauthenticated
	ErrUnavailable     = admin.ErrUnavailable
)

// ErrorDetail wraps a base error with sanitized machine-readable diagnostics.
// Domain and Field carry only known enum identifiers and never echo query inputs.
type ErrorDetail struct {
	Base   error  `json:"-"`
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
	Domain string `json:"domain,omitempty"`
	Field  string `json:"field,omitempty"`
}

func (e *ErrorDetail) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != "" {
		return e.Code
	}
	if e.Base != nil {
		return e.Base.Error()
	}
	return "unavailable"
}

func (e *ErrorDetail) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Base
}

type Query struct {
	Kind    string      `json:"kind"`
	Value   string      `json:"value"`
	Scope   admin.Scope `json:"scope"`
	Domains []string    `json:"domains"`
	Fields  []string    `json:"fields"`
	Purpose string      `json:"purpose"`
	Limit   int         `json:"limit"`
	After   string      `json:"after"`
}

// String prevents accidental query-value disclosure through common log formatting.
func (Query) String() string     { return "informationquery.Query{redacted}" }
func (q Query) GoString() string { return q.String() }

type Field struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Value    string `json:"value"`
	Masked   bool   `json:"masked"`
}
type Record struct {
	ID        string      `json:"id"`
	Subject   string      `json:"subject"`
	Scope     admin.Scope `json:"scope"`
	Source    string      `json:"source"`
	Current   bool        `json:"current"`
	ChangedAt time.Time   `json:"changed_at"`
	Fields    []Field     `json:"fields"`
}
type Result struct {
	Groups             []CandidateGroup `json:"groups"`
	NextCursor         string           `json:"next_cursor"`
	UnavailableDomains []string         `json:"unavailable_domains"`
}

// Delivery is supplied by authenticated host middleware, never from JSON or headers.
// Bot adapters must bind the requesting account and actual conversation to this value.
type Delivery struct{ Channel, Group string }
type Authorizer interface {
	Evaluate(context.Context, account.Principal, string, admin.Scope) error
}

// Provider belongs to the owning business module. It must authorize the principal,
// restrict requested fields, filter by scope BEFORE pagination, and return stable IDs.
// Records retain binding source, revision time and current/historical status. Providers
// must never classify sensitive values as business fields or place them in identifiers.
// After is an exclusive stable record ID; return at most Limit records in ID order.
type Provider interface {
	Query(context.Context, account.Principal, Query) ([]Record, error)
}
type Audit struct {
	ID           string                   `json:"id"`
	Actor        string                   `json:"actor"`
	RequestID    string                   `json:"request_id"`
	Purpose      string                   `json:"purpose"`
	Scope        admin.Scope              `json:"scope"`
	Channel      string                   `json:"channel"`
	TargetGroup  string                   `json:"target_group"`
	Action       string                   `json:"action"`
	Result       string                   `json:"result"`
	Count        int                      `json:"count"`
	Targets      []string                 `json:"targets"`
	Fields       []string                 `json:"fields"`
	Basis        []string                 `json:"basis"`
	CreatedAt    time.Time                `json:"created_at"`
	Scopes       []admin.Scope            `json:"-"`
	TargetScopes map[string][]admin.Scope `json:"-"`
}
type AuditFilter struct {
	Scope        admin.Scope `json:"scope"`
	Purpose      string      `json:"purpose"`
	After        string      `json:"after"`
	Limit        int         `json:"limit"`
	Actor        string      `json:"actor,omitempty"`
	Target       string      `json:"target,omitempty"`
	Action       string      `json:"action,omitempty"`
	Result       string      `json:"result,omitempty"`
	Channel      string      `json:"channel,omitempty"`
	CreatedFrom  *time.Time  `json:"created_from,omitempty"`
	CreatedUntil *time.Time  `json:"created_until,omitempty"`
}
type AuditPage struct {
	Items      []Audit `json:"items"`
	NextCursor string  `json:"next_cursor"`
}
type Repository interface {
	Append(context.Context, Audit) error
	Read(context.Context, AuditFilter) (AuditPage, error)
}

// Lead is resolved only by the module that owns the identity facts.
type Lead struct {
	Kind, Value string
	Scope       admin.Scope
	Purpose     string
	Limit       int
	After       string
}

func (Lead) String() string     { return "informationquery.Lead{redacted}" }
func (l Lead) GoString() string { return l.String() }

type Candidate struct {
	Account   string      `json:"account"`
	Source    string      `json:"source"`
	Current   bool        `json:"current"`
	ChangedAt time.Time   `json:"changed_at"`
	Scope     admin.Scope `json:"scope"`
	Label     []Field     `json:"label"`
}
type CandidateGroup struct {
	Candidate Candidate `json:"candidate"`
	Items     []Record  `json:"items"`
}

type CapabilitiesRequest struct {
	Scope *admin.Scope `json:"scope,omitempty"`
}

type Capabilities struct {
	Scope            admin.Scope `json:"scope"`
	AllowedDomains   []string    `json:"allowed_domains"`
	AllowedFields    []string    `json:"allowed_fields"`
	AvailableDomains []string    `json:"available_domains"`
	AvailableKinds   []string    `json:"available_kinds"`
	AuditReadable    bool        `json:"audit_readable"`
	BotEnabled       bool        `json:"bot_enabled"`
}

// Resolver filters effective scope before stable exclusive pagination (maximum 50).
// Labels must be masked; identifiers and cursors must not contain raw lead values.
type Resolver interface {
	Resolve(context.Context, account.Principal, Lead) ([]Candidate, string, error)
}

// AuditPruner is exposed only to the separately authenticated maintenance process.
type AuditPruner interface {
	PruneAudit(ctx context.Context, before time.Time, limit int) (int, error)
}

// AuditRetentionMonitor inspects expired audit backlog using read-only maintenance privileges.
type AuditRetentionMonitor interface {
	PendingStats(ctx context.Context, before time.Time) (oldest time.Time, hasExpired bool, boundedCount int, err error)
}

type Stage string

const (
	StageAuth     Stage = "auth"
	StageResolve  Stage = "resolve"
	StageProvider Stage = "provider"
	StageContract Stage = "contract"
	StageAudit    Stage = "audit"
)

// Event carries strictly sanitized diagnostic telemetry. It cannot hold query
// values, candidate labels, or record field values.
type Event struct {
	RequestID string
	Stage     Stage
	Domain    string
	Kind      string
	Code      string
	Duration  time.Duration
}

type AuditHold struct {
	ID            string     `json:"id"`
	AuditID       string     `json:"audit_id,omitempty"`
	RequestID     string     `json:"request_id,omitempty"`
	TargetAccount string     `json:"target_account,omitempty"`
	Reason        string     `json:"reason"`
	CreatedBy     string     `json:"created_by"`
	ReviewAt      time.Time  `json:"review_at"`
	CreatedAt     time.Time  `json:"created_at"`
	ReleasedAt    *time.Time `json:"released_at,omitempty"`
	ReleasedBy    string     `json:"released_by,omitempty"`
	ReleaseReason string     `json:"release_reason,omitempty"`
}

type AuditHoldInput struct {
	AuditID       string
	RequestID     string
	TargetAccount string
	Reason        string
	CreatedBy     string
	ReviewAt      time.Time
}

type AuditHoldRelease struct {
	ID     string
	Actor  string
	Reason string
}

// AuditHoldManager records and releases per-object legal holds under a dedicated governance role.
type AuditHoldManager interface {
	CreateHold(ctx context.Context, in AuditHoldInput) (AuditHold, error)
	ReleaseHold(ctx context.Context, in AuditHoldRelease) (AuditHold, error)
	ListActiveHolds(ctx context.Context, after string, limit int) ([]AuditHold, string, error)
}

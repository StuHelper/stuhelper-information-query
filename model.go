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
	Items              []Record `json:"items"`
	NextCursor         string   `json:"next_cursor"`
	UnavailableDomains []string `json:"unavailable_domains"`
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
	ID          string      `json:"id"`
	Actor       string      `json:"actor"`
	RequestID   string      `json:"request_id"`
	Purpose     string      `json:"purpose"`
	Scope       admin.Scope `json:"scope"`
	Channel     string      `json:"channel"`
	TargetGroup string      `json:"target_group"`
	Action      string      `json:"action"`
	Result      string      `json:"result"`
	Count       int         `json:"count"`
	Targets     []string    `json:"targets"`
	Fields      []string    `json:"fields"`
	Basis       []string    `json:"basis"`
	CreatedAt   time.Time   `json:"created_at"`
}
type AuditFilter struct {
	Scope   admin.Scope `json:"scope"`
	Purpose string      `json:"purpose"`
	After   string      `json:"after"`
	Limit   int         `json:"limit"`
}
type AuditPage struct {
	Items      []Audit `json:"items"`
	NextCursor string  `json:"next_cursor"`
}
type Repository interface {
	Append(context.Context, Audit) error
	Read(context.Context, AuditFilter) (AuditPage, error)
}

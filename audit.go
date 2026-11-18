package informationquery

import (
	"github.com/StuHelper/stuhelper-platform/admin"
	"slices"
	"strings"
	"unicode"
)

func sanitizeString(v string, max int, keepTextWhitespace bool) string {
	v = strings.ToValidUTF8(v, "\uFFFD")
	var b strings.Builder
	b.Grow(min(len(v), max*4))
	count := 0
	for _, r := range v {
		if keepTextWhitespace {
			if isDisallowedTextControl(r) {
				continue
			}
		} else if unicode.IsControl(r) {
			continue
		}
		if count >= max {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

// SanitizeAudit normalizes an Audit entry so malformed inputs or nil slices never
// corrupt append-only storage or violate the OpenAPI AuditPage response schema.
func SanitizeAudit(a Audit) Audit {
	a.Actor = sanitizeString(a.Actor, 2048, false)
	a.RequestID = sanitizeString(a.RequestID, 128, false)
	a.Purpose = sanitizeString(a.Purpose, 512, true)
	if !a.Scope.Valid() {
		a.Scope = admin.Global
	}
	if !slices.Contains(auditChannels, a.Channel) {
		a.Channel = "unknown"
	}
	if a.Channel != "bot_group" {
		a.TargetGroup = ""
	} else {
		a.TargetGroup = sanitizeString(a.TargetGroup, 128, false)
	}
	if !slices.Contains(auditActions, a.Action) {
		a.Action = "unknown"
	}
	if a.Result == "forbidden" {
		a.Result = "denied"
	} else if !slices.Contains(auditResults, a.Result) {
		a.Result = "unknown"
	}
	if a.Count < 0 {
		a.Count = 0
	}
	targets := make([]string, 0, len(a.Targets))
	for _, t := range a.Targets {
		if ct := sanitizeString(t, 2048, false); ct != "" {
			targets = append(targets, ct)
		}
	}
	a.Targets = targets
	fields := make([]string, 0, len(a.Fields))
	for _, f := range a.Fields {
		if slices.Contains(categories, f) && !slices.Contains(fields, f) {
			fields = append(fields, f)
		}
	}
	a.Fields = fields
	basis := make([]string, 0, len(a.Basis))
	for _, item := range a.Basis {
		if cb := sanitizeString(item, 128, false); cb != "" && !slices.Contains(basis, cb) {
			basis = append(basis, cb)
		}
	}
	a.Basis = basis
	return a
}

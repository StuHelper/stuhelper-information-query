// Package httpapi accepts identity and delivery metadata from trusted middleware.
package httpapi

import (
	"encoding/json"
	"errors"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/StuHelper/stuhelper-platform/account"
	"io"
	"mime"
	"net/http"
	"slices"
)

type Identity func(*http.Request) (account.Principal, iq.Delivery, string)
type Handler struct {
	Service  *iq.Service
	Identity Identity
}

var allowedDomains = []string{"profiles", "verification", "catalog", "reviews", "resources", "billing", "groups"}
var allowedFields = []string{"identity", "document", "material", "refund_payee"}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return &iq.ErrorDetail{Base: iq.ErrInvalid, Code: iq.ErrInvalid.Error(), Reason: "invalid_parameter"}
	}
	if d.Decode(new(any)) != io.EOF {
		return &iq.ErrorDetail{Base: iq.ErrInvalid, Code: iq.ErrInvalid.Error(), Reason: "invalid_parameter"}
	}
	return nil
}
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	const queryPath = "/api/v1/information-query/query"
	const auditPath = "/api/v1/information-query/audit/query"
	if r.URL.Path != queryPath && r.URL.Path != auditPath {
		writeCode(w, 404, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeCode(w, 405, "method_not_allowed")
		return
	}
	if h.Service == nil || h.Identity == nil {
		write(w, nil, iq.ErrUnavailable)
		return
	}
	p, d, id := h.Identity(r)
	if !p.Valid() {
		write(w, nil, iq.ErrUnauthenticated)
		return
	}
	reject := h.Service.Reject
	if r.URL.Path == auditPath {
		reject = h.Service.RejectAudit
		if d.Channel != "admin" {
			write(w, nil, reject(r.Context(), p, id, d, &iq.ErrorDetail{Base: iq.ErrForbidden, Code: iq.ErrForbidden.Error(), Reason: "channel_forbidden"}))
			return
		}
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		if err = reject(r.Context(), p, id, d, iq.ErrInvalid); errors.Is(err, iq.ErrInvalid) {
			writeCode(w, 415, "unsupported_media_type")
		} else {
			write(w, nil, err)
		}
		return
	}
	var out any
	if r.URL.Path == auditPath {
		var f iq.AuditFilter
		if err = decode(w, r, &f); err == nil {
			out, err = h.Service.Audit(r.Context(), p, id, f)
		} else {
			err = reject(r.Context(), p, id, d, err)
		}
	} else {
		var q iq.Query
		if err = decode(w, r, &q); err == nil {
			out, err = h.Service.Query(r.Context(), p, id, d, q)
		} else {
			err = reject(r.Context(), p, id, d, err)
		}
	}
	write(w, out, err)
}
func writeCode(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
}
func write(w http.ResponseWriter, out any, err error) {
	if err != nil {
		status := 503
		code := "unavailable"
		for _, e := range []struct {
			err    error
			status int
		}{{iq.ErrInvalid, 400}, {iq.ErrUnauthenticated, 401}, {iq.ErrForbidden, 403}} {
			if errors.Is(err, e.err) {
				status = e.status
				code = e.err.Error()
			}
		}
		resp := iq.ErrorDetail{Code: code}
		var detail *iq.ErrorDetail
		if errors.As(err, &detail) && detail != nil {
			resp.Reason = detail.Reason
			if slices.Contains(allowedDomains, detail.Domain) {
				resp.Domain = detail.Domain
			}
			if slices.Contains(allowedFields, detail.Field) {
				resp.Field = detail.Field
			}
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

package postgres

import (
	"context"
	"errors"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// HoldStore manages legal holds using a dedicated governance database role
// granted SELECT, INSERT, UPDATE on information_query.audit_holds.
type HoldStore struct {
	Pool *pgxpool.Pool
	Now  func() time.Time
}

func validHoldToken(v string, maxBytes int) bool {
	return v != "" && len(v) <= maxBytes && utf8.ValidString(v) && !strings.ContainsFunc(v, unicode.IsControl)
}

func validHoldReason(v string) bool {
	return v != "" && utf8.ValidString(v) && utf8.RuneCountInString(v) <= 512 && len(v) <= 2048 && !strings.ContainsFunc(v, unicode.IsControl)
}

func (h HoldStore) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func scanHold(row pgx.Row) (iq.AuditHold, error) {
	var id int64
	var auditID *int64
	var out iq.AuditHold
	err := row.Scan(
		&id,
		&auditID,
		&out.RequestID,
		&out.TargetAccount,
		&out.Reason,
		&out.CreatedBy,
		&out.ReviewAt,
		&out.CreatedAt,
		&out.ReleasedAt,
		&out.ReleasedBy,
		&out.ReleaseReason,
	)
	if err != nil {
		return iq.AuditHold{}, err
	}
	out.ID = strconv.FormatInt(id, 10)
	if auditID != nil {
		out.AuditID = strconv.FormatInt(*auditID, 10)
	}
	out.ReviewAt = out.ReviewAt.UTC()
	out.CreatedAt = out.CreatedAt.UTC()
	if out.ReleasedAt != nil {
		utc := out.ReleasedAt.UTC()
		out.ReleasedAt = &utc
	}
	return out, nil
}

func (h HoldStore) CreateHold(ctx context.Context, in iq.AuditHoldInput) (iq.AuditHold, error) {
	if h.Pool == nil {
		return iq.AuditHold{}, iq.ErrUnavailable
	}
	if in.AuditID == "" && in.RequestID == "" && in.TargetAccount == "" {
		return iq.AuditHold{}, iq.ErrInvalid
	}
	var auditID *int64
	if in.AuditID != "" {
		parsed, err := strconv.ParseInt(in.AuditID, 10, 64)
		if err != nil || parsed <= 0 {
			return iq.AuditHold{}, iq.ErrInvalid
		}
		auditID = &parsed
	}
	if (in.RequestID != "" && !validHoldToken(in.RequestID, 128)) || (in.TargetAccount != "" && !validHoldToken(in.TargetAccount, 2048)) {
		return iq.AuditHold{}, iq.ErrInvalid
	}
	now := h.now()
	if !validHoldToken(in.CreatedBy, 2048) || !validHoldReason(in.Reason) || in.ReviewAt.IsZero() || !in.ReviewAt.After(now) {
		return iq.AuditHold{}, iq.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	row := h.Pool.QueryRow(ctx, `INSERT INTO information_query.audit_holds(
 audit_id,request_id,target_account,reason,created_by,review_at,created_at
) VALUES($1,$2,$3,$4,$5,$6,$7)
RETURNING id,audit_id,request_id,target_account,reason,created_by,review_at,created_at,released_at,released_by,release_reason`,
		auditID, in.RequestID, in.TargetAccount, in.Reason, in.CreatedBy, in.ReviewAt.UTC(), now)
	return scanHold(row)
}

func (h HoldStore) ReleaseHold(ctx context.Context, in iq.AuditHoldRelease) (iq.AuditHold, error) {
	if h.Pool == nil {
		return iq.AuditHold{}, iq.ErrUnavailable
	}
	holdID, err := strconv.ParseInt(in.ID, 10, 64)
	if err != nil || holdID <= 0 || !validHoldToken(in.Actor, 2048) || !validHoldReason(in.Reason) {
		return iq.AuditHold{}, iq.ErrInvalid
	}
	now := h.now()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	row := h.Pool.QueryRow(ctx, `UPDATE information_query.audit_holds
SET released_at=$2,released_by=$3,release_reason=$4
WHERE id=$1 AND released_at IS NULL
RETURNING id,audit_id,request_id,target_account,reason,created_by,review_at,created_at,released_at,released_by,release_reason`,
		holdID, now, in.Actor, in.Reason)
	out, err := scanHold(row)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return iq.AuditHold{}, err
	}
	// Idempotent replay: return existing released record if already released, or ErrInvalid if absent.
	existing, err := scanHold(h.Pool.QueryRow(ctx, `SELECT id,audit_id,request_id,target_account,reason,created_by,review_at,created_at,released_at,released_by,release_reason
FROM information_query.audit_holds WHERE id=$1`, holdID))
	if errors.Is(err, pgx.ErrNoRows) {
		return iq.AuditHold{}, iq.ErrInvalid
	}
	return existing, err
}

func (h HoldStore) ListActiveHolds(ctx context.Context, after string, limit int) ([]iq.AuditHold, string, error) {
	if h.Pool == nil {
		return nil, "", iq.ErrUnavailable
	}
	if limit < 1 || limit > 100 {
		return nil, "", iq.ErrInvalid
	}
	afterID := int64(0)
	if after != "" {
		parsed, err := strconv.ParseInt(after, 10, 64)
		if err != nil || parsed < 0 {
			return nil, "", iq.ErrInvalid
		}
		afterID = parsed
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := h.Pool.Query(ctx, `SELECT id,audit_id,request_id,target_account,reason,created_by,review_at,created_at,released_at,released_by,release_reason
FROM information_query.audit_holds
WHERE released_at IS NULL AND id > $1
ORDER BY id ASC
LIMIT $2`, afterID, limit)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := []iq.AuditHold{}
	for rows.Next() {
		item, scanErr := scanHold(rows)
		if scanErr != nil {
			return nil, "", scanErr
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].ID
	}
	return items, next, nil
}

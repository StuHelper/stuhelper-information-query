package postgres

import (
	"context"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// Maintenance uses a separate pool with SELECT/DELETE only. Never mount it in HTTP.
// RetentionMonths defaults to 12 calendar months. Hosts configure approved retention.
type Maintenance struct {
	Pool            *pgxpool.Pool
	RetentionMonths int
	Now             func() time.Time
}

const maxPendingStatsSample = 10001

func (m Maintenance) validateCutoff(before time.Time) error {
	months := m.RetentionMonths
	if months == 0 {
		months = 12
	}
	if months < 1 || months > 1200 || before.IsZero() {
		return iq.ErrInvalid
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	if before.After(now.AddDate(0, -months, 0)) {
		return iq.ErrInvalid
	}
	return nil
}

func (m Maintenance) PruneAudit(ctx context.Context, before time.Time, limit int) (int, error) {
	if m.Pool == nil {
		return 0, iq.ErrUnavailable
	}
	if limit < 1 || limit > 1000 {
		return 0, iq.ErrInvalid
	}
	if err := m.validateCutoff(before); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	result, err := m.Pool.Exec(ctx, `WITH expired AS (
 SELECT id FROM information_query.audit WHERE created_at < $1 ORDER BY created_at,id LIMIT $2
 ) DELETE FROM information_query.audit a USING expired e WHERE a.id=e.id`, before, limit)
	if err != nil {
		return 0, err
	}
	return int(result.RowsAffected()), nil
}

// PendingStats inspects the oldest unpruned audit timestamp and a bounded expired backlog
// count (capped at 10001) using only the maintenance role's read-only SELECT privilege.
func (m Maintenance) PendingStats(ctx context.Context, before time.Time) (oldest time.Time, hasExpired bool, boundedCount int, err error) {
	if m.Pool == nil {
		return time.Time{}, false, 0, iq.ErrUnavailable
	}
	if err = m.validateCutoff(before); err != nil {
		return time.Time{}, false, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var minAt *time.Time
	var count int
	err = m.Pool.QueryRow(ctx, `WITH bounded AS (
 SELECT created_at FROM information_query.audit WHERE created_at < $1 ORDER BY created_at,id LIMIT $2
 ) SELECT count(*), min(created_at) FROM bounded`, before, maxPendingStatsSample).Scan(&count, &minAt)
	if err != nil {
		return time.Time{}, false, 0, err
	}
	if count == 0 || minAt == nil {
		return time.Time{}, false, 0, nil
	}
	return minAt.UTC(), true, count, nil
}
